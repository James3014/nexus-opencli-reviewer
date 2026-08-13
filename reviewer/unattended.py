"""Durable, serial unattended review scheduler.

This module is intentionally transport-neutral.  Discovery and the existing
``review_ready``/``publish_review`` product-path functions are supplied as
callbacks, while this layer owns polling, bootstrap admission, persistence and
replay safety.  It never guesses whether an external semantic call happened:
an unknown attempt is persisted and blocks replay until reconciled.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping


SCHEMA = "reviewer.unattended_service.v1"
STATE = "service-state.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _atomic(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        try:
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            pass
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _identity(value: Any) -> tuple[Any, ...]:
    """Normalize an exact identity without dropping context binding."""
    if isinstance(value, Mapping):
        value = value.get("review_identity") or value.get("identity")
    if not isinstance(value, (tuple, list)) or len(value) < 5:
        raise ValueError("REVIEW_IDENTITY_INCOMPLETE")
    return tuple(value)


def _key(identity: Iterable[Any], context_sha256: str = "", prompt_sha256: str = "") -> str:
    material = {"review_identity": list(identity), "context_pack_sha256": context_sha256,
                "prompt_sha256": prompt_sha256}
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class ServicePolicy:
    """Admission and retry controls; conservative defaults avoid call storms."""

    poll_interval_seconds: float = 60.0
    max_retries: int = 3
    backoff_seconds: float = 30.0
    bootstrap_canary: bool = False


class ServiceStateStore:
    """Atomic JSON state store suitable for a user-local service."""

    def __init__(self, root: str | os.PathLike[str]):
        self.root = Path(root)
        self.path = self.root / STATE

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"schema": SCHEMA, "version": 1, "bootstrapped": False,
                    "baseline": {}, "queue": {}, "attempts": {},
                    "last_scan": None, "next_scan": None, "status": "NEW"}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeError) as exc:
            raise RuntimeError("SERVICE_STATE_INVALID") from exc
        if not isinstance(value, dict) or value.get("schema") != SCHEMA:
            raise RuntimeError("SERVICE_STATE_INVALID")
        return value

    def save(self, state: Mapping[str, Any]) -> None:
        value = dict(state)
        value["schema"] = SCHEMA
        value["version"] = 1
        _atomic(self.path, value)


class UnattendedReviewService:
    """Poll, queue and execute at most one semantic identity per invocation.

    ``discover`` returns mappings (or Classification-like objects) containing
    an exact ``review_identity`` and ``disposition``.  ``review`` receives the
    identity and must return a PRE_REVIEW receipt/result.  ``publish`` receives
    that result and performs the existing advisory publication path.
    """

    def __init__(self, *, repository: str, discover: Callable[[], Iterable[Any]],
                 review: Callable[[tuple[Any, ...]], Any],
                 publish: Callable[[tuple[Any, ...], Any], Any],
                 reconcile: Callable[[tuple[Any, ...]], Any] | None = None,
                 root: str | os.PathLike[str] = ".reviewer-state/unattended",
                 policy: ServicePolicy | None = None,
                 clock: Callable[[], float] = time.time):
        self.repository = repository
        self.discover = discover
        self.review = review
        self.publish = publish
        self.reconcile = reconcile
        self.store = ServiceStateStore(root)
        self.policy = policy or ServicePolicy()
        self.clock = clock

    @staticmethod
    def _record(value: Any) -> dict[str, Any]:
        if isinstance(value, Mapping):
            record = dict(value)
            ident = _identity(record)
            disposition = str(record.get("disposition", ""))
        else:
            ident = _identity(getattr(value, "review_identity", None))
            disposition = str(getattr(getattr(value, "disposition", ""), "value", getattr(value, "disposition", "")))
            record = {"review_identity": list(ident), "disposition": disposition}
        record["review_identity"] = list(ident)
        record["identity_key"] = _key(ident, str(record.get("context_pack_sha256", "")),
                                       str(record.get("prompt_sha256", "")))
        record["disposition"] = disposition
        return record

    def _eligible(self, record: Mapping[str, Any]) -> bool:
        return str(record.get("disposition", "")).upper() == "REVIEW_READY"

    def _discover(self, state: dict[str, Any]) -> list[dict[str, Any]]:
        records = [self._record(item) for item in self.discover()]
        now = _now()
        state["last_scan"] = now
        state["next_scan"] = self.clock() + self.policy.poll_interval_seconds
        if not state.get("bootstrapped"):
            eligible = sorted((r for r in records if self._eligible(r)), key=lambda r: tuple(r["review_identity"])[1:])
            state["baseline"] = {r["identity_key"]: r for r in records}
            state["bootstrapped"] = True
            if self.policy.bootstrap_canary and eligible:
                self._enqueue(state, eligible[0], reason="bootstrap_canary")
            return records
        baseline = state.setdefault("baseline", {})
        by_pr = {int(r.get("review_identity", [None, -1])[1]): r for r in baseline.values()
                 if isinstance(r, Mapping) and len(r.get("review_identity", [])) >= 2}
        for record in records:
            key = record["identity_key"]
            # A new head/base/main/context identity is a new task, even when
            # the PR number was observed during an earlier polling cycle.
            previous = baseline.get(key) or by_pr.get(int(record["review_identity"][1]))
            if key not in baseline:
                baseline[key] = record
                if self._eligible(record):
                    reason = "new_identity"
                    if previous and previous.get("review_identity", [None, None, None])[2] != record["review_identity"][2]:
                        reason = "head_changed"
                    elif previous and not self._eligible(previous):
                        reason = "eligibility_changed"
                    self._enqueue(state, record, reason=reason)
            elif previous and not self._eligible(previous) and self._eligible(record):
                baseline[key] = record
                self._enqueue(state, record, reason="eligibility_changed")
            else:
                baseline[key] = record
        return records

    def _enqueue(self, state: dict[str, Any], record: Mapping[str, Any], *, reason: str) -> None:
        key = str(record["identity_key"])
        queue = state.setdefault("queue", {})
        existing = queue.get(key)
        if existing and existing.get("state") in {"published", "complete", "semantic_completed", "semantic_failed", "outcome_unknown"}:
            return
        if existing:
            return
        queue[key] = {"review_identity": list(record["review_identity"]), "record": dict(record),
                      "state": "queued", "reason": reason, "attempts": 0,
                      "next_action_at": 0.0, "updated_at": _now()}

    def _next(self, state: Mapping[str, Any]) -> tuple[str, dict[str, Any]] | None:
        now = self.clock()
        candidates = []
        for key, item in state.get("queue", {}).items():
            if item.get("state") in {"queued", "retry_wait", "publication_pending"} and float(item.get("next_action_at", 0)) <= now:
                candidates.append((str(key), item))
        return sorted(candidates, key=lambda pair: pair[0])[0] if candidates else None

    def run_once(self) -> dict[str, Any]:
        state = self.store.load()
        interrupted = [item for item in state.get("queue", {}).values()
                       if item.get("state") in {"semantic_prepared", "publication_uncertain", "outcome_unknown"}]
        if interrupted:
            state["status"] = "RECONCILIATION_REQUIRED"
            self.store.save(state)
            return {"status": "RECONCILIATION_REQUIRED", "identity": interrupted[0].get("review_identity")}
        try:
            self._discover(state)
        except Exception as exc:
            state["status"] = "DEGRADED"
            state["last_error"] = type(exc).__name__
            state["last_error_detail"] = str(exc)[:500]
            self.store.save(state)
            return {"status": "DISCOVERY_FAILED", "error": type(exc).__name__,
                    "detail": str(exc)[:500]}
        selected = self._next(state)
        if selected is None:
            state["status"] = "IDLE"
            self.store.save(state)
            return {"status": "IDLE", "queued": len(state.get("queue", {}))}
        key, item = selected
        identity = tuple(item["review_identity"])
        if item.get("state") == "publication_pending":
            try:
                result = self.publish(identity, item.get("semantic_result"))
                item["state"] = "published"; item["publication_result"] = result
                item["updated_at"] = _now(); state["status"] = "PUBLISHED"
            except Exception as exc:
                uncertain = bool(getattr(exc, "outcome_unknown", False)) or any(
                    marker in str(exc).upper() for marker in ("UNCERTAIN", "RECONCILIATION", "OUTCOME_UNKNOWN")
                )
                item["state"] = "publication_uncertain" if uncertain else "retry_wait"
                item["last_error"] = type(exc).__name__
                item["retry_safe"] = not uncertain
                if uncertain:
                    state["status"] = "RECONCILIATION_REQUIRED"
                else:
                    item["next_action_at"] = self.clock() + self.policy.backoff_seconds
                    state["status"] = "PUBLICATION_RETRY_WAIT"
            self.store.save(state)
            return {"status": state["status"], "identity": list(identity)}
        item["attempts"] = int(item.get("attempts", 0)) + 1
        try:
            result = self.review(identity)
        except Exception as exc:
            # The callback is responsible for journaling dispatch uncertainty.
            # An explicit marker lets it block replay; ordinary pre-dispatch
            # operational errors can be retried with bounded backoff.
            unknown = bool(getattr(exc, "outcome_unknown", False)) or "UNKNOWN" in str(exc).upper()
            if unknown:
                item["state"] = "outcome_unknown"; item["retry_safe"] = False
                state["status"] = "RECONCILIATION_REQUIRED"
            elif item["attempts"] <= self.policy.max_retries:
                item["state"] = "retry_wait"; item["next_action_at"] = self.clock() + self.policy.backoff_seconds * (2 ** (item["attempts"] - 1))
                state["status"] = "RETRY_WAIT"
            else:
                item["state"] = "semantic_failed"; state["status"] = "SEMANTIC_FAILED"
            item["last_error"] = type(exc).__name__; item["updated_at"] = _now(); self.store.save(state)
            return {"status": state["status"], "identity": list(identity), "error": type(exc).__name__}
        item["semantic_result"] = result; item["state"] = "publication_pending"; item["updated_at"] = _now()
        self.store.save(state)
        try:
            published = self.publish(identity, result)
            item["state"] = "complete"; item["publication_result"] = published
            item["updated_at"] = _now(); state["status"] = "COMPLETE"
        except Exception as exc:
            uncertain = bool(getattr(exc, "outcome_unknown", False)) or any(
                marker in str(exc).upper() for marker in ("UNCERTAIN", "RECONCILIATION", "OUTCOME_UNKNOWN")
            )
            item["state"] = "publication_uncertain" if uncertain else "retry_wait"
            item["last_error"] = type(exc).__name__; item["retry_safe"] = not uncertain
            if uncertain:
                state["status"] = "RECONCILIATION_REQUIRED"
            else:
                item["next_action_at"] = self.clock() + self.policy.backoff_seconds
                state["status"] = "PUBLICATION_RETRY_WAIT"
        self.store.save(state)
        return {"status": state["status"], "identity": list(identity)}

    def status(self) -> dict[str, Any]:
        state = self.store.load()
        return {"schema": SCHEMA, "repository": self.repository, "status": state.get("status"),
                "last_scan": state.get("last_scan"), "next_scan": state.get("next_scan"),
                "queued": sum(1 for x in state.get("queue", {}).values() if x.get("state") in {"queued", "retry_wait", "publication_pending"}),
                "blocked": sum(1 for x in state.get("queue", {}).values() if x.get("state") in {"semantic_prepared", "outcome_unknown", "publication_uncertain"}),
                "queue": state.get("queue", {})}


__all__ = ["SCHEMA", "ServicePolicy", "ServiceStateStore", "UnattendedReviewService"]
