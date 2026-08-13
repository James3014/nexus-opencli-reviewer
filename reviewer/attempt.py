"""Crash-safe journal for semantic review attempts.

The journal is deliberately transport-agnostic.  Call :func:`prepare_attempt`,
then :func:`mark_dispatching` immediately before an external invocation, and
finally :func:`finish_attempt` when that invocation has a known result.
"""
from __future__ import annotations

import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "reviewer.semantic_attempt.v1"
PREPARED = "PREPARED"
DISPATCHING = "DISPATCHING"
COMPLETED = "COMPLETED"
FAILED = "FAILED"
OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
FINAL_STATES = frozenset({COMPLETED, FAILED, OUTCOME_UNKNOWN})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _attempt_path(root: str | os.PathLike[str], attempt_id: str) -> Path:
    path = Path(root) / "reviews" / "attempts" / f"{attempt_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _atomic_write(path: Path, value: dict[str, Any]) -> None:
    """Write JSON durably, replacing the old record only after fsync."""
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            # Directory fsync is unavailable on a few platforms/filesystems;
            # the file itself remains atomically replaced and durable.
            pass
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("INVALID_ATTEMPT_JOURNAL") from exc
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise ValueError("INVALID_ATTEMPT_JOURNAL")
    return value


def prepare_attempt(
    root: str | os.PathLike[str],
    review_identity: Iterable[Any],
    context_pack_sha256: str,
    prompt_sha256: str,
    provenance: dict[str, Any],
    *,
    attempt_id: str | None = None,
    now: str | None = None,
    safe_argv: Iterable[str] | None = None,
    executable: str | None = None,
    version: str | None = None,
    browser_profile: str | None = None,
    session_mode: str = "ephemeral",
) -> tuple[dict[str, Any], Path]:
    """Create a PREPARED record, refusing accidental attempt-id reuse."""
    ident = list(review_identity)
    if not ident or not isinstance(provenance, dict):
        raise ValueError("INVALID_ATTEMPT_INPUT")
    aid = attempt_id or str(uuid.uuid4())
    path = _attempt_path(root, aid)
    if path.exists():
        raise FileExistsError(path)
    timestamp = now or _now()
    record: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": aid,
        "state": PREPARED,
        "review_identity": ident,
        "context_pack_sha256": context_pack_sha256,
        "prompt_sha256": prompt_sha256,
        "provenance": provenance,
        "safe_argv": list(safe_argv or []),
        "opencli_executable": executable or provenance.get("executable", ""),
        "opencli_version": version or provenance.get("version", ""),
        "browser_profile": browser_profile or provenance.get("browser_profile", ""),
        "session_mode": session_mode,
        "prepared_at": timestamp,
        "started_at": timestamp,
        "dispatching_at": None,
        "finished_at": None,
        "retry_safe": True,
    }
    _atomic_write(path, record)
    return record, path


def mark_dispatching(
    path_or_root: str | os.PathLike[str],
    attempt_id: str | None = None,
    *,
    now: str | None = None,
) -> dict[str, Any]:
    """Atomically record DISPATCHING before making an external call."""
    path = Path(path_or_root) if attempt_id is None else _attempt_path(path_or_root, attempt_id)
    record = _load(path)
    if record.get("state") != PREPARED:
        raise ValueError("INVALID_ATTEMPT_TRANSITION")
    record["state"] = DISPATCHING
    record["dispatching_at"] = now or _now()
    record["retry_safe"] = False
    _atomic_write(path, record)
    return record


def finish_attempt(
    path_or_root: str | os.PathLike[str],
    state: str,
    *,
    attempt_id: str | None = None,
    result: Any = None,
    retry_safe: bool = False,
    now: str | None = None,
) -> dict[str, Any]:
    """Record a terminal result; only DISPATCHING attempts may finish."""
    if state not in FINAL_STATES:
        raise ValueError("INVALID_FINAL_STATE")
    path = Path(path_or_root) if attempt_id is None else _attempt_path(path_or_root, attempt_id)
    record = _load(path)
    if record.get("state") != DISPATCHING:
        raise ValueError("INVALID_ATTEMPT_TRANSITION")
    record["state"] = state
    record["finished_at"] = now or _now()
    record["retry_safe"] = bool(retry_safe) if state != OUTCOME_UNKNOWN else False
    if result is not None:
        record["result"] = result
    _atomic_write(path, record)
    return record


def discover_unfinished(root: str | os.PathLike[str]) -> list[dict[str, Any]]:
    """Return valid PREPARED/DISPATCHING records for restart reconciliation."""
    directory = Path(root) / "reviews" / "attempts"
    if not directory.exists():
        return []
    records: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        try:
            record = _load(path)
        except ValueError:
            continue
        if record.get("state") in (PREPARED, DISPATCHING):
            records.append(record)
    return records


def discover_for_identity(root: str | os.PathLike[str], review_identity: Iterable[Any],
                          *, context_pack_sha256: str | None = None,
                          prompt_sha256: str | None = None) -> list[dict[str, Any]]:
    """Return attempts for one exact physical and semantic identity."""
    directory = Path(root) / "reviews" / "attempts"
    if not directory.exists():
        return []
    identity = list(review_identity)
    records = []
    for path in sorted(directory.glob("*.json")):
        try:
            record = _load(path)
        except ValueError:
            continue
        if (record.get("review_identity") == identity
                and (context_pack_sha256 is None or record.get("context_pack_sha256") == context_pack_sha256)
                and (prompt_sha256 is None or record.get("prompt_sha256") == prompt_sha256)):
            records.append(record)
    return records


def reconcile_unfinished(
    root: str | os.PathLike[str],
    *,
    now: str | None = None,
) -> list[dict[str, Any]]:
    """Fail closed: unfinished attempts become OUTCOME_UNKNOWN, never retry-safe."""
    reconciled = []
    for record in discover_unfinished(root):
        path = _attempt_path(root, record["attempt_id"])
        if record["state"] == PREPARED:
            record["state"] = OUTCOME_UNKNOWN
            record["dispatching_at"] = record.get("dispatching_at") or now or _now()
        else:
            record["state"] = OUTCOME_UNKNOWN
        record["finished_at"] = now or _now()
        record["retry_safe"] = False
        record["reconciled"] = True
        _atomic_write(path, record)
        reconciled.append(record)
    return reconciled


def reconcile_attempt(root: str | os.PathLike[str], attempt_id: str, *, now: str | None = None) -> dict[str, Any]:
    """Reconcile one explicitly selected unfinished semantic attempt."""
    path = _attempt_path(root, attempt_id)
    record = _load(path)
    if record.get("state") not in (PREPARED, DISPATCHING):
        raise ValueError("ATTEMPT_NOT_UNFINISHED")
    record["state"] = OUTCOME_UNKNOWN
    record["finished_at"] = now or _now()
    record["retry_safe"] = False
    record["reconciled"] = True
    _atomic_write(path, record)
    return record


__all__ = [
    "SCHEMA", "PREPARED", "DISPATCHING", "COMPLETED", "FAILED", "OUTCOME_UNKNOWN",
    "prepare_attempt", "mark_dispatching", "finish_attempt", "discover_unfinished", "discover_for_identity",
    "reconcile_unfinished", "reconcile_attempt",
]
