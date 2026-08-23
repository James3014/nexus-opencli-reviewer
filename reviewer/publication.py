"""Durable, comment-only GitHub publication for PRE_REVIEW receipts.

The module deliberately keeps publication separate from semantic review.  A
publication is an automated advisory comment, never an approval or a review
state change.  Journal files are written before a network write so an
uncertain process can be reconciled without blindly sending a duplicate.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol
from .render import render_advisory
from .semantic import parse_response, SemanticParseError
from .receipt import ci_failure_evidence_manifest


class PublicationError(RuntimeError):
    pass


class PublicationTransport(Protocol):
    def create_comment(self, repo: str, pr_number: int, body: str) -> dict[str, Any]: ...
    def list_comments(self, repo: str, pr_number: int) -> list[dict[str, Any]]: ...


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        try:
            dfd = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def _attempt_dir(root: str | Path) -> Path:
    return Path(root) / "publication-attempts"


def _receipt_dir(root: str | Path) -> Path:
    return Path(root) / "publication-receipts"


def _identity(receipt: dict[str, Any]) -> tuple[str, int, str, str, str]:
    try:
        value = receipt["review_identity"]
        repo, number, head, base, main = value
        if (type(repo) is not str or not repo or type(number) is not int or number <= 0
                or any(type(item) is not str or not item for item in (head, base, main))):
            raise ValueError("identity domain")
        return repo, number, head, base, main
    except (KeyError, TypeError, ValueError) as exc:
        raise PublicationError("INVALID_PRE_REVIEW_IDENTITY") from exc


def _validate_receipt(receipt: dict[str, Any]) -> tuple[str, int, str, str, str]:
    identity = _identity(receipt)
    if receipt.get("schema") != "reviewer.pre_review.v1":
        raise PublicationError("PUBLICATION_REQUIRES_PRE_REVIEW")
    if receipt.get("claim_ceiling") != "PRE_REVIEW_ONLY":
        raise PublicationError("PUBLICATION_CLAIM_CEILING_INVALID")
    if receipt.get("outcome_unknown") is not False or receipt.get("retry_safe") is not False:
        raise PublicationError("PUBLICATION_SEMANTIC_OUTCOME_INVALID")
    if not receipt.get("receipt_id") or not receipt.get("context_pack_sha256") or not receipt.get("prompt_sha256"):
        raise PublicationError("PUBLICATION_RECEIPT_IDENTITY_INCOMPLETE")
    if receipt.get("transport_result") != "REVIEW_COMPLETED" or receipt.get("parse_result") != "PARSED":
        raise PublicationError("PUBLICATION_REQUIRES_SEMANTIC_RESULT")
    result = receipt.get("semantic_result")
    if not isinstance(result, dict) or result.get("schema") != "reviewer.semantic_response.v1":
        raise PublicationError("PUBLICATION_REQUIRES_SEMANTIC_RESULT")
    status = result.get("status")
    ci = receipt.get("ci_failure_evidence")
    if status not in {"PASS", "FINDINGS"}:
        if status == "BLOCKED" and ci is not None:
            pass
        else:
            raise PublicationError("PUBLICATION_STATUS_NOT_ELIGIBLE")
    if (not isinstance(result.get("summary"), str)
            or not isinstance(result.get("findings"), list)
            or not isinstance(result.get("evidence_gaps"), list)):
        raise PublicationError("PUBLICATION_SEMANTIC_RESULT_INVALID")
    try:
        parse_response(json.dumps(result, sort_keys=True, separators=(",", ":")))
    except SemanticParseError as exc:
        raise PublicationError("PUBLICATION_SEMANTIC_RESULT_INVALID") from exc
    if ci is not None:
        try:
            ci_failure_evidence_manifest(ci)
        except ValueError as exc:
            raise PublicationError("PUBLICATION_CI_EVIDENCE_INVALID") from exc
        if ci.get("review_identity") != list(identity):
            raise PublicationError("PUBLICATION_CI_EVIDENCE_IDENTITY_MISMATCH")
    return identity


def render_body(receipt: dict[str, Any], *, attempt_id: str, content_hash: str | None = None) -> str:
    identity = _identity(receipt)
    result = receipt["semantic_result"]
    return render_advisory(result, reviewed_head=identity[2], attempt_id=attempt_id,
                           content_hash=content_hash or "pending",
                           ci_failure_evidence=receipt.get("ci_failure_evidence"),
                           review_identity=identity)


def _content_hash(receipt: dict[str, Any], attempt_id: str) -> tuple[str, str]:
    provisional = render_body(receipt, attempt_id=attempt_id)
    digest = hashlib.sha256(provisional.encode()).hexdigest()
    body = render_body(receipt, attempt_id=attempt_id, content_hash=digest)
    # The marker is the hash of the marker-free body; hashing the final body
    # would be circular because the final body contains that marker.
    return digest, body


def _stable_attempt_id(receipt: dict[str, Any]) -> str:
    """Derive a retry-stable operation id for one exact semantic result."""
    material = json.dumps(
        {"review_identity": receipt["review_identity"], "receipt_id": receipt["receipt_id"],
         "context_pack_sha256": receipt["context_pack_sha256"],
         "prompt_sha256": receipt["prompt_sha256"], "semantic_result": receipt["semantic_result"],
         "ci_failure_evidence": receipt.get("ci_failure_evidence")},
        sort_keys=True, separators=(",", ":"),
    ).encode()
    return hashlib.sha256(material).hexdigest()[:32]


def _matches(comment: dict[str, Any], marker: str) -> bool:
    return marker in str(comment.get("body", ""))


def _fresh_identity(transport: Any, identity: tuple[str, int, str, str, str]) -> tuple[str, int, str, str, str]:
    repo, number, *_ = identity
    if not hasattr(transport, "get_pr") or not hasattr(transport, "get_ref"):
        raise PublicationError("PUBLICATION_REBIND_REQUIRED")
    pr = transport.get_pr(repo, number)
    main = transport.get_ref(repo, "main").get("object", {}).get("sha", "")
    return (repo, number, (pr.get("head") or {}).get("sha", ""),
            (pr.get("base") or {}).get("sha", ""), main)


def _find_receipt(root: str | Path, identity: tuple[str, int, str, str, str], content_hash: str) -> Path | None:
    for path in _receipt_dir(root).glob("*.json"):
        try:
            value = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if (value.get("schema") == "reviewer.publication_receipt.v1"
                and value.get("claim_ceiling") == "PRE_REVIEW_ONLY"
                and value.get("review_identity") == list(identity)
                and value.get("reviewed_head") == identity[2]
                and value.get("content_hash") == content_hash
                and value.get("state") == "COMPLETED"):
            return path
    return None


def _finalize(root: str | Path, attempt: dict[str, Any], comment: dict[str, Any], evidence: str) -> Path:
    attempt_id = attempt["publication_attempt_id"]
    value = {
        "schema": "reviewer.publication_receipt.v1",
        "publication_attempt_id": attempt_id,
        "semantic_receipt_id": attempt.get("semantic_receipt_id"),
        "repository": attempt["repository"],
        "pr_number": attempt["pr_number"],
        "review_identity": attempt["review_identity"],
        "reviewed_head": attempt["review_identity"][2],
        "content_hash": attempt["content_hash"],
        "comment_id": comment.get("id"),
        "url": comment.get("html_url") or comment.get("url"),
        "created_at": comment.get("created_at") or _now(),
        "reconciliation_evidence": evidence,
        "state": "COMPLETED",
        "claim_ceiling": "PRE_REVIEW_ONLY",
    }
    path = _receipt_dir(root) / f"{attempt_id}.json"
    _atomic_json(path, value)
    attempt["state"] = "COMPLETED"
    attempt["retry_safe"] = False
    attempt["finished_at"] = _now()
    _atomic_json(_attempt_dir(root) / f"{attempt_id}.json", attempt)
    return path


def _reconcile_attempt(root: str | Path, transport: PublicationTransport, attempt: dict[str, Any]) -> Path:
    if (attempt.get("schema") != "reviewer.publication_attempt.v1"
            or attempt.get("state") not in {"DISPATCHING", "OUTCOME_UNKNOWN"}
            or attempt.get("retry_safe") is not False
            or attempt.get("publication_type") != "COMMENT"
            or attempt.get("claim_ceiling") != "PRE_REVIEW_ONLY"):
        raise PublicationError("PUBLICATION_ATTEMPT_STATE_INVALID")
    identity = tuple(attempt["review_identity"])
    current = _fresh_identity(transport, identity)  # type: ignore[arg-type]
    if current != identity:
        raise PublicationError("PUBLICATION_REBIND_REQUIRED")
    marker = f"reviewer-publication-v1:{attempt['publication_attempt_id']}:{attempt['content_hash']}"
    comments = transport.list_comments(attempt["repository"], attempt["pr_number"])
    matches = [comment for comment in comments if _matches(comment, marker)]
    if len(matches) > 1:
        raise PublicationError("PUBLICATION_DUPLICATE_DETECTED")
    if not matches:
        raise PublicationError("PUBLICATION_RECONCILIATION_REQUIRED")
    return _finalize(root, attempt, matches[0], "readback_existing")


def publish_review(root: str | Path, transport: PublicationTransport, receipt: dict[str, Any], *, attempt_id: str | None = None) -> Path:
    """Publish one eligible receipt, or reconcile an unfinished publication."""
    identity = _validate_receipt(receipt)
    # Normal re-runs must address the same operation.  An explicit id is only
    # for recovery/tests; the product path uses this deterministic id.
    attempt_id = attempt_id or _stable_attempt_id(receipt)
    content_hash, body = _content_hash(receipt, attempt_id)
    existing = _find_receipt(root, identity, content_hash)
    if existing:
        current = _fresh_identity(transport, identity)
        if current != identity:
            raise PublicationError("PUBLICATION_REBIND_REQUIRED")
        marker = f"reviewer-publication-v1:{attempt_id}:{content_hash}"
        matches = [comment for comment in transport.list_comments(identity[0], identity[1])
                   if _matches(comment, marker)]
        if len(matches) > 1:
            raise PublicationError("PUBLICATION_DUPLICATE_DETECTED")
        if not matches:
            raise PublicationError("PUBLICATION_RECONCILIATION_REQUIRED")
        return existing
    directory = _attempt_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{attempt_id}.json"
    if path.exists():
        try:
            attempt = json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            raise PublicationError("PUBLICATION_ATTEMPT_CORRUPT") from exc
        if (attempt.get("schema") != "reviewer.publication_attempt.v1"
                or attempt.get("publication_attempt_id") != attempt_id
                or attempt.get("review_identity") != list(identity)
                or attempt.get("content_hash") != content_hash
                or attempt.get("publication_type") != "COMMENT"
                or attempt.get("claim_ceiling") != "PRE_REVIEW_ONLY"):
            raise PublicationError("PUBLICATION_ATTEMPT_ID_COLLISION")
        if attempt.get("state") == "DISPATCHING":
            return _reconcile_attempt(root, transport, attempt)
        if attempt.get("state") in {"OUTCOME_UNKNOWN", "COMPLETED", "FAILED"}:
            raise PublicationError("PUBLICATION_RECONCILIATION_REQUIRED")
        if attempt.get("state") != "PREPARED" or attempt.get("retry_safe") is not True:
            raise PublicationError("PUBLICATION_ATTEMPT_STATE_INVALID")
    current = _fresh_identity(transport, identity)
    if current != identity:
        raise PublicationError("PUBLICATION_REBIND_REQUIRED")
    attempt = {
        "schema": "reviewer.publication_attempt.v1",
        "publication_attempt_id": attempt_id,
        "semantic_receipt_id": receipt.get("receipt_id") or receipt.get("review_identity"),
        "repository": identity[0], "pr_number": identity[1],
        "review_identity": list(identity), "content_hash": content_hash,
        "publication_type": "COMMENT", "target": f"issues/{identity[1]}/comments",
        "started_at": _now(), "state": "PREPARED", "retry_safe": True,
        "claim_ceiling": "PRE_REVIEW_ONLY",
    }
    _atomic_json(path, attempt)
    marker = f"reviewer-publication-v1:{attempt_id}:{content_hash}"
    comments = transport.list_comments(identity[0], identity[1])
    matches = [comment for comment in comments if _matches(comment, marker)]
    if len(matches) > 1:
        raise PublicationError("PUBLICATION_DUPLICATE_DETECTED")
    if matches:
        return _finalize(root, attempt, matches[0], "readback_before_write")
    attempt["state"] = "DISPATCHING"
    attempt["retry_safe"] = False
    attempt["dispatched_at"] = _now()
    _atomic_json(path, attempt)
    try:
        comment = transport.create_comment(identity[0], identity[1], body)
    except Exception as exc:
        attempt["state"] = "OUTCOME_UNKNOWN"
        attempt["error"] = type(exc).__name__
        _atomic_json(path, attempt)
        raise PublicationError("PUBLICATION_RECONCILIATION_REQUIRED") from exc
    if not comment:
        return _reconcile_attempt(root, transport, attempt)
    # Always read back the exact marker after a successful response.  This
    # keeps a transport response from being mistaken for durable GitHub state.
    try:
        readback = [c for c in transport.list_comments(identity[0], identity[1]) if _matches(c, marker)]
    except Exception as exc:
        attempt["state"] = "OUTCOME_UNKNOWN"
        attempt["error"] = type(exc).__name__
        _atomic_json(path, attempt)
        raise PublicationError("PUBLICATION_RECONCILIATION_REQUIRED") from exc
    if len(readback) > 1:
        raise PublicationError("PUBLICATION_DUPLICATE_DETECTED")
    if not readback:
        raise PublicationError("PUBLICATION_RECONCILIATION_REQUIRED")
    return _finalize(root, attempt, readback[0], "write_then_readback")


def reconcile_publication(root: str | Path, transport: PublicationTransport, attempt_id: str) -> Path:
    path = _attempt_dir(root) / f"{attempt_id}.json"
    try:
        attempt = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise PublicationError("PUBLICATION_ATTEMPT_NOT_FOUND") from exc
    return _reconcile_attempt(root, transport, attempt)
