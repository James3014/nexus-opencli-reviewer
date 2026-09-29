"""Session-independent semantic-review workflow state projection (issue #46).

Existing semantic attempt and publication journals remain the durable owners.
This module composes them into operator state without using browser or
conversation memory as authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .status import inventory

WORKFLOW_SCHEMA = "reviewer.workflow_state.v1"
CLAIM_CEILING = "PRE_REVIEW_ONLY"
STATES = ("NEW", "REVIEWING", "REVIEWED", "PUBLISH_PENDING", "PUBLISHED", "BLOCKED", "STALE")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _operation_id(identity: Sequence[Any]) -> str:
    return "reviewop_" + hashlib.sha256(_canonical(list(identity)).encode()).hexdigest()[:24]


def _same_identity(entry: dict[str, Any], identity: list[Any]) -> bool:
    return entry.get("review_identity") == identity


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return None
    return value if isinstance(value, dict) else None


def _durable_records(root: Path, directory: str, identity: list[Any]) -> list[dict[str, Any]]:
    base = root / directory
    if not base.exists():
        return []
    rows: list[dict[str, Any]] = []
    for path in sorted(base.glob("*.json")):
        value = _read_json(path)
        if value is not None and value.get("review_identity") == identity:
            rows.append(value)
    return rows


def workflow_readback(
    root: str | Path,
    *,
    review_identity: Sequence[Any],
    current_identity: Sequence[Any],
) -> dict[str, Any]:
    """Return machine-readable durable review state for any controlling session."""
    target = list(review_identity)
    current = list(current_identity)
    if len(target) != 5 or len(current) != 5:
        raise ValueError("review identity must be [repository, pr, head, base, current_main]")

    base = Path(root)
    state = inventory(base)
    matching_semantic = [
        item
        for bucket in state["semantic_attempts"].values()
        for item in bucket
        if _same_identity(item, target)
    ]
    semantic_receipts = _durable_records(base, "reviews/receipts", target)
    publication_attempts = _durable_records(base, "publication-attempts", target)
    publication_receipts = _durable_records(base, "publication-receipts", target)

    attempt_ids = sorted(
        {str(item.get("attempt_id")) for item in matching_semantic if item.get("attempt_id")}
    )
    semantic_result_ids = sorted(
        {
            str(row.get("receipt_id") or row.get("attempt_id"))
            for row in semantic_receipts
            if row.get("receipt_id") or row.get("attempt_id")
        }
    )
    publication_keys = sorted(
        {
            str(row.get("publication_attempt_id"))
            for row in publication_attempts + publication_receipts
            if row.get("publication_attempt_id")
        }
    )
    publication_content_hashes = sorted(
        {
            str(row.get("content_hash"))
            for row in publication_attempts + publication_receipts
            if row.get("content_hash")
        }
    )

    if current != target:
        workflow_state, reason = "STALE", "REVIEW_IDENTITY_DRIFT"
    elif publication_receipts:
        workflow_state, reason = "PUBLISHED", "PUBLICATION_READBACK_PRESENT"
    elif publication_attempts:
        workflow_state, reason = "PUBLISH_PENDING", "PUBLICATION_ATTEMPT_PRESENT"
    elif semantic_receipts:
        workflow_state, reason = "REVIEWED", "SEMANTIC_RECEIPT_PRESENT"
    elif any(item.get("state") in {"PREPARED", "DISPATCHING"} for item in matching_semantic):
        workflow_state, reason = "REVIEWING", "SEMANTIC_ATTEMPT_IN_PROGRESS"
    elif any(item.get("state") in {"FAILED", "OUTCOME_UNKNOWN"} for item in matching_semantic):
        workflow_state, reason = "BLOCKED", "SEMANTIC_RECONCILIATION_REQUIRED"
    else:
        workflow_state, reason = "NEW", "NO_DURABLE_REVIEW_EFFECT"

    result: dict[str, Any] = {
        "schema": WORKFLOW_SCHEMA,
        "operation_id": _operation_id(target),
        "attempt_ids": attempt_ids,
        "semantic_result_ids": semantic_result_ids,
        "publication_idempotency_keys": publication_keys,
        "publication_content_hashes": publication_content_hashes,
        "review_identity": target,
        "current_identity": current,
        "state": workflow_state,
        "reason": reason,
        "semantic_attempt_count": len(matching_semantic),
        "semantic_receipt_count": len(semantic_receipts),
        "publication_attempt_count": len(publication_attempts),
        "publication_receipt_count": len(publication_receipts),
        "replay_semantic_review": False if matching_semantic or semantic_receipts else workflow_state == "NEW",
        "replay_publication": False,
        "requires_reconciliation": workflow_state in {"BLOCKED", "STALE", "PUBLISH_PENDING"},
        "invalid_files": list(state["invalid_files"]),
        "claim_ceiling": CLAIM_CEILING,
    }
    result["workflow_hash"] = hashlib.sha256(_canonical(result).encode()).hexdigest()
    return result


def _identity_arg(raw: str) -> list[Any]:
    value = json.loads(raw)
    if not isinstance(value, list) or len(value) != 5:
        raise ValueError("identity JSON must be a five-element list")
    return value


def _main() -> int:
    parser = argparse.ArgumentParser(description="Read-only durable reviewer workflow doctor")
    parser.add_argument("--root", required=True)
    parser.add_argument("--review-identity-json", required=True)
    parser.add_argument("--current-identity-json", required=True)
    args = parser.parse_args()
    result = workflow_readback(
        args.root,
        review_identity=_identity_arg(args.review_identity_json),
        current_identity=_identity_arg(args.current_identity_json),
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())


__all__ = ["WORKFLOW_SCHEMA", "CLAIM_CEILING", "STATES", "workflow_readback"]
