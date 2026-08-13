"""Read-only inventory of reviewer state for operational status surfaces."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .attempt import COMPLETED, DISPATCHING, FAILED, OUTCOME_UNKNOWN, PREPARED


def _read(path: Path) -> dict[str, Any] | list[Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, (dict, list)) else None
    except (OSError, ValueError, UnicodeError):
        return None


def _entry(value: dict[str, Any], path: Path) -> dict[str, Any]:
    """Expose only stable operational fields, including exact identity."""
    return {
        "path": str(path),
        "schema": value.get("schema"),
        "attempt_id": value.get("attempt_id"),
        "review_identity": value.get("review_identity"),
        "state": value.get("state"),
        "transport_result": value.get("transport_result"),
        "parse_result": value.get("parse_result"),
        "outcome_unknown": value.get("outcome_unknown"),
        "retry_safe": value.get("retry_safe"),
    }


def inventory(root: str | Path) -> dict[str, Any]:
    """Return a deterministic, fail-closed state inventory without mutation.

    Malformed JSON is never surfaced as live state: it is counted under
    ``invalid_files`` and omitted from all valid inventories.
    """
    base = Path(root)
    result: dict[str, Any] = {
        "schema": "reviewer.status.v1",
        "root": str(base),
        "latest_scans": [],
        "queues": [],
        "semantic_attempts": {"unfinished": [], "completed": [], "failed": [], "outcome_unknown": []},
        "pre_review_receipts": [],
        "publication_attempts": [],
        "publication_receipts": [],
        "invalid_files": [],
    }
    if not base.exists():
        return result
    for path in sorted(base.rglob("*.json")):
        value = _read(path)
        if value is None:
            result["invalid_files"].append(str(path))
            continue
        name = path.name
        schema = value.get("schema") if isinstance(value, dict) else None
        if name == "latest-scan.json" and isinstance(value, dict):
            result["latest_scans"].append({"path": str(path), **{k: value.get(k) for k in ("repository", "observed_at", "current_main_sha")}})
        elif name == "queue-state.json" and isinstance(value, list):
            result["queues"].append({"path": str(path), "identities": value})
        elif schema == "reviewer.semantic_attempt.v1" and isinstance(value, dict):
            item = _entry(value, path)
            state = value.get("state")
            if state in (PREPARED, DISPATCHING): result["semantic_attempts"]["unfinished"].append(item)
            elif state == COMPLETED: result["semantic_attempts"]["completed"].append(item)
            elif state == FAILED: result["semantic_attempts"]["failed"].append(item)
            elif state == OUTCOME_UNKNOWN: result["semantic_attempts"]["outcome_unknown"].append(item)
            else: result["invalid_files"].append(str(path))
        elif schema == "reviewer.pre_review.v1" and isinstance(value, dict):
            valid = (
                isinstance(value.get("review_identity"), list)
                and value.get("claim_ceiling") == "PRE_REVIEW_ONLY"
                and value.get("context_pack_sha256") and value.get("prompt_sha256")
                and value.get("outcome_unknown") is False
                and value.get("transport_result") == "REVIEW_COMPLETED"
                and value.get("parse_result") == "PARSED"
                and isinstance(value.get("semantic_result"), dict)
            )
            if valid: result["pre_review_receipts"].append(_entry(value, path))
            else: result["invalid_files"].append(str(path))
        elif "publication" in str(path).lower():
            if isinstance(value, dict) and ("attempt" in str(schema).lower() or "attempt" in name.lower()):
                result["publication_attempts"].append(_entry(value, path))
            elif isinstance(value, dict):
                result["publication_receipts"].append(_entry(value, path))
    return result


status = inventory

__all__ = ["inventory", "status"]
