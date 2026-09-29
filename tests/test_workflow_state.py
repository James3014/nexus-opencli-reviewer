from __future__ import annotations

import json
from pathlib import Path

from reviewer.workflow_state import workflow_readback


IDENTITY = ["owner/repo", 7, "head", "base", "main"]


def write(root: Path, rel: str, value):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def semantic(state: str, aid: str = "a1"):
    return {
        "schema": "reviewer.semantic_attempt.v1",
        "attempt_id": aid,
        "review_identity": IDENTITY,
        "state": state,
        "retry_safe": state == "PREPARED",
    }


def pre_review():
    return {
        "schema": "reviewer.pre_review.v1",
        "attempt_id": "a1",
        "receipt_id": "receipt-semantic-1",
        "review_identity": IDENTITY,
        "claim_ceiling": "PRE_REVIEW_ONLY",
        "context_pack_sha256": "c",
        "prompt_sha256": "p",
        "outcome_unknown": False,
        "transport_result": "REVIEW_COMPLETED",
        "parse_result": "PARSED",
        "semantic_result": {},
    }


def publication_attempt():
    return {
        "schema": "reviewer.publication_attempt.v1",
        "publication_attempt_id": "pub-key-1",
        "review_identity": IDENTITY,
        "content_hash": "content-1",
        "state": "DISPATCHING",
    }


def publication_receipt():
    return {
        "schema": "reviewer.publication_receipt.v1",
        "publication_attempt_id": "pub-key-1",
        "review_identity": IDENTITY,
        "content_hash": "content-1",
        "state": "COMPLETED",
    }


def test_new_and_stable_operation_identity(tmp_path):
    first = workflow_readback(tmp_path, review_identity=IDENTITY, current_identity=IDENTITY)
    second = workflow_readback(tmp_path, review_identity=IDENTITY, current_identity=IDENTITY)
    assert first["state"] == "NEW"
    assert first["operation_id"] == second["operation_id"]


def test_restart_after_semantic_review_does_not_request_replay(tmp_path):
    write(tmp_path, "reviews/attempts/a1.json", semantic("COMPLETED"))
    write(tmp_path, "reviews/receipts/a1.json", pre_review())
    reviewed = workflow_readback(tmp_path, review_identity=IDENTITY, current_identity=IDENTITY)
    assert reviewed["state"] == "REVIEWED"
    assert reviewed["semantic_result_ids"] == ["receipt-semantic-1"]
    assert reviewed["replay_semantic_review"] is False


def test_outcome_unknown_blocks_instead_of_replaying(tmp_path):
    write(tmp_path, "reviews/attempts/a1.json", semantic("OUTCOME_UNKNOWN"))
    out = workflow_readback(tmp_path, review_identity=IDENTITY, current_identity=IDENTITY)
    assert out["state"] == "BLOCKED"
    assert out["requires_reconciliation"] is True
    assert out["replay_semantic_review"] is False


def test_identity_drift_is_stale(tmp_path):
    write(tmp_path, "reviews/attempts/a1.json", semantic("COMPLETED"))
    out = workflow_readback(
        tmp_path,
        review_identity=IDENTITY,
        current_identity=["owner/repo", 7, "new-head", "base", "main"],
    )
    assert out["state"] == "STALE"
    assert out["requires_reconciliation"] is True


def test_restart_after_publication_preserves_idempotency_key_and_no_replay(tmp_path):
    write(tmp_path, "reviews/receipts/a1.json", pre_review())
    write(tmp_path, "publication-attempts/p1.json", publication_attempt())
    pending = workflow_readback(tmp_path, review_identity=IDENTITY, current_identity=IDENTITY)
    assert pending["state"] == "PUBLISH_PENDING"
    assert pending["publication_idempotency_keys"] == ["pub-key-1"]
    assert pending["replay_publication"] is False

    write(tmp_path, "publication-receipts/p1.json", publication_receipt())
    published = workflow_readback(tmp_path, review_identity=IDENTITY, current_identity=IDENTITY)
    assert published["state"] == "PUBLISHED"
    assert published["publication_idempotency_keys"] == ["pub-key-1"]
    assert published["publication_content_hashes"] == ["content-1"]
    assert published["replay_publication"] is False
