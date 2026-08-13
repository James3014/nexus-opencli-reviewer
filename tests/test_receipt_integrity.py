import copy
import json

import pytest

from reviewer.receipt import persist_receipt, reusable_receipt, receipt_path


IDENTITY = ["o/r", 7, "head", "base", "main"]


def valid_receipt():
    return {
        "schema": "reviewer.pre_review.v1",
        "review_identity": list(IDENTITY),
        "context_pack_sha256": "ctx-a",
        "prompt_sha256": "prompt-a",
        "transport_result": "REVIEW_COMPLETED",
        "parse_result": "PARSED",
        "claim_ceiling": "PRE_REVIEW_ONLY",
        "outcome_unknown": False,
        "retry_safe": False,
        "semantic_result": {
            "schema": "reviewer.semantic_response.v1",
            "status": "PASS",
            "summary": "ok",
            "findings": [],
            "evidence_gaps": [],
        },
    }


def test_reuse_requires_exact_context_and_prompt_hashes(tmp_path):
    persist_receipt(tmp_path, valid_receipt())
    assert reusable_receipt(tmp_path, IDENTITY, context_sha256="ctx-a", prompt_sha256="prompt-a")
    assert reusable_receipt(tmp_path, IDENTITY, context_sha256="ctx-b") is None
    assert reusable_receipt(tmp_path, IDENTITY, prompt_sha256="prompt-b") is None
    assert reusable_receipt(tmp_path, [*IDENTITY[:-1], "other-main"], context_sha256="ctx-a", prompt_sha256="prompt-a") is None


@pytest.mark.parametrize("field,value", [
    ("schema", "reviewer.other.v1"),
    ("review_identity", ["o/r", 7, "other-head", "base", "main"]),
    ("context_pack_sha256", ""),
    ("prompt_sha256", None),
    ("claim_ceiling", "APPROVAL"),
    ("outcome_unknown", True),
    ("semantic_result", {"schema": "wrong", "status": "PASS"}),
])
def test_tampered_receipt_fails_closed(tmp_path, field, value):
    record = valid_receipt()
    record[field] = value
    persist_receipt(tmp_path, record)
    assert reusable_receipt(tmp_path, IDENTITY, context_sha256="ctx-a", prompt_sha256="prompt-a") is None


def test_atomic_persist_failure_preserves_previous_valid_receipt(tmp_path, monkeypatch):
    original = valid_receipt()
    path = persist_receipt(tmp_path, original)
    before = path.read_bytes()
    replacement = copy.deepcopy(original)
    replacement["prompt_sha256"] = "new-prompt"

    def interrupted_replace(*args, **kwargs):
        raise OSError("simulated interruption")

    monkeypatch.setattr("reviewer.receipt.os.replace", interrupted_replace)
    with pytest.raises(OSError):
        persist_receipt(tmp_path, replacement)
    assert path.read_bytes() == before
    assert reusable_receipt(tmp_path, IDENTITY, context_sha256="ctx-a", prompt_sha256="prompt-a")
