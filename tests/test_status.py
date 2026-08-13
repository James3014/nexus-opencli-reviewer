import json

from reviewer.attempt import COMPLETED, mark_dispatching, prepare_attempt, finish_attempt
from reviewer.status import inventory


def test_inventory_reports_scans_attempts_and_valid_receipts(tmp_path):
    scan = tmp_path / "repo"; scan.mkdir()
    (scan / "latest-scan.json").write_text(json.dumps({"repository": "o/r", "current_main_sha": "m"}))
    (scan / "queue-state.json").write_text(json.dumps([["o/r", 1, "h", "b", "m"]]))
    _, path = prepare_attempt(tmp_path, ["o/r", 1, "h", "b", "m"], "ctx", "prompt", {}, attempt_id="a")
    mark_dispatching(path); finish_attempt(path, COMPLETED)
    (tmp_path / "reviews" / "receipt.json").write_text(json.dumps({
        "schema": "reviewer.pre_review.v1", "review_identity": ["o/r", 1, "h", "b", "m"],
        "claim_ceiling": "PRE_REVIEW_ONLY", "context_pack_sha256": "c", "prompt_sha256": "p",
        "outcome_unknown": False, "transport_result": "REVIEW_COMPLETED", "parse_result": "PARSED",
        "semantic_result": {"schema": "reviewer.semantic_response.v1"},
    }))
    out = inventory(tmp_path)
    assert out["schema"] == "reviewer.status.v1"
    assert len(out["latest_scans"]) == len(out["queues"]) == 1
    assert out["semantic_attempts"]["completed"][0]["review_identity"] == ["o/r", 1, "h", "b", "m"]
    assert len(out["pre_review_receipts"]) == 1


def test_inventory_fails_closed_on_malformed_and_unfinished(tmp_path):
    bad = tmp_path / "bad.json"; bad.write_text("{")
    prepare_attempt(tmp_path, ["r", 2], "c", "p", {}, attempt_id="pending")
    (tmp_path / "reviews" / "publication-attempt.json").write_text("not-json")
    out = inventory(tmp_path)
    assert str(bad) in out["invalid_files"]
    assert out["semantic_attempts"]["unfinished"][0]["attempt_id"] == "pending"
    assert str(tmp_path / "reviews" / "publication-attempt.json") in out["invalid_files"]
