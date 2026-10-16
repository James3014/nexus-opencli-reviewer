"""Issue #84 R84-A: receipt_id must bind the semantic verdict, parse and transport result."""
import copy

import pytest

from reviewer.publication import PublicationError, publish_review
from reviewer.receipt import compute_receipt_id, persist_receipt, reusable_receipt

IDENTITY = ["o/r", 7, "h", "b", "m"]


def _id(semantic, parse="PARSED", transport="REVIEW_COMPLETED"):
    return compute_receipt_id(IDENTITY, "context", "prompt", None, semantic, parse, transport)


def _receipt():
    semantic = {"schema": "reviewer.semantic_response.v1", "status": "FINDINGS", "summary": "bad",
                "findings": [{"severity": "HIGH", "category": "x", "path": None, "line": None,
                              "message": "m", "evidence": []}],
                "evidence_gaps": []}
    return {
        "schema": "reviewer.pre_review.v1", "receipt_id": _id(semantic),
        "review_identity": list(IDENTITY), "claim_ceiling": "PRE_REVIEW_ONLY",
        "context_pack_sha256": "context", "prompt_sha256": "prompt",
        "outcome_unknown": False, "retry_safe": False,
        "transport_result": "REVIEW_COMPLETED", "parse_result": "PARSED",
        "semantic_result": semantic,
    }


class _T:
    writes = 0

    def get_authenticated_login(self):
        return "bot"

    def get_pr(self, repo, n):
        return {"head": {"sha": "h"}, "base": {"sha": "b"}}

    def get_ref(self, repo, branch):
        return {"object": {"sha": "m"}}

    def list_comments(self, repo, n):
        return []

    def create_comment(self, repo, n, body):
        self.writes += 1
        return {"id": 1, "html_url": "u", "body": body, "user": {"login": "bot"}}


def _semantic_only(r):
    r["semantic_result"] = {**r["semantic_result"], "status": "PASS", "findings": [], "summary": "ok"}


def _parse_only(r):
    r["parse_result"] = "PARSED "


def _transport_only(r):
    r["transport_result"] = "REVIEW_COMPLETED "


TAMPERS = [_semantic_only, _parse_only, _transport_only]


def test_untampered_receipt_verifies_for_reuse(tmp_path):
    persist_receipt(tmp_path, _receipt())
    assert reusable_receipt(tmp_path, IDENTITY) is not None


@pytest.mark.parametrize("tamper", TAMPERS)
def test_tampered_verdict_fields_rejected_by_reuse(tmp_path, tamper):
    r = _receipt(); tamper(r)
    persist_receipt(tmp_path, r)
    assert reusable_receipt(tmp_path, IDENTITY) is None


@pytest.mark.parametrize("tamper", TAMPERS)
def test_tampered_verdict_fields_rejected_by_publication(tmp_path, tamper):
    r = _receipt(); tamper(r)
    t = _T()
    with pytest.raises(PublicationError):
        publish_review(tmp_path, t, r, attempt_id="a1")
    assert t.writes == 0


def test_tampered_semantic_result_reports_id_mismatch(tmp_path):
    r = _receipt(); _semantic_only(r)
    with pytest.raises(PublicationError, match="PUBLICATION_RECEIPT_ID_MISMATCH"):
        publish_review(tmp_path, _T(), r, attempt_id="a2")


def test_legacy_four_field_receipt_id_no_longer_verifies(tmp_path):
    import hashlib, json
    r = _receipt()
    r["receipt_id"] = hashlib.sha256(json.dumps(
        {"identity": IDENTITY, "context": "context", "prompt": "prompt", "raw": None},
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    persist_receipt(tmp_path, r)
    assert reusable_receipt(tmp_path, IDENTITY) is None
    with pytest.raises(PublicationError, match="PUBLICATION_RECEIPT_ID_MISMATCH"):
        publish_review(tmp_path, _T(), r, attempt_id="a3")
