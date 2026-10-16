"""Issue #84: receipt_id must bind ci_failure_evidence (insert / substitute / remove)."""
import copy

import pytest

from reviewer.publication import PublicationError, publish_review
from reviewer.receipt import build_ci_failure_evidence, compute_receipt_id, persist_receipt, reusable_receipt

IDENTITY = ["o/r", 7, "h", "b", "m"]
SEMANTIC = {"schema": "reviewer.semantic_response.v1", "status": "PASS", "summary": "ok",
            "findings": [], "evidence_gaps": []}


def _capsule(disposition="NEW_REGRESSION", run_id=2):
    return build_ci_failure_evidence(
        repository="o/r", pr_number=7, base_sha="b", head_sha="h", current_main_sha="m",
        canonical_disposition=disposition, expected_check_run_id=1, expected_run_id=run_id,
        expected_artifact_identity="art",
        checks=[{"name": "exact", "status": "failure", "check_run_id": 1, "run_id": run_id,
                 "external_id": "art", "head_sha": "h"}])


def _rid(r):
    args = (r["review_identity"], r["context_pack_sha256"], r["prompt_sha256"], None,
            r["semantic_result"], r["parse_result"], r["transport_result"])
    return compute_receipt_id(*args, r.get("ci_failure_evidence"))


def _receipt(ci=None):
    r = {"schema": "reviewer.pre_review.v1", "review_identity": list(IDENTITY),
         "claim_ceiling": "PRE_REVIEW_ONLY", "context_pack_sha256": "context",
         "prompt_sha256": "prompt", "outcome_unknown": False, "retry_safe": False,
         "transport_result": "REVIEW_COMPLETED", "parse_result": "PARSED",
         "semantic_result": copy.deepcopy(SEMANTIC)}
    if ci is not None:
        r["ci_failure_evidence"] = ci
    r["receipt_id"] = _rid(r)
    return r


class _T:
    def __init__(self):
        self.writes = 0
        self.comments = []

    def get_authenticated_login(self):
        return "bot"

    def get_pr(self, repo, n):
        return {"head": {"sha": "h"}, "base": {"sha": "b"}}

    def get_ref(self, repo, branch):
        return {"object": {"sha": "m"}}

    def list_comments(self, repo, n):
        return list(self.comments)

    def create_comment(self, repo, n, body):
        self.writes += 1
        c = {"id": 10 + self.writes, "html_url": "https://example/10", "body": body, "user": {"login": "bot"}}
        self.comments.append(c)
        return c


def _insert():
    r = _receipt(); r["ci_failure_evidence"] = _capsule(); return r


def _substitute():
    r = _receipt(_capsule("IMPACT_UNKNOWN")); r["ci_failure_evidence"] = _capsule("NEW_REGRESSION"); return r


def _remove():
    r = _receipt(_capsule()); del r["ci_failure_evidence"]; return r


CASES = [_insert, _substitute, _remove]


def test_untampered_receipts_with_and_without_capsule_verify(tmp_path):
    t = _T()
    publish_review(tmp_path, t, _receipt(_capsule()), attempt_id="ok1")
    publish_review(tmp_path, t, _receipt(), attempt_id="ok2")
    persist_receipt(tmp_path, _receipt(_capsule()))
    assert reusable_receipt(tmp_path, IDENTITY) is not None


@pytest.mark.parametrize("build", CASES)
def test_ci_capsule_tamper_rejected_by_publication(tmp_path, build):
    t = _T()
    with pytest.raises(PublicationError, match="PUBLICATION_RECEIPT_ID_MISMATCH"):
        publish_review(tmp_path, t, build(), attempt_id="x")
    assert t.writes == 0


@pytest.mark.parametrize("build", CASES)
def test_ci_capsule_tamper_rejected_by_reuse(tmp_path, build):
    persist_receipt(tmp_path, build())
    assert reusable_receipt(tmp_path, IDENTITY) is None
