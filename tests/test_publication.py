import json

import pytest

from reviewer.publication import PublicationError, publish_review, reconcile_publication, _content_hash
from reviewer.receipt import build_ci_failure_evidence


def receipt(status="PASS"):
    return {
        "schema": "reviewer.pre_review.v1",
        "receipt_id": "receipt-1",
        "review_identity": ["o/r", 7, "h", "b", "m"],
        "claim_ceiling": "PRE_REVIEW_ONLY",
        "context_pack_sha256": "context", "prompt_sha256": "prompt",
        "outcome_unknown": False, "retry_safe": False,
        "transport_result": "REVIEW_COMPLETED", "parse_result": "PARSED",
        "semantic_result": {"schema": "reviewer.semantic_response.v1", "status": status,
                             "summary": "summary", "findings": [], "evidence_gaps": []},
    }


def ci_evidence(head="h"):
    return build_ci_failure_evidence(
        repository="o/r", pr_number=7, base_sha="b", head_sha=head,
        current_main_sha="m", canonical_disposition="NEW_REGRESSION",
        expected_check_run_id=1, expected_run_id=2, expected_artifact_identity="artifact",
        checks=[{"name": "exact", "status": "failure", "check_run_id": 1,
                 "run_id": 2, "external_id": "artifact", "head_sha": head}],
    )


class Fake:
    def __init__(self, moved=False, fail=False):
        self.comments = []
        self.moved = moved
        self.fail = fail
        self.writes = 0
        self.main = "m"
        self.base = "b"

    def get_pr(self, repo, number):
        return {"head": {"sha": "new" if self.moved else "h"}, "base": {"sha": self.base}}

    def get_ref(self, repo, branch):
        return {"object": {"sha": self.main}}

    def list_comments(self, repo, number):
        return list(self.comments)

    def create_comment(self, repo, number, body):
        self.writes += 1
        if self.fail:
            self.comments.append({"id": 10, "body": body, "html_url": "https://example/10"})
            raise TimeoutError("after write")
        comment = {"id": 10 + self.writes, "body": body, "html_url": "https://example/10"}
        self.comments.append(comment)
        return comment


def test_pass_comment_write_readback_and_idempotency(tmp_path):
    t = Fake()
    p = publish_review(tmp_path, t, receipt(), attempt_id="a1")
    assert p.exists() and t.writes == 1
    value = json.loads(p.read_text())
    assert value["state"] == "COMPLETED"
    assert value["claim_ceiling"] == "PRE_REVIEW_ONLY"
    assert "NOT APPROVAL" in t.comments[0]["body"].upper()
    assert publish_review(tmp_path, t, receipt(), attempt_id="a1") == p
    assert t.writes == 1


def test_completed_publication_requires_physical_readback(tmp_path):
    t = Fake()
    p = publish_review(tmp_path, t, receipt(), attempt_id="physical")
    t.comments.clear()
    with pytest.raises(PublicationError, match="RECONCILIATION"):
        publish_review(tmp_path, t, receipt(), attempt_id="physical")
    assert p.exists() and t.writes == 1


def test_findings_and_timeout_after_write_reconcile_without_duplicate(tmp_path):
    t = Fake(fail=True)
    with pytest.raises(PublicationError, match="RECONCILIATION"):
        publish_review(tmp_path, t, receipt("FINDINGS"), attempt_id="a2")
    assert t.writes == 1
    p = reconcile_publication(tmp_path, t, "a2")
    assert json.loads(p.read_text())["reconciliation_evidence"] == "readback_existing"
    assert t.writes == 1


def test_moved_pr_blocks_stale_publication(tmp_path):
    with pytest.raises(PublicationError, match="REBIND"):
        publish_review(tmp_path, Fake(moved=True), receipt(), attempt_id="a3")


@pytest.mark.parametrize("field", ["main", "base"])
def test_moved_main_or_base_blocks_stale_publication(tmp_path, field):
    t = Fake()
    setattr(t, field, "changed")
    with pytest.raises(PublicationError, match="REBIND"):
        publish_review(tmp_path, t, receipt(), attempt_id="move-" + field)


def test_restart_dispatching_reconciles_existing_without_post(tmp_path):
    t = Fake()
    rid = "restart"
    content_hash, _ = _content_hash(receipt(), rid)
    attempt_dir = tmp_path / "publication-attempts"
    attempt_dir.mkdir()
    (attempt_dir / f"{rid}.json").write_text(json.dumps({
        "schema": "reviewer.publication_attempt.v1", "publication_attempt_id": rid,
        "semantic_receipt_id": "x", "repository": "o/r", "pr_number": 7,
        "review_identity": ["o/r", 7, "h", "b", "m"], "content_hash": content_hash,
        "publication_type": "COMMENT", "claim_ceiling": "PRE_REVIEW_ONLY",
        "state": "DISPATCHING", "retry_safe": False,
    }))
    t.comments.append({"id": 19, "body": f"reviewer-publication-v1:{rid}:{content_hash}"})
    p = publish_review(tmp_path, t, receipt(), attempt_id=rid)
    assert p.exists() and t.writes == 0


def test_multiple_matching_comments_fail_closed(tmp_path):
    t = Fake()
    rid = "dupe"
    content_hash, _ = _content_hash(receipt(), rid)
    marker = f"reviewer-publication-v1:{rid}:{content_hash}"
    t.comments[:] = [{"id": 1, "body": marker}, {"id": 2, "body": marker}]
    with pytest.raises(PublicationError, match="DUPLICATE"):
        publish_review(tmp_path, t, receipt(), attempt_id=rid)
    assert t.writes == 0


def test_readback_mismatch_fails_closed(tmp_path):
    class Mismatch(Fake):
        def create_comment(self, repo, number, body):
            self.writes += 1
            return {"id": 1, "body": "different"}
    with pytest.raises(PublicationError, match="RECONCILIATION"):
        publish_review(tmp_path, Mismatch(), receipt(), attempt_id="mismatch")


def test_attempt_id_collision_never_overwrites(tmp_path):
    t = Fake()
    publish_review(tmp_path, t, receipt(), attempt_id="collision")
    other = receipt("FINDINGS")
    with pytest.raises(PublicationError, match="COLLISION"):
        publish_review(tmp_path, t, other, attempt_id="collision")
    assert t.writes == 1


def test_missing_rebind_capabilities_fails_closed(tmp_path):
    class NoRebind:
        def list_comments(self, repo, number): return []
        def create_comment(self, repo, number, body): raise AssertionError("must not write")
    with pytest.raises(PublicationError, match="REBIND"):
        publish_review(tmp_path, NoRebind(), receipt(), attempt_id="no-rebind")


def test_malformed_receipt_fails_closed(tmp_path):
    bad = receipt()
    bad["semantic_result"] = {"schema": "reviewer.semantic_response.v1", "status": "PASS"}
    with pytest.raises(PublicationError):
        publish_review(tmp_path, Fake(), bad, attempt_id="bad")


def test_invalid_or_blocked_result_never_publishes(tmp_path):
    t = Fake()
    blocked = receipt("BLOCKED")
    with pytest.raises(PublicationError):
        publish_review(tmp_path, t, blocked, attempt_id="a4")
    assert t.writes == 0

def test_tampered_semantic_shape_never_publishes(tmp_path):
    t=Fake(); value=receipt('FINDINGS')
    value['semantic_result']['findings']=[{'severity':'HIGH','category':'x','path':None,
        'evidence':'e','reason':'r'}]
    with pytest.raises(PublicationError,match='SEMANTIC_RESULT_INVALID'):
        publish_review(tmp_path,t,value)
    assert t.writes==0


def test_publication_wires_valid_ci_evidence_and_rejects_foreign_or_tampered(tmp_path):
    valid = receipt(); valid["ci_failure_evidence"] = ci_evidence()
    t = Fake()
    publish_review(tmp_path, t, valid, attempt_id="ci-valid")
    assert "CI Failure Intelligence" in t.comments[0]["body"]
    foreign = receipt(); foreign["ci_failure_evidence"] = ci_evidence("foreign")
    with pytest.raises(PublicationError):
        publish_review(tmp_path, Fake(), foreign, attempt_id="ci-foreign")
    tampered = receipt(); tampered["ci_failure_evidence"] = ci_evidence()
    tampered["ci_failure_evidence"]["trigger"] = "ATTACKER"
    with pytest.raises(PublicationError):
        publish_review(tmp_path, Fake(), tampered, attempt_id="ci-tampered")


@pytest.mark.parametrize("identity", [
    ["o/r", True, "h", "b", "m"], [[], 7, "h", "b", "m"],
    ["", 7, "h", "b", "m"], ["o/r", 7, None, "b", "m"],
])
def test_publication_identity_never_coerces_malformed_values(tmp_path, identity):
    value = receipt(); value["review_identity"] = identity
    with pytest.raises(PublicationError, match="IDENTITY"):
        publish_review(tmp_path, Fake(), value, attempt_id="identity-bad")


def test_valid_cfi_blocked_receipt_publishes_advisory_comment_with_ci_section(tmp_path):
    t = Fake()
    valid_cfi = receipt("BLOCKED")
    valid_cfi["ci_failure_evidence"] = ci_evidence()
    p = publish_review(tmp_path, t, valid_cfi, attempt_id="cfi-blocked-1")
    assert p.exists() and t.writes == 1
    value = json.loads(p.read_text())
    assert value["state"] == "COMPLETED"
    assert value["claim_ceiling"] == "PRE_REVIEW_ONLY"

    body = t.comments[0]["body"]
    assert "Result: BLOCKED" in body
    assert "CI Failure Intelligence" in body
    assert "ADVISORY ONLY — NOT APPROVAL, ACCEPTANCE, VERIFICATION, OR MERGE AUTHORIZATION." in body
    assert "Claim ceiling: CI\\_EVIDENCE\\_ONLY" in body

    # Idempotent republish
    assert publish_review(tmp_path, t, valid_cfi, attempt_id="cfi-blocked-1") == p
    assert t.writes == 1


def test_cfi_blocked_rejects_tampered_or_foreign_ci_evidence(tmp_path):
    foreign = receipt("BLOCKED")
    foreign["ci_failure_evidence"] = ci_evidence("foreign")
    with pytest.raises(PublicationError):
        publish_review(tmp_path, Fake(), foreign, attempt_id="cfi-foreign")

    tampered = receipt("BLOCKED")
    tampered["ci_failure_evidence"] = ci_evidence()
    tampered["ci_failure_evidence"]["trigger"] = "ATTACKER"
    with pytest.raises(PublicationError):
        publish_review(tmp_path, Fake(), tampered, attempt_id="cfi-tampered")

    missing_ci = receipt("BLOCKED")
    with pytest.raises(PublicationError):
        publish_review(tmp_path, Fake(), missing_ci, attempt_id="cfi-missing")
