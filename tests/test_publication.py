import json

import pytest

from reviewer.publication import PublicationError, publish_review, reconcile_publication, _content_hash


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
