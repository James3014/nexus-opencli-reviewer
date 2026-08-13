from reviewer.service import ReviewWorkflowService


def service(state, calls):
    def scan(identity):
        calls.append("scan")
        return state.copy()
    def review(identity):
        calls.append("review")
        return {"semantic": "COMPLETE", "publication": "NONE"}
    def publish(identity, result):
        calls.append("publish")
        return {"status": "PUBLISHED"}
    def reconcile(identity):
        calls.append("reconcile")
        return state.get("reconciled", {})
    return ReviewWorkflowService(scan=scan, review=review, publish=publish, reconcile=reconcile)


def test_exact_complete_skips_semantic_and_publication():
    calls = []
    result = service({"semantic": "COMPLETE", "publication": "COMPLETE"}, calls).run(("r", 1, "h"))
    assert result.outcome == "ALREADY_COMPLETE"
    assert calls == ["scan"]


def test_unresolved_semantic_reconciles_and_blocks():
    calls = []
    result = service({"semantic": "UNRESOLVED", "publication": "NONE", "reconciled": {"semantic": "UNRESOLVED"}}, calls).run(("r", 1, "h"))
    assert result.outcome == "RECONCILIATION_REQUIRED"
    assert calls == ["scan", "reconcile"]


def test_valid_semantic_pending_publication_publishes_once():
    calls = []
    result = service({"semantic": "COMPLETE", "publication": "NONE"}, calls).run(("r", 1, "h"))
    assert result.outcome == "PUBLISHED"
    assert calls == ["scan", "publish"]


def test_unresolved_publication_reconciles_without_replay():
    calls = []
    result = service({"semantic": "COMPLETE", "publication": "UNKNOWN", "reconciled": {"publication": "COMPLETE"}}, calls).run(("r", 1, "h"))
    assert result.outcome == "PUBLICATION_RECONCILED"
    assert calls == ["scan", "reconcile"]


def test_new_identity_reviews_then_publishes():
    calls = []
    result = service({}, calls).run(("r", 2, "new"))
    assert result.outcome == "PUBLISHED"
    assert calls == ["scan", "review", "publish"]
