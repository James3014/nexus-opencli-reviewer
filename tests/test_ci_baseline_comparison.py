"""Issue #75: scan-path CI failure evidence derives its canonical disposition
from the same-named check on the PR base commit."""
from reviewer.classifier import classify
from reviewer.normalize import snapshot_from_github
from reviewer.receipt import ci_failure_evidence_manifest
from reviewer.scan import _ci_evidence_for

REPO = "o/r"


def _classification(base="base", main="base", checks=None):
    if checks is None:
        checks = [{"name": "CI", "conclusion": "failure", "id": 1, "run_id": 2,
                   "external_id": "artifact", "artifact_identity": "artifact",
                   "head_sha": "head"}]
    return classify(snapshot_from_github(
        REPO, {"number": 7, "base": {"sha": base}, "head": {"sha": "head"}},
        main, [], checks))


def _row(name="CI", conclusion="success", status="completed", head_sha="base"):
    return {"name": name, "status": status, "conclusion": conclusion,
            "head_sha": head_sha, "id": 99}


class FakeTransport:
    def __init__(self, result=None, exc=None):
        self.result, self.exc, self.calls = result, exc, []

    def list_checks(self, repo, sha):
        self.calls.append((repo, sha))
        if self.exc:
            raise self.exc
        return self.result


def _unknown(capsule, gap):
    assert capsule["state"] == "UNKNOWN"
    assert capsule["trigger"] is None
    assert capsule["canonical_disposition"] == "NOT_AVAILABLE"
    assert gap in capsule["evidence_gaps"]
    assert "canonical disposition unavailable" in capsule["evidence_gaps"]


def test_base_success_head_fail_is_new_regression():
    t = FakeTransport([_row()])
    capsule = _ci_evidence_for(_classification(), t)
    assert capsule["state"] == "TRIGGERED"
    assert capsule["canonical_disposition"] == "NEW_REGRESSION"
    assert capsule["evidence_gaps"] == []
    assert t.calls == [(REPO, "base")]
    ci_failure_evidence_manifest(capsule)


def test_base_also_failing_is_exact_baseline_debt():
    capsule = _ci_evidence_for(_classification(), FakeTransport([_row(conclusion="failure")]))
    assert capsule["state"] == "CLEAR"
    assert capsule["trigger"] is None
    assert capsule["canonical_disposition"] == "EXACT_BASELINE_DEBT"
    assert capsule["evidence_gaps"] == []


def test_no_same_name_check_on_base():
    _unknown(_ci_evidence_for(_classification(), FakeTransport([_row(name="Other")])),
             "baseline: no same-name check on base")


def test_lookup_exception_never_triggers_and_hides_message():
    capsule = _ci_evidence_for(_classification(), FakeTransport(exc=RuntimeError("boom")))
    _unknown(capsule, "baseline: check lookup failed: RuntimeError")
    assert not any("boom" in g for g in capsule["evidence_gaps"])


def test_pending_base_check():
    _unknown(_ci_evidence_for(_classification(), FakeTransport(
        [_row(conclusion=None, status="in_progress")])),
        "baseline: same-name check on base still pending")


def test_ambiguous_base_checks():
    _unknown(_ci_evidence_for(_classification(), FakeTransport([_row(), _row()])),
             "baseline: ambiguous same-name checks on base")


def test_foreign_base_check_head():
    _unknown(_ci_evidence_for(_classification(), FakeTransport([_row(head_sha="other")])),
             "baseline: foreign base check head identity")


def test_stale_base_skips_lookup():
    t = FakeTransport([_row()])
    capsule = _ci_evidence_for(_classification(base="base", main="newer"), t)
    _unknown(capsule, "baseline: PR base is not current main")
    assert t.calls == []


def test_transport_none():
    _unknown(_ci_evidence_for(_classification(), None), "baseline: transport unavailable")


def test_no_failing_checks_returns_none_without_lookup():
    t = FakeTransport([_row()])
    ok = [{"name": "CI", "conclusion": "success", "id": 1, "head_sha": "head"}]
    assert _ci_evidence_for(_classification(checks=ok), t) is None
    assert t.calls == []


def test_neutral_base_conclusion_is_inconclusive():
    _unknown(_ci_evidence_for(_classification(), FakeTransport([_row(conclusion="neutral")])),
             "baseline: same-name check on base inconclusive")


def test_invalid_response():
    _unknown(_ci_evidence_for(_classification(), FakeTransport({"check_runs": []})),
             "baseline: check lookup failed: invalid response")


def _head(conclusion):
    return [{"name": "CI", "conclusion": conclusion, "id": 1, "run_id": 2,
             "external_id": "artifact", "artifact_identity": "artifact",
             "head_sha": "head"}]


def test_cancelled_head_check_never_triggers_even_if_base_passes():
    for conclusion in ("cancelled", "action_required"):
        capsule = _ci_evidence_for(_classification(checks=_head(conclusion)),
                                   FakeTransport([_row()]))
        _unknown(capsule, "baseline: head failure is not a regression signal")


def test_timed_out_head_check_with_passing_base_triggers():
    capsule = _ci_evidence_for(_classification(checks=_head("timed_out")),
                               FakeTransport([_row()]))
    assert capsule["state"] == "TRIGGERED"


def test_cancelled_base_check_is_inconclusive_not_debt():
    capsule = _ci_evidence_for(_classification(), FakeTransport([_row(conclusion="cancelled")]))
    _unknown(capsule, "baseline: same-name check on base inconclusive")


def test_two_failing_head_checks_never_trigger():
    checks = _head("failure") + [{"name": "Lint", "conclusion": "failure", "id": 3,
                                  "run_id": 4, "artifact_identity": "artifact",
                                  "head_sha": "head"}]
    capsule = _ci_evidence_for(_classification(checks=checks),
                               FakeTransport([_row(), _row(name="Lint")]))
    # The builder binds one expected check identity, so a second failing check
    # is a foreign-identity gap; the capsule then fails its own manifest and is
    # not bound at all.  Either way it must never be TRIGGERED.
    assert capsule is None or capsule["state"] != "TRIGGERED"
