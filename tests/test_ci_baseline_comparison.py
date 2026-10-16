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


def test_base_row_without_status_is_pending_not_completed():
    row = _row(); del row["status"]
    _unknown(_ci_evidence_for(_classification(), FakeTransport([row])),
             "baseline: same-name check on base still pending")


def test_uppercase_base_status_and_conclusion_are_normalised():
    capsule = _ci_evidence_for(_classification(),
                               FakeTransport([_row(conclusion="SUCCESS", status="COMPLETED")]))
    assert capsule["state"] == "TRIGGERED"


def test_hostile_base_rows_that_raise_fail_closed():
    class Boom(dict):
        def get(self, key, default=None):
            raise RuntimeError("hostile")
    _unknown(_ci_evidence_for(_classification(), FakeTransport([Boom()])),
             "baseline: check lookup failed: RuntimeError")


def test_head_app_slug_requires_same_app_on_base():
    head = _head("failure"); head[0]["app_slug"] = "github-actions"
    other = _row(); other["app"] = {"slug": "circleci"}
    _unknown(_ci_evidence_for(_classification(checks=head), FakeTransport([other])),
             "baseline: no same-name check on base")
    same = _row(); same["app"] = {"slug": "github-actions"}
    assert _ci_evidence_for(_classification(checks=head),
                            FakeTransport([same]))["state"] == "TRIGGERED"


class _ScanTransport:
    """Real scan() path: head check from GitHub Actions, base rows supplied."""
    def __init__(self, base_rows):
        self.base_rows = base_rows

    def get_ref(self, r, b): return {"object": {"sha": "m"}}
    def list_open_prs(self, r):
        return [{"number": 1, "title": "x", "state": "open", "draft": False, "mergeable": True,
                 "base": {"ref": "main", "sha": "m"}, "head": {"ref": "f", "sha": "h"},
                 "body": "", "labels": []}]
    def list_files(self, r, n): return [{"filename": "a.py"}]
    def list_checks(self, r, sha):
        if sha == "h":
            return [{"name": "CI", "conclusion": "failure", "status": "completed", "id": 7,
                     "check_suite": {"id": 11}, "head_sha": "h", "app": {"slug": "github-actions"}}]
        return self.base_rows
    def list_check_annotations(self, r, i): return []
    def list_workflow_runs_for_suite(self, r, i): return [{"id": 9, "head_sha": "h"}]
    def get_workflow_run(self, r, i): return {"id": 9, "name": "CI", "head_sha": "h"}
    def list_workflow_artifacts(self, r, i): return [{"id": 42, "name": "evidence"}]


def _base(slug):
    return [{"name": "CI", "conclusion": "success", "status": "completed", "id": 5,
             "head_sha": "m", "app": {"slug": slug}}]


def test_scan_path_end_to_end_triggers_only_for_same_app_base():
    from reviewer.scan import scan
    t = _ScanTransport(_base("github-actions"))
    _, _, items, _ = scan("o/r", t)
    assert items[0].snapshot.checks[0].app_slug == "github-actions"
    capsule = _ci_evidence_for(items[0], t)
    assert capsule["state"] == "TRIGGERED", capsule["evidence_gaps"]
    t = _ScanTransport(_base("circleci"))
    _, _, items, _ = scan("o/r", t)
    _unknown(_ci_evidence_for(items[0], t), "baseline: no same-name check on base")


def test_review_ready_passes_its_transport_to_ci_evidence(tmp_path, monkeypatch):
    import json
    import reviewer.scan as scan_mod
    from reviewer.opencli import TransportResult
    from tests.test_receipt_history_and_default_branch import _DevelopTransport
    good = json.dumps({"schema": "reviewer.semantic_response.v1", "status": "PASS",
                       "summary": "ok", "findings": [], "evidence_gaps": []})

    class S:
        def invoke(self, p):
            return TransportResult("REVIEW_COMPLETED", good, version="fake")

    seen = []
    monkeypatch.setattr(scan_mod, "_ci_evidence_for",
                        lambda classification, transport=None: seen.append(transport))
    t = _DevelopTransport()
    scan_mod.review_ready("o/r", t, 1, S(), state_root=tmp_path)
    assert seen == [t]


def test_head_rerun_with_same_name_never_compares_the_old_failure():
    for later in ("success", None):
        rerun = {"name": "CI", "id": 2, "run_id": 2, "artifact_identity": "artifact",
                 "head_sha": "head"}
        if later:
            rerun["conclusion"] = later
        else:
            rerun["state"] = "in_progress"
        capsule = _ci_evidence_for(_classification(checks=_head("failure") + [rerun]),
                                   FakeTransport([_row()]))
        _unknown(capsule, "baseline: multiple same-name checks on head")
