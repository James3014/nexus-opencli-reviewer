"""Issue #103: v2 CI failure evidence capsules record and hash-bind the exact
base check-run / workflow run the head failure was compared against.  v1
capsules keep verifying unchanged (transition window)."""
import copy
import hashlib
import json

import pytest

from reviewer.receipt import build_ci_failure_evidence, ci_failure_evidence_manifest
from reviewer.scan import _ci_evidence_for
from tests.test_ci_baseline_comparison import FakeTransport, _classification, _row


def _rehash(capsule):
    body = {k: v for k, v in capsule.items() if k != "content_sha256"}
    capsule["content_sha256"] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return capsule


def _triggered():
    capsule = _ci_evidence_for(_classification(), FakeTransport([_row()]))
    assert capsule["state"] == "TRIGGERED"
    return capsule


def _clear():
    capsule = _ci_evidence_for(_classification(), FakeTransport([_row(conclusion="failure")]))
    assert capsule["state"] == "CLEAR"
    return capsule


def test_v2_triggered_happy_path_records_base_basis():
    capsule = _triggered()
    assert capsule["schema"] == "reviewer.ci_failure_evidence.v2"
    assert capsule["baseline"] == {
        "base_sha": "base", "check_run_id": 99, "check_conclusion": "success",
        "app_slug": "github-actions", "workflow_run_id": 5, "workflow_name": "PR CI"}
    assert ci_failure_evidence_manifest(capsule)["schema"] == "reviewer.ci_failure_evidence.v2"


def test_v2_clear_happy_path_records_failed_base_check():
    capsule = _clear()
    assert capsule["schema"] == "reviewer.ci_failure_evidence.v2"
    assert capsule["baseline"]["check_conclusion"] == "failure"
    assert capsule["baseline"]["check_run_id"] == 99
    ci_failure_evidence_manifest(capsule)


def test_unknown_without_comparison_stays_v1_and_verifies():
    capsule = _ci_evidence_for(_classification())
    assert capsule["schema"] == "reviewer.ci_failure_evidence.v1"
    assert "baseline" not in capsule
    ci_failure_evidence_manifest(capsule)


@pytest.mark.parametrize("make", [_triggered, _clear])
def test_v2_missing_basis_fails_manifest(make):
    capsule = make()
    del capsule["baseline"]
    with pytest.raises(ValueError, match="CI_FAILURE_EVIDENCE_HASH_MISMATCH"):
        ci_failure_evidence_manifest(capsule)
    with pytest.raises(ValueError, match="CI_FAILURE_EVIDENCE_SCHEMA_FIELDS_INVALID"):
        ci_failure_evidence_manifest(_rehash(capsule))
    capsule["baseline"] = None
    with pytest.raises(ValueError, match="CI_FAILURE_EVIDENCE_BASELINE_INCOMPLETE"):
        ci_failure_evidence_manifest(_rehash(capsule))


@pytest.mark.parametrize("field,value", [
    ("check_run_id", 100), ("check_conclusion", "failure"), ("app_slug", "other-app"),
    ("workflow_run_id", 6), ("workflow_name", "Other"), ("base_sha", "evil")])
def test_v2_substituted_basis_fails_manifest(field, value):
    capsule = _triggered()
    capsule["baseline"][field] = value
    with pytest.raises(ValueError, match="CI_FAILURE_EVIDENCE_HASH_MISMATCH"):
        ci_failure_evidence_manifest(capsule)
    # A forger who also recomputes content_sha256 still cannot keep the
    # failure fingerprint: the basis is bound into it.
    with pytest.raises(ValueError):
        ci_failure_evidence_manifest(_rehash(capsule))


def test_v2_fingerprint_binds_basis():
    a, b = _triggered(), _triggered()
    assert a["failure_fingerprint"] == b["failure_fingerprint"]
    other = _ci_evidence_for(_classification(), FakeTransport([{**_row(), "id": 100}]))
    assert other["failure_fingerprint"] != a["failure_fingerprint"]


def test_v2_triggered_with_incomplete_workflow_basis_rejected():
    capsule = _triggered()
    capsule["baseline"]["workflow_run_id"] = None
    capsule["baseline"]["workflow_name"] = None
    capsule["failure_fingerprint"] = "x"
    with pytest.raises(ValueError, match="CI_FAILURE_EVIDENCE_BASELINE_INCOMPLETE"):
        ci_failure_evidence_manifest(_rehash(capsule))


def test_builder_with_incomplete_baseline_never_triggers():
    capsule = build_ci_failure_evidence(
        repository="o/r", pr_number=1, base_sha="base", head_sha="head",
        current_main_sha="base", checks=[{"name": "CI", "status": "failure", "check_run_id": 1,
                                          "run_id": 2, "external_id": "a", "head_sha": "head"}],
        canonical_disposition="NEW_REGRESSION", expected_check_run_id=1, expected_run_id=2,
        expected_artifact_identity="a", baseline={"base_sha": "base"})
    assert capsule["state"] == "UNKNOWN"
    assert "baseline basis incomplete" in capsule["evidence_gaps"]
    # A malformed basis object is also rejected by the manifest, so scan
    # (which verifies its own capsule) binds nothing.
    with pytest.raises(ValueError, match="CI_FAILURE_EVIDENCE_BASELINE_INVALID"):
        ci_failure_evidence_manifest(capsule)


def test_existing_v1_triggered_capsule_still_verifies():
    capsule = build_ci_failure_evidence(
        repository="o/r", pr_number=1, base_sha="base", head_sha="head",
        current_main_sha="base", checks=[{"name": "CI", "status": "failure", "check_run_id": 1,
                                          "run_id": 2, "external_id": "a", "head_sha": "head"}],
        canonical_disposition="NEW_REGRESSION", expected_check_run_id=1, expected_run_id=2,
        expected_artifact_identity="a")
    assert capsule["schema"] == "reviewer.ci_failure_evidence.v1"
    assert capsule["state"] == "TRIGGERED"
    assert "baseline" not in capsule
    ci_failure_evidence_manifest(capsule)
    with_extra = copy.deepcopy(capsule)
    with_extra["baseline"] = {"base_sha": "base"}
    with pytest.raises(ValueError):
        ci_failure_evidence_manifest(_rehash(with_extra))
