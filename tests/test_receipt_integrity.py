import copy
import json

import pytest
from reviewer.normalize import snapshot_from_github
from reviewer.classifier import classify
from reviewer.scan import _ci_evidence_for

from reviewer.receipt import (
    persist_receipt, reusable_receipt, receipt_path,
    build_ci_failure_evidence, ci_failure_evidence_manifest,
)


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


def test_ci_failure_evidence_is_content_addressed_and_exact_identity_bound():
    checks = [{"name": "Exact-base impact gate", "status": "failure",
               "check_run_id": 42, "run_id": 9, "external_id": "artifact-9",
               "details_url": "https://ci.example/9", "workflow_name": "Nexus Pytest CI",
               "head_sha": "head"}]
    evidence = build_ci_failure_evidence(
        repository="James3014/Nexus-new", pr_number=358,
        base_sha="base", head_sha="head", current_main_sha="main",
        checks=checks, canonical_disposition="NEW_REGRESSION",
        expected_check_run_id=42, expected_run_id=9,
        expected_artifact_identity="artifact-9", collection_complete=True,
    )
    assert evidence["schema"] == "reviewer.ci_failure_evidence.v1"
    assert evidence["state"] == "TRIGGERED"
    assert evidence["review_identity"] == ["James3014/Nexus-new", 358, "head", "base", "main"]
    assert evidence["content_sha256"] == build_ci_failure_evidence(
        repository="James3014/Nexus-new", pr_number=358,
        base_sha="base", head_sha="head", current_main_sha="main",
        checks=checks, canonical_disposition="NEW_REGRESSION",
        expected_check_run_id=42, expected_run_id=9,
        expected_artifact_identity="artifact-9", collection_complete=True,
    )["content_sha256"]
    assert evidence["checks"][0]["run_id"] == 9
    manifest = ci_failure_evidence_manifest(evidence)
    assert manifest["content_sha256"] == evidence["content_sha256"]


def test_ci_capsule_preserves_bounded_job_log_and_artifact_evidence():
    check = {
        "name": "Exact-base impact gate", "status": "failure",
        "check_run_id": 42, "run_id": 9, "external_id": "artifact-9",
        "head_sha": "head", "job_identity": "job-77",
        "log_sha256": "a" * 64, "log_truncated": True,
        "artifact_sha256": "b" * 64, "artifact_truncated": False,
        "run_attempt": 3,
    }
    evidence = build_ci_failure_evidence(
        repository="o/r", pr_number=358, base_sha="base", head_sha="head",
        current_main_sha="main", checks=[check], canonical_disposition="NEW_REGRESSION",
        expected_check_run_id=42, expected_run_id=9,
        expected_artifact_identity="artifact-9",
    )
    normalized = evidence["checks"][0]
    for field in ("job_identity", "log_sha256", "log_truncated",
                  "artifact_sha256", "artifact_truncated", "run_attempt"):
        assert normalized[field] == check[field]
    assert ci_failure_evidence_manifest(evidence)["content_sha256"] == evidence["content_sha256"]


@pytest.mark.parametrize("field,value", [
    ("job_identity", ""),
    ("log_sha256", "not-a-sha"),
    ("log_truncated", "true"),
    ("artifact_sha256", "not-a-sha"),
    ("artifact_truncated", 0),
    ("run_attempt", 0),
    ("run_attempt", True),
])
def test_ci_capsule_rejects_malformed_bounded_evidence_fields(field, value):
    check = {
        "name": "Exact-base impact gate", "status": "failure",
        "check_run_id": 42, "run_id": 9, "external_id": "artifact-9",
        "head_sha": "head", "job_identity": "job-77",
        "log_sha256": "a" * 64, "log_truncated": True,
        "artifact_sha256": "b" * 64, "artifact_truncated": False,
        "run_attempt": 3,
    }
    check[field] = value
    evidence = build_ci_failure_evidence(
        repository="o/r", pr_number=358, base_sha="base", head_sha="head",
        current_main_sha="main", checks=[check], canonical_disposition="NEW_REGRESSION",
        expected_check_run_id=42, expected_run_id=9,
        expected_artifact_identity="artifact-9",
    )
    assert evidence["state"] == "UNKNOWN"
    assert "check identity type or shape invalid" in evidence["evidence_gaps"]


def test_ci_capsule_rejects_hash_valid_bounded_evidence_tamper():
    check = {
        "name": "Exact-base impact gate", "status": "failure",
        "check_run_id": 42, "run_id": 9, "external_id": "artifact-9",
        "head_sha": "head", "job_identity": "job-77",
        "log_sha256": "a" * 64, "log_truncated": True,
        "artifact_sha256": "b" * 64, "artifact_truncated": False,
        "run_attempt": 3,
    }
    evidence = build_ci_failure_evidence(
        repository="o/r", pr_number=358, base_sha="base", head_sha="head",
        current_main_sha="main", checks=[check], canonical_disposition="NEW_REGRESSION",
        expected_check_run_id=42, expected_run_id=9,
        expected_artifact_identity="artifact-9",
    )
    tampered = copy.deepcopy(evidence)
    tampered["checks"][0]["log_sha256"] = "c" * 64
    unsigned = {key: value for key, value in tampered.items() if key != "content_sha256"}
    tampered["content_sha256"] = __import__("hashlib").sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    with pytest.raises(ValueError, match="CI_FAILURE_EVIDENCE_FINGERPRINT_MISMATCH"):
        ci_failure_evidence_manifest(tampered)


def test_ci_failure_manifest_rejects_capsule_or_manifest_hash_tamper():
    evidence = build_ci_failure_evidence(
        repository="o/r", pr_number=1, base_sha="base", head_sha="head",
        current_main_sha="main", checks=[{"name": "exact", "status": "failure",
        "check_run_id": 1, "run_id": 2, "external_id": "artifact", "head_sha": "head"}],
        canonical_disposition="NEW_REGRESSION", expected_check_run_id=1,
        expected_run_id=2, expected_artifact_identity="artifact",
    )
    tampered = copy.deepcopy(evidence)
    tampered["state"] = "CLEAR"
    with pytest.raises(ValueError, match="CI_FAILURE_EVIDENCE_HASH_MISMATCH"):
        ci_failure_evidence_manifest(tampered)
    tampered = copy.deepcopy(evidence)
    tampered["content_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="CI_FAILURE_EVIDENCE_HASH_MISMATCH"):
        ci_failure_evidence_manifest(tampered)


@pytest.mark.parametrize("bad", [
    {"head_sha": "foreign"}, {"run_id": 10}, {"external_id": "other-artifact"},
])
def test_ci_failure_evidence_foreign_identity_is_unknown(bad):
    check = {"name": "Exact-base impact gate", "status": "failure",
             "head_sha": "head", "run_id": 9, "external_id": "artifact-9"}
    check.update(bad)
    evidence = build_ci_failure_evidence(
        repository="o/r", pr_number=1, base_sha="base", head_sha="head",
        current_main_sha="main", checks=[check], canonical_disposition="NEW_REGRESSION",
        expected_check_run_id=9, expected_run_id=9,
        expected_artifact_identity="artifact-9", collection_complete=True,
    )
    assert evidence["state"] == "UNKNOWN"
    assert evidence["evidence_gaps"]


def test_ci_failure_evidence_missing_collection_is_unknown():
    evidence = build_ci_failure_evidence(
        repository="o/r", pr_number=1, base_sha="base", head_sha="head",
        current_main_sha="main", checks=[], canonical_disposition="NEW_REGRESSION",
        expected_check_run_id=1, expected_run_id=9, expected_artifact_identity="artifact",
        collection_complete=False,
        collection_errors=["checks: timeout"],
    )
    assert evidence["state"] == "UNKNOWN"
    assert "checks: timeout" in evidence["evidence_gaps"]


def test_ci_failure_evidence_missing_identity_or_disposition_is_unknown():
    check = {"name": "exact", "status": "failure", "head_sha": "head"}
    evidence = build_ci_failure_evidence(
        repository="o/r", pr_number=1, base_sha="base", head_sha="head",
        current_main_sha="main", checks=[check], canonical_disposition=None,
        expected_check_run_id=1, expected_run_id=2, expected_artifact_identity="artifact",
    )
    assert evidence["state"] == "UNKNOWN"
    assert "canonical disposition unavailable" in evidence["evidence_gaps"]
    assert any("identity" in gap for gap in evidence["evidence_gaps"])


def test_ci_failure_builder_never_triggers_without_exact_terminal_identity():
    for checks in ([], [{"name": "exact", "status": "failure", "check_run_id": 1,
                         "run_id": 2, "external_id": "artifact"}],
                   [{"name": "exact", "status": "failure", "check_run_id": 1,
                     "run_id": 2, "external_id": "artifact", "head_sha": "foreign"}]):
        evidence = build_ci_failure_evidence(
            repository="o/r", pr_number=1, base_sha="base", head_sha="head",
            current_main_sha="main", checks=checks,
            canonical_disposition="NEW_REGRESSION", expected_check_run_id=1,
            expected_run_id=2, expected_artifact_identity="artifact",
        )
        assert evidence["state"] == "UNKNOWN"
        assert evidence["evidence_gaps"]


def test_receipt_rejects_foreign_but_self_valid_capsule(tmp_path):
    from types import SimpleNamespace
    from reviewer.receipt import make_receipt
    evidence = build_ci_failure_evidence(
        repository="o/r", pr_number=1, base_sha="base", head_sha="foreign",
        current_main_sha="main", checks=[{"name": "exact", "status": "failure",
        "check_run_id": 1, "run_id": 2, "external_id": "artifact", "head_sha": "foreign"}],
        canonical_disposition="NEW_REGRESSION", expected_check_run_id=1,
        expected_run_id=2, expected_artifact_identity="artifact",
    )
    context = SimpleNamespace(review_identity=("o/r", 1, "head", "base", "main"), context_sha256="ctx")
    classification = SimpleNamespace(snapshot=SimpleNamespace(source_identity="fixture", changed_files=()), findings=[], risk="LOW")
    transport = SimpleNamespace(raw="", version="", executable="fake", profile=None,
                                session_mode="ephemeral", argv=[], started_at="now", finished_at="now",
                                status="REVIEW_COMPLETED", outcome_unknown=False, retry_safe=False)
    with pytest.raises(ValueError, match="CI_FAILURE_EVIDENCE_REVIEW_IDENTITY_MISMATCH"):
        make_receipt(context, classification, transport, "prompt", "now",
                     parsed={}, parse_result="PARSED", ci_failure_evidence=evidence)


def test_ci_manifest_rejects_hash_valid_semantic_tamper():
    evidence = build_ci_failure_evidence(
        repository="o/r", pr_number=1, base_sha="base", head_sha="head",
        current_main_sha="main", checks=[{"name": "exact", "status": "failure",
        "check_run_id": 1, "run_id": 2, "external_id": "artifact", "head_sha": "head"}],
        canonical_disposition="NEW_REGRESSION", expected_check_run_id=1,
        expected_run_id=2, expected_artifact_identity="artifact",
    )
    for field, value in (("state", "CLEAR"), ("trigger", "attacker"),
                         ("failure_fingerprint", "attacker"),
                         ("claim_ceiling", "APPROVAL"),
                         ("schema", "attacker.schema"),
                         ("canonical_disposition", "attacker")):
        tampered = copy.deepcopy(evidence)
        tampered[field] = value
        unsigned = {key: value for key, value in tampered.items() if key != "content_sha256"}
        tampered["content_sha256"] = __import__("hashlib").sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with pytest.raises(ValueError):
            ci_failure_evidence_manifest(tampered)


def test_ci_manifest_rejects_hash_valid_non_mapping_check():
    evidence = build_ci_failure_evidence(
        repository="o/r", pr_number=1, base_sha="base", head_sha="head",
        current_main_sha="main", checks=[{"name": "exact", "status": "failure",
        "check_run_id": 1, "run_id": 2, "external_id": "artifact", "head_sha": "head"}],
        canonical_disposition="NEW_REGRESSION", expected_check_run_id=1,
        expected_run_id=2, expected_artifact_identity="artifact",
    )
    tampered = copy.deepcopy(evidence)
    tampered["checks"] = ["attacker"]
    unsigned = {key: value for key, value in tampered.items() if key != "content_sha256"}
    tampered["content_sha256"] = __import__("hashlib").sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    with pytest.raises(ValueError):
        ci_failure_evidence_manifest(tampered)


def test_ci_artifact_identity_only_is_valid_and_conflicts_are_unknown():
    base = {"name": "exact", "status": "failure", "check_run_id": 1,
            "run_id": 2, "artifact_identity": "artifact", "head_sha": "head"}
    valid = build_ci_failure_evidence(
        repository="o/r", pr_number=1, base_sha="base", head_sha="head",
        current_main_sha="main", checks=[base], canonical_disposition="NEW_REGRESSION",
        expected_check_run_id=1, expected_run_id=2, expected_artifact_identity="artifact")
    assert valid["state"] == "TRIGGERED"
    matching = dict(base, external_id="artifact")
    matching_evidence = build_ci_failure_evidence(
        repository="o/r", pr_number=1, base_sha="base", head_sha="head",
        current_main_sha="main", checks=[matching], canonical_disposition="NEW_REGRESSION",
        expected_check_run_id=1, expected_run_id=2, expected_artifact_identity="artifact")
    assert matching_evidence["state"] == "TRIGGERED"
    # ``external_id`` is the provider's opaque check identifier (GitHub Actions
    # uses a UUID) and lives in a different namespace from the Actions artifact
    # identity; its presence must never invalidate exact artifact binding.
    live_shape = dict(base, external_id="5b58ae80-d984-5173-ba6d-00dc0014718c")
    live_evidence = build_ci_failure_evidence(
        repository="o/r", pr_number=1, base_sha="base", head_sha="head",
        current_main_sha="main", checks=[live_shape], canonical_disposition="NEW_REGRESSION",
        expected_check_run_id=1, expected_run_id=2, expected_artifact_identity="artifact")
    assert live_evidence["state"] == "TRIGGERED"
    ci_failure_evidence_manifest(live_evidence)
    missing = dict(base); missing.pop("artifact_identity")
    missing_evidence = build_ci_failure_evidence(
        repository="o/r", pr_number=1, base_sha="base", head_sha="head",
        current_main_sha="main", checks=[missing], canonical_disposition="NEW_REGRESSION",
        expected_check_run_id=1, expected_run_id=2, expected_artifact_identity="artifact")
    assert missing_evidence["state"] == "UNKNOWN"
    conflict = dict(base, external_id="other", artifact_identity="other-artifact")
    conflict_evidence = build_ci_failure_evidence(
        repository="o/r", pr_number=1, base_sha="base", head_sha="head",
        current_main_sha="main", checks=[conflict], canonical_disposition="NEW_REGRESSION",
        expected_check_run_id=1, expected_run_id=2, expected_artifact_identity="artifact")
    assert conflict_evidence["state"] == "UNKNOWN"
    assert "foreign check artifact identity" in conflict_evidence["evidence_gaps"]
    with pytest.raises(ValueError, match="CI_FAILURE_EVIDENCE_IDENTITY_MISMATCH"):
        ci_failure_evidence_manifest(conflict_evidence)


@pytest.mark.parametrize("field,value", [
    ("details_url", 7), ("check_suite_id", "7"), ("annotation_count", -1),
    ("annotation_count", True), ("completed_at", {"bad": "value"}),
    ("app_slug", ["bad"]),
])
def test_ci_optional_identity_type_errors_are_unknown(field, value):
    check = {"name": "exact", "status": "failure", "check_run_id": 1,
             "run_id": 2, "external_id": "artifact", "head_sha": "head", field: value}
    evidence = build_ci_failure_evidence(
        repository="o/r", pr_number=1, base_sha="base", head_sha="head",
        current_main_sha="main", checks=[check], canonical_disposition="NEW_REGRESSION",
        expected_check_run_id=1, expected_run_id=2, expected_artifact_identity="artifact")
    assert evidence["state"] == "UNKNOWN"
    assert any("type" in gap for gap in evidence["evidence_gaps"])


def test_ci_identity_domain_rejects_coercion_and_nonpositive_ids():
    valid = build_ci_failure_evidence(
        repository="o/r", pr_number=1, base_sha="base", head_sha="head",
        current_main_sha="main", checks=[{"name": "exact", "status": "failure",
        "check_run_id": 1, "run_id": 2, "external_id": "artifact", "head_sha": "head"}],
        canonical_disposition="NEW_REGRESSION", expected_check_run_id=1,
        expected_run_id=2, expected_artifact_identity="artifact")
    for identity in (["o/r", True, "head", "base", "main"],
                     [[], 1, "head", "base", "main"],
                     ["", 1, "head", "base", "main"],
                     ["o/r", 1, None, "base", "main"],
                     ["o/r", 1, "head", "base", "main"]):
        tampered = copy.deepcopy(valid); tampered["review_identity"] = identity
        if identity == valid["review_identity"]:
            tampered["review_identity"][2] = type("Sha", (str,), {})("head")
        unsigned = {key: value for key, value in tampered.items() if key != "content_sha256"}
        tampered["content_sha256"] = __import__("hashlib").sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with pytest.raises(ValueError):
            ci_failure_evidence_manifest(tampered)
    for expected_check, expected_run in ((0, 2), (-1, 2), (True, 2), (1, 0), (1, -2), (1, False)):
        evidence = build_ci_failure_evidence(
            repository="o/r", pr_number=1, base_sha="base", head_sha="head",
            current_main_sha="main", checks=[{"name": "exact", "status": "failure",
            "check_run_id": expected_check, "run_id": expected_run,
            "external_id": "artifact", "head_sha": "head"}],
            canonical_disposition="NEW_REGRESSION", expected_check_run_id=expected_check,
            expected_run_id=expected_run, expected_artifact_identity="artifact")
        assert evidence["state"] == "UNKNOWN"

def test_collected_failure_is_adapted_to_identity_bound_receipt_capsule():
    snapshot=snapshot_from_github(
        "o/r", {"number": 7, "base": {"sha": "base"}, "head": {"sha": "head"}},
        "main", [], [{"name": "CI", "conclusion": "failure", "id": 1,
                       "run_id": 2, "external_id": "artifact",
                       "artifact_identity": "artifact", "head_sha": "head"}],
    )
    capsule=_ci_evidence_for(classify(snapshot))
    assert capsule["schema"] == "reviewer.ci_failure_evidence.v1"
    assert capsule["review_identity"] == ["o/r", 7, "head", "base", "main"]
    assert capsule["state"] == "UNKNOWN"
    assert "collection" not in " ".join(capsule["evidence_gaps"])


def test_live_github_actions_failure_shape_produces_valid_capsule():
    """Regression: real GitHub Actions checks carry a UUID ``external_id``
    distinct from the numeric Actions artifact identity.  The live PR #537
    failing-check shape must produce a capsule that passes its own manifest
    instead of being rejected with CI_FAILURE_EVIDENCE_IDENTITY_MISMATCH."""
    from reviewer.models import CheckObservation, Classification, Disposition, PRSnapshot
    snapshot = PRSnapshot(
        repository="James3014/Nexus-new", pr_number=537,
        title="canary", state="OPEN", draft=False, mergeable=True,
        base_branch="main", base_sha="35a18e91", head_branch="feature",
        head_sha="4b6fa2bf", current_main_sha="6e261f22",
        checks=(CheckObservation(
            name="Exact-base impact gate", status="failure", expected_failure=False,
            check_run_id=97237033874, run_id=32656935066, run_attempt=1,
            external_id="5b58ae80-d984-5173-ba6d-00dc0014718c",
            artifact_identity="9497704193", job_identity="97237033874",
            head_sha="4b6fa2bf",
        ),),
    )
    classification = Classification(snapshot=snapshot, disposition=Disposition.REVIEW_READY)
    capsule = _ci_evidence_for(classification)
    assert capsule is not None
    assert ci_failure_evidence_manifest(capsule)["state"] == "UNKNOWN"
    # And it must be bindable by make_receipt without raising ValueError.
    from reviewer.receipt import make_receipt

    class Context:
        review_identity = ("James3014/Nexus-new", 537, "4b6fa2bf", "35a18e91", "6e261f22")
        context_sha256 = "ctx"

    class Transport:
        raw = "response"
        status = "REVIEW_COMPLETED"

    receipt = make_receipt(Context(), classification, Transport(), "prompt", "observed",
                           parsed={"schema": "reviewer.semantic_response.v1", "status": "BLOCKED",
                                   "summary": "s", "findings": [], "evidence_gaps": []},
                           parse_result="PARSED", ci_failure_evidence=capsule)
    assert receipt["ci_failure_evidence"] == capsule


def test_incomplete_enrichment_drops_evidence_instead_of_raising():
    """When workflow-run/artifact enrichment cannot bind exact identities the
    capsule would fail its own manifest; _ci_evidence_for must drop it (None)
    rather than poison a completed semantic result with a post-invocation
    ValueError."""
    from reviewer.models import CheckObservation, Classification, Disposition, PRSnapshot
    snapshot = PRSnapshot(
        repository="o/r", pr_number=1, title="t", state="OPEN", draft=False,
        mergeable=True, base_branch="main", base_sha="base", head_branch="feature",
        head_sha="head", current_main_sha="main",
        collection_errors=("workflow run: missing or ambiguous exact-head relationship",),
        checks=(CheckObservation(name="CI", status="failure", check_run_id=1),),
    )
    assert _ci_evidence_for(Classification(snapshot=snapshot,
                                           disposition=Disposition.REVIEW_READY)) is None
