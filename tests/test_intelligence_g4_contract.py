from __future__ import annotations

import copy
import hashlib
import json

import reviewer.intelligence as ri
from reviewer.models import Disposition, PRSnapshot
import reviewer.intelligence_cli as intelligence_cli


def _snapshot(**overrides):
    data = {
        "repository": "owner/repo",
        "pr_number": 1,
        "title": "demo",
        "state": "OPEN",
        "draft": False,
        "mergeable": True,
        "base_branch": "main",
        "base_sha": "main-sha",
        "head_branch": "feature",
        "head_sha": "head-sha",
        "current_main_sha": "main-sha",
        "changed_files": [],
        "issue_numbers": [],
        "labels": [],
        "checks": [],
        "source_identity": "fixture:g4",
        "collection_complete": True,
        "collection_errors": [],
        "do_not_merge": False,
        "expected_failure": False,
    }
    data.update(overrides)
    return data


def test_g4_invalid_identity_never_review_ready():
    result = ri.classify_readiness(
        _snapshot(repository="", pr_number=0, head_sha="", base_sha="", current_main_sha="")
    )
    assert result.identity.is_valid is False
    assert result.disposition != Disposition.REVIEW_READY
    assert result.is_review_ready is False
    assert "INVALID_IDENTITY" in result.findings
    assert result.evidence_completeness.value == "INCOMPLETE"


def test_g4_generic_policy_defaults_empty_and_nexus_paths_require_explicit_profile():
    assert hasattr(ri, "RepositoryIntelligencePolicyV1")
    generic = ri.RepositoryIntelligencePolicyV1()
    assert generic.protected_path_patterns == ()

    snap = _snapshot(changed_files=["AGENTS.md"])
    default_result = ri.classify_readiness(snap)
    assert "AUTHORITY_OVERLAP" not in default_result.findings

    nexus_policy = ri.RepositoryIntelligencePolicyV1(
        protected_path_patterns=("AGENTS.md", "docs/agents/", "docs/governance/", "policy/")
    )
    nexus_result = ri.classify_readiness(snap, policy=nexus_policy)
    assert "AUTHORITY_OVERLAP" in nexus_result.findings


def test_g4_core_ignores_provider_prose_and_uses_normalized_flags_only():
    prose_only = _snapshot(body="DO NOT MERGE this PR", do_not_merge=False)
    normalized = _snapshot(body="ordinary prose", do_not_merge=True)

    prose_result = ri.classify_readiness(prose_only)
    normalized_result = ri.classify_readiness(normalized)

    assert "DO_NOT_MERGE" not in prose_result.findings
    assert prose_result.disposition == Disposition.REVIEW_READY
    assert "DO_NOT_MERGE" in normalized_result.findings
    assert normalized_result.disposition == Disposition.EVIDENCE_ONLY


def test_g4_raw_declared_identity_prose_is_not_core_input():
    physical_head = "1" * 40
    declared_other = "2" * 40
    prose_only = _snapshot(
        head_sha=physical_head,
        body=f"Exact head: {declared_other}",
        declared_head_sha=None,
    )
    explicit = _snapshot(
        head_sha=physical_head,
        body="ordinary prose",
        declared_head_sha=declared_other,
    )

    assert "STALE_EVIDENCE" not in ri.classify_readiness(prose_only).findings
    assert "STALE_EVIDENCE" in ri.classify_readiness(explicit).findings


def test_g4_claim_ceilings_are_distinct_and_exact():
    assert ri.CLAIM_CEILING == "PR_INTELLIGENCE_ONLY"
    assert ri.CI_EVIDENCE_CLAIM_CEILING == "CI_EVIDENCE_ONLY"

    readiness = ri.classify_readiness(_snapshot())
    assert readiness.claim_ceiling == "PR_INTELLIGENCE_ONLY"

    ci = ri.fingerprint_ci_failures(
        _snapshot(
            checks=[{
                "name": "ci",
                "status": "failure",
                "expected_failure": False,
                "head_sha": "head-sha",
                "check_run_id": 11,
                "run_id": 22,
                "job_identity": "job-33",
                "artifact_identity": "artifact-44",
            }]
        ),
        expected_check_run_id=11,
        expected_run_id=22,
        expected_job_identity="job-33",
        expected_artifact_identity="artifact-44",
    )
    assert ci.claim_ceiling == "CI_EVIDENCE_ONLY"


def test_g4_ci_foreign_run_job_artifact_fail_closed():
    ci = ri.fingerprint_ci_failures(
        _snapshot(
            checks=[{
                "name": "ci",
                "status": "failure",
                "expected_failure": False,
                "head_sha": "head-sha",
                "check_run_id": 11,
                "run_id": 999,
                "job_identity": "job-foreign",
                "artifact_identity": "artifact-foreign",
            }]
        ),
        expected_check_run_id=11,
        expected_run_id=22,
        expected_job_identity="job-33",
        expected_artifact_identity="artifact-44",
    )
    assert ci.is_complete is False
    assert ci.evidence_completeness.value == "INCOMPLETE"
    joined = " | ".join(ci.evidence_gaps)
    assert "run" in joined
    assert "job" in joined
    assert "artifact" in joined


def test_g4_ci_content_hash_tamper_is_rejected():
    assert hasattr(ri, "verify_ci_failure_evidence")
    ci = ri.fingerprint_ci_failures(
        _snapshot(
            checks=[{
                "name": "ci",
                "status": "failure",
                "expected_failure": False,
                "head_sha": "head-sha",
                "check_run_id": 11,
            }]
        )
    )
    payload = ci.to_dict()
    assert payload["content_sha256"]
    assert ri.verify_ci_failure_evidence(payload) is True

    tampered = copy.deepcopy(payload)
    tampered["identity"]["head_sha"] = "foreign-head"
    assert ri.verify_ci_failure_evidence(tampered) is False

    # Recomputing the self-hash must not hide an internally inconsistent identity.
    rehashed = copy.deepcopy(payload)
    rehashed["identity"]["head_sha"] = "foreign-head"
    unsigned = dict(rehashed)
    unsigned.pop("content_sha256", None)
    rehashed["content_sha256"] = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert ri.verify_ci_failure_evidence(rehashed) is False


def test_g4_evidence_completeness_has_three_states():
    assert {x.value for x in ri.EvidenceCompleteness} == {"COMPLETE", "PARTIAL", "INCOMPLETE"}

    complete = ri.classify_readiness(_snapshot())
    partial = ri.classify_readiness(
        _snapshot(collection_complete=True, collection_errors=["optional metadata unavailable"])
    )
    incomplete = ri.classify_readiness(
        _snapshot(collection_complete=False, collection_errors=["checks unavailable"])
    )

    assert complete.evidence_completeness == ri.EvidenceCompleteness.COMPLETE
    assert partial.evidence_completeness == ri.EvidenceCompleteness.PARTIAL
    assert incomplete.evidence_completeness == ri.EvidenceCompleteness.INCOMPLETE


def test_g4_repository_report_is_hash_bound_and_tamper_detectable():
    assert hasattr(ri, "build_repository_intelligence_report")
    assert hasattr(ri, "verify_repository_intelligence_report")

    report = ri.build_repository_intelligence_report([
        _snapshot(pr_number=1, head_sha="h1"),
        _snapshot(pr_number=2, head_sha="h2", changed_files=["shared.py"]),
    ])
    payload = report.to_dict()
    assert payload["schema"] == "reviewer.repository_intelligence.v1"
    assert payload["claim_ceiling"] == "PR_INTELLIGENCE_ONLY"
    assert payload["content_sha256"]
    assert ri.verify_repository_intelligence_report(payload) is True

    tampered = copy.deepcopy(payload)
    tampered["items"][0]["disposition"] = "REVIEW_READY" if tampered["items"][0]["disposition"] != "REVIEW_READY" else "STALE"
    assert ri.verify_repository_intelligence_report(tampered) is False


def test_g4_stale_label_policy_is_injected():
    assert hasattr(ri, "RepositoryIntelligencePolicyV1")
    snap = _snapshot(labels=["custom-stale"])

    default_result = ri.classify_readiness(snap)
    custom_result = ri.classify_readiness(
        snap,
        policy=ri.RepositoryIntelligencePolicyV1(stale_labels=("custom-stale",)),
    )

    assert "STALE_LONG_LIVED" not in default_result.findings
    assert "STALE_LONG_LIVED" in custom_result.findings
    assert custom_result.disposition == Disposition.STALE


def test_g4_v11_change_impact_is_public_with_advisory_ceiling():
    assert hasattr(ri, "analyze_change_impact")
    assert hasattr(ri, "ChangeImpactReportV1")
    assert hasattr(ri, "verify_change_impact_report")
    assert "impact" in intelligence_cli.OPERATIONS
