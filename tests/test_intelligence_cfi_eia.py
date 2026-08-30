from __future__ import annotations

import copy
import hashlib
import json

import reviewer.intelligence as ri
import reviewer.intelligence_cli as cli


def _rehash(payload: dict) -> None:
    unsigned = dict(payload)
    unsigned.pop("content_sha256", None)
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"))
    payload["content_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _snapshot(*, status: str = "failure", expected_failure: bool = False, complete: bool = True, stale: bool = False) -> dict:
    base = "a" * 40
    main = "c" * 40 if stale else base
    return {
        "repository": "owner/repo",
        "pr_number": 42,
        "base_sha": base,
        "head_sha": "b" * 40,
        "current_main_sha": main,
        "changed_files": ["src/core.ts"],
        "checks": [
            {
                "name": "ci/test",
                "status": status,
                "expected_failure": expected_failure,
                "head_sha": "b" * 40,
                "check_run_id": 1001,
                "run_id": 2001,
                "job_identity": "3001",
            }
        ],
        "collection_complete": complete,
        "collection_errors": [] if complete else ["checks page 2 unavailable"],
    }


def test_cfi_complete_unexpected_failure_is_diagnosis_eligible():
    report = ri.analyze_ci_failure_intelligence(_snapshot())
    payload = report.to_dict()

    assert report.status == ri.CIFailureTriageStatus.UNEXPECTED_FAILURE_OBSERVED
    assert report.diagnosis_eligible is True
    assert report.failed_check_names == ("ci/test",)
    assert report.claim_ceiling == "CI_EVIDENCE_ONLY"
    assert payload["failure_evidence"]["is_complete"] is True
    assert ri.verify_ci_failure_intelligence_report(payload) is True


def test_cfi_expected_failure_is_not_diagnosis_eligible():
    report = ri.analyze_ci_failure_intelligence(_snapshot(expected_failure=True))
    assert report.status == ri.CIFailureTriageStatus.EXPECTED_FAILURE_ONLY
    assert report.diagnosis_eligible is False
    assert report.reason_codes == ("EXPECTED_FAILURE_ONLY",)


def test_cfi_successful_check_is_no_terminal_failure():
    report = ri.analyze_ci_failure_intelligence(_snapshot(status="success"))
    assert report.status == ri.CIFailureTriageStatus.NO_TERMINAL_FAILURE
    assert report.diagnosis_eligible is False


def test_cfi_incomplete_collection_fails_closed():
    report = ri.analyze_ci_failure_intelligence(_snapshot(complete=False))
    assert report.status == ri.CIFailureTriageStatus.INSUFFICIENT_EVIDENCE
    assert report.diagnosis_eligible is False
    assert report.evidence_completeness == ri.EvidenceCompleteness.INCOMPLETE


def test_cfi_verifier_rejects_rehashed_semantic_tamper():
    payload = ri.analyze_ci_failure_intelligence(_snapshot()).to_dict()
    tampered = copy.deepcopy(payload)
    tampered["status"] = ri.CIFailureTriageStatus.NO_TERMINAL_FAILURE.value
    tampered["diagnosis_eligible"] = False
    _rehash(tampered)
    assert ri.verify_ci_failure_intelligence_report(tampered) is False


def test_eia_ready_only_for_complete_unexpected_failure_on_current_base():
    envelope = ri.plan_external_intelligence_automation({"snapshot": _snapshot()})
    payload = envelope.to_dict()

    assert envelope.decision == ri.ExternalIntelligenceDecision.READY
    assert envelope.action_kind == "CI_FAILURE_DIAGNOSIS"
    assert len(envelope.idempotency_key) == 64
    assert envelope.claim_ceiling == "AUTOMATION_ADVISORY_ONLY"
    assert ri.verify_external_intelligence_automation_envelope(payload) is True

    replay = ri.plan_external_intelligence_automation({"snapshot": _snapshot()})
    assert replay.idempotency_key == envelope.idempotency_key
    assert replay.content_sha256 == envelope.content_sha256


def test_eia_no_action_for_expected_or_no_failure():
    expected = ri.plan_external_intelligence_automation({"snapshot": _snapshot(expected_failure=True)})
    success = ri.plan_external_intelligence_automation({"snapshot": _snapshot(status="success")})
    assert expected.decision == ri.ExternalIntelligenceDecision.NO_ACTION
    assert success.decision == ri.ExternalIntelligenceDecision.NO_ACTION
    assert expected.action_kind == success.action_kind == "NONE"


def test_eia_blocks_incomplete_or_stale_identity():
    incomplete = ri.plan_external_intelligence_automation({"snapshot": _snapshot(complete=False)})
    stale = ri.plan_external_intelligence_automation({"snapshot": _snapshot(stale=True)})

    assert incomplete.decision == ri.ExternalIntelligenceDecision.BLOCKED
    assert "EVIDENCE_INSUFFICIENT_FOR_AUTOMATION" in incomplete.reason_codes
    assert stale.decision == ri.ExternalIntelligenceDecision.BLOCKED
    assert "IDENTITY_STALE_FOR_AUTOMATION" in stale.reason_codes
    assert "identity_stale_for_automation" in stale.evidence_gaps


def test_eia_verified_cfi_report_path_and_tamper_rejection():
    cfi = ri.analyze_ci_failure_intelligence(_snapshot()).to_dict()
    envelope = ri.plan_external_intelligence_automation({"cfi_report": cfi})
    assert envelope.decision == ri.ExternalIntelligenceDecision.READY

    cfi["diagnosis_eligible"] = False
    try:
        ri.plan_external_intelligence_automation({"cfi_report": cfi})
    except ValueError as exc:
        assert "invalid or tampered" in str(exc)
    else:
        raise AssertionError("tampered CFI report must fail closed")


def test_eia_verifier_rejects_rehashed_authority_upgrade():
    payload = ri.plan_external_intelligence_automation({"snapshot": _snapshot()}).to_dict()
    tampered = copy.deepcopy(payload)
    tampered["claim_ceiling"] = "MERGE_READY"
    _rehash(tampered)
    assert ri.verify_external_intelligence_automation_envelope(tampered) is False


def test_cli_exposes_cfi_and_eia_with_exact_claim_ceilings():
    cfi = cli.execute_operation("cfi", _snapshot())
    eia = cli.execute_operation("eia", {"snapshot": _snapshot()})

    assert cfi["operation"] == "cfi"
    assert cfi["claim_ceiling"] == "CI_EVIDENCE_ONLY"
    assert cfi["result"]["status"] == "UNEXPECTED_FAILURE_OBSERVED"
    assert eia["operation"] == "eia"
    assert eia["claim_ceiling"] == "AUTOMATION_ADVISORY_ONLY"
    assert eia["result"]["decision"] == "READY"
