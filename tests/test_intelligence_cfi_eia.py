from __future__ import annotations

import copy
import hashlib
import json

import pytest

import reviewer.intelligence as ri
import reviewer.intelligence_cli as cli


def _rehash(payload: dict) -> None:
    unsigned = dict(payload)
    unsigned.pop("content_sha256", None)
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"))
    payload["content_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _rehash_nested_cfi(payload: dict) -> None:
    _rehash(payload["failure_evidence"])
    _rehash(payload)


def _snapshot(
    *,
    status: str = "failure",
    expected_failure: bool = False,
    complete: bool = True,
    stale_base: bool = False,
    stale_evidence: bool = False,
) -> dict:
    base = "a" * 40
    main = "c" * 40 if stale_base else base
    snapshot = {
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
    if stale_evidence:
        snapshot["declared_head_sha"] = "d" * 40
    return snapshot


def test_cfi_complete_unexpected_failure_is_diagnosis_eligible():
    report = ri.analyze_ci_failure_intelligence(_snapshot())
    payload = report.to_dict()

    assert report.status == ri.CIFailureTriageStatus.UNEXPECTED_FAILURE_OBSERVED
    assert report.diagnosis_eligible is True
    assert report.reason_codes == ("UNEXPECTED_TERMINAL_FAILURE",)
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
    assert report.failed_check_names == ()


def test_cfi_incomplete_collection_fails_closed():
    report = ri.analyze_ci_failure_intelligence(_snapshot(complete=False))
    assert report.status == ri.CIFailureTriageStatus.INSUFFICIENT_EVIDENCE
    assert report.diagnosis_eligible is False
    assert report.evidence_completeness == ri.EvidenceCompleteness.INCOMPLETE
    assert "checks page 2 unavailable" in report.evidence_gaps


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", ri.CIFailureTriageStatus.NO_TERMINAL_FAILURE.value),
        ("diagnosis_eligible", False),
        ("reason_codes", ["ROOT_CAUSE_CONFIRMED"]),
        ("evidence_gaps", ["invented-gap"]),
        ("failed_check_names", ["ci/other"]),
        ("claim_ceiling", "MERGE_READY"),
    ],
)
def test_cfi_verifier_rejects_rehashed_semantic_tamper(field: str, value: object):
    tampered = copy.deepcopy(ri.analyze_ci_failure_intelligence(_snapshot()).to_dict())
    tampered[field] = value
    _rehash(tampered)
    assert ri.verify_ci_failure_intelligence_report(tampered) is False


def test_cfi_verifier_rejects_rehashed_nested_count_tamper():
    tampered = copy.deepcopy(ri.analyze_ci_failure_intelligence(_snapshot()).to_dict())
    tampered["failure_evidence"]["unexpected_count"] = 0
    _rehash_nested_cfi(tampered)
    assert ri.verify_ci_failure_intelligence_report(tampered) is False


def test_cfi_verifier_rejects_rehashed_nonterminal_failure_group():
    tampered = copy.deepcopy(ri.analyze_ci_failure_intelligence(_snapshot()).to_dict())
    tampered["failure_evidence"]["unexpected_failures"][0]["status"] = "success"
    _rehash_nested_cfi(tampered)
    assert ri.verify_ci_failure_intelligence_report(tampered) is False


def test_eia_ready_only_for_complete_unexpected_failure_on_current_base():
    envelope = ri.plan_external_intelligence_automation({"snapshot": _snapshot()})
    payload = envelope.to_dict()

    assert envelope.decision == ri.ExternalIntelligenceDecision.READY
    assert envelope.action_kind == "CI_FAILURE_DIAGNOSIS"
    assert envelope.reason_codes == ("UNEXPECTED_FAILURE_WITH_COMPLETE_EVIDENCE",)
    assert envelope.evidence_gaps == ()
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
    assert expected.reason_codes == ("EXPECTED_FAILURE_ONLY",)
    assert success.reason_codes == ("NO_TERMINAL_FAILURE",)


def test_eia_blocks_incomplete_stale_base_or_stale_evidence():
    incomplete = ri.plan_external_intelligence_automation({"snapshot": _snapshot(complete=False)})
    stale_base = ri.plan_external_intelligence_automation({"snapshot": _snapshot(stale_base=True)})
    stale_evidence = ri.plan_external_intelligence_automation({"snapshot": _snapshot(stale_evidence=True)})

    assert incomplete.decision == ri.ExternalIntelligenceDecision.BLOCKED
    assert incomplete.reason_codes == ("EVIDENCE_INSUFFICIENT_FOR_AUTOMATION",)
    for stale in (stale_base, stale_evidence):
        assert stale.decision == ri.ExternalIntelligenceDecision.BLOCKED
        assert stale.reason_codes == ("IDENTITY_STALE_FOR_AUTOMATION",)
        assert "identity_stale_for_automation" in stale.evidence_gaps


def test_eia_verified_cfi_report_path_and_tamper_rejection():
    cfi = ri.analyze_ci_failure_intelligence(_snapshot()).to_dict()
    envelope = ri.plan_external_intelligence_automation({"cfi_report": cfi})
    assert envelope.decision == ri.ExternalIntelligenceDecision.READY

    cfi["diagnosis_eligible"] = False
    with pytest.raises(ValueError, match="invalid or tampered"):
        ri.plan_external_intelligence_automation({"cfi_report": cfi})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("claim_ceiling", "MERGE_READY"),
        ("action_kind", "MERGE"),
        ("reason_codes", ["MERGE_READY"]),
        ("evidence_gaps", ["ignored-gap"]),
    ],
)
def test_eia_verifier_rejects_rehashed_authority_or_semantic_tamper(field: str, value: object):
    tampered = copy.deepcopy(ri.plan_external_intelligence_automation({"snapshot": _snapshot()}).to_dict())
    tampered[field] = value
    if field == "action_kind":
        # Recompute idempotency via public planner is intentionally unavailable;
        # changing the action while retaining the old key must fail closed.
        pass
    _rehash(tampered)
    assert ri.verify_external_intelligence_automation_envelope(tampered) is False


def test_eia_verifier_rejects_rehashed_ready_on_stale_identity():
    payload = ri.plan_external_intelligence_automation({"snapshot": _snapshot(stale_base=True)}).to_dict()
    payload["decision"] = ri.ExternalIntelligenceDecision.READY.value
    payload["action_kind"] = "CI_FAILURE_DIAGNOSIS"
    payload["reason_codes"] = ["UNEXPECTED_FAILURE_WITH_COMPLETE_EVIDENCE"]
    payload["evidence_gaps"] = []
    _rehash(payload)
    assert ri.verify_external_intelligence_automation_envelope(payload) is False


def test_eia_verifier_rejects_rehashed_no_action_on_stale_identity():
    payload = ri.plan_external_intelligence_automation({
        "snapshot": _snapshot(stale_base=True, expected_failure=True)
    }).to_dict()
    payload["decision"] = ri.ExternalIntelligenceDecision.NO_ACTION.value
    payload["action_kind"] = "NONE"
    payload["reason_codes"] = ["EXPECTED_FAILURE_ONLY"]
    payload["evidence_gaps"] = []
    _rehash(payload)
    assert ri.verify_external_intelligence_automation_envelope(payload) is False


def test_eia_verifier_rejects_insufficient_block_without_gap():
    payload = ri.plan_external_intelligence_automation({"snapshot": _snapshot(complete=False)}).to_dict()
    payload["evidence_gaps"] = []
    _rehash(payload)
    assert ri.verify_external_intelligence_automation_envelope(payload) is False


def test_cli_exposes_cfi_and_eia_with_exact_claim_ceilings():
    cfi = cli.execute_operation("cfi", _snapshot())
    eia = cli.execute_operation("eia", {"snapshot": _snapshot()})

    assert cfi["operation"] == "cfi"
    assert cfi["claim_ceiling"] == "CI_EVIDENCE_ONLY"
    assert cfi["result"]["status"] == "UNEXPECTED_FAILURE_OBSERVED"
    assert eia["operation"] == "eia"
    assert eia["claim_ceiling"] == "AUTOMATION_ADVISORY_ONLY"
    assert eia["result"]["decision"] == "READY"


def test_n4_adds_read_only_cloud_adapter_without_direct_mcp_authority():
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    assert (root / "action.yml").exists()
    assert (root / "reviewer" / "github_action.py").exists()
    assert not (root / "reviewer" / "mcp_server.py").exists()
    action_text = (root / "action.yml").read_text(encoding="utf-8")
    assert "actions/checkout" not in action_text
    assert "pull_request_target" not in action_text
