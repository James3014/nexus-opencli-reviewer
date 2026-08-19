from reviewer.render import MAX_BODY, render_advisory
from reviewer.receipt import build_ci_failure_evidence


def test_render_escapes_markdown_and_html_comment_controls():
    result = render_advisory(
        {"status": "FINDINGS", "summary": "<!-- hide --> **spoof** [x]", "findings": [{"severity": "HIGH", "category": "x|y", "path": "a`b", "reason": "</div>"}]},
        reviewed_head="head",
        attempt_id="a1",
    )
    assert "<!--" not in result and "-->" not in result
    assert "\\*\\*spoof\\*\\*" in result
    assert result.count("NOT APPROVAL") == 2


def test_render_caps_fields_and_body():
    result = render_advisory(
        {"status": "PASS", "summary": "x" * 10000, "findings": [{"severity": "LOW", "category": "c", "path": "p", "reason": "r" * 10000}]},
        reviewed_head="h",
        attempt_id="id",
    )
    assert len(result) <= MAX_BODY
    assert len(result) > 0


def test_render_reserves_terminal_claim_boundary_for_hostile_maximum_payload():
    result = render_advisory(
        {"status": "FINDINGS", "summary": "x" * 10000,
         "findings": [{"severity": "LOW", "category": "c", "path": "p",
                       "evidence": "e", "reason": "r" * 10000,
                       "recommended_action": "a" * 10000} for _ in range(50)]},
        reviewed_head="head", attempt_id="attempt", content_hash="hash",
    )
    assert len(result) <= MAX_BODY
    assert result.rstrip().endswith(
        "reviewer-publication-v1:attempt:hash"
    )
    assert result.count("NOT APPROVAL") == 2


def test_render_uses_only_semantic_fields_and_fixed_disclaimer():
    result = render_advisory(
        {"status": "PASS", "summary": "ok", "findings": [], "raw_response": "SECRET", "prompt": "PRIVATE"},
        reviewed_head="h",
        attempt_id="id",
    )
    assert "SECRET" not in result and "PRIVATE" not in result
    assert result.startswith("Automated PRE_REVIEW\nADVISORY ONLY")
    assert result.rstrip().endswith("id:pending")


def test_render_includes_bounded_ci_failure_intelligence_capsule():
    evidence = build_ci_failure_evidence(
        repository="o/r", pr_number=1, base_sha="base", head_sha="head",
        current_main_sha="main", canonical_disposition="NEW_REGRESSION",
        expected_check_run_id=1, expected_run_id=2,
        expected_artifact_identity="artifact",
        checks=[{"name": "exact", "status": "failure", "check_run_id": 1,
                 "run_id": 2, "external_id": "artifact", "head_sha": "head"}],
    )
    result = render_advisory(
        {"status": "FINDINGS", "summary": "ci", "findings": []},
        reviewed_head="head", attempt_id="id",
        ci_failure_evidence=evidence,
        review_identity=("o/r", 1, "head", "base", "main"),
    )
    assert "CI Failure Intelligence" in result
    assert "NEXUS\\_EXACT\\_BASE" in result
    assert "CI\\_EVIDENCE\\_ONLY" in result
    assert evidence["content_sha256"] in result


def test_render_marks_incomplete_ci_evidence_unknown():
    result = render_advisory(
        {"status": "PASS", "summary": "ok", "findings": []},
        reviewed_head="head", attempt_id="id",
        ci_failure_evidence={
            "schema": "reviewer.ci_failure_evidence.v1", "state": "UNKNOWN",
            "trigger": None, "content_sha256": "b" * 64,
            "evidence_gaps": ["checks unavailable"],
            "claim_ceiling": "CI_EVIDENCE_ONLY",
        },
    )
    assert "State: UNKNOWN" in result and "CI evidence unavailable" in result


def test_render_rejects_unvalidated_ci_capsule_as_unknown_gap():
    result = render_advisory(
        {"status": "PASS", "summary": "ok", "findings": []},
        reviewed_head="head", attempt_id="id",
        ci_failure_evidence={"schema": "reviewer.ci_failure_evidence.v1",
                             "state": "TRIGGERED", "content_sha256": "0" * 64},
    )
    assert "State: UNKNOWN" in result
    assert "CI evidence unavailable" in result


def test_render_rejects_foreign_but_self_valid_capsule():
    evidence = build_ci_failure_evidence(
        repository="o/r", pr_number=1, base_sha="base", head_sha="foreign",
        current_main_sha="main", canonical_disposition="NEW_REGRESSION",
        expected_check_run_id=1, expected_run_id=2,
        expected_artifact_identity="artifact",
        checks=[{"name": "exact", "status": "failure", "check_run_id": 1,
                 "run_id": 2, "external_id": "artifact", "head_sha": "foreign"}],
    )
    result = render_advisory({"status": "PASS", "summary": "ok", "findings": []},
                             reviewed_head="head", attempt_id="id",
                             ci_failure_evidence=evidence)
    assert "State: UNKNOWN" in result
    assert "CI evidence unavailable" in result
    assert "NEXUS\\_EXACT\\_BASE" not in result


def test_render_hash_valid_semantic_tamper_is_unavailable_without_attacker_values():
    evidence = build_ci_failure_evidence(
        repository="o/r", pr_number=1, base_sha="base", head_sha="head",
        current_main_sha="main", canonical_disposition="NEW_REGRESSION",
        expected_check_run_id=1, expected_run_id=2,
        expected_artifact_identity="artifact",
        checks=[{"name": "exact", "status": "failure", "check_run_id": 1,
                 "run_id": 2, "external_id": "artifact", "head_sha": "head"}],
    )
    evidence["trigger"] = "ATTACKER_TRIGGER"
    unsigned = {key: value for key, value in evidence.items() if key != "content_sha256"}
    evidence["content_sha256"] = __import__("hashlib").sha256(
        __import__("json").dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    result = render_advisory({"status": "PASS", "summary": "ok", "findings": []},
                             reviewed_head="head", attempt_id="id",
                             ci_failure_evidence=evidence)
    assert "State: UNKNOWN" in result and "CI evidence unavailable" in result
    assert "ATTACKER_TRIGGER" not in result
