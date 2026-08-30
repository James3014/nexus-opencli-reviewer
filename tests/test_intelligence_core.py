"""Deterministic golden oracle tests for reviewer.intelligence core operations (G4-G6).

Covers:
- Exact revision identity stability and stale-base / stale-declared evidence distinctions
- Readiness classifier preserving existing dispositions (DRAFT, STALE_BASE, DO_NOT_MERGE,
  COLLECTION_INCOMPLETE, AUTHORITY_OVERLAP / risk, REVIEW_READY)
- Cross-PR overlap symmetry and WAIT_REBIND only for originally eligible peers (stale/draft
  peers add risk context without blocking eligible peers), including shared issue chains
- Generic CI fingerprinting: deterministic hashing, expected vs unexpected failures,
  terminal statuses, foreign check head_sha detection, and evidence gaps without false certainty
- Architectural import isolation ensuring no transport, semantic LLM, or ops imports
"""
from __future__ import annotations

import json
import sys
from typing import Any

import pytest

from reviewer.intelligence import (
    CLAIM_CEILING,
    CI_EVIDENCE_CLAIM_CEILING,
    TERMINAL_FAILURE_STATUSES,
    CIFailureFingerprint,
    CrossPROverlapResult,
    Disposition,
    NormalizedCheckEvidence,
    ReadinessClassification,
    RevisionIdentity,
    analyze_cross_pr_overlap,
    classify_readiness,
    fingerprint_ci_failures,
    revision_identity,
)
from reviewer.models import CheckObservation, PRSnapshot


# ---------------------------------------------------------------------------
# 1. Architectural Isolation Tests
# ---------------------------------------------------------------------------


def test_architectural_import_isolation():
    """reviewer.intelligence must not import transport, publication, webmcp, service, or CLI."""
    import ast
    from pathlib import Path

    forbidden_prefixes = (
        "reviewer.github",
        "reviewer.publication",
        "reviewer.webmcp",
        "reviewer.service",
        "reviewer.service_cli",
        "reviewer.opencli",
        "reviewer.unattended",
        "reviewer.semantic",
        "reviewer.receipt",
        "reviewer.render",
        "reviewer.scan",
    )

    intelligence_dir = Path(__file__).resolve().parent.parent / "reviewer" / "intelligence"
    py_files = sorted(intelligence_dir.glob("*.py"))
    assert len(py_files) >= 3, f"Expected at least 3 python files in {intelligence_dir}"

    for py_file in py_files:
        code = py_file.read_text(encoding="utf-8")
        tree = ast.parse(code, filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    for forbidden in forbidden_prefixes:
                        assert not (alias.name == forbidden or alias.name.startswith(forbidden + ".")), (
                            f"File {py_file.name} illegally imports '{alias.name}'"
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    for forbidden in forbidden_prefixes:
                        assert not (node.module == forbidden or node.module.startswith(forbidden + ".")), (
                            f"File {py_file.name} illegally imports from '{node.module}'"
                        )
                for alias in node.names:
                    full_name = f"{node.module}.{alias.name}" if node.module else alias.name
                    for forbidden in forbidden_prefixes:
                        assert not (full_name == forbidden or full_name.startswith(forbidden + ".")), (
                            f"File {py_file.name} illegally imports '{full_name}'"
                        )


# ---------------------------------------------------------------------------
# 2. Revision Identity & Stale Distinctions
# ---------------------------------------------------------------------------


def test_revision_identity_deterministic_and_stable():
    snap = PRSnapshot.from_dict(
        {
            "repository": "owner/repo",
            "pr_number": 42,
            "base_sha": "base123",
            "head_sha": "head456",
        },
        main="base123",
    )
    rev_id = revision_identity(snap)

    assert rev_id.repository == "owner/repo"
    assert rev_id.pr_number == 42
    assert rev_id.base_sha == "base123"
    assert rev_id.head_sha == "head456"
    assert rev_id.current_main_sha == "base123"
    assert rev_id.is_valid is True
    assert rev_id.stale_base is False
    assert rev_id.stale_evidence is False
    assert rev_id.review_identity == ("owner/repo", 42, "head456", "base123", "base123")

    # Byte-for-byte serialization stability
    d1 = rev_id.to_dict()
    d2 = rev_id.to_dict()
    assert json.dumps(d1, sort_keys=True) == json.dumps(d2, sort_keys=True)


def test_revision_identity_stale_base_detection():
    snap = PRSnapshot.from_dict(
        {
            "repository": "owner/repo",
            "pr_number": 1,
            "base_sha": "old_base",
            "head_sha": "head_sha",
        },
        main="new_main",
    )
    rev_id = revision_identity(snap)
    assert rev_id.stale_base is True
    assert rev_id.stale_evidence is False


def test_revision_identity_stale_declared_evidence():
    # Base declared mismatch via declared_base
    snap_base = PRSnapshot.from_dict(
        {
            "repository": "owner/repo",
            "pr_number": 1,
            "base_sha": "actual_base",
            "head_sha": "head_sha",
            "declared_base": "other_base",
        },
        main="actual_base",
    )
    rev_base = revision_identity(snap_base)
    assert rev_base.stale_base is False
    assert rev_base.stale_declared_base is True
    assert rev_base.stale_evidence is True

    # Head declared mismatch via body regex
    snap_head = PRSnapshot.from_dict(
        {
            "repository": "owner/repo",
            "pr_number": 2,
            "base_sha": "base_sha",
            "head_sha": "1111111111111111111111111111111111111111",
            "body": "Exact head: 2222222222222222222222222222222222222222",
        },
        main="base_sha",
    )
    rev_head = revision_identity(snap_head)
    assert rev_head.stale_declared_head is True
    assert rev_head.stale_evidence is True

    # Main declared mismatch via declared_main
    snap_main = PRSnapshot.from_dict(
        {
            "repository": "owner/repo",
            "pr_number": 3,
            "base_sha": "base_sha",
            "head_sha": "head_sha",
            "declared_main": "divergent_main",
        },
        main="base_sha",
    )
    rev_main = revision_identity(snap_main)
    assert rev_main.stale_declared_main is True
    assert rev_main.stale_evidence is True


def test_revision_identity_validation_gaps():
    invalid_snap = {
        "repository": "not-a-valid-repo-no-slash",
        "pr_number": -5,
        "base_sha": "",
        "head_sha": "",
        "current_main_sha": "",
    }
    rev_id = revision_identity(invalid_snap)
    assert rev_id.is_valid is False
    assert len(rev_id.evidence_gaps) >= 4
    assert any("repository" in g for g in rev_id.evidence_gaps)
    assert any("pr_number" in g for g in rev_id.evidence_gaps)
    assert any("head_sha" in g for g in rev_id.evidence_gaps)


# ---------------------------------------------------------------------------
# 3. Classifier Readiness Projection
# ---------------------------------------------------------------------------


def test_classify_readiness_review_ready():
    snap = PRSnapshot.from_dict(
        {
            "repository": "owner/repo",
            "pr_number": 10,
            "base_sha": "main_sha",
            "head_sha": "head_sha",
            "changed_files": ["src/app.py"],
        },
        main="main_sha",
    )
    res = classify_readiness(snap)
    assert isinstance(res, ReadinessClassification)
    assert res.disposition == Disposition.REVIEW_READY
    assert res.is_review_ready is True
    assert res.claim_ceiling == CLAIM_CEILING
    assert res.risk == "MED"
    assert len(res.findings) == 0

    d = res.to_dict()
    assert d["repository"] == "owner/repo"
    assert d["pr_number"] == 10
    assert d["disposition"] == "REVIEW_READY"
    assert d["claim_ceiling"] == CLAIM_CEILING


def test_classify_readiness_preserves_all_standard_dispositions():
    # Draft -> EXCLUDED
    draft_snap = PRSnapshot.from_dict(
        {"repository": "o/r", "pr_number": 1, "base_sha": "m", "head_sha": "h", "draft": True},
        main="m",
    )
    assert classify_readiness(draft_snap).disposition == Disposition.EXCLUDED
    assert "DRAFT" in classify_readiness(draft_snap).findings

    # Non-mergeable -> EXCLUDED
    nm_snap = PRSnapshot.from_dict(
        {"repository": "o/r", "pr_number": 2, "base_sha": "m", "head_sha": "h", "mergeable": False},
        main="m",
    )
    assert classify_readiness(nm_snap).disposition == Disposition.EXCLUDED
    assert "NON_MERGEABLE" in classify_readiness(nm_snap).findings

    # Stale base -> STALE
    stale_snap = PRSnapshot.from_dict(
        {"repository": "o/r", "pr_number": 3, "base_sha": "old", "head_sha": "h"},
        main="new",
    )
    assert classify_readiness(stale_snap).disposition == Disposition.STALE
    assert "STALE_BASE" in classify_readiness(stale_snap).findings

    # Do not merge -> EVIDENCE_ONLY
    dnm_snap = PRSnapshot.from_dict(
        {"repository": "o/r", "pr_number": 4, "base_sha": "m", "head_sha": "h", "do_not_merge": True},
        main="m",
    )
    assert classify_readiness(dnm_snap).disposition == Disposition.EVIDENCE_ONLY
    assert "DO_NOT_MERGE" in classify_readiness(dnm_snap).findings

    # Collection incomplete -> NEEDS_ATTENTION
    inc_snap = PRSnapshot.from_dict(
        {
            "repository": "o/r",
            "pr_number": 5,
            "base_sha": "m",
            "head_sha": "h",
            "collection_complete": False,
            "collection_errors": ["api timeout"],
        },
        main="m",
    )
    assert classify_readiness(inc_snap).disposition == Disposition.NEEDS_ATTENTION
    assert "COLLECTION_INCOMPLETE" in classify_readiness(inc_snap).findings

    # Authority overlap -> Risk HIGH
    auth_snap = PRSnapshot.from_dict(
        {
            "repository": "o/r",
            "pr_number": 6,
            "base_sha": "m",
            "head_sha": "h",
            "changed_files": ["policy/rules.md"],
        },
        main="m",
    )
    auth_res = classify_readiness(auth_snap, authority_patterns=("policy/",))
    assert auth_res.disposition == Disposition.REVIEW_READY
    assert auth_res.risk == "HIGH"
    assert "AUTHORITY_OVERLAP" in auth_res.findings


def test_classify_readiness_injectable_authority_patterns():
    snap = PRSnapshot.from_dict(
        {
            "repository": "o/r",
            "pr_number": 1,
            "base_sha": "m",
            "head_sha": "h",
            "changed_files": ["custom_gov/guardrails.py"],
        },
        main="m",
    )
    default_res = classify_readiness(snap)
    assert "AUTHORITY_OVERLAP" not in default_res.findings
    assert default_res.risk == "MED"

    custom_res = classify_readiness(snap, authority_patterns=("custom_gov/",))
    assert "AUTHORITY_OVERLAP" in custom_res.findings
    assert custom_res.risk == "HIGH"


# ---------------------------------------------------------------------------
# 4. Cross-PR Overlap Analysis
# ---------------------------------------------------------------------------


def test_cross_pr_overlap_symmetric_and_wait_rebind_for_eligible():
    pr1 = PRSnapshot.from_dict(
        {"repository": "o/r", "pr_number": 1, "base_sha": "m", "head_sha": "h1", "changed_files": ["common.py"]},
        main="m",
    )
    pr2 = PRSnapshot.from_dict(
        {"repository": "o/r", "pr_number": 2, "base_sha": "m", "head_sha": "h2", "changed_files": ["common.py", "b.py"]},
        main="m",
    )
    result = analyze_cross_pr_overlap([pr1, pr2])
    assert isinstance(result, CrossPROverlapResult)
    assert len(result.classifications) == 2

    c1, c2 = result.classifications
    assert c1.disposition == Disposition.WAIT_REBIND
    assert c2.disposition == Disposition.WAIT_REBIND
    assert c1.overlaps == {2: ("common.py",)}
    assert c2.overlaps == {1: ("common.py",)}
    assert "PATH_OVERLAP" in c1.findings
    assert "PATH_OVERLAP" in c2.findings

    assert result.overlap_pairs == ((1, 2, ("common.py",)),)


def test_cross_pr_overlap_stale_or_draft_does_not_block_eligible():
    eligible = PRSnapshot.from_dict(
        {"repository": "o/r", "pr_number": 10, "base_sha": "m", "head_sha": "h1", "changed_files": ["file.py"]},
        main="m",
    )
    stale = PRSnapshot.from_dict(
        {"repository": "o/r", "pr_number": 20, "base_sha": "old", "head_sha": "h2", "changed_files": ["file.py"]},
        main="m",
    )
    draft = PRSnapshot.from_dict(
        {"repository": "o/r", "pr_number": 30, "base_sha": "m", "head_sha": "h3", "changed_files": ["file.py"], "draft": True},
        main="m",
    )

    result = analyze_cross_pr_overlap([eligible, stale, draft])
    by_num = {c.identity.pr_number: c for c in result.classifications}

    # Eligible PR remains REVIEW_READY despite overlapping with stale/draft PRs
    assert by_num[10].disposition == Disposition.REVIEW_READY
    assert by_num[10].overlaps == {20: ("file.py",), 30: ("file.py",)}
    assert "PATH_OVERLAP" in by_num[10].findings

    # Stale and draft retain their respective dispositions
    assert by_num[20].disposition == Disposition.STALE
    assert by_num[30].disposition == Disposition.EXCLUDED


def test_cross_pr_overlap_same_issue_chain():
    eligible1 = PRSnapshot.from_dict(
        {"repository": "o/r", "pr_number": 1, "base_sha": "m", "head_sha": "h1", "issue_numbers": [99]},
        main="m",
    )
    eligible2 = PRSnapshot.from_dict(
        {"repository": "o/r", "pr_number": 2, "base_sha": "m", "head_sha": "h2", "issue_numbers": [99]},
        main="m",
    )
    stale = PRSnapshot.from_dict(
        {"repository": "o/r", "pr_number": 3, "base_sha": "old", "head_sha": "h3", "issue_numbers": [99]},
        main="m",
    )

    result = analyze_cross_pr_overlap([eligible1, eligible2, stale])
    by_num = {c.identity.pr_number: c for c in result.classifications}

    # Both eligible PRs get WAIT_REBIND because they share an issue
    assert by_num[1].disposition == Disposition.WAIT_REBIND
    assert by_num[2].disposition == Disposition.WAIT_REBIND
    assert "SAME_ISSUE_CHAIN" in by_num[1].findings
    assert "SAME_ISSUE_CHAIN" in by_num[2].findings

    # Stale PR gets the SAME_ISSUE_CHAIN finding but remains STALE
    assert by_num[3].disposition == Disposition.STALE
    assert "SAME_ISSUE_CHAIN" in by_num[3].findings


# ---------------------------------------------------------------------------
# 5. Generic CI Failure Fingerprinting
# ---------------------------------------------------------------------------


def test_ci_fingerprint_deterministic_and_hash_stability():
    checks = [
        {
            "name": "lint",
            "status": "failure",
            "check_run_id": 101,
            "run_id": 201,
            "head_sha": "head_sha",
            "workflow_name": "Lint",
        },
        {
            "name": "build",
            "status": "success",
            "check_run_id": 102,
            "run_id": 202,
            "head_sha": "head_sha",
        },
    ]

    snap = PRSnapshot.from_dict(
        {
            "repository": "owner/repo",
            "pr_number": 7,
            "base_sha": "base_sha",
            "head_sha": "head_sha",
            "checks": checks,
        },
        main="base_sha",
    )

    fp1 = fingerprint_ci_failures(snap)
    fp2 = fingerprint_ci_failures(snap)

    assert fp1.fingerprint == fp2.fingerprint
    assert len(fp1.fingerprint) == 64
    assert fp1.has_unexpected_failures is True
    assert fp1.unexpected_count == 1
    assert fp1.expected_count == 0
    assert fp1.total_checks_count == 2
    assert fp1.claim_ceiling == CI_EVIDENCE_CLAIM_CEILING
    assert fp1.is_complete is True


def test_ci_fingerprint_expected_failures_never_unexpected():
    checks = [
        {"name": "flaky_test", "status": "failure", "expected_failure": True, "check_run_id": 1, "head_sha": "h"},
        {"name": "canary", "status": "error", "expected_failure": True, "check_run_id": 2, "head_sha": "h"},
    ]
    fp = fingerprint_ci_failures(
        repository="owner/repo",
        pr_number=1,
        base_sha="b",
        head_sha="h",
        current_main_sha="b",
        checks=checks,
    )
    assert fp.has_unexpected_failures is False
    assert fp.unexpected_count == 0
    assert fp.expected_count == 2
    assert fp.terminal_failure_count == 2
    assert fp.is_complete is True


@pytest.mark.parametrize("terminal_status", [
    "failure",
    "failed",
    "error",
    "cancelled",
    "timed_out",
    "action_required",
    "FAILURE",
    "Cancelled",
])
def test_ci_fingerprint_recognizes_all_terminal_statuses(terminal_status):
    checks = [{"name": "job", "status": terminal_status, "check_run_id": 99, "head_sha": "h"}]
    fp = fingerprint_ci_failures(
        repository="owner/repo",
        pr_number=1,
        base_sha="b",
        head_sha="h",
        current_main_sha="b",
        checks=checks,
    )
    assert fp.has_unexpected_failures is True
    assert fp.unexpected_count == 1
    assert fp.is_complete is True


def test_ci_fingerprint_terminal_name_status_only_incomplete():
    """Terminal failure with only name and status lacks head anchoring and locators -> incomplete."""
    checks = [{"name": "ci_test", "status": "failure"}]
    fp = fingerprint_ci_failures(
        repository="owner/repo",
        pr_number=1,
        base_sha="b",
        head_sha="h",
        current_main_sha="b",
        checks=checks,
    )
    assert fp.is_complete is False
    assert any("missing head_sha" in g for g in fp.evidence_gaps)
    assert any("missing material execution/evidence locator" in g for g in fp.evidence_gaps)


@pytest.mark.parametrize("locator_key,locator_val", [
    ("check_run_id", 101),
    ("run_id", 202),
    ("external_id", "ext-303"),
    ("job_identity", "job-404"),
    ("log_sha256", "logsha505"),
    ("artifact_identity", "art-606"),
    ("artifact_sha256", "artsha707"),
    ("details_url", "https://ci.example.com/details"),
    ("html_url", "https://ci.example.com/html"),
])
def test_ci_fingerprint_terminal_with_matching_head_and_one_locator_complete(locator_key, locator_val):
    """Terminal with matching head + at least one material locator is complete."""
    check_payload = {
        "name": "build",
        "status": "failure",
        "head_sha": "target_head",
        locator_key: locator_val,
    }
    fp = fingerprint_ci_failures(
        repository="owner/repo",
        pr_number=1,
        base_sha="b",
        head_sha="target_head",
        current_main_sha="b",
        checks=[check_payload],
    )
    assert fp.is_complete is True
    assert fp.has_unexpected_failures is True
    assert fp.unexpected_count == 1
    assert len(fp.evidence_gaps) == 0


def test_ci_fingerprint_foreign_head_remains_incomplete():
    """Terminal check with mismatched foreign head remains incomplete even with locator."""
    checks = [{"name": "ci", "status": "failure", "head_sha": "foreign_sha", "check_run_id": 999}]
    fp = fingerprint_ci_failures(
        repository="owner/repo",
        pr_number=1,
        base_sha="b",
        head_sha="expected_sha",
        current_main_sha="b",
        checks=checks,
    )
    assert any("mismatches PR head_sha" in g for g in fp.evidence_gaps)
    assert fp.is_complete is False


def test_ci_fingerprint_expected_terminal_failures_require_anchoring():
    """Expected terminal failures also require head and locator anchoring."""
    # Name+status only expected failure -> incomplete
    fp_incomplete = fingerprint_ci_failures(
        repository="owner/repo",
        pr_number=1,
        base_sha="b",
        head_sha="h",
        current_main_sha="b",
        checks=[{"name": "flaky", "status": "failure", "expected_failure": True}],
    )
    assert fp_incomplete.is_complete is False
    assert any("missing head_sha" in g for g in fp_incomplete.evidence_gaps)
    assert any("missing material execution/evidence locator" in g for g in fp_incomplete.evidence_gaps)

    # Anchored expected failure -> complete
    fp_complete = fingerprint_ci_failures(
        repository="owner/repo",
        pr_number=1,
        base_sha="b",
        head_sha="h",
        current_main_sha="b",
        checks=[{"name": "flaky", "status": "failure", "expected_failure": True, "head_sha": "h", "run_id": 12}],
    )
    assert fp_complete.is_complete is True
    assert fp_complete.has_unexpected_failures is False
    assert fp_complete.expected_count == 1


def test_ci_fingerprint_foreign_head_sha_gap():
    checks = [{"name": "ci", "status": "failure", "head_sha": "mismatched_sha"}]
    fp = fingerprint_ci_failures(
        repository="owner/repo",
        pr_number=1,
        base_sha="b",
        head_sha="expected_sha",
        current_main_sha="b",
        checks=checks,
    )
    assert any("mismatches PR head_sha" in g for g in fp.evidence_gaps)
    assert fp.is_complete is False


def test_ci_fingerprint_evidence_gaps_on_missing_identities():
    # Incomplete collection and missing check fields
    fp = fingerprint_ci_failures(
        repository="",
        pr_number=0,
        base_sha="",
        head_sha="",
        current_main_sha="",
        checks=[{"invalid_key": "no name or status"}],
        collection_complete=False,
    )
    assert fp.is_complete is False
    assert "collection_incomplete" in fp.evidence_gaps
    assert any("repository" in g for g in fp.evidence_gaps)
    assert any("check name" in g or "check status" in g for g in fp.evidence_gaps)


def test_ci_fingerprint_no_nexus_policy_leaks():
    """Ensure generic CI fingerprint contains no Nexus-only policy fields or strings."""
    snap = PRSnapshot.from_dict(
        {"repository": "o/r", "pr_number": 1, "base_sha": "b", "head_sha": "h"},
        main="b",
    )
    fp = fingerprint_ci_failures(snap)
    dumped = json.dumps(fp.to_dict())

    for forbidden in [
        "NEXUS_EXACT_BASE",
        "NEW_REGRESSION",
        "EXACT_BASELINE_DEBT",
        "CI_BOOTSTRAP_DEFECT",
        "standing_grant",
        "merge_candidate",
    ]:
        assert forbidden not in dumped


# ---------------------------------------------------------------------------
# 6. Immutable Contracts Tests
# ---------------------------------------------------------------------------


def test_readiness_classification_overlaps_immutable():
    snap = PRSnapshot.from_dict(
        {"repository": "o/r", "pr_number": 1, "base_sha": "m", "head_sha": "h"},
        main="m",
    )
    c = classify_readiness(snap)
    assert isinstance(c, ReadinessClassification)

    # In-place mutation must raise TypeError
    with pytest.raises(TypeError):
        c.overlaps[999] = ("forbidden.py",)  # type: ignore[index]

    with pytest.raises(AttributeError):
        c.overlaps.clear()  # type: ignore[attr-defined]

    # Serialization stability
    d = c.to_dict()
    assert isinstance(d["overlaps"], dict)
    assert json.dumps(d, sort_keys=True) == json.dumps(c.to_dict(), sort_keys=True)
