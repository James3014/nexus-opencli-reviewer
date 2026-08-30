from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import reviewer.intelligence_cli as cli
import reviewer.webmcp as webmcp
from reviewer.intelligence import (
    CLAIM_CEILING,
    CI_EVIDENCE_CLAIM_CEILING,
    classify_readiness,
    fingerprint_ci_failures,
)
from reviewer.models import Classification, Disposition, PRSnapshot


def _snapshot(
    *,
    pr_number: int = 1,
    base_sha: str = "main-sha",
    head_sha: str = "head-sha",
    current_main_sha: str = "main-sha",
    changed_files: list[str] | None = None,
    checks: list[dict] | None = None,
    draft: bool = False,
) -> PRSnapshot:
    return PRSnapshot.from_dict(
        {
            "repository": "owner/repo",
            "pr_number": pr_number,
            "title": "fixture",
            "state": "OPEN",
            "draft": draft,
            "mergeable": True,
            "base_branch": "main",
            "base_sha": base_sha,
            "head_branch": f"branch-{pr_number}",
            "head_sha": head_sha,
            "changed_files": changed_files or [],
            "checks": checks or [],
            "collection_complete": True,
            "collection_errors": [],
        },
        main=current_main_sha,
    )


def _scan_result(classifications: list[Classification], main_sha: str = "main-sha"):
    return main_sha, "2026-08-30T00:00:00Z", classifications, []


def _transport(main_sha: str = "main-sha"):
    transport = MagicMock()
    transport.get_ref.return_value = {"object": {"sha": main_sha}}
    return transport


def test_g7_cli_ci_preserves_ci_evidence_claim_ceiling():
    data = {
        "repository": "owner/repo",
        "pr_number": 1,
        "base_sha": "main-sha",
        "head_sha": "head-sha",
        "current_main_sha": "main-sha",
        "checks": [
            {
                "name": "ci/test",
                "status": "failure",
                "expected_failure": False,
                "head_sha": "head-sha",
                "check_run_id": 11,
            }
        ],
    }
    direct = fingerprint_ci_failures(data)
    result = cli.execute_operation("ci", data)
    assert result["claim_ceiling"] == CI_EVIDENCE_CLAIM_CEILING
    assert result["result"] == direct.to_dict()
    assert result["result"]["claim_ceiling"] == CI_EVIDENCE_CLAIM_CEILING


def test_g7_webmcp_inspect_pr_ignores_legacy_scan_disposition():
    snap = _snapshot(pr_number=11)
    # Deliberately wrong legacy classification: adapter must not trust this decision.
    poisoned = Classification(
        snapshot=snap,
        disposition=Disposition.STALE,
        findings=["FAKE_LEGACY_DECISION"],
        reasons=["FAKE_LEGACY_DECISION"],
    )
    expected = classify_readiness(snap)
    assert expected.disposition == Disposition.REVIEW_READY

    with patch("reviewer.webmcp.scan", return_value=_scan_result([poisoned])):
        result = webmcp.tool_inspect_pr("owner/repo", 11, _transport())

    assert result["disposition"] == expected.disposition.value
    assert result["findings"] == list(expected.findings)
    assert "FAKE_LEGACY_DECISION" not in result["findings"]
    assert result["claim_ceiling"] == CLAIM_CEILING


def test_g7_webmcp_list_recomputes_canonical_cross_pr_collision():
    s1 = _snapshot(pr_number=21, head_sha="h1", changed_files=["shared.py"])
    s2 = _snapshot(pr_number=22, head_sha="h2", changed_files=["shared.py"])
    # Legacy scan output is deliberately green for both. Canonical Core overlap must override it.
    legacy = [
        Classification(snapshot=s1, disposition=Disposition.REVIEW_READY),
        Classification(snapshot=s2, disposition=Disposition.REVIEW_READY),
    ]

    with patch("reviewer.webmcp.scan", return_value=_scan_result(legacy)):
        result = webmcp.tool_list_review_ready_prs("owner/repo", _transport())

    assert result["review_ready_prs"] == []
    assert result["claim_ceiling"] == CLAIM_CEILING


def test_g7_webmcp_ci_uses_ci_evidence_ceiling_end_to_end():
    snap = _snapshot(
        pr_number=31,
        checks=[
            {
                "name": "ci/test",
                "status": "failure",
                "expected_failure": False,
                "head_sha": "head-sha",
                "check_run_id": 31,
            }
        ],
    )
    legacy = Classification(snapshot=snap, disposition=Disposition.NEEDS_ATTENTION)

    with patch("reviewer.webmcp.scan", return_value=_scan_result([legacy])):
        result = webmcp.tool_inspect_ci_failure("owner/repo", 31, _transport())

    assert result["claim_ceiling"] == CI_EVIDENCE_CLAIM_CEILING
    assert result["ci_failure_fingerprint"]["claim_ceiling"] == CI_EVIDENCE_CLAIM_CEILING


def test_g7_webmcp_page_declares_exact_adapter_claim_boundaries():
    assert "PR_INTELLIGENCE_ONLY" in webmcp._BROWSER_PAGE_TEMPLATE
    assert "CI_EVIDENCE_ONLY" in webmcp._BROWSER_PAGE_TEMPLATE
    assert "PRE_REVIEW_ONLY" not in webmcp._BROWSER_PAGE_TEMPLATE


def test_g7_v11_adapter_scope_keeps_cli_and_webmcp_boundary():
    reviewer_dir = Path(__file__).resolve().parent.parent / "reviewer"
    assert cli.OPERATIONS == frozenset({"revision", "readiness", "overlap", "ci", "impact"})
    assert hasattr(webmcp, "WebMCPServer")
    assert not (reviewer_dir / "mcp_server.py").exists()
    assert not (reviewer_dir / "github_action.py").exists()
    assert not (reviewer_dir / "action.py").exists()


def test_g7_adapters_do_not_gain_write_or_semantic_authority():
    for module in (cli, webmcp):
        for forbidden in ("publication", "opencli", "semantic"):
            assert not hasattr(module, forbidden)
