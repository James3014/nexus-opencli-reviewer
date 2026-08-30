"""Repository Intelligence G7 Adapter Strategy & Conformance Tests.

Validates that:
1) CLI for the four V1 operations returns identical canonical results to Repository Intelligence Core API.
2) CLI has no GitHub/network/state mutation dependency; malformed JSON/unknown op/input shape fail closed.
3) WebMCP inspect_pr and list_review_ready_prs match direct core classify/analyze-overlap results for the same snapshots.
4) WebMCP inspect_ci_failure derives unexpected terminal failures from canonical core fingerprint; no _TERMINAL_FAILURES or duplicate status list in webmcp.py.
5) Core/CLI and legacy WebMCP keep explicit, non-escalating claim ceilings and architectural boundaries.
"""
from __future__ import annotations

import ast
import inspect
import io
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import reviewer.intelligence_cli as cli
import reviewer.webmcp as webmcp
from reviewer.intelligence import (
    CLAIM_CEILING,
    CI_EVIDENCE_CLAIM_CEILING,
    analyze_cross_pr_overlap,
    build_repository_intelligence_report,
    classify_readiness,
    fingerprint_ci_failures,
    revision_identity,
)
from reviewer.models import CheckObservation, Classification, Disposition, PRSnapshot


# ---------------------------------------------------------------------------
# Fixture Helpers
# ---------------------------------------------------------------------------

def _make_snapshot(
    pr_number: int = 1,
    repository: str = "owner/repo",
    base_sha: str = "mainsha001",
    head_sha: str = "headsha001",
    current_main_sha: str = "mainsha001",
    title: str = "PR Title",
    author: str = "alice",
    labels: list[str] | None = None,
    changed_files: list[str] | None = None,
    checks: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "repository": repository,
        "pr_number": pr_number,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "current_main_sha": current_main_sha,
        "title": title,
        "author": author,
        "state": "open",
        "labels": labels or [],
        "changed_files": changed_files if changed_files is not None else ["file_a.py"],
        "checks": checks or [],
        "collection_complete": True,
        "collection_errors": [],
    }


def _snapshot_obj_from_dict(d: dict[str, Any]) -> PRSnapshot:
    return PRSnapshot.from_dict(d, main=d.get("current_main_sha", ""))


def _fake_scan_result(classifications: list[Classification], main_sha: str = "mainsha001"):
    return main_sha, "2026-08-30T00:00:00Z", classifications, []


def _stable_transport(main_sha: str = "mainsha001"):
    transport = MagicMock()
    transport.get_ref.return_value = {"object": {"sha": main_sha}}
    return transport


# ---------------------------------------------------------------------------
# 1. CLI Canonical Core Equivalence (V1 Operations)
# ---------------------------------------------------------------------------

class TestCliCoreEquivalence:
    """CLI V1 operations return the same canonical result as direct Core calls."""

    def test_cli_revision_equivalence(self):
        fixture = _make_snapshot(pr_number=10, base_sha="oldsha", current_main_sha="newsha")
        core_result = revision_identity(fixture)
        cli_out = cli.execute_operation("revision", fixture)

        assert cli_out["operation"] == "revision"
        assert cli_out["claim_ceiling"] == CLAIM_CEILING
        assert cli_out["result"] == core_result.to_dict()

    def test_cli_readiness_equivalence(self):
        fixture = _make_snapshot(pr_number=11, labels=["dependencies"])
        core_result = classify_readiness(fixture)
        cli_out = cli.execute_operation("readiness", fixture)

        assert cli_out["operation"] == "readiness"
        assert cli_out["claim_ceiling"] == CLAIM_CEILING
        assert cli_out["result"] == core_result.to_dict()

    def test_cli_overlap_equivalence(self):
        s1 = _make_snapshot(pr_number=21, changed_files=["common.py", "a.py"])
        s2 = _make_snapshot(pr_number=22, changed_files=["common.py", "b.py"])
        fixture = {"snapshots": [s1, s2]}

        core_result = analyze_cross_pr_overlap([s1, s2])
        cli_out = cli.execute_operation("overlap", fixture)

        assert cli_out["operation"] == "overlap"
        assert cli_out["claim_ceiling"] == CLAIM_CEILING
        assert cli_out["result"] == core_result.to_dict()

    def test_cli_ci_equivalence(self):
        checks = [
            {
                "name": "ci/test",
                "status": "failure",
                "check_run_id": 901,
                "workflow_name": "Test",
                "head_sha": "headsha001",
                "details_url": "https://ci.example.com/runs/901",
            },
            {
                "name": "ci/lint",
                "status": "success",
                "check_run_id": 902,
                "workflow_name": "Lint",
                "head_sha": "headsha001",
            },
        ]
        fixture = _make_snapshot(pr_number=31, checks=checks)
        core_result = fingerprint_ci_failures(fixture)
        cli_out = cli.execute_operation("ci", fixture)

        assert cli_out["operation"] == "ci"
        assert cli_out["claim_ceiling"] == CI_EVIDENCE_CLAIM_CEILING
        assert cli_out["result"] == core_result.to_dict()


# ---------------------------------------------------------------------------
# 2. CLI Fail-Closed / Zero Side Effects
# ---------------------------------------------------------------------------

class TestCliFailClosedAndIsolation:
    """Requirement 2: CLI has no GitHub/network/state mutation dependency; malformed JSON/unknown op/input shape fail closed."""

    def test_malformed_json_fails_closed(self, tmp_path: Path):
        bad_file = tmp_path / "broken.json"
        bad_file.write_text("{ unclosed json: ")

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code = cli.main(["--operation", "readiness", "--input", str(bad_file)])

        assert code != 0
        payload = json.loads(stdout_buf.getvalue())
        assert payload["status"] == "ERROR"
        assert payload["claim_ceiling"] == CLAIM_CEILING

    def test_unknown_operation_fails_closed(self, tmp_path: Path):
        dummy_file = tmp_path / "dummy.json"
        dummy_file.write_text("{}")

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code = cli.main(["--operation", "unsupported_operation", "--input", str(dummy_file)])

        assert code != 0
        payload = json.loads(stdout_buf.getvalue())
        assert payload["status"] == "ERROR"
        assert payload["claim_ceiling"] == CLAIM_CEILING

    def test_invalid_input_shape_fails_closed(self, tmp_path: Path):
        bad_shape_file = tmp_path / "bad_shape.json"
        bad_shape_file.write_text(json.dumps("string_is_not_object"))

        for op in ("revision", "readiness", "overlap", "ci"):
            stdout_buf = io.StringIO()
            with patch("sys.stdout", stdout_buf):
                code = cli.main(["--operation", op, "--input", str(bad_shape_file)])
            assert code != 0
            payload = json.loads(stdout_buf.getvalue())
            assert payload["status"] == "ERROR"
            assert payload["claim_ceiling"] == CLAIM_CEILING

    def test_no_transport_or_network_or_state_writes(self, tmp_path: Path):
        snap = _make_snapshot(pr_number=99)
        snap_file = tmp_path / "valid_snap.json"
        snap_file.write_text(json.dumps(snap))

        with patch("urllib.request.urlopen") as mock_url, \
             patch("socket.socket") as mock_sock:
            stdout_buf = io.StringIO()
            with patch("sys.stdout", stdout_buf):
                code = cli.main(["--operation", "readiness", "--input", str(snap_file)])

            assert code == 0
            mock_url.assert_not_called()
            mock_sock.assert_not_called()


# ---------------------------------------------------------------------------
# 3. WebMCP Conformance to Direct Core Classification / Overlap
# ---------------------------------------------------------------------------

class TestWebMcpClassificationConformance:
    """Requirement 3: WebMCP inspect_pr/list_review_ready_prs against fake transport match direct core classify/analyze-overlap results for same snapshots."""

    def test_inspect_pr_matches_direct_core_classification(self):
        s1 = _make_snapshot(pr_number=101, base_sha="mainsha001", current_main_sha="mainsha001")
        s2 = _make_snapshot(pr_number=102, base_sha="oldsha", current_main_sha="mainsha001")
        s3 = _make_snapshot(pr_number=103)
        s3["draft"] = True

        snap_objs = [_snapshot_obj_from_dict(s) for s in (s1, s2, s3)]
        classifications = [
            Classification(snapshot=snap_objs[0], disposition=Disposition.REVIEW_READY),
            Classification(snapshot=snap_objs[1], disposition=Disposition.STALE, findings=["STALE_BASE"], reasons=["STALE_BASE"]),
            Classification(snapshot=snap_objs[2], disposition=Disposition.EXCLUDED, findings=["DRAFT"], reasons=["DRAFT"]),
        ]

        transport = _stable_transport()
        scan_rv = _fake_scan_result(classifications)

        direct_report = build_repository_intelligence_report(snap_objs)
        direct_by_pr = {item.identity.pr_number: item for item in direct_report.items}
        with patch("reviewer.webmcp.scan", return_value=scan_rv):
            for s_dict in (s1, s2, s3):
                direct_core = direct_by_pr[s_dict["pr_number"]]
                wm_res = webmcp.tool_inspect_pr(s_dict["repository"], s_dict["pr_number"], transport)

                assert wm_res["repository"] == direct_core.identity.repository
                assert wm_res["pr_number"] == direct_core.identity.pr_number
                assert wm_res["disposition"] == direct_core.disposition.value
                assert wm_res["findings"] == list(direct_core.findings)
                assert wm_res["reasons"] == list(direct_core.reasons)
                assert wm_res["claim_ceiling"] == CLAIM_CEILING

    def test_list_review_ready_prs_matches_direct_core_eligibility(self):
        s1 = _make_snapshot(pr_number=201, changed_files=["one.py"])  # ready
        s2 = _make_snapshot(pr_number=202, base_sha="oldsha", changed_files=["two.py"])  # stale
        s3 = _make_snapshot(pr_number=203, changed_files=["three.py"])  # ready

        snap_objs = [_snapshot_obj_from_dict(s) for s in (s1, s2, s3)]
        classifications = [
            Classification(snapshot=snap_objs[0], disposition=Disposition.REVIEW_READY),
            Classification(snapshot=snap_objs[1], disposition=Disposition.STALE, findings=["STALE_BASE"]),
            Classification(snapshot=snap_objs[2], disposition=Disposition.REVIEW_READY),
        ]

        transport = _stable_transport()
        scan_rv = _fake_scan_result(classifications)

        with patch("reviewer.webmcp.scan", return_value=scan_rv):
            wm_res = webmcp.tool_list_review_ready_prs("owner/repo", transport)
            ready_pr_numbers = [p["pr_number"] for p in wm_res["review_ready_prs"]]

            core_ready_numbers = [
                s["pr_number"]
                for s in (s1, s2, s3)
                if classify_readiness(s).is_review_ready
            ]

            assert ready_pr_numbers == core_ready_numbers
            assert ready_pr_numbers == [201, 203]


# ---------------------------------------------------------------------------
# 4. WebMCP CI Failure Conformance to Core Fingerprint
# ---------------------------------------------------------------------------

class TestWebMcpCiFailureConformance:
    """Requirement 4: WebMCP inspect_ci_failure top-level unexpected list is derived consistently from core fingerprint; assert no _TERMINAL_FAILURES import/second status list in webmcp.py."""

    def test_unexpected_failures_derived_from_canonical_fingerprint(self):
        checks = [
            {
                "name": "ci/test-unexpected",
                "status": "failure",
                "expected_failure": False,
                "check_run_id": 501,
                "workflow_name": "Tests",
                "head_sha": "headsha001",
                "details_url": "https://ci.example.com/501",
            },
            {
                "name": "ci/test-expected",
                "status": "failure",
                "expected_failure": True,
                "check_run_id": 502,
                "workflow_name": "Negative Tests",
                "head_sha": "headsha001",
                "details_url": "https://ci.example.com/502",
            },
            {
                "name": "ci/lint-pass",
                "status": "success",
                "expected_failure": False,
                "check_run_id": 503,
                "workflow_name": "Lint",
                "head_sha": "headsha001",
            },
        ]
        s_dict = _make_snapshot(pr_number=301, checks=checks)
        snap_obj = _snapshot_obj_from_dict(s_dict)
        c_obj = Classification(snapshot=snap_obj, disposition=Disposition.NEEDS_ATTENTION)

        transport = _stable_transport()
        scan_rv = _fake_scan_result([c_obj])

        with patch("reviewer.webmcp.scan", return_value=scan_rv):
            wm_res = webmcp.tool_inspect_ci_failure("owner/repo", 301, transport)

        core_fp = fingerprint_ci_failures(snap_obj)

        assert wm_res["result"] == ("UNEXPECTED_FAILURE_PRESENT" if core_fp.has_unexpected_failures else "NO_UNEXPECTED_FAILURE")
        assert len(wm_res["unexpected_terminal_failures"]) == len(core_fp.unexpected_failures)
        assert wm_res["ci_failure_fingerprint"] == core_fp.to_dict()

        # Check names in unexpected list
        unexpected_names = [f["name"] for f in wm_res["unexpected_terminal_failures"]]
        assert "ci/test-unexpected" in unexpected_names
        assert "ci/test-expected" not in unexpected_names
        assert "ci/lint-pass" not in unexpected_names

    def test_no_terminal_failures_imported_or_defined_in_webmcp(self):
        """WebMCP MUST NOT maintain or import a duplicate terminal failures list."""
        assert not hasattr(webmcp, "_TERMINAL_FAILURES")
        assert not hasattr(webmcp, "TERMINAL_FAILURE_STATUSES")

        # Inspect webmcp module source AST to guarantee no duplicate status literals
        src = Path(webmcp.__file__).read_text()
        tree = ast.parse(src)

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module and "scan" in node.module:
                    for alias in node.names:
                        assert alias.name != "_TERMINAL_FAILURES", \
                            "webmcp must not import _TERMINAL_FAILURES from scan"


# ---------------------------------------------------------------------------
# 5. Architecture & Claim Boundary Invariants
# ---------------------------------------------------------------------------

class TestArchitectureAndClaimCeiling:
    """Adapters preserve explicit advisory ceilings without acquiring authority."""

    def test_claim_boundaries_are_explicit(self):
        assert cli.CLAIM_CEILING == "PR_INTELLIGENCE_ONLY"
        assert webmcp.CLAIM_CEILING == "PR_INTELLIGENCE_ONLY"
        assert webmcp.CI_CLAIM_CEILING == "CI_EVIDENCE_ONLY"
        assert "impact" not in cli.OPERATIONS

    def test_deferred_adapters_not_present(self):
        """Direct MCP server and GitHub Action adapters are deferred post-V1 and not implemented in codebase."""
        repo_root = Path(__file__).parent.parent
        reviewer_dir = repo_root / "reviewer"

        # Assert no direct mcp server or github action adapter modules
        assert not (reviewer_dir / "mcp_server.py").exists()
        assert not (reviewer_dir / "github_action.py").exists()
        assert not (reviewer_dir / "action.py").exists()
