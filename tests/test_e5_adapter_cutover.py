"""Tests for E5 adapter cutover to extracted repository_intelligence package."""
from __future__ import annotations

import ast
import hashlib
import io
import json
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import reviewer.github_action as gha
import reviewer.intelligence_cli as icli
import reviewer.webmcp as webmcp
import repository_intelligence
import repository_intelligence.cli as rcli
from reviewer.models import CheckObservation, Classification, Disposition, PRSnapshot


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_provenance_and_wheel_integrity():
    """Verify vendor provenance metadata matches wheel artifact and extraction commits."""
    provenance_path = REPO_ROOT / "vendor" / "repository-intelligence-engine.provenance.json"
    assert provenance_path.exists(), "Provenance file must exist in vendor/"

    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    wheel_filename = provenance.get("wheel_filename")
    assert wheel_filename == "repository_intelligence_engine-0.1.0-py3-none-any.whl"

    wheel_path = REPO_ROOT / "vendor" / wheel_filename
    assert wheel_path.exists(), f"Vendored wheel {wheel_filename} must exist"

    computed_sha = hashlib.sha256(wheel_path.read_bytes()).hexdigest()
    assert provenance["wheel_sha256"] == computed_sha
    assert provenance["source_commit"] == "693ae7cf59e3b090ee873b7196ee330b30e26221"
    assert provenance["source_tree"] == "f5f8496ed16e775e8767827f66d1fa35355d2968"
    assert provenance["source_repository"] == "https://github.com/James3014/repository-intelligence-engine"
    assert provenance["source_ref"] == "refs/heads/main"
    assert provenance["publication_status"] == "PUBLIC_MAIN_VERIFIED"
    assert provenance["prior_e4_parity_subject"] == "da96b51f04faf6705280f7b7214b496ab74d1e5b"
    assert provenance["claim_ceiling"] == "DISTRIBUTION_ARTIFACT_ONLY"
    assert provenance["package_name"] == "repository-intelligence-engine"
    assert provenance["version"] == "0.1.0"


def test_adapters_no_longer_import_reviewer_intelligence():
    """Ensure adapter modules do not import reviewer.intelligence or .intelligence."""
    adapter_paths = [
        REPO_ROOT / "reviewer" / "intelligence_cli.py",
        REPO_ROOT / "reviewer" / "github_action.py",
        REPO_ROOT / "reviewer" / "webmcp.py",
    ]
    for path in adapter_paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith("reviewer.intelligence"), (
                        f"{path.name} imports {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    assert node.module != "reviewer.intelligence", (
                        f"{path.name} imports from {node.module}"
                    )
                    assert not (node.level > 0 and node.module == "intelligence"), (
                        f"{path.name} imports relative .intelligence"
                    )


def test_legacy_cli_is_thin_projection(tmp_path: Path):
    """Assert reviewer.intelligence_cli is a thin projection to repository_intelligence.cli."""
    assert icli.main is rcli.main
    assert icli.execute_operation is rcli.execute_operation
    assert icli.load_input_data is rcli.load_input_data
    assert icli.OPERATIONS is rcli.OPERATIONS

    snapshot_data = {
        "repository": "owner/repo",
        "pr_number": 1,
        "head_sha": "head123",
        "base_sha": "base123",
        "current_main_sha": "base123",
        "changed_files": ["foo.py"],
        "checks": [],
    }
    input_file = tmp_path / "snap.json"
    input_file.write_text(json.dumps(snapshot_data), encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, "-m", "reviewer.intelligence_cli", "--operation", "readiness", "--input", str(input_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["operation"] == "readiness"
    assert payload["claim_ceiling"] == "PR_INTELLIGENCE_ONLY"
    assert payload["result"]["disposition"] == "REVIEW_READY"


def test_action_installs_pinned_wheel_and_preserves_safety():
    """Verify action.yml installs the pinned wheel locally without network."""
    action_text = (REPO_ROOT / "action.yml").read_text(encoding="utf-8")
    assert "python3 -m pip install --no-deps --no-index" in action_text
    assert "vendor/repository_intelligence_engine-0.1.0-py3-none-any.whl" in action_text
    assert "actions/checkout" not in action_text
    assert "pull_request_target" not in action_text
    assert "python3 -m reviewer.github_action" in action_text


def test_webmcp_acquisition_legacy_and_decisions_canonical():
    """Verify WebMCP uses legacy acquisition (scan, github) and canonical decisions."""
    assert hasattr(webmcp, "scan")
    assert hasattr(webmcp, "GhCliTransport")
    assert webmcp.build_repository_intelligence_report is repository_intelligence.build_repository_intelligence_report
    assert webmcp.fingerprint_ci_failures is repository_intelligence.fingerprint_ci_failures


def test_poisoned_legacy_reviewer_intelligence_cannot_override_canonical(tmp_path: Path):
    """Assert poisoned reviewer.intelligence cannot affect canonical adapter behavior."""
    import reviewer.intelligence as legacy_intel

    poisoned_marker = "POISONED_LEGACY_SHOULD_NOT_APPEAR"

    with patch.object(legacy_intel, "classify_readiness", side_effect=RuntimeError(poisoned_marker)), \
         patch.object(legacy_intel, "build_repository_intelligence_report", side_effect=RuntimeError(poisoned_marker)), \
         patch.object(legacy_intel, "analyze_ci_failure_intelligence", side_effect=RuntimeError(poisoned_marker)), \
         patch.object(legacy_intel, "fingerprint_ci_failures", side_effect=RuntimeError(poisoned_marker)):

        # 1. CLI operation execution must use canonical repository_intelligence
        snap_dict = {
            "repository": "owner/repo",
            "pr_number": 42,
            "head_sha": "h42",
            "base_sha": "b42",
            "current_main_sha": "b42",
            "changed_files": ["main.py"],
            "checks": [],
        }
        res_cli = icli.execute_operation("readiness", snap_dict)
        assert res_cli["result"]["disposition"] == "REVIEW_READY"

        # 2. GitHub action bundle execution must use canonical repository_intelligence
        cloud_snap = {
            "repository": "owner/repo",
            "pr_number": 42,
            "head_sha": "b" * 40,
            "base_sha": "a" * 40,
            "current_main_sha": "a" * 40,
            "changed_files": ["main.py"],
            "checks": [],
            "source_identity": "github_action_rest_v1",
            "observed_at": "2026-08-30T00:00:00Z",
            "collection_complete": True,
            "collection_errors": [],
        }
        bundle = gha.run_cloud_bundle(cloud_snap)
        assert bundle["reports"]["readiness"]["result"]["disposition"] == "REVIEW_READY"
        assert gha.verify_cloud_bundle(bundle) is True

        # 3. WebMCP execution must use canonical repository_intelligence
        snap_model = PRSnapshot.from_dict({
            "repository": "owner/repo",
            "pr_number": 42,
            "head_sha": "h42",
            "base_sha": "b42",
            "current_main_sha": "b42",
            "changed_files": ["main.py"],
            "checks": [
                {
                    "name": "ci/test",
                    "status": "failure",
                    "expected_failure": False,
                    "head_sha": "h42",
                }
            ],
            "collection_complete": True,
            "collection_errors": [],
            "draft": False,
            "do_not_merge": False,
        }, "b42")
        classification = Classification(snapshot=snap_model)
        from reviewer.queue import ReviewQueue
        q = ReviewQueue()
        q.ingest([classification])
        scan_rv = ("b42", "2026-08-30T00:00:00Z", [classification], q)

        transport = MagicMock()
        transport.get_ref.return_value = {"object": {"sha": "b42"}}

        with patch("reviewer.webmcp.scan", return_value=scan_rv):
            ready_res = webmcp.tool_list_review_ready_prs("owner/repo", transport)
            assert len(ready_res["review_ready_prs"]) == 1
            assert ready_res["review_ready_prs"][0]["disposition"] == "REVIEW_READY"

            ci_res = webmcp.tool_inspect_ci_failure("owner/repo", 42, transport)
            assert ci_res["result"] == "UNEXPECTED_FAILURE_PRESENT"
