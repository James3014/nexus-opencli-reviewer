"""Tests for Repository Intelligence CLI Adapter (reviewer.intelligence_cli).

Verifies deterministic JSON output, error fail-closed semantics,
and transport/network/state-free execution.
"""
from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

import reviewer.intelligence_cli as cli
from reviewer.intelligence import (
    CLAIM_CEILING,
    CI_EVIDENCE_CLAIM_CEILING,
    analyze_cross_pr_overlap,
    classify_readiness,
    fingerprint_ci_failures,
    revision_identity,
)


@pytest.fixture
def sample_snapshot_dict() -> dict[str, Any]:
    return {
        "repository": "owner/repo",
        "pr_number": 42,
        "base_sha": "mainsha123",
        "head_sha": "headsha456",
        "current_main_sha": "mainsha123",
        "title": "feat: test pr",
        "author": "alice",
        "state": "open",
        "changed_files": ["foo/bar.py", "tests/test_bar.py"],
        "checks": [
            {
                "name": "ci/test",
                "status": "success",
                "check_run_id": 1001,
                "workflow_name": "Tests",
                "head_sha": "headsha456",
            },
            {
                "name": "ci/build",
                "status": "failure",
                "check_run_id": 1002,
                "workflow_name": "Build",
                "head_sha": "headsha456",
                "details_url": "https://ci.example.com/build/1002",
            },
        ],
    }


@pytest.fixture
def sample_overlap_dict(sample_snapshot_dict: dict[str, Any]) -> dict[str, Any]:
    snap2 = dict(sample_snapshot_dict)
    snap2["pr_number"] = 43
    snap2["changed_files"] = ["foo/bar.py", "foo/other.py"]
    return {"snapshots": [sample_snapshot_dict, snap2]}


class TestIntelligenceCliOperations:
    """Test all V1 operations via direct main() and subprocess invocation."""

    def test_revision_operation_file(self, tmp_path: Path, sample_snapshot_dict: dict[str, Any]):
        infile = tmp_path / "snap.json"
        infile.write_text(json.dumps(sample_snapshot_dict))

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code = cli.main(["--operation", "revision", "--input", str(infile)])
        assert code == 0
        output = json.loads(stdout_buf.getvalue())
        assert output["operation"] == "revision"
        assert output["claim_ceiling"] == CLAIM_CEILING
        assert output["result"] == revision_identity(sample_snapshot_dict).to_dict()

    def test_revision_operation_stdin(self, sample_snapshot_dict: dict[str, Any]):
        stdin_buf = io.StringIO(json.dumps(sample_snapshot_dict))
        stdout_buf = io.StringIO()
        with patch("sys.stdin", stdin_buf), patch("sys.stdout", stdout_buf):
            code = cli.main(["--operation", "revision", "--input", "-"])
        assert code == 0
        output = json.loads(stdout_buf.getvalue())
        assert output["operation"] == "revision"
        assert output["claim_ceiling"] == CLAIM_CEILING
        assert output["result"] == revision_identity(sample_snapshot_dict).to_dict()

    def test_readiness_operation_file(self, tmp_path: Path, sample_snapshot_dict: dict[str, Any]):
        infile = tmp_path / "snap.json"
        infile.write_text(json.dumps(sample_snapshot_dict))

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code = cli.main(["--operation", "readiness", "--input", str(infile)])
        assert code == 0
        output = json.loads(stdout_buf.getvalue())
        assert output["operation"] == "readiness"
        assert output["claim_ceiling"] == CLAIM_CEILING
        assert output["result"] == classify_readiness(sample_snapshot_dict).to_dict()

    def test_overlap_operation_file(self, tmp_path: Path, sample_overlap_dict: dict[str, Any]):
        infile = tmp_path / "overlap.json"
        infile.write_text(json.dumps(sample_overlap_dict))

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code = cli.main(["--operation", "overlap", "--input", str(infile)])
        assert code == 0
        output = json.loads(stdout_buf.getvalue())
        assert output["operation"] == "overlap"
        assert output["claim_ceiling"] == CLAIM_CEILING
        expected = analyze_cross_pr_overlap(sample_overlap_dict["snapshots"]).to_dict()
        assert output["result"] == json.loads(json.dumps(expected))

    def test_ci_operation_file(self, tmp_path: Path, sample_snapshot_dict: dict[str, Any]):
        infile = tmp_path / "ci.json"
        infile.write_text(json.dumps(sample_snapshot_dict))

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code = cli.main(["--operation", "ci", "--input", str(infile)])
        assert code == 0
        output = json.loads(stdout_buf.getvalue())
        assert output["operation"] == "ci"
        assert output["claim_ceiling"] == CI_EVIDENCE_CLAIM_CEILING
        assert output["result"] == fingerprint_ci_failures(sample_snapshot_dict).to_dict()

    def test_impact_operation_is_deferred_from_v1(self, tmp_path: Path):
        infile = tmp_path / "impact.json"
        infile.write_text(json.dumps({"sources": {}, "changed_files": []}))
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code = cli.main(["--operation", "impact", "--input", str(infile)])
        assert code != 0
        output = json.loads(stdout_buf.getvalue())
        assert output["status"] == "ERROR"
        assert output["claim_ceiling"] == CLAIM_CEILING

    def test_subprocess_module_execution(self, tmp_path: Path, sample_snapshot_dict: dict[str, Any]):
        infile = tmp_path / "snap.json"
        infile.write_text(json.dumps(sample_snapshot_dict))

        res = subprocess.run(
            [sys.executable, "-m", "reviewer.intelligence_cli", "--operation", "readiness", "--input", str(infile)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        output = json.loads(res.stdout)
        assert output["operation"] == "readiness"
        assert output["claim_ceiling"] == CLAIM_CEILING
        assert output["result"]["disposition"] == "REVIEW_READY"


class TestIntelligenceCliFailClosed:
    """Test fail closed semantics on errors, malformed input, missing args, etc."""

    def test_missing_operation_flag(self, tmp_path: Path):
        infile = tmp_path / "snap.json"
        infile.write_text("{}")

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code = cli.main(["--input", str(infile)])
        assert code != 0
        output = json.loads(stdout_buf.getvalue())
        assert output["status"] == "ERROR"
        assert output["claim_ceiling"] == CLAIM_CEILING
        assert "operation" in output["error"].lower() or "required" in output["error"].lower()

    def test_unknown_operation(self, tmp_path: Path):
        infile = tmp_path / "snap.json"
        infile.write_text("{}")

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code = cli.main(["--operation", "invalid_op", "--input", str(infile)])
        assert code != 0
        output = json.loads(stdout_buf.getvalue())
        assert output["status"] == "ERROR"
        assert output["claim_ceiling"] == CLAIM_CEILING

    def test_nonexistent_input_file(self, tmp_path: Path):
        nonexistent = tmp_path / "nonexistent.json"
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code = cli.main(["--operation", "revision", "--input", str(nonexistent)])
        assert code != 0
        output = json.loads(stdout_buf.getvalue())
        assert output["status"] == "ERROR"
        assert output["claim_ceiling"] == CLAIM_CEILING
        assert "does not exist" in output["error"] or "not found" in output["error"].lower()

    def test_malformed_json_input(self, tmp_path: Path):
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("{not valid json")
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code = cli.main(["--operation", "revision", "--input", str(bad_json)])
        assert code != 0
        output = json.loads(stdout_buf.getvalue())
        assert output["status"] == "ERROR"
        assert output["claim_ceiling"] == CLAIM_CEILING
        assert "Malformed JSON" in output["error"]

    def test_invalid_shape_for_revision(self, tmp_path: Path):
        bad_shape = tmp_path / "bad_shape.json"
        bad_shape.write_text(json.dumps(["not", "an", "object"]))
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code = cli.main(["--operation", "revision", "--input", str(bad_shape)])
        assert code != 0
        output = json.loads(stdout_buf.getvalue())
        assert output["status"] == "ERROR"
        assert "JSON object" in output["error"]

    def test_invalid_shape_for_overlap(self, tmp_path: Path):
        bad_shape = tmp_path / "bad_overlap.json"
        bad_shape.write_text(json.dumps({"snapshots": "not_a_list"}))
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code = cli.main(["--operation", "overlap", "--input", str(bad_shape)])
        assert code != 0
        output = json.loads(stdout_buf.getvalue())
        assert output["status"] == "ERROR"


class TestIntelligenceCliIsolation:
    """Ensure CLI is completely isolated from network, semantic, and state persistence."""

    def test_no_transport_or_semantic_imports(self):
        import reviewer.intelligence_cli as icli
        forbidden = ("github", "semantic", "opencli", "publication", "service", "scan")
        for mod in forbidden:
            assert not hasattr(icli, mod), f"intelligence_cli must not import {mod}"

    def test_no_state_filesystem_writes(self, tmp_path: Path, sample_snapshot_dict: dict[str, Any]):
        infile = tmp_path / "snap.json"
        infile.write_text(json.dumps(sample_snapshot_dict))
        before = list(tmp_path.iterdir())

        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            code = cli.main(["--operation", "revision", "--input", str(infile)])
        assert code == 0

        after = list(tmp_path.iterdir())
        assert before == after
