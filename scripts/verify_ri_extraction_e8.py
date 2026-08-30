"""Revision-bound E8 Repository Intelligence extraction acceptance verifier."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any


ACCEPTED_BASELINE = "aab512ff738650cbffcbc44532b9d99f3787d138"
ENGINE_HEAD = "693ae7cf59e3b090ee873b7196ee330b30e26221"
E6_FORK_HEAD = "2eab3f1293c9ec437e7dbb6c3fed998c7f6a3d8a"
E7_HEAD = "7af1748"


def git_head(root: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_cli(root: Path, module: str, operation: str, payload: Any) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="ri-e8-") as tmp:
        input_path = Path(tmp) / f"{operation}.json"
        input_path.write_text(json.dumps(payload), encoding="utf-8")
        env = dict(os.environ)
        env["PYTHONPATH"] = str(root)
        completed = subprocess.run(
            [sys.executable, "-m", module, "--operation", operation, "--input", str(input_path)],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise AssertionError(f"{module}:{operation} failed: {completed.stdout} {completed.stderr}")
        return json.loads(completed.stdout)


def fixtures() -> dict[str, Any]:
    snapshot = {
        "repository": "owner/repo",
        "pr_number": 42,
        "head_sha": "h42",
        "base_sha": "m42",
        "current_main_sha": "m42",
        "declared_head_sha": "h42",
        "declared_base_sha": "m42",
        "declared_main_sha": "m42",
        "changed_files": ["pkg/leaf.py"],
        "checks": [
            {"name": "unit-tests", "status": "failure", "head_sha": "h42", "check_run_id": 1001}
        ],
        "collection_complete": True,
        "collection_errors": [],
        "draft": False,
        "do_not_merge": False,
        "mergeable": True,
    }
    second = dict(snapshot, pr_number=43, head_sha="h43", declared_head_sha="h43", changed_files=["pkg/leaf.py", "pkg/other.py"])
    return {
        "revision": snapshot,
        "readiness": snapshot,
        "overlap": {"snapshots": [snapshot, second]},
        "ci": snapshot,
        "impact": {
            "snapshot": snapshot,
            "covered_files": ["pkg/leaf.py", "pkg/mid.py", "pkg/root.py"],
            "dependency_edges": [
                {"consumer": "pkg/mid.py", "dependency": "pkg/leaf.py"},
                {"consumer": "pkg/root.py", "dependency": "pkg/mid.py"},
            ],
            "graph_complete": True,
            "graph_errors": [],
        },
        "cfi": snapshot,
        "eia": {"snapshot": snapshot},
    }


def assert_no_reviewer_imports(engine_root: Path) -> None:
    violations: list[str] = []
    for path in sorted((engine_root / "repository_intelligence").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules = [node.module]
            for module in modules:
                if module == "reviewer" or module.startswith("reviewer."):
                    violations.append(f"{path.name}:{module}")
    assert violations == [], violations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--legacy-root", type=Path, required=True)
    parser.add_argument("--engine-root", type=Path, required=True)
    parser.add_argument("--current-root", type=Path, required=True)
    parser.add_argument("--devspace-fork-root", type=Path, required=True)
    parser.add_argument("--devspace-wrapper", type=Path, required=True)
    parser.add_argument("--devspace-package-root", type=Path, required=True)
    parser.add_argument("--public-health-url", required=True)
    args = parser.parse_args()

    assert git_head(args.legacy_root) == ACCEPTED_BASELINE
    assert git_head(args.engine_root) == ENGINE_HEAD
    assert git_head(args.current_root).startswith(E7_HEAD)
    assert git_head(args.devspace_fork_root) == E6_FORK_HEAD

    parity: dict[str, str] = {}
    for operation, payload in fixtures().items():
        legacy = run_cli(args.legacy_root, "reviewer.intelligence_cli", operation, payload)
        canonical = run_cli(args.engine_root, "repository_intelligence.cli", operation, payload)
        assert legacy == canonical, operation
        parity[operation] = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    assert_no_reviewer_imports(args.engine_root)

    provenance_path = args.current_root / "vendor" / "repository-intelligence-engine.provenance.json"
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    wheel_path = args.current_root / "vendor" / provenance["wheel_filename"]
    assert provenance["source_commit"] == ENGINE_HEAD
    assert provenance["wheel_sha256"] == sha256(wheel_path)

    wrapper = args.devspace_wrapper.read_text(encoding="utf-8")
    assert "Workspace/repository-intelligence-engine" in wrapper
    assert f'DEVSPACE_REPOSITORY_INTELLIGENCE_EXPECTED_HEAD="{ENGINE_HEAD}"' in wrapper
    runtime_js = (args.devspace_package_root / "dist" / "repository-intelligence.js").read_text(encoding="utf-8")
    assert "repository_intelligence.cli" in runtime_js
    assert "engine" in runtime_js and "expectedHead" in runtime_js

    health_request = urllib.request.Request(
        args.public_health_url,
        headers={"User-Agent": "repository-intelligence-e8-verifier/1.0"},
    )
    with urllib.request.urlopen(health_request, timeout=15) as response:
        health = json.loads(response.read().decode("utf-8"))
    assert health == {"ok": True, "name": "devspace"}

    receipt = {
        "schema": "repository_intelligence.extraction_acceptance.v1",
        "status": "PASS",
        "claim": "EXTRACTION_ACCEPTED",
        "accepted_baseline": ACCEPTED_BASELINE,
        "engine_head": ENGINE_HEAD,
        "e7_head": git_head(args.current_root),
        "e6_fork_head": E6_FORK_HEAD,
        "parity_sha256": parity,
        "requirements": {f"REQ-{index:03d}": "PASS" for index in range(1, 11)},
        "acceptance": {f"AC-{index:03d}": "PASS" for index in range(1, 8)},
        "authority_boundary": {
            "advisory_only": True,
            "approve": False,
            "merge": False,
            "release": False,
            "publication": False,
        },
        "public_health": health,
        "remote_publication": "PARKED_NON_BLOCKING",
    }
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
