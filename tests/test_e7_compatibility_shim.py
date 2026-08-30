"""E7 compatibility-shim and single-authority acceptance controls."""
from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import repository_intelligence as canonical
import repository_intelligence.cli as canonical_cli
import reviewer.intelligence as legacy
import reviewer.intelligence_cli as legacy_cli
from repository_intelligence.eia import AUTOMATION_CLAIM_CEILING


REPO_ROOT = Path(__file__).resolve().parent.parent
ENGINE_ROOT = Path("/Users/jameschen/Workspace/repository-intelligence-engine")
ENGINE_HEAD = "693ae7cf59e3b090ee873b7196ee330b30e26221"


def test_legacy_package_entrypoint_is_a_thin_canonical_forwarder() -> None:
    path = REPO_ROOT / "reviewer" / "intelligence" / "__init__.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    assert not any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) for node in ast.walk(tree))
    imported_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert imported_modules == {"__future__", "repository_intelligence"}


def test_legacy_public_api_is_object_identical_to_canonical_package() -> None:
    assert legacy.__all__ is canonical.__all__
    for name in canonical.__all__:
        assert getattr(legacy, name) is getattr(canonical, name), name
    assert legacy_cli.main is canonical_cli.main
    assert legacy_cli.execute_operation is canonical_cli.execute_operation
    assert legacy_cli.load_input_data is canonical_cli.load_input_data
    assert legacy_cli.OPERATIONS is canonical_cli.OPERATIONS


def test_claim_ceilings_remain_exact() -> None:
    assert legacy.CLAIM_CEILING == "PR_INTELLIGENCE_ONLY"
    assert legacy.CI_EVIDENCE_CLAIM_CEILING == "CI_EVIDENCE_ONLY"
    assert AUTOMATION_CLAIM_CEILING == "AUTOMATION_ADVISORY_ONLY"


def test_no_production_consumer_imports_legacy_intelligence_authority() -> None:
    violations: list[str] = []
    for path in sorted((REPO_ROOT / "reviewer").rglob("*.py")):
        if path.parent == REPO_ROOT / "reviewer" / "intelligence":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("reviewer.intelligence"):
                        violations.append(f"{path.relative_to(REPO_ROOT)} imports {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module.startswith("reviewer.intelligence") or (node.level and module.startswith("intelligence")):
                    violations.append(f"{path.relative_to(REPO_ROOT)} imports {'.' * node.level}{module}")
    assert violations == []


def test_poisoned_legacy_core_cannot_intercept_compatibility_imports() -> None:
    script = r'''
import importlib.abc
import json
import sys

class LegacyCoreBlocker(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith("reviewer.intelligence."):
            raise ImportError("POISONED_LEGACY_CORE_BLOCKED")
        return None

sys.meta_path.insert(0, LegacyCoreBlocker())
import reviewer.intelligence as legacy
import reviewer.classifier as classifier
import reviewer.models as models
import reviewer.overlap as overlap

snapshot = {
    "repository": "owner/repo",
    "pr_number": 7,
    "head_sha": "h7",
    "base_sha": "m7",
    "current_main_sha": "m7",
    "changed_files": ["README.md"],
    "checks": [],
}
result = legacy.classify_readiness(snapshot).to_dict()
assert result["disposition"] == "REVIEW_READY"
assert classifier.classify is not None
assert models.PRSnapshot is not None
assert overlap.detect is not None
print(json.dumps({"claim_ceiling": legacy.CLAIM_CEILING, "disposition": result["disposition"]}))
'''
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(ENGINE_ROOT), str(REPO_ROOT), env.get("PYTHONPATH", "")])
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert '"claim_ceiling": "PR_INTELLIGENCE_ONLY"' in completed.stdout
    assert '"disposition": "REVIEW_READY"' in completed.stdout
