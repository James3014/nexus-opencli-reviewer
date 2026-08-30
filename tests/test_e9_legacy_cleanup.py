"""E9 physical cleanup and hidden-consumer negative controls."""
from __future__ import annotations

import ast
import importlib
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
LEGACY_PACKAGE = ROOT / "reviewer" / "intelligence"
MODULES = ("classifier", "models", "contracts", "core", "overlap", "impact", "cfi", "eia")


def test_legacy_modules_contain_forwarding_only() -> None:
    for name in MODULES:
        path = LEGACY_PACKAGE / f"{name}.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        assert not any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            for node in ast.walk(tree)
        ), name
        imports = [
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        ]
        assert imports == [f"repository_intelligence.{name}"], (name, imports)


def test_legacy_submodule_exports_resolve_to_canonical_objects() -> None:
    for name in MODULES:
        legacy = importlib.import_module(f"reviewer.intelligence.{name}")
        canonical = importlib.import_module(f"repository_intelligence.{name}")
        public = [symbol for symbol in vars(canonical) if not symbol.startswith("_")]
        for symbol in public:
            if hasattr(legacy, symbol):
                assert getattr(legacy, symbol) is getattr(canonical, symbol), f"{name}.{symbol}"


def test_no_production_caller_imports_legacy_intelligence_submodules() -> None:
    violations: list[str] = []
    for path in sorted((ROOT / "reviewer").rglob("*.py")):
        if path.parent == LEGACY_PACKAGE:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules = [node.module]
            for module in modules:
                if module.startswith("reviewer.intelligence"):
                    violations.append(f"{path.relative_to(ROOT)}:{module}")
    assert violations == []


def test_obsolete_duplicate_semantic_tests_are_removed() -> None:
    for name in (
        "test_intelligence_core.py",
        "test_intelligence_g4_contract.py",
        "test_intelligence_impact.py",
        "test_intelligence_cfi_eia.py",
    ):
        assert not (ROOT / "tests" / name).exists(), name


def test_docs_name_extracted_package_as_only_canonical_authority() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "`repository_intelligence` is the canonical" in readme
    assert "`reviewer.intelligence` package is a forwarding-only compatibility shim" in readme
    assert "KEEP_IN_CURRENT_REPOSITORY_FOR_V1" not in readme
    assert "DEFER_REPO_EXTRACTION_TO_POST_V1" not in readme
