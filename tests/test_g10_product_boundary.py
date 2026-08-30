from __future__ import annotations

import ast
from pathlib import Path

import reviewer.intelligence as ri
import reviewer.intelligence_cli as cli
import reviewer.webmcp as webmcp


ROOT = Path(__file__).resolve().parent.parent


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module)
    return out


def test_g10_v1_stays_in_current_repository_without_second_package_authority():
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert 'name = "nexus-opencli-reviewer"' in pyproject
    assert not (ROOT / "repository-intelligence").exists()
    assert not (ROOT / "repository_intelligence").exists()


def test_g10_v11_change_impact_stays_inside_canonical_core_boundary():
    assert hasattr(ri, "analyze_change_impact")
    assert hasattr(ri, "ChangeImpactReportV1")
    assert "impact" in cli.OPERATIONS
    assert (ROOT / "reviewer" / "intelligence" / "impact.py").exists()


def test_g10_core_has_no_transport_semantic_or_governance_dependencies():
    imports = set()
    for filename in ("__init__.py", "contracts.py", "core.py"):
        imports |= _imports(ROOT / "reviewer" / "intelligence" / filename)
    forbidden_fragments = (
        "reviewer.github",
        "reviewer.webmcp",
        "reviewer.scan",
        "reviewer.semantic",
        "reviewer.opencli",
        "reviewer.publication",
        "reviewer.service",
        "reviewer.unattended",
    )
    for module in imports:
        assert not any(fragment in module for fragment in forbidden_fragments), module


def test_g10_v11_adapter_boundary_is_exact():
    assert cli.OPERATIONS == frozenset({"revision", "readiness", "overlap", "ci", "impact", "cfi", "eia"})
    assert hasattr(webmcp, "WebMCPServer")
    assert not (ROOT / "reviewer" / "mcp_server.py").exists()
    assert not (ROOT / "reviewer" / "github_action.py").exists()


def test_g10_semantic_reviewer_remains_separate_surface():
    for name in ("semantic.py", "opencli.py", "publication.py"):
        assert (ROOT / "reviewer" / name).exists()
    assert not hasattr(ri, "semantic")
    assert not hasattr(ri, "opencli")
    assert not hasattr(ri, "publication")


def test_g10_legacy_scan_is_compatibility_consumer_not_core_dependency():
    core_imports = _imports(ROOT / "reviewer" / "intelligence" / "core.py")
    assert "reviewer.scan" not in core_imports
    webmcp_source = (ROOT / "reviewer" / "webmcp.py").read_text()
    assert "discard its decisions" in webmcp_source
    assert "build_repository_intelligence_report" in webmcp_source


def test_g10_product_boundary_doc_is_explicit():
    text = (ROOT / "README.md").read_text()
    assert "Productization Boundary — G10 Frozen" in text
    assert "KEEP_IN_CURRENT_REPOSITORY_FOR_V1" in text
    assert "DEFER_REPO_EXTRACTION_TO_POST_V1" in text
