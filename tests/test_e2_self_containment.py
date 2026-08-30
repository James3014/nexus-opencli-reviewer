from __future__ import annotations

import ast
from pathlib import Path


def test_repository_intelligence_has_no_reverse_reviewer_imports():
    root = Path("reviewer/intelligence")
    violations = []
    for path in sorted(root.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("reviewer"):
                violations.append(f"{path}:{node.lineno}:{node.module}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("reviewer"):
                        violations.append(f"{path}:{node.lineno}:{alias.name}")
    assert violations == []


def test_legacy_primitives_forward_to_canonical_authority():
    import reviewer.classifier as legacy_classifier
    import reviewer.models as legacy_models
    import reviewer.overlap as legacy_overlap
    import repository_intelligence.classifier as canonical_classifier
    import repository_intelligence.models as canonical_models
    import repository_intelligence.overlap as canonical_overlap

    assert legacy_models.PRSnapshot is canonical_models.PRSnapshot
    assert legacy_models.CheckObservation is canonical_models.CheckObservation
    assert legacy_models.Disposition is canonical_models.Disposition
    assert legacy_classifier.classify is canonical_classifier.classify
    assert legacy_overlap.detect is canonical_overlap.detect
