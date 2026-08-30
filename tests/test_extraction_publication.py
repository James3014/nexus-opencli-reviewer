"""Static binding of the published canonical engine identity."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ENGINE_REPOSITORY = "https://github.com/James3014/repository-intelligence-engine"
ENGINE_COMMIT = "693ae7cf59e3b090ee873b7196ee330b30e26221"
ENGINE_TREE = "f5f8496ed16e775e8767827f66d1fa35355d2968"


def test_published_engine_identity_is_bound_in_provenance() -> None:
    provenance = json.loads(
        (ROOT / "vendor" / "repository-intelligence-engine.provenance.json").read_text(encoding="utf-8")
    )
    assert provenance["source_repository"] == ENGINE_REPOSITORY
    assert provenance["source_ref"] == "refs/heads/main"
    assert provenance["source_commit"] == ENGINE_COMMIT
    assert provenance["source_tree"] == ENGINE_TREE
    assert provenance["publication_status"] == "PUBLIC_MAIN_VERIFIED"
    wheel = ROOT / "vendor" / provenance["wheel_filename"]
    assert hashlib.sha256(wheel.read_bytes()).hexdigest() == provenance["wheel_sha256"]


def test_package_metadata_and_docs_use_the_same_public_identity() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f'canonical-repository = "{ENGINE_REPOSITORY}"' in pyproject
    assert f'canonical-commit = "{ENGINE_COMMIT}"' in pyproject
    assert ENGINE_REPOSITORY in readme
    assert ENGINE_COMMIT in readme
    assert ENGINE_TREE in readme
