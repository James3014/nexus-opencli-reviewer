"""Static binding of the published canonical engine identity."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ENGINE_REPOSITORY = "https://github.com/James3014/repository-intelligence-engine"
VENDORED_SOURCE_COMMIT = "693ae7cf59e3b090ee873b7196ee330b30e26221"
VENDORED_SOURCE_TREE = "f5f8496ed16e775e8767827f66d1fa35355d2968"
PUBLISHED_TAG = "v0.1.0"
PUBLISHED_COMMIT = "a8b9a00a6f3ea3e9ade0c6ef494d0fa88a2d73b2"
PUBLISHED_TREE = "410c0e647f8edbe9d250f7e93f86c52a0b982fb8"


def test_published_engine_identity_is_bound_in_provenance() -> None:
    provenance = json.loads(
        (ROOT / "vendor" / "repository-intelligence-engine.provenance.json").read_text(encoding="utf-8")
    )
    assert provenance["source_repository"] == ENGINE_REPOSITORY
    assert provenance["source_ref"] == "refs/heads/main"
    assert provenance["source_commit"] == VENDORED_SOURCE_COMMIT
    assert provenance["source_tree"] == VENDORED_SOURCE_TREE
    assert provenance["publication_status"] == "PUBLIC_MAIN_VERIFIED"
    wheel = ROOT / "vendor" / provenance["wheel_filename"]
    assert hashlib.sha256(wheel.read_bytes()).hexdigest() == provenance["wheel_sha256"]


def test_package_metadata_and_docs_use_the_same_public_identity() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f'canonical-repository = "{ENGINE_REPOSITORY}"' in pyproject
    assert f'canonical-tag = "{PUBLISHED_TAG}"' in pyproject
    assert f'canonical-commit = "{PUBLISHED_COMMIT}"' in pyproject
    assert ENGINE_REPOSITORY in readme
    assert PUBLISHED_TAG in readme
    assert PUBLISHED_COMMIT in readme
    assert PUBLISHED_TREE in readme
    assert "uses: James3014/repository-intelligence-engine@v0.1.0" in readme
