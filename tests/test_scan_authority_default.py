"""REV-2: the reviewer scan path must not inherit the wheel's governance defaults.

README documents the protected-path (authority) policy default as empty.  The
legacy ``repository_intelligence.classifier.classify`` default is governance-
specific, so the scan path must pass an explicit, config-derived pattern tuple.
"""
import pytest

from reviewer import service_cli
from reviewer.config import ConfigError, ReviewerConfig
from reviewer.scan import scan


class _Transport:
    def __init__(self, files):
        self._files = list(files)

    def auth_preflight(self):
        return None

    def get_ref(self, repo, branch):
        return {"object": {"sha": "main"}}

    def list_open_prs(self, repo):
        return [{
            "number": 3, "title": "fixture", "state": "open", "draft": False,
            "mergeable": True,
            "base": {"ref": "main", "sha": "main"},
            "head": {"ref": "candidate", "sha": "head"},
            "body": "Implements Issue #3", "labels": [],
        }]

    def list_files(self, repo, number):
        return [{"filename": name} for name in self._files]

    def list_checks(self, repo, sha):
        return []


def _only_item(items):
    assert len(items) == 1
    return items[0]


def test_default_scan_does_not_apply_wheel_governance_patterns(tmp_path):
    _, _, items, _ = scan("o/r", _Transport(["AGENTS.md"]))
    item = _only_item(items)
    assert "AUTHORITY_OVERLAP" not in item.findings
    assert item.risk != "HIGH"


def test_explicit_authority_patterns_flag_overlap():
    _, _, items, _ = scan("o/r", _Transport(["AGENTS.md"]), authority_patterns=("AGENTS.md",))
    item = _only_item(items)
    assert "AUTHORITY_OVERLAP" in item.findings
    assert item.risk == "HIGH"


def test_config_authority_patterns_default_empty_and_round_trip():
    assert ReviewerConfig().authority_patterns == ()
    config = ReviewerConfig.from_mapping({"authority_patterns": ["AGENTS.md", "policy/"]})
    assert config.authority_patterns == ("AGENTS.md", "policy/")
    assert config.to_dict()["authority_patterns"] == ["AGENTS.md", "policy/"]
    assert ReviewerConfig.from_mapping(config.to_dict()).authority_patterns == ("AGENTS.md", "policy/")


@pytest.mark.parametrize("raw", [
    {"authority_patterns": "AGENTS.md"},
    {"authority_patterns": [""]},
    {"authority_patterns": [3]},
    {"authority_patterns": [" "]},
])
def test_config_rejects_malformed_authority_patterns(raw):
    with pytest.raises(ConfigError):
        ReviewerConfig.from_mapping(raw)


def test_service_scan_receives_configured_authority_patterns(monkeypatch):
    seen = {}

    def fake_scan(repository, transport, **kwargs):
        seen.update(kwargs)
        return "main", "observed", [], None

    monkeypatch.setattr(service_cli, "scan", fake_scan)
    config = ReviewerConfig.from_mapping({"authority_patterns": ["AGENTS.md"],
                                          "state_root": "/tmp/rev2-state"})
    service_cli.build_service(config, "o/r").discover()
    assert tuple(seen["authority_patterns"]) == ("AGENTS.md",)


def test_service_scan_defaults_to_explicit_empty_patterns(monkeypatch):
    seen = {}

    def fake_scan(repository, transport, **kwargs):
        seen.update(kwargs)
        return "main", "observed", [], None

    monkeypatch.setattr(service_cli, "scan", fake_scan)
    service_cli.build_service(ReviewerConfig(), "o/r").discover()
    assert tuple(seen["authority_patterns"]) == ()
