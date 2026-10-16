"""RIE #86 mirror: re-hashed identity-flag forgeries must not verify."""
import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reviewer.github_action as gha  # noqa: E402
from test_github_action_cloud import FakeGitHubAPI, _StaleBaseAPI  # noqa: E402

READY = dict(disposition="REVIEW_READY", is_review_ready=True, findings=[], reasons=[], evidence_gaps=[], risk="LOW")


def _rehash(b):
    b["content_sha256"] = gha._hash_payload(b)
    return b


def _stale():
    return gha.run_cloud_bundle(gha.collect_pr_snapshot(_StaleBaseAPI(), "owner/repo", 7))


def _genuine():
    return gha.run_cloud_bundle(gha.collect_pr_snapshot(FakeGitHubAPI(), "owner/repo", 7))


def _ident(b, name):
    return b["reports"][name]["result"]["identity"]


def _stale_base_flag_flipped(b):
    b["reports"]["readiness"]["result"].update(READY)
    _ident(b, "readiness")["stale_base"] = False


def _stale_base_flipped_everywhere(b):
    b["reports"]["readiness"]["result"].update(READY)
    for n in ("readiness", "cfi", "eia"):
        _ident(b, n)["stale_base"] = False


def _declared_flag_hidden(b):
    ident = _ident(b, "readiness")
    ident["declared_head_sha"] = "d" * 40
    ident["stale_declared_head"] = False


def _stale_evidence_mismatch(b):
    _ident(b, "readiness")["stale_declared_main"] = True


def _flag_true_but_derivation_false(b):
    _ident(b, "readiness")["stale_base"] = True


def _cross_report_disagree(b):
    _ident(b, "cfi")["stale_base"] = False


@pytest.mark.parametrize("forge", [_stale_base_flag_flipped, _stale_base_flipped_everywhere, _cross_report_disagree])
def test_stale_bundle_forgeries_rejected(forge):
    b = _stale()
    assert gha.verify_cloud_bundle(b) is True
    f = copy.deepcopy(b)
    forge(f)
    assert gha.verify_cloud_bundle(_rehash(f)) is False


@pytest.mark.parametrize("forge", [_declared_flag_hidden, _stale_evidence_mismatch, _flag_true_but_derivation_false])
def test_genuine_bundle_flag_forgeries_rejected(forge):
    b = _genuine()
    assert gha.verify_cloud_bundle(b) is True
    f = copy.deepcopy(b)
    forge(f)
    assert gha.verify_cloud_bundle(_rehash(f)) is False
