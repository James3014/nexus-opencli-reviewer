from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import reviewer.webmcp as webmcp
from reviewer.github import GitHubError, GhCliTransport
from reviewer.intelligence import (
    CI_EVIDENCE_CLAIM_CEILING,
    EvidenceCompleteness,
    fingerprint_ci_failures,
    verify_ci_failure_evidence,
)
from reviewer.models import Classification, Disposition, PRSnapshot


def _snapshot(*, pr_number=1, main_sha="main-a", base_sha="main-a", head_sha="head-a", checks=(), complete=True, errors=()):
    return PRSnapshot.from_dict(
        {
            "repository": "owner/repo",
            "pr_number": pr_number,
            "title": "fixture",
            "state": "open",
            "draft": False,
            "mergeable": True,
            "base": {"ref": "main", "sha": base_sha},
            "head": {"ref": "feature", "sha": head_sha},
            "base_sha": base_sha,
            "head_sha": head_sha,
            "changed_files": ["src/x.py"],
            "checks": list(checks),
            "collection_complete": complete,
            "collection_errors": list(errors),
            "observed_at": "2026-08-30T00:00:00Z",
        },
        main=main_sha,
    )


def _scan_result(snapshot, main_sha="main-a"):
    return main_sha, "2026-08-30T00:00:00Z", [Classification(snapshot=snapshot, disposition=Disposition.REVIEW_READY)], []


class RebindingTransport:
    def __init__(self, shas):
        self._shas = iter(shas)
        self.get_ref_calls = 0

    def get_ref(self, repo, branch):
        self.get_ref_calls += 1
        return {"object": {"sha": next(self._shas)}}


def test_main_change_during_adapter_acquisition_fails_closed():
    snap = _snapshot()
    transport = RebindingTransport(["main-b"])
    with patch("reviewer.webmcp.scan", return_value=_scan_result(snap, "main-a")):
        with pytest.raises(RuntimeError, match="MAIN_CHANGED_DURING_ACQUISITION"):
            webmcp.tool_inspect_pr("owner/repo", 1, transport)


def test_stable_main_rebind_allows_result():
    snap = _snapshot()
    transport = RebindingTransport(["main-a"])
    with patch("reviewer.webmcp.scan", return_value=_scan_result(snap, "main-a")):
        result = webmcp.tool_inspect_pr("owner/repo", 1, transport)
    assert result["current_main_sha"] == "main-a"
    assert result["claim_ceiling"] == "PR_INTELLIGENCE_ONLY"
    assert transport.get_ref_calls == 1


def test_missing_checks_never_becomes_complete_clean_ci_evidence():
    fp = fingerprint_ci_failures(_snapshot(checks=()))
    assert fp.has_unexpected_failures is False
    assert fp.is_complete is False
    assert fp.evidence_completeness is EvidenceCompleteness.INCOMPLETE
    assert "no_check_evidence_provided" in fp.evidence_gaps
    assert fp.claim_ceiling == CI_EVIDENCE_CLAIM_CEILING


def test_collection_error_never_becomes_complete_report():
    snap = _snapshot(complete=False, errors=("checks: timeout",))
    with patch("reviewer.webmcp.scan", return_value=_scan_result(snap)):
        transport = RebindingTransport(["main-a"])
        result = webmcp.tool_inspect_pr("owner/repo", 1, transport)
    assert result["evidence_completeness"] == "INCOMPLETE"
    assert "checks: timeout" in result["evidence_gaps"]


def test_foreign_ci_head_is_retained_only_as_incomplete_evidence():
    fp = fingerprint_ci_failures(
        _snapshot(
            checks=(
                {
                    "name": "ci/test",
                    "status": "failure",
                    "expected_failure": False,
                    "head_sha": "foreign-head",
                    "check_run_id": 99,
                },
            )
        )
    )
    assert fp.has_unexpected_failures is True
    assert fp.is_complete is False
    assert any("mismatches PR head_sha" in gap for gap in fp.evidence_gaps)
    assert verify_ci_failure_evidence(fp.to_dict()) is True


def test_duplicate_read_request_is_deterministic_and_has_no_write_call():
    snap = _snapshot(chacks=()) if False else _snapshot()
    transport = RebindingTransport(["main-a", "main-a"])
    transport.create_comment = MagicMock()
    with patch("reviewer.webmcp.scan", side_effect=[_scan_result(snap), _scan_result(snap)]):
        first = webmcp.tool_inspect_pr("owner/repo", 1, transport)
        second = webmcp.tool_inspect_pr("owner/repo", 1, transport)
    assert first == second
    transport.create_comment.assert_not_called()


def test_http_read_retry_is_bounded_and_fails_closed(monkeypatch):
    calls = []

    def urlopen(request, *, timeout):
        calls.append(timeout)
        raise TimeoutError("still unavailable")

    monkeypatch.setattr("reviewer.github.urllib.request.urlopen", urlopen)
    monkeypatch.setattr("reviewer.github.time.sleep", lambda _: None)
    transport = GhCliTransport()
    transport._token = "cached"
    with pytest.raises(GitHubError, match="still unavailable"):
        transport.get_ref("owner/repo", "main")
    assert calls == [30, 15]


def test_invalid_repository_and_pr_fail_before_acquisition():
    transport = MagicMock()
    with pytest.raises(ValueError):
        webmcp.tool_inspect_pr("not-a-repository", 1, transport)
    with pytest.raises(ValueError):
        webmcp.tool_inspect_pr("owner/repo", 0, transport)
    transport.get_ref.assert_not_called()


def test_pr_not_found_is_structured_and_non_escalating():
    transport = RebindingTransport(["main-a"])
    with patch("reviewer.webmcp.scan", return_value=("main-a", "2026-08-30T00:00:00Z", [], [])):
        result = webmcp.tool_inspect_pr("owner/repo", 999, transport)
    assert result["error"] == "PR_NOT_FOUND"
    assert result["claim_ceiling"] == "PR_INTELLIGENCE_ONLY"
