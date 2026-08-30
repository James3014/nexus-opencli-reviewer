"""Deterministic tests for reviewer/webmcp.py – WEBMCP_PR_INTELLIGENCE_PILOT_V1.

Coverage:
  - Input validation (_validate_repo, _validate_pr_number)
  - REVIEW_READY filtering (tool_list_review_ready_prs)
  - inspect_pr: all dispositions, PR_NOT_FOUND, stale identity evidence
  - inspect_ci_failure: expected vs unexpected CI failures, identity evidence fields
  - Tool metadata: annotations readOnlyHint=true / untrustedContentHint=true in browser page
  - Server binding: 127.0.0.1 only, no CORS wildcard in response headers
  - No persistence side effect (persist_state=False plumbing)
  - No semantic/OpenCLI/publication call paths reachable from tool functions
  - Claim ceilings PR_INTELLIGENCE_ONLY and CI_EVIDENCE_ONLY present in outputs
  - HTTP handler: valid / invalid JSON body, unknown path, GET root
"""
from __future__ import annotations

import json
import socket
from http.client import HTTPConnection
from unittest.mock import MagicMock, patch

import pytest

from reviewer.models import CheckObservation, Classification, Disposition, PRSnapshot
from reviewer.webmcp import (
    CLAIM_CEILING,
    CI_CLAIM_CEILING,
    _BIND_HOST,
    _BROWSER_PAGE_TEMPLATE,
    WebMCPServer,
    _validate_pr_number,
    _validate_repo,
    tool_inspect_ci_failure,
    tool_inspect_pr,
    tool_list_review_ready_prs,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _snapshot(
    repository="owner/repo",
    pr_number=1,
    base_sha="aaa",
    head_sha="bbb",
    main_sha="aaa",
    checks=(),
    source_identity="github:owner/repo:pr:1@bbb",
    collection_complete=True,
    collection_errors=(),
    declared_base_sha=None,
    declared_head_sha=None,
    declared_main_sha=None,
    draft=False,
    do_not_merge=False,
    changed_files=None,
):
    d = {
        "repository": repository,
        "pr_number": pr_number,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "checks": [
            {
                "name": c.name,
                "status": c.status,
                "expected_failure": c.expected_failure,
                "check_run_id": c.check_run_id,
                "run_id": c.run_id,
                "job_identity": c.job_identity,
                "artifact_identity": c.artifact_identity,
                "external_id": c.external_id,
                "workflow_name": c.workflow_name,
                "head_sha": c.head_sha,
                "details_url": c.details_url,
            }
            for c in checks
        ],
        "source_identity": source_identity,
        "collection_complete": collection_complete,
        "collection_errors": list(collection_errors),
        "draft": draft,
        "do_not_merge": do_not_merge,
        "changed_files": list(changed_files if changed_files is not None else [f"file_{pr_number}.py"]),
    }
    if declared_base_sha is not None:
        d["declared_base_sha"] = declared_base_sha
    if declared_head_sha is not None:
        d["declared_head_sha"] = declared_head_sha
    if declared_main_sha is not None:
        d["declared_main_sha"] = declared_main_sha
    return PRSnapshot.from_dict(d, main_sha)


def _classification(snap, disposition=Disposition.REVIEW_READY, findings=None, reasons=None):
    c = Classification(snapshot=snap)
    c.disposition = disposition
    c.findings = list(findings or [])
    c.reasons = list(reasons or [])
    return c


def _fake_transport(main_sha="aaa"):
    transport = MagicMock()
    transport.get_ref.return_value = {"object": {"sha": main_sha}}
    return transport


def _scan_returning(items, main_sha="aaa", observed="2025-01-01T00:00:00Z"):
    """Return a fake scan() return value."""
    from reviewer.queue import ReviewQueue
    q = ReviewQueue()
    q.ingest(items)
    return main_sha, observed, items, q


# ---------------------------------------------------------------------------
# 1. Input validation
# ---------------------------------------------------------------------------

class TestValidateRepo:
    def test_valid(self):
        assert _validate_repo("owner/repo") == "owner/repo"
        assert _validate_repo("James3014/Nexus-new") == "James3014/Nexus-new"
        assert _validate_repo("a.b/c_d-e") == "a.b/c_d-e"

    def test_rejects_non_string(self):
        with pytest.raises(ValueError, match="owner/name"):
            _validate_repo(123)

    def test_rejects_missing_slash(self):
        with pytest.raises(ValueError):
            _validate_repo("noslash")

    def test_rejects_double_slash(self):
        with pytest.raises(ValueError):
            _validate_repo("a//b")

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            _validate_repo("")

    def test_rejects_path_traversal(self):
        with pytest.raises(ValueError):
            _validate_repo("../evil/path")

    def test_rejects_wildcard(self):
        with pytest.raises(ValueError):
            _validate_repo("owner/*")


class TestValidatePrNumber:
    def test_valid_int(self):
        assert _validate_pr_number(1) == 1
        assert _validate_pr_number(999) == 999
        assert _validate_pr_number("42") == 42

    def test_rejects_zero(self):
        with pytest.raises(ValueError, match="positive"):
            _validate_pr_number(0)

    def test_rejects_negative(self):
        with pytest.raises(ValueError, match="positive"):
            _validate_pr_number(-1)

    def test_rejects_non_integer_float(self):
        with pytest.raises(ValueError, match="positive integer"):
            _validate_pr_number(1.5)

    def test_accepts_integer_float(self):
        assert _validate_pr_number(3.0) == 3

    def test_rejects_string_non_numeric(self):
        with pytest.raises(ValueError):
            _validate_pr_number("abc")

    def test_rejects_none(self):
        with pytest.raises(ValueError):
            _validate_pr_number(None)


# ---------------------------------------------------------------------------
# 2. tool_list_review_ready_prs – REVIEW_READY filtering
# ---------------------------------------------------------------------------

class TestListReviewReadyPrs:
    def _run(self, items, repo="owner/repo"):
        transport = _fake_transport()
        main_sha, observed = "aaa", "2025-01-01T00:00:00Z"
        with patch("reviewer.webmcp.scan", return_value=_scan_returning(items, main_sha, observed)):
            return tool_list_review_ready_prs(repo, transport)

    def test_returns_only_review_ready(self):
        ready_snap = _snapshot(pr_number=1, base_sha="aaa", main_sha="aaa")
        stale_snap = _snapshot(pr_number=2, base_sha="old", main_sha="aaa")
        ready = _classification(ready_snap, Disposition.REVIEW_READY)
        stale = _classification(stale_snap, Disposition.STALE, findings=["STALE_BASE"])
        result = self._run([ready, stale])
        prs = result["review_ready_prs"]
        assert len(prs) == 1
        assert prs[0]["pr_number"] == 1
        assert prs[0]["disposition"] == "REVIEW_READY"

    def test_empty_when_none_ready(self):
        stale_snap = _snapshot(pr_number=3, base_sha="old", main_sha="new")
        stale = _classification(stale_snap, Disposition.STALE, findings=["STALE_BASE"])
        result = self._run([stale])
        assert result["review_ready_prs"] == []

    def test_claim_ceiling_in_output(self):
        snap = _snapshot(pr_number=1)
        c = _classification(snap)
        result = self._run([c])
        assert result["claim_ceiling"] == CLAIM_CEILING
        assert result["claim_ceiling"] == "PR_INTELLIGENCE_ONLY"
        for pr in result["review_ready_prs"]:
            assert pr["claim_ceiling"] == "PR_INTELLIGENCE_ONLY"

    def test_repository_field_present(self):
        snap = _snapshot(pr_number=1)
        c = _classification(snap)
        result = self._run([c])
        assert result["repository"] == "owner/repo"

    def test_invalid_repo_raises_validation_error(self):
        with pytest.raises(ValueError):
            tool_list_review_ready_prs("bad-repo", _fake_transport())

    def test_persist_state_false(self):
        """scan() must always be called with persist_state=False."""
        snap = _snapshot(pr_number=1)
        c = _classification(snap)
        transport = _fake_transport()
        with patch("reviewer.webmcp.scan") as mock_scan:
            mock_scan.return_value = _scan_returning([c])
            tool_list_review_ready_prs("owner/repo", transport)
            _args, kwargs = mock_scan.call_args
            assert kwargs.get("persist_state") is False

    def test_no_semantic_review_call(self):
        """tool functions must never call review_ready or semantic dispatch."""
        snap = _snapshot(pr_number=1)
        c = _classification(snap)
        transport = _fake_transport()
        with patch("reviewer.webmcp.scan", return_value=_scan_returning([c])):
            with patch("reviewer.scan.review_ready") as mock_rr:
                tool_list_review_ready_prs("owner/repo", transport)
                mock_rr.assert_not_called()


# ---------------------------------------------------------------------------
# 3. tool_inspect_pr – all dispositions, PR_NOT_FOUND, stale identity
# ---------------------------------------------------------------------------

class TestInspectPr:
    def _run(self, items, pr_number=1, repo="owner/repo", main_sha="aaa"):
        transport = _fake_transport()
        observed = "2025-01-01T00:00:00Z"
        with patch("reviewer.webmcp.scan", return_value=_scan_returning(items, main_sha, observed)):
            return tool_inspect_pr(repo, pr_number, transport)

    def test_review_ready_disposition(self):
        snap = _snapshot(pr_number=1)
        c = _classification(snap, Disposition.REVIEW_READY)
        result = self._run([c], pr_number=1)
        assert result["disposition"] == "REVIEW_READY"
        assert result["pr_number"] == 1
        assert result["claim_ceiling"] == "PR_INTELLIGENCE_ONLY"

    def test_stale_disposition(self):
        snap = _snapshot(pr_number=1, base_sha="old", main_sha="aaa")
        c = _classification(snap, Disposition.STALE, findings=["STALE_BASE"])
        result = self._run([c], pr_number=1)
        assert result["disposition"] == "STALE"
        assert "STALE_BASE" in result["findings"]

    def test_excluded_disposition(self):
        snap = _snapshot(pr_number=2, draft=True)
        c = _classification(snap, Disposition.EXCLUDED, findings=["DRAFT"])
        result = self._run([c], pr_number=2)
        assert result["disposition"] == "EXCLUDED"

    def test_evidence_only_disposition(self):
        snap = _snapshot(pr_number=3, do_not_merge=True)
        c = _classification(snap, Disposition.EVIDENCE_ONLY, findings=["DO_NOT_MERGE"])
        result = self._run([c], pr_number=3)
        assert result["disposition"] == "EVIDENCE_ONLY"

    def test_needs_attention_disposition(self):
        snap = _snapshot(pr_number=4, collection_complete=False, collection_errors=["timeout"])
        c = _classification(snap, Disposition.NEEDS_ATTENTION, findings=["COLLECTION_INCOMPLETE"])
        result = self._run([c], pr_number=4)
        assert result["disposition"] == "NEEDS_ATTENTION"

    def test_pr_not_found(self):
        snap = _snapshot(pr_number=1)
        c = _classification(snap)
        result = self._run([c], pr_number=99)
        assert result["error"] == "PR_NOT_FOUND"
        assert result["pr_number"] == 99
        assert result["claim_ceiling"] == "PR_INTELLIGENCE_ONLY"

    def test_stale_identity_evidence_fields_present(self):
        """head_sha/base_sha/current_main_sha must be present for identity binding."""
        snap = _snapshot(
            pr_number=1,
            source_identity="github:owner/repo:pr:1@bbb",
            declared_base_sha="aaa",
            declared_head_sha="bbb",
        )
        c = _classification(snap)
        result = self._run([c], pr_number=1)
        assert "head_sha" in result
        assert "base_sha" in result
        assert "current_main_sha" in result
        assert result["claim_ceiling"] == "PR_INTELLIGENCE_ONLY"

    def test_collection_complete_field(self):
        snap = _snapshot(pr_number=1, collection_complete=False, collection_errors=["checks: timeout"])
        c = _classification(snap, Disposition.NEEDS_ATTENTION, findings=["COLLECTION_INCOMPLETE"])
        result = self._run([c], pr_number=1)
        assert result["evidence_completeness"] == "INCOMPLETE"
        assert "checks: timeout" in result["evidence_gaps"]

    def test_invalid_repo(self):
        with pytest.raises(ValueError):
            tool_inspect_pr("bad", 1, _fake_transport())

    def test_invalid_pr_number(self):
        with pytest.raises(ValueError):
            tool_inspect_pr("owner/repo", -5, _fake_transport())


# ---------------------------------------------------------------------------
# 4. tool_inspect_ci_failure – expected vs unexpected CI, identity evidence
# ---------------------------------------------------------------------------

class TestInspectCiFailure:
    def _check(self, name, status, expected_failure=False, **kwargs):
        return CheckObservation(
            name=name,
            status=status,
            expected_failure=expected_failure,
            job_identity=kwargs.get("job_identity"),
            artifact_identity=kwargs.get("artifact_identity"),
            external_id=kwargs.get("external_id"),
            workflow_name=kwargs.get("workflow_name"),
            head_sha=kwargs.get("head_sha"),
            details_url=kwargs.get("details_url"),
            check_run_id=kwargs.get("check_run_id"),
            run_id=kwargs.get("run_id"),
        )

    def _run(self, checks, pr_number=1, repo="owner/repo"):
        snap = _snapshot(pr_number=pr_number, checks=checks)
        c = _classification(snap)
        transport = _fake_transport()
        with patch("reviewer.webmcp.scan", return_value=_scan_returning([c])):
            return tool_inspect_ci_failure(repo, pr_number, transport)

    def test_no_failures_returns_no_unexpected(self):
        result = self._run([self._check("ci/pass", "success")])
        assert result["result"] == "NO_UNEXPECTED_FAILURE"
        assert result["unexpected_terminal_failures"] == []
        assert result["claim_ceiling"] == "CI_EVIDENCE_ONLY"

    def test_expected_failure_never_reported_as_unexpected(self):
        """Expected failures MUST NOT appear in unexpected_terminal_failures."""
        checks = [
            self._check("controlled-neg-test", "failure", expected_failure=True),
            self._check("ci/lint", "success"),
        ]
        result = self._run(checks)
        assert result["result"] == "NO_UNEXPECTED_FAILURE"
        assert result["unexpected_terminal_failures"] == []

    def test_unexpected_failure_reported(self):
        checks = [
            self._check(
                "ci/build",
                "failure",
                expected_failure=False,
                job_identity="job-abc",
                artifact_identity="art-xyz",
                external_id="ext-001",
                workflow_name="CI Build",
                head_sha="bbb",
                details_url="https://github.com/owner/repo/runs/1",
                check_run_id=42,
                run_id=99,
            )
        ]
        result = self._run(checks)
        assert result["result"] == "UNEXPECTED_FAILURE_PRESENT"
        assert len(result["unexpected_terminal_failures"]) == 1
        f = result["unexpected_terminal_failures"][0]
        assert f["name"] == "ci/build"
        assert f["status"] == "failure"

    def test_identity_evidence_fields_present_in_unexpected(self):
        """All identity evidence fields must be present in output."""
        checks = [
            self._check(
                "ci/test",
                "failed",
                expected_failure=False,
                job_identity="job-123",
                artifact_identity="art-456",
                external_id="ext-789",
                workflow_name="Test Suite",
                head_sha="bbb",
                details_url="https://github.com/owner/repo/actions",
                check_run_id=10,
                run_id=20,
            )
        ]
        result = self._run(checks)
        f = result["unexpected_terminal_failures"][0]
        for field in ("name", "status", "check_run_id", "run_id", "job_identity",
                      "artifact_identity", "external_id", "workflow_name", "head_sha", "details_url"):
            assert field in f, f"Missing identity evidence field: {field}"
        assert f["job_identity"] == "job-123"
        assert f["artifact_identity"] == "art-456"
        assert f["workflow_name"] == "Test Suite"

    def test_mixed_expected_and_unexpected(self):
        checks = [
            self._check("expected-neg", "failure", expected_failure=True),
            self._check("real-fail", "error", expected_failure=False),
        ]
        result = self._run(checks)
        assert result["result"] == "UNEXPECTED_FAILURE_PRESENT"
        names = [f["name"] for f in result["unexpected_terminal_failures"]]
        assert "real-fail" in names
        assert "expected-neg" not in names

    def test_all_terminal_statuses_treated_as_unexpected(self):
        for status in ("failure", "failed", "error", "cancelled", "timed_out", "action_required"):
            checks = [self._check(f"check-{status}", status, expected_failure=False)]
            result = self._run(checks)
            assert result["result"] == "UNEXPECTED_FAILURE_PRESENT", \
                f"status={status!r} should be unexpected terminal failure"

    def test_pr_not_found(self):
        # Run with no matching PR
        snap = _snapshot(pr_number=1)
        c = _classification(snap)
        transport = _fake_transport()
        with patch("reviewer.webmcp.scan", return_value=_scan_returning([c])):
            result = tool_inspect_ci_failure("owner/repo", 999, transport)
        assert result["error"] == "PR_NOT_FOUND"
        assert result["pr_number"] == 999
        assert result["claim_ceiling"] == "CI_EVIDENCE_ONLY"

    def test_claim_ceiling_always_present(self):
        result = self._run([])
        assert result["claim_ceiling"] == "CI_EVIDENCE_ONLY"

    def test_invalid_repo(self):
        with pytest.raises(ValueError):
            tool_inspect_ci_failure("", 1, _fake_transport())

    def test_ci_failure_fingerprint_field_present(self):
        checks = [self._check("ci/test", "failure", expected_failure=False)]
        result = self._run(checks)
        assert "ci_failure_fingerprint" in result
        fp = result["ci_failure_fingerprint"]
        assert "fingerprint" in fp
        assert fp["has_unexpected_failures"] is True
        assert fp["claim_ceiling"] == "CI_EVIDENCE_ONLY"
        assert len(fp["unexpected_failures"]) == 1



# ---------------------------------------------------------------------------
# 5. Tool metadata – browser page annotations
# ---------------------------------------------------------------------------

class TestBrowserPageMetadata:
    """Verify the static HTML page encodes required tool metadata."""

    def test_register_tool_present(self):
        assert "document.modelContext.registerTool" in _BROWSER_PAGE_TEMPLATE

    def test_read_only_hint_annotation(self):
        assert "readOnlyHint: true" in _BROWSER_PAGE_TEMPLATE

    def test_untrusted_content_hint_annotation(self):
        assert "untrustedContentHint: true" in _BROWSER_PAGE_TEMPLATE

    def test_three_tools_registered(self):
        assert _BROWSER_PAGE_TEMPLATE.count("document.modelContext.registerTool({") == 3

    def test_tool_names_present(self):
        for name in ("list_review_ready_prs", "inspect_pr", "inspect_ci_failure"):
            assert f"name: '{name}'" in _BROWSER_PAGE_TEMPLATE

    def test_claim_ceiling_in_page(self):
        assert "PR_INTELLIGENCE_ONLY" in _BROWSER_PAGE_TEMPLATE
        assert "CI_EVIDENCE_ONLY" in _BROWSER_PAGE_TEMPLATE
        assert "PRE_REVIEW_ONLY" not in _BROWSER_PAGE_TEMPLATE

    def test_no_cors_wildcard_in_template(self):
        """The static template must not include a CORS wildcard."""
        assert "Access-Control-Allow-Origin" not in _BROWSER_PAGE_TEMPLATE

    def test_no_semantic_review_in_descriptions(self):
        assert "Never invokes semantic review" in _BROWSER_PAGE_TEMPLATE

    def test_exactly_three_register_tool_calls(self):
        """Exactly three document.modelContext.registerTool({ calls must be present."""
        count = _BROWSER_PAGE_TEMPLATE.count("document.modelContext.registerTool({")
        assert count == 3, (
            f"Expected exactly 3 registerTool registrations, found {count}"
        )

    def test_exactly_three_execute_callbacks(self):
        """Each of the three tool registrations must use 'execute:' (not 'invoke:')."""
        count = _BROWSER_PAGE_TEMPLATE.count("execute: async function")
        assert count == 3, (
            f"Expected exactly 3 'execute: async function' callbacks, found {count}"
        )

    def test_no_invoke_callback_remains(self):
        """No 'invoke:' callback must remain; the correct key is 'execute:'."""
        assert "invoke: async function" not in _BROWSER_PAGE_TEMPLATE, (
            "Found forbidden 'invoke: async function' – must use 'execute:' per WebMCP API"
        )


# ---------------------------------------------------------------------------
# 6. Server binding – 127.0.0.1 only, no CORS wildcard in HTTP headers
# ---------------------------------------------------------------------------

class TestServerBinding:
    def _make_server(self):
        transport = MagicMock()
        return WebMCPServer(transport=transport, port=0)

    def test_binds_to_localhost_only(self):
        server = self._make_server()
        assert server.host == "127.0.0.1"
        server.shutdown()

    def test_bind_host_constant(self):
        assert _BIND_HOST == "127.0.0.1"

    def test_port_assigned(self):
        server = self._make_server()
        assert server.port > 0
        server.shutdown()

    def test_no_cors_wildcard_header_on_json_response(self):
        """HTTP responses must not contain Access-Control-Allow-Origin: *."""
        snap = _snapshot(pr_number=1)
        c = _classification(snap)

        with patch("reviewer.webmcp.scan", return_value=_scan_returning([c])):
            transport = MagicMock()
            with WebMCPServer(transport=transport, port=0) as server:
                server.serve_in_thread()
                conn = HTTPConnection("127.0.0.1", server.port)
                body = json.dumps({"repository": "owner/repo"}).encode()
                conn.request(
                    "POST",
                    "/tool/list_review_ready_prs",
                    body=body,
                    headers={"Content-Type": "application/json"},
                )
                resp = conn.getresponse()
                resp.read()
                headers = {k.lower(): v for k, v in resp.getheaders()}
                assert "access-control-allow-origin" not in headers, \
                    "CORS wildcard header must not be present"

    def test_get_root_returns_html(self):
        transport = MagicMock()
        with WebMCPServer(transport=transport, port=0) as server:
            server.serve_in_thread()
            conn = HTTPConnection("127.0.0.1", server.port)
            conn.request("GET", "/", headers={"Host": f"127.0.0.1:{server.port}"})
            resp = conn.getresponse()
            content_type = resp.getheader("Content-Type", "")
            body = resp.read().decode()
            assert resp.status == 200
            assert "text/html" in content_type
            assert "registerTool" in body
            assert body.count("await document.modelContext.registerTool({") == 3
            assert "{{" not in body
            assert "}}" not in body

    def test_unknown_path_returns_404(self):
        transport = MagicMock()
        with WebMCPServer(transport=transport, port=0) as server:
            server.serve_in_thread()
            conn = HTTPConnection("127.0.0.1", server.port)
            conn.request("GET", "/nonexistent")
            resp = conn.getresponse()
            resp.read()
            assert resp.status == 404

    def test_invalid_json_body_returns_400(self):
        transport = MagicMock()
        with WebMCPServer(transport=transport, port=0) as server:
            server.serve_in_thread()
            conn = HTTPConnection("127.0.0.1", server.port)
            conn.request(
                "POST",
                "/tool/list_review_ready_prs",
                body=b"not-json",
                headers={"Content-Type": "application/json", "Content-Length": "8"},
            )
            resp = conn.getresponse()
            data = json.loads(resp.read())
            assert resp.status == 400
            assert data["error"] == "INVALID_JSON"

    def test_validation_error_returns_400(self):
        transport = MagicMock()
        with WebMCPServer(transport=transport, port=0) as server:
            server.serve_in_thread()
            conn = HTTPConnection("127.0.0.1", server.port)
            body = json.dumps({"repository": "bad_repo_no_slash"}).encode()
            conn.request(
                "POST",
                "/tool/list_review_ready_prs",
                body=body,
                headers={"Content-Type": "application/json"},
            )
            resp = conn.getresponse()
            data = json.loads(resp.read())
            assert resp.status == 400
            assert data["error"] == "VALIDATION_ERROR"

    def test_context_manager_shuts_down(self):
        transport = MagicMock()
        server = WebMCPServer(transport=transport, port=0)
        port = server.port
        with server:
            server.serve_in_thread()
        # After shutdown, binding the port should succeed (it was released)
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
        finally:
            s.close()


# ---------------------------------------------------------------------------
# 7. No persistence / semantic / publication side effects
# ---------------------------------------------------------------------------

class TestNoPersistenceOrSideEffects:
    def test_scan_called_with_persist_state_false_for_inspect_pr(self):
        snap = _snapshot(pr_number=1)
        c = _classification(snap)
        transport = _fake_transport()
        with patch("reviewer.webmcp.scan") as mock_scan:
            mock_scan.return_value = _scan_returning([c])
            tool_inspect_pr("owner/repo", 1, transport)
            _args, kwargs = mock_scan.call_args
            assert kwargs.get("persist_state") is False

    def test_scan_called_with_persist_state_false_for_inspect_ci_failure(self):
        snap = _snapshot(pr_number=1)
        c = _classification(snap)
        transport = _fake_transport()
        with patch("reviewer.webmcp.scan") as mock_scan:
            mock_scan.return_value = _scan_returning([c])
            tool_inspect_ci_failure("owner/repo", 1, transport)
            _args, kwargs = mock_scan.call_args
            assert kwargs.get("persist_state") is False

    def test_no_publication_attr_in_webmcp(self):
        """publication module must not be imported into webmcp namespace."""
        import reviewer.webmcp as wm
        assert not hasattr(wm, "publication")

    def test_no_opencli_attr_in_webmcp(self):
        """opencli module must not be imported into webmcp namespace."""
        import reviewer.webmcp as wm
        assert not hasattr(wm, "opencli")

    def test_no_semantic_attr_in_webmcp(self):
        """semantic module must not be imported into webmcp namespace."""
        import reviewer.webmcp as wm
        assert not hasattr(wm, "semantic")

    def test_no_terminal_failures_attr_in_webmcp(self):
        """_TERMINAL_FAILURES must not be imported or defined in webmcp namespace."""
        import reviewer.webmcp as wm
        assert not hasattr(wm, "_TERMINAL_FAILURES")


    def test_transport_create_comment_never_called(self):
        """Tool functions must never call transport.create_comment (GitHub write)."""
        snap = _snapshot(pr_number=1)
        c = _classification(snap)
        transport = _fake_transport()
        scan_rv = _scan_returning([c])
        with patch("reviewer.webmcp.scan", return_value=scan_rv):
            tool_list_review_ready_prs("owner/repo", transport)
        with patch("reviewer.webmcp.scan", return_value=scan_rv):
            tool_inspect_pr("owner/repo", 1, transport)
        with patch("reviewer.webmcp.scan", return_value=scan_rv):
            tool_inspect_ci_failure("owner/repo", 1, transport)
        transport.create_comment.assert_not_called()


# ---------------------------------------------------------------------------
# 8. Exact identity and claim ceilings in all outputs
# ---------------------------------------------------------------------------

class TestIdentityAndClaimCeiling:
    def test_claim_ceiling_constants(self):
        assert CLAIM_CEILING == "PR_INTELLIGENCE_ONLY"
        assert CI_CLAIM_CEILING == "CI_EVIDENCE_ONLY"

    def test_all_three_tools_include_claim_ceiling(self):
        snap = _snapshot(pr_number=1)
        c = _classification(snap)
        transport = _fake_transport()

        with patch("reviewer.webmcp.scan", return_value=_scan_returning([c])):
            r1 = tool_list_review_ready_prs("owner/repo", transport)
        with patch("reviewer.webmcp.scan", return_value=_scan_returning([c])):
            r2 = tool_inspect_pr("owner/repo", 1, transport)
        with patch("reviewer.webmcp.scan", return_value=_scan_returning([c])):
            r3 = tool_inspect_ci_failure("owner/repo", 1, transport)

        assert r1.get("claim_ceiling") == "PR_INTELLIGENCE_ONLY"
        assert r2.get("claim_ceiling") == "PR_INTELLIGENCE_ONLY"
        assert r3.get("claim_ceiling") == "CI_EVIDENCE_ONLY"

    def test_not_found_includes_claim_ceiling(self):
        transport = _fake_transport()
        with patch("reviewer.webmcp.scan", return_value=_scan_returning([])):
            r = tool_inspect_pr("owner/repo", 99, transport)
        assert r["claim_ceiling"] == "PR_INTELLIGENCE_ONLY"

        with patch("reviewer.webmcp.scan", return_value=_scan_returning([])):
            r_ci = tool_inspect_ci_failure("owner/repo", 99, transport)
        assert r_ci["claim_ceiling"] == "CI_EVIDENCE_ONLY"

    def test_list_prs_each_entry_has_claim_ceiling(self):
        snaps = [_snapshot(pr_number=i, changed_files=[f"f{i}.py"]) for i in range(1, 4)]
        items = [_classification(s) for s in snaps]
        transport = _fake_transport()
        with patch("reviewer.webmcp.scan", return_value=_scan_returning(items)):
            result = tool_list_review_ready_prs("owner/repo", transport)
        for pr in result["review_ready_prs"]:
            assert pr["claim_ceiling"] == "PR_INTELLIGENCE_ONLY"
