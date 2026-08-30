"""WebMCP browser adapter over Repository Intelligence Core V1.

Exposes three Site tools via the WebMCP Imperative API (document.modelContext):
  • list_review_ready_prs(repository)
  • inspect_pr(repository, pr_number)
  • inspect_ci_failure(repository, pr_number)

All tools are advisory / read-only. The server binds to 127.0.0.1 only and
never invokes semantic review, OpenCLI, publication, write GitHub APIs, or
persistence. PR tools are bounded by PR_INTELLIGENCE_ONLY; CI evidence is
bounded by CI_EVIDENCE_ONLY.
"""

from __future__ import annotations

import html
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from .github import REPO_RE, GhCliTransport
from repository_intelligence import (
    CLAIM_CEILING as PR_CLAIM_CEILING,
    CI_EVIDENCE_CLAIM_CEILING as CI_CLAIM_CEILING,
    build_repository_intelligence_report,
    fingerprint_ci_failures,
)
from .scan import scan

CLAIM_CEILING = PR_CLAIM_CEILING
_BIND_HOST = "127.0.0.1"


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _validate_repo(repository: Any) -> str:
    """Validate and return repository as 'owner/name'; raise ValueError otherwise."""
    if not isinstance(repository, str) or not REPO_RE.fullmatch(repository):
        raise ValueError(
            f"repository must be owner/name (letters, digits, '_', '.', '-'): "
            f"got {repository!r}"
        )
    return repository


def _validate_pr_number(pr_number: Any) -> int:
    """Validate and return pr_number as a positive int; raise ValueError otherwise."""
    if isinstance(pr_number, float) and not pr_number.is_integer():
        raise ValueError(f"pr_number must be a positive integer, got {pr_number!r}")
    try:
        n = int(pr_number)
    except (TypeError, ValueError):
        raise ValueError(f"pr_number must be a positive integer, got {pr_number!r}")
    if n <= 0:
        raise ValueError(f"pr_number must be positive, got {n!r}")
    return n


# ---------------------------------------------------------------------------
# Tool implementations (pure functions – no I/O side effects beyond GitHub reads)
# ---------------------------------------------------------------------------

def _acquire_snapshots(repository: str, transport: Any) -> tuple[str, str, list[Any]]:
    """Use legacy scan only for read-only acquisition; discard its decisions.

    Rebind ``main`` after acquisition. If main advanced while PR/files/checks were
    being collected, the snapshot set is stale as a unit and must fail closed
    instead of being exposed as a complete current report.
    """
    main_sha, observed, items, _queue = scan(repository, transport, persist_state=False)
    try:
        rebound = transport.get_ref(repository, "main")
        rebound_sha = (rebound.get("object") or {}).get("sha") if isinstance(rebound, dict) else None
    except Exception as exc:
        raise RuntimeError("MAIN_REBIND_UNAVAILABLE") from exc
    if not rebound_sha:
        raise RuntimeError("MAIN_REBIND_UNAVAILABLE")
    if rebound_sha != main_sha:
        raise RuntimeError("MAIN_CHANGED_DURING_ACQUISITION")
    return main_sha, observed, [item.snapshot for item in items]


def _core_report(repository: str, transport: Any):
    main_sha, observed, snapshots = _acquire_snapshots(repository, transport)
    report = build_repository_intelligence_report(snapshots)
    return main_sha, observed, snapshots, report


def tool_list_review_ready_prs(repository: str, transport: Any) -> dict:
    """Return PRs that canonical Core V1 classifies as review-ready."""
    _validate_repo(repository)
    main_sha, observed, _snapshots, report = _core_report(repository, transport)
    ready = []
    for item in report.items:
        if not item.is_review_ready:
            continue
        ready.append({
            "repository": item.identity.repository,
            "pr_number": item.identity.pr_number,
            "base_sha": item.identity.base_sha,
            "head_sha": item.identity.head_sha,
            "current_main_sha": item.identity.current_main_sha,
            "observed_at": observed,
            "disposition": item.disposition.value,
            "findings": list(item.findings),
            "reasons": list(item.reasons),
            "evidence_completeness": item.evidence_completeness.value,
            "evidence_gaps": list(item.evidence_gaps),
            "claim_ceiling": PR_CLAIM_CEILING,
        })
    return {
        "repository": repository,
        "current_main_sha": main_sha,
        "observed_at": observed,
        "review_ready_prs": ready,
        "evidence_completeness": report.evidence_completeness.value,
        "evidence_gaps": list(report.evidence_gaps),
        "content_sha256": report.content_sha256,
        "claim_ceiling": PR_CLAIM_CEILING,
    }


def tool_inspect_pr(repository: str, pr_number: Any, transport: Any) -> dict:
    """Return canonical Core V1 classification for one currently open PR."""
    _validate_repo(repository)
    n = _validate_pr_number(pr_number)
    main_sha, observed, _snapshots, report = _core_report(repository, transport)
    selected = next((item for item in report.items if item.identity.pr_number == n), None)
    if selected is None:
        return {
            "error": "PR_NOT_FOUND",
            "repository": repository,
            "pr_number": n,
            "current_main_sha": main_sha,
            "observed_at": observed,
            "claim_ceiling": PR_CLAIM_CEILING,
        }
    return {
        "repository": selected.identity.repository,
        "pr_number": selected.identity.pr_number,
        "base_sha": selected.identity.base_sha,
        "head_sha": selected.identity.head_sha,
        "current_main_sha": selected.identity.current_main_sha,
        "observed_at": observed,
        "disposition": selected.disposition.value,
        "findings": list(selected.findings),
        "reasons": list(selected.reasons),
        "risk": selected.risk,
        "overlaps": {k: list(v) for k, v in selected.overlaps.items()},
        "evidence_completeness": selected.evidence_completeness.value,
        "evidence_gaps": list(selected.evidence_gaps),
        "claim_ceiling": PR_CLAIM_CEILING,
    }


def tool_inspect_ci_failure(repository: str, pr_number: Any, transport: Any) -> dict:
    """Return unexpected terminal CI failure evidence already present in scan data.

    Expected failures are NEVER reported as unexpected.  If no unexpected
    terminal failure exists, returns a structured no-unexpected-failure result.
    Missing PR fails closed with a structured error.
    """
    _validate_repo(repository)
    n = _validate_pr_number(pr_number)
    main_sha, observed, snapshots = _acquire_snapshots(repository, transport)
    selected = next((snapshot for snapshot in snapshots if snapshot.pr_number == n), None)
    if selected is None:
        return {
            "error": "PR_NOT_FOUND",
            "repository": repository,
            "pr_number": n,
            "current_main_sha": main_sha,
            "observed_at": observed,
            "claim_ceiling": CI_CLAIM_CEILING,
        }
    s = selected
    fp = fingerprint_ci_failures(s)
    # Only unexpected terminal failures – derived from canonical core fingerprint.
    unexpected = [
        {
            "name": c.name,
            "status": c.status,
            "check_run_id": c.check_run_id,
            "run_id": c.run_id,
            "job_identity": c.job_identity,
            "artifact_identity": c.artifact_identity,
            "external_id": c.external_id,
            "workflow_name": c.workflow_name,
            "head_sha": c.head_sha,
            "details_url": c.details_url,
        }
        for c in fp.unexpected_failures
    ]
    base = {
        "repository": s.repository,
        "pr_number": s.pr_number,
        "base_sha": s.base_sha,
        "head_sha": s.head_sha,
        "current_main_sha": s.current_main_sha,
        "observed_at": s.observed_at,
        "collection_complete": s.collection_complete,
        "collection_errors": list(s.collection_errors),
        "ci_failure_fingerprint": fp.to_dict(),
        "claim_ceiling": CI_CLAIM_CEILING,
    }
    if not unexpected:
        base["unexpected_terminal_failures"] = []
        base["result"] = "NO_UNEXPECTED_FAILURE"
        return base
    base["unexpected_terminal_failures"] = unexpected
    base["result"] = "UNEXPECTED_FAILURE_PRESENT"
    return base


# ---------------------------------------------------------------------------
# Browser page (WebMCP Imperative API – document.modelContext.registerTool)
# ---------------------------------------------------------------------------

_BROWSER_PAGE_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PR Intelligence Pilot – WebMCP</title>
</head>
<body>
<h1>PR Intelligence Pilot – WebMCP (read-only, advisory)</h1>
<p>
  <strong>Claim ceilings: PR_INTELLIGENCE_ONLY for PR intelligence; CI_EVIDENCE_ONLY for CI evidence.</strong>
  Repository and PR content surfaced by these tools is untrusted advisory input
  collected from GitHub via the reviewer acquisition substrate. No write, publish,
  semantic-review, or lifecycle action is performed.
</p>
<p id="status">Registering tools…</p>
<script>
(async function () {
  if (!document.modelContext || typeof document.modelContext.registerTool !== 'function') {
    document.getElementById('status').textContent =
      'WebMCP not available (document.modelContext.registerTool absent).';
    return;
  }

  const BASE_URL = {base_url!s};

  async function callTool(path, params) {
    const resp = await fetch(BASE_URL + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error('HTTP ' + resp.status + ': ' + text);
    }
    return resp.json();
  }

  try {
    await document.modelContext.registerTool({{
      name: 'list_review_ready_prs',
      description: (
        'List currently open pull requests whose deterministic classification is ' +
        'REVIEW_READY for the given GitHub repository. ' +
        'Advisory read-only tool. Repository and PR content is untrusted advisory ' +
        'input sourced from GitHub. Claim ceiling: PR_INTELLIGENCE_ONLY. ' +
        'Never invokes semantic review, OpenCLI, write GitHub APIs, publication, ' +
        'or Nexus lifecycle actions.'
      ),
      annotations: {{ readOnlyHint: true, untrustedContentHint: true }},
      inputSchema: {{
        type: 'object',
        properties: {{
          repository: {{
            type: 'string',
            description: 'GitHub repository as owner/name (e.g. "acme/myrepo"). Untrusted advisory input.',
          }},
        }},
        required: ['repository'],
      }},
      execute: async function (params) {{
        const result = await callTool('/tool/list_review_ready_prs', params);
        return JSON.stringify(result, null, 2);
      }},
    }});

    await document.modelContext.registerTool({{
      name: 'inspect_pr',
      description: (
        'Return the current deterministic classification for a specific open PR ' +
        '(any disposition: REVIEW_READY, STALE, EXCLUDED, EVIDENCE_ONLY, NEEDS_ATTENTION). ' +
        'Advisory read-only tool. Repository and PR content is untrusted advisory ' +
        'input sourced from GitHub. Missing PR fails closed with a structured error. ' +
        'Claim ceiling: PR_INTELLIGENCE_ONLY. ' +
        'Never invokes semantic review, OpenCLI, write GitHub APIs, publication, ' +
        'or Nexus lifecycle actions.'
      ),
      annotations: {{ readOnlyHint: true, untrustedContentHint: true }},
      inputSchema: {{
        type: 'object',
        properties: {{
          repository: {{
            type: 'string',
            description: 'GitHub repository as owner/name. Untrusted advisory input.',
          }},
          pr_number: {{
            type: 'integer',
            description: 'Pull request number (positive integer).',
            minimum: 1,
          }},
        }},
        required: ['repository', 'pr_number'],
      }},
      execute: async function (params) {{
        const result = await callTool('/tool/inspect_pr', params);
        return JSON.stringify(result, null, 2);
      }},
    }});

    await document.modelContext.registerTool({{
      name: 'inspect_ci_failure',
      description: (
        'Return unexpected terminal CI failure evidence already present in the PR ' +
        "scan data. Expected failures are NEVER reported as unexpected. " +
        'Returns a structured no-unexpected-failure result if none exist. ' +
        'Advisory read-only tool. Repository and PR content is untrusted advisory ' +
        'input sourced from GitHub. Missing PR fails closed. ' +
        'Claim ceiling: CI_EVIDENCE_ONLY. ' +
        'Never invokes semantic review, OpenCLI, write GitHub APIs, publication, ' +
        'or Nexus lifecycle actions.'
      ),
      annotations: {{ readOnlyHint: true, untrustedContentHint: true }},
      inputSchema: {{
        type: 'object',
        properties: {{
          repository: {{
            type: 'string',
            description: 'GitHub repository as owner/name. Untrusted advisory input.',
          }},
          pr_number: {{
            type: 'integer',
            description: 'Pull request number (positive integer).',
            minimum: 1,
          }},
        }},
        required: ['repository', 'pr_number'],
      }},
      execute: async function (params) {{
        const result = await callTool('/tool/inspect_ci_failure', params);
        return JSON.stringify(result, null, 2);
      }},
    }});

    document.getElementById('status').textContent =
      'Tools registered: list_review_ready_prs, inspect_pr, inspect_ci_failure.';
  }} catch (err) {{
    document.getElementById('status').textContent =
      'Tool registration failed: ' + String(err).slice(0, 200);
  }}
}());
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    """Minimal HTTP handler for the WebMCP pilot."""

    # Injected by WebMCPServer
    transport: Any = None

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass  # suppress default stderr logging

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # No CORS wildcard header.
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status: int, body: str) -> None:
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def _read_json_body(self) -> dict | None:
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0:
            return {}
        raw = self.rfile.read(min(length, 65536))
        try:
            return json.loads(raw.decode())
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None

    # noinspection PyPep8Naming
    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/index.html"):
            host = self.headers.get("Host", "")
            base_url = f"http://{html.escape(host)}"
            page = (
                _BROWSER_PAGE_TEMPLATE
                .replace("{base_url!s}", json.dumps(base_url))
                .replace("{{", "{")
                .replace("}}", "}")
            )
            self._send_html(200, page)
        else:
            self._send_json(404, {"error": "NOT_FOUND"})

    # noinspection PyPep8Naming
    def do_POST(self) -> None:  # noqa: N802
        body = self._read_json_body()
        if body is None:
            self._send_json(400, {"error": "INVALID_JSON"})
            return

        transport = type(self).transport
        path = self.path

        try:
            if path == "/tool/list_review_ready_prs":
                result = tool_list_review_ready_prs(
                    repository=body.get("repository"),
                    transport=transport,
                )
            elif path == "/tool/inspect_pr":
                result = tool_inspect_pr(
                    repository=body.get("repository"),
                    pr_number=body.get("pr_number"),
                    transport=transport,
                )
            elif path == "/tool/inspect_ci_failure":
                result = tool_inspect_ci_failure(
                    repository=body.get("repository"),
                    pr_number=body.get("pr_number"),
                    transport=transport,
                )
            else:
                self._send_json(404, {"error": "NOT_FOUND"})
                return
        except ValueError as exc:
            self._send_json(400, {"error": "VALIDATION_ERROR", "detail": str(exc)})
            return
        except Exception as exc:
            self._send_json(500, {"error": "INTERNAL_ERROR", "detail": str(exc)})
            return

        self._send_json(200, result)


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

class WebMCPServer:
    """Localhost-only WebMCP pilot server.

    Binds to 127.0.0.1 only; no CORS wildcard; read-only transport calls.
    """

    def __init__(self, transport: Any, port: int = 0) -> None:
        self._transport = transport
        # Build a per-instance handler class that captures the transport.
        handler = type(
            "_BoundHandler",
            (_Handler,),
            {"transport": transport},
        )
        self._server = HTTPServer((_BIND_HOST, port), handler)
        self._started = False  # True once serve_forever / serve_in_thread is called

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def host(self) -> str:
        return self._server.server_address[0]

    def serve_forever(self) -> None:
        self._started = True
        self._server.serve_forever()

    def serve_in_thread(self) -> threading.Thread:
        self._started = True
        thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        thread.start()
        return thread

    def shutdown(self) -> None:
        """Stop the server and release its socket.

        Safe to call even if serve_forever() was never started.  When started,
        shutdown() signals the serve_forever loop to exit before closing the
        socket; when not started, only server_close() is called so the bound
        port is released without blocking.
        """
        if self._started:
            self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> "WebMCPServer":
        return self

    def __exit__(self, *_: Any) -> None:
        self.shutdown()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _main() -> None:
    import sys

    port = 0
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"usage: python -m reviewer.webmcp [port]", file=sys.stderr)
            sys.exit(1)

    transport = GhCliTransport()
    server = WebMCPServer(transport=transport, port=port)
    print(
        f"WebMCP pilot listening on http://{server.host}:{server.port}/ "
        f"(127.0.0.1 only, read-only, PR_INTELLIGENCE_ONLY / CI_EVIDENCE_ONLY)",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()


if __name__ == "__main__":
    _main()
