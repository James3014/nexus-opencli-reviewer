# Nexus OpenCLI Reviewer Sidecar V1

Local advisory reviewer for GitHub pull requests. It collects physical PR state,
classifies deterministic eligibility, builds a SHA-bound semantic context, invokes
ChatGPT through OpenCLI, persists crash-safe attempt and PRE_REVIEW evidence, and
can publish one idempotent GitHub issue comment after a fresh identity rebind.

The Sidecar never approves, requests changes, merges, accepts a Candidate, or
changes Nexus lifecycle state. Its maximum claim is `PRE_REVIEW_ONLY`; published
results are explicitly marked automated and advisory.

Runtime state is stored below `.reviewer-state/` and is intentionally ignored by
Git. Use `python -m reviewer.cli --help` for scan, review, status, reconciliation,
and publication operations.

## Unattended service configuration

The service configuration is a local JSON file at
`~/.config/nexus-opencli-reviewer/config.json` (or a path supplied to the
service command). It is optional: safe defaults watch `James3014/Nexus-new`,
poll every 60 seconds, publish advisory comments, serialize semantic work at
concurrency `1`, and use a `new_only` bootstrap policy so installation cannot
create a historical review storm. State and logs default to
`~/.local/state/nexus-opencli-reviewer/`.

Example:

```json
{
  "repositories": ["James3014/Nexus-new"],
  "poll_interval_seconds": 60,
  "publication_enabled": true,
  "semantic_concurrency": 1,
  "bootstrap": {"mode": "new_only", "max_reviews": 0},
  "state_root": "/Users/you/.local/state/nexus-opencli-reviewer",
  "log_path": "/Users/you/.local/state/nexus-opencli-reviewer/reviewer.log"
}
```

Configuration is validated before a service starts. Repository values must be
`owner/name`, poll intervals are bounded to 5 seconds–24 hours, paths must be
absolute local paths, and semantic concurrency is fixed at one. The config
contains no GitHub credentials, cookies, prompts, or browser profile data.

Normal operation is unattended: keep the Mac user session and the logged-in
Chrome/OpenCLI Browser Bridge available; the service discovers eligible PRs,
reviews each exact identity once, publishes one advisory comment, and resumes
after temporary transport outages. No PR number is required.

```bash
/opt/homebrew/bin/python3 -m reviewer.service_cli status --json
/opt/homebrew/bin/python3 -m reviewer.service_cli start
/opt/homebrew/bin/python3 -m reviewer.service_cli stop
/opt/homebrew/bin/python3 -m reviewer.service_cli restart
/opt/homebrew/bin/python3 -m reviewer.service_cli logs --json
/opt/homebrew/bin/python3 -m reviewer.service_cli reconcile --json
```

`status` answers whether the LaunchAgent is running and exposes each repository's
last/next scan, queue depth, blocked identities, and exact durable state. If the
Browser Bridge requires a human reconnection, reconnect the extension; the
service remains degraded and retries read-only preflight on later polls.
