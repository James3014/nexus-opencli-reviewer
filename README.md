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

## Architectural Layers

The V1 architecture is structured as a unidirectional pipeline with strict layer boundaries:

**Raw GitHub / Collection Transport**
`reviewer.github`, `reviewer.collector`, `reviewer.normalize` collect untrusted physical PR and CI state from GitHub without interpreting review readiness or applying business rules.

**Repository Intelligence Core V1 (Canonical Product)**
`reviewer.intelligence` is the pure, deterministic, transport-neutral advisory facade. Its V1 public surface exposes four core operations (`revision_identity`, `classify_readiness`, `analyze_cross_pr_overlap`, and `fingerprint_ci_failures`) plus hash-bound repository-report helpers. It contains zero network calls, zero state mutation, and zero LLM invocations. Nexus governance policies (merge rights, authority grants, lifecycle state promotions) remain strictly out of core.

**V1 Adapters & Consumers**
- **Structured Local CLI (`reviewer.intelligence_cli`)**: Pure local JSON adapter executing core operations on fixture snapshots or stdin without network/state dependencies.
- **WebMCP Browser Adapter (`reviewer.webmcp`)**: Localhost HTTP adapter exposing three Site tools (`list_review_ready_prs`, `inspect_pr`, `inspect_ci_failure`) to WebMCP-capable browsers. Note: any WebMCP native Chat projection compatibility gap is an adapter/browser transport detail and does not affect core correctness.
- **Legacy / Application Workflow**: `reviewer.scan`, `reviewer.service`, and `reviewer.cli` remain application consumers.

**Optional Semantic Review & Publication**
`reviewer.semantic`, `reviewer.opencli`, and `reviewer.publication` handle optional LLM review dispatch and one-time advisory comment publication under the strict `PRE_REVIEW_ONLY` claim ceiling.

```
┌─────────────────────────────────────────────────────────────┐
│                 Raw GitHub / Collection                     │
│  (reviewer.github, reviewer.collector, reviewer.normalize)   │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│               Repository Intelligence Core V1               │
│                   (reviewer.intelligence)                   │
│                                                             │
│  - revision_identity: Deterministic PR revision tracking    │
│  - classify_readiness: Advisory readiness classification    │
│  - analyze_cross_pr_overlap: Peer conflict / WAIT_REBIND    │
│  - fingerprint_ci_failures: Hash-bound CI failure evidence  │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                        V1 Adapters                          │
│                                                             │
│  - Local CLI Adapter (reviewer.intelligence_cli)            │
│  - WebMCP Browser Adapter (reviewer.webmcp)                 │
│  - Application / Scan Consumer (reviewer.scan, cli)         │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 Optional Semantic Review                    │
│  (reviewer.semantic, reviewer.opencli, reviewer.publication)│
└─────────────────────────────────────────────────────────────┘
```

### Adapter Strategy — G7 Frozen
- **Canonical product**: `reviewer.intelligence` Python Core API. Adapters acquire/transport/serialize evidence; they do not own or reimplement intelligence decisions.
- **V1 adapters**: (1) structured local CLI (`reviewer.intelligence_cli`) as the reference JSON adapter, and (2) WebMCP (`reviewer.webmcp`) as the browser-facing compatibility adapter. WebMCP uses the legacy scan path only to acquire snapshots, then recomputes PR decisions through the canonical Core.
- **Next adapter**: a direct MCP adapter is the highest-priority post-V1 adapter because it can expose the same Core operations directly to agent/controller surfaces without requiring a browser page. It is not a V1 completion blocker.
- **Deferred adapter**: GitHub Action / unattended Repository Intelligence publication is deferred until operational-reliability behavior is closed.
- **Claim ceilings**: PR intelligence output is bounded by `PR_INTELLIGENCE_ONLY`; CI failure evidence is bounded by `CI_EVIDENCE_ONLY`. The semantic reviewer/publication workflow remains a separate product surface with its existing `PRE_REVIEW_ONLY` ceiling.
- **WebMCP compatibility**: native ChatGPT Site-tool projection remains a separately tracked OpenAI Desktop compatibility concern; Browser WebMCP support is not promoted into proof of native-chat projection and the compatibility gap does not block Core/V1.
- **Change Impact**: deferred to V1.1 and excluded from the V1 Candidate tree, public Core surface, and CLI.

### Productization Boundary — G10 Frozen
- **V1 repository decision**: `KEEP_IN_CURRENT_REPOSITORY_FOR_V1`. Repository Intelligence Core V1 remains inside `nexus-opencli-reviewer` for the V1 release rather than creating a second repository/package authority during stabilization.
- **Package authority**: `reviewer.intelligence` is the canonical deterministic Core; `reviewer.intelligence_cli` and `reviewer.webmcp` are adapters; `reviewer.semantic`, `reviewer.opencli`, and `reviewer.publication` remain separate semantic/application surfaces.
- **Legacy compatibility seam**: `reviewer.scan` remains a brownfield application/acquisition consumer. Adapters may reuse it for acquisition, but its legacy classification is not canonical Repository Intelligence authority.
- **Extraction timing**: `DEFER_REPO_EXTRACTION_TO_POST_V1`. A dedicated `repository-intelligence` repository/package may be reconsidered after V1 acceptance and post-merge verification, when migration can be evaluated against an immutable accepted surface.
- **No V1 expansion**: direct MCP, GitHub Action publication, Change Impact, CFI/EIA, and semantic-reviewer redesign remain outside V1 productization.

## Repository Intelligence Core V1 Operations

The `reviewer.intelligence` package exposes four deterministic, immutable V1 advisory operations:

1. **`revision_identity(snapshot)`**: Deterministic repository revision identity with stale base (`base_sha != current_main_sha`) and declared evidence mismatch detection.
2. **`classify_readiness(snapshot, policy=...)`**: Immutable advisory readiness classification (`REVIEW_READY`, `WAIT_REBIND`, `NEEDS_ATTENTION`, `EVIDENCE_ONLY`, `STALE`, `EXCLUDED`) over normalized structured evidence. Generic protected-path policy defaults empty and may be explicitly injected by a consumer.
3. **`analyze_cross_pr_overlap(snapshots, policy=...)`**: Deterministic cross-PR path overlap and shared issue chain analysis, applying `WAIT_REBIND` only between originally eligible peers.
4. **`fingerprint_ci_failures(snapshot or ...)`**: Hash-bound CI failure evidence distinguishing expected vs unexpected terminal failures, retaining exact identity/evidence gaps and the `CI_EVIDENCE_ONLY` ceiling.

`build_repository_intelligence_report(...)` produces the canonical `reviewer.repository_intelligence.v1` report with `COMPLETE | PARTIAL | INCOMPLETE` evidence state and a tamper-detectable `content_sha256`.

## Structured Local CLI Adapter (`reviewer.intelligence_cli`)

Run pure local core operations over JSON files or stdin:

```bash
# Revision identity
python -m reviewer.intelligence_cli --operation revision --input snapshot.json

# Readiness classification
python -m reviewer.intelligence_cli --operation readiness --input snapshot.json

# Cross-PR overlap
python -m reviewer.intelligence_cli --operation overlap --input overlap_snapshots.json

# CI failure fingerprinting
python -m reviewer.intelligence_cli --operation ci --input snapshot.json

# Read from stdin
cat snapshot.json | python -m reviewer.intelligence_cli --operation readiness --input -
```

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

## WebMCP PR Intelligence Pilot (WEBMCP_PR_INTELLIGENCE_PILOT_V1)

A read-only, localhost-only HTTP server that exposes three advisory tools to any
WebMCP-capable browser session via `document.modelContext.registerTool`.

**Claim ceilings:** PR intelligence outputs are bounded by `PR_INTELLIGENCE_ONLY`; CI failure evidence is bounded by `CI_EVIDENCE_ONLY`. No semantic review, OpenCLI invocation,
GitHub write, publication, or Nexus lifecycle action is ever performed. All tool
outputs are advisory and explicitly marked with the appropriate boundary.

### Start the pilot

```bash
python -m reviewer.webmcp          # random port
python -m reviewer.webmcp 8765     # fixed port
```

The server prints its URL (`http://127.0.0.1:<port>/`) and binds exclusively to
`127.0.0.1`. Open the URL in a WebMCP-enabled browser; the page registers the
three tools automatically.

### Tools

| Tool | Description |
|---|---|
| `list_review_ready_prs` | List PRs whose deterministic classification is `REVIEW_READY` for a `owner/name` repository. |
| `inspect_pr` | Return the current classification (any disposition) for a specific PR number. Missing PR → structured `PR_NOT_FOUND` error. |
| `inspect_ci_failure` | Return unexpected terminal CI failure evidence from scan data. Expected failures are **never** reported as unexpected. No failure → `NO_UNEXPECTED_FAILURE`. |

All tools carry `readOnlyHint: true` and `untrustedContentHint: true` annotations.
Repository and PR content surfaced by these tools is untrusted advisory input
collected from GitHub via the reviewer scan substrate.

### Claim boundary

- **Does**: read open PRs, classify deterministically, surface CI failure evidence.
- **Does not**: approve PRs, request changes, merge, invoke ChatGPT/OpenCLI,
  publish GitHub comments, write state, or perform any Nexus lifecycle action.
- PR intelligence outputs include `"claim_ceiling": "PR_INTELLIGENCE_ONLY"`; CI failure evidence outputs include `"claim_ceiling": "CI_EVIDENCE_ONLY"`.

