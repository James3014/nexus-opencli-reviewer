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

**Repository Intelligence Core V1/V1.1 (Extracted Canonical Product)**
`repository_intelligence` is the canonical pure, deterministic, transport-neutral advisory package. The local `reviewer.intelligence` package is a forwarding-only compatibility shim and owns no intelligence decisions. The extracted package contains zero network calls, zero state mutation, and zero LLM invocations. Nexus governance policies (merge rights, authority grants, lifecycle state promotions) remain strictly out of core.

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
│            Repository Intelligence Core V1/V1.1             │
│                 (repository_intelligence)                   │
│                                                             │
│  - revision_identity: Deterministic PR revision tracking    │
│  - classify_readiness: Advisory readiness classification    │
│  - analyze_cross_pr_overlap: Peer conflict / WAIT_REBIND    │
│  - fingerprint_ci_failures: Hash-bound CI failure evidence  │
│  - analyze_change_impact: V1.1 graph-bound blast radius      │
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
- **Canonical product**: `repository_intelligence` Python package. Adapters acquire/transport/serialize evidence; they do not own or reimplement intelligence decisions.
- **V1 adapters**: (1) structured local CLI (`reviewer.intelligence_cli`) as the reference JSON adapter, and (2) WebMCP (`reviewer.webmcp`) as the browser-facing compatibility adapter. WebMCP uses the legacy scan path only to acquire snapshots, then recomputes PR decisions through the canonical Core.
- **Next adapter**: a direct MCP adapter is the highest-priority post-V1 adapter because it can expose the same Core operations directly to agent/controller surfaces without requiring a browser page. It is not a V1 completion blocker.
- **GitHub Action / cloud adapter (N4)**: implemented as a read-only acquisition/transport surface. It reads PR metadata, changed-file names, default-branch identity, and check-run evidence through GitHub REST, never checks out or executes PR code, and emits only a hash-bound advisory bundle plus Step Summary/outputs.
- **Claim ceilings**: PR intelligence output is bounded by `PR_INTELLIGENCE_ONLY`; CI failure evidence is bounded by `CI_EVIDENCE_ONLY`. The semantic reviewer/publication workflow remains a separate product surface with its existing `PRE_REVIEW_ONLY` ceiling.
- **WebMCP compatibility**: native ChatGPT Site-tool projection remains a separately tracked OpenAI Desktop compatibility concern; Browser WebMCP support is not promoted into proof of native-chat projection and the compatibility gap does not block Core/V1.
- **Change Impact V1.1**: implemented as language-neutral normalized dependency-graph evidence. `repository_intelligence` owns deterministic direct/transitive closure and tamper-bound reporting; language parsers, GitNexus, or other CodeIntel systems remain upstream graph producers rather than Core authority.
- **CFI V1.1**: CI Failure Intelligence classifies exact hash-bound CI evidence as `NO_TERMINAL_FAILURE | EXPECTED_FAILURE_ONLY | UNEXPECTED_FAILURE_OBSERVED | INSUFFICIENT_EVIDENCE`. `diagnosis_eligible=true` means only that complete unexpected-failure evidence exists; it does not claim root cause, regression attribution, repair correctness, or merge readiness.
- **EIA V1.1**: External Intelligence Automation emits only `READY | NO_ACTION | BLOCKED` with a deterministic idempotency key. `READY` is bounded to considering `CI_FAILURE_DIAGNOSIS` from current complete evidence under `AUTOMATION_ADVISORY_ONLY`; it grants no worker, comment, approval, merge, or repository-write authority.

### Extraction Boundary — E9 Closed
- **Package authority**: `repository_intelligence` is the only canonical deterministic Core and CLI package. `reviewer.intelligence`, `reviewer.intelligence_cli`, and the legacy primitive modules are forwarding-only compatibility shims.
- **Consumers**: WebMCP, the GitHub Action, and Dev MCP invoke the extracted package; `reviewer.scan` remains only a brownfield acquisition/application consumer.
- **Legacy cleanup**: duplicate classifier, models, overlap, readiness, CI, Change Impact, CFI, and EIA implementations have been removed from this repository. Compatibility modules contain imports only.
- **Authority ceiling**: Repository Intelligence remains advisory. It has no comment, approval, merge, release, publication, worker-dispatch, or production authority.
- **Publication**: an independent GitHub remote for `repository-intelligence-engine` remains a parked operational item and is not an extraction correctness gate; immutable source, vendored artifact, and exact-head runtime binding remain authoritative evidence.

## Extracted Repository Intelligence Operations

The canonical `repository_intelligence` package exposes the four accepted V1 operations plus three deterministic V1.1 advisory operations. `reviewer.intelligence` forwards this surface for compatibility:

1. **`revision_identity(snapshot)`**: Deterministic repository revision identity with stale base (`base_sha != current_main_sha`) and declared evidence mismatch detection.
2. **`classify_readiness(snapshot, policy=...)`**: Immutable advisory readiness classification (`REVIEW_READY`, `WAIT_REBIND`, `NEEDS_ATTENTION`, `EVIDENCE_ONLY`, `STALE`, `EXCLUDED`) over normalized structured evidence. Generic protected-path policy defaults empty and may be explicitly injected by a consumer.
3. **`analyze_cross_pr_overlap(snapshots, policy=...)`**: Deterministic cross-PR path overlap and shared issue chain analysis, applying `WAIT_REBIND` only between originally eligible peers.
4. **`fingerprint_ci_failures(snapshot or ...)`**: Hash-bound CI failure evidence distinguishing expected vs unexpected terminal failures, retaining exact identity/evidence gaps and the `CI_EVIDENCE_ONLY` ceiling.
5. **`analyze_change_impact(graph_evidence)`**: Language-neutral downstream blast-radius analysis over normalized `covered_files` plus `consumer -> dependency` edges. It binds the exact PR revision identity, records graph completeness/errors, computes deterministic direct/transitive impacted files, and emits `reviewer.change_impact.v1` with `PR_INTELLIGENCE_ONLY`. Optional `observed_symbols` are upstream observations only; Core does not claim they are modified symbols.
6. **`analyze_ci_failure_intelligence(snapshot)`**: Deterministic triage over the existing hash-bound CI evidence. It distinguishes expected, unexpected, absent, and incomplete failure evidence under `CI_EVIDENCE_ONLY`, without inferring root cause or regression attribution.
7. **`plan_external_intelligence_automation(snapshot|cfi_report)`**: Deterministic automation advisory. It emits `READY` only for current, non-stale, complete unexpected CI failure evidence; stale or incomplete evidence fails closed to `BLOCKED`. Claim ceiling: `AUTOMATION_ADVISORY_ONLY`.

`build_repository_intelligence_report(...)` produces the canonical `reviewer.repository_intelligence.v1` report with `COMPLETE | PARTIAL | INCOMPLETE` evidence state and a tamper-detectable `content_sha256`.

## Canonical CLI and Legacy Compatibility

The canonical command is `python -m repository_intelligence.cli`. The historical
`python -m reviewer.intelligence_cli` entrypoint forwards to the same function
objects and remains available for existing callers. Run pure local operations
over JSON files or stdin:

```bash
# Revision identity
python -m repository_intelligence.cli --operation revision --input snapshot.json

# Readiness classification
python -m repository_intelligence.cli --operation readiness --input snapshot.json

# Cross-PR overlap
python -m repository_intelligence.cli --operation overlap --input overlap_snapshots.json

# CI failure fingerprinting
python -m repository_intelligence.cli --operation ci --input snapshot.json

# V1.1 Change Impact from normalized dependency graph evidence
python -m repository_intelligence.cli --operation impact --input impact.json

# V1.1 CI Failure Intelligence
python -m repository_intelligence.cli --operation cfi --input snapshot.json

# V1.1 External Intelligence Automation advisory
python -m repository_intelligence.cli --operation eia --input automation-evidence.json

# Read from stdin
cat snapshot.json | python -m repository_intelligence.cli --operation readiness --input -
```

## GitHub Action / cloud execution (N4)

The root `action.yml` exposes Repository Intelligence to generic GitHub repositories without checking out pull-request code. It uses GitHub REST to acquire only PR metadata, changed-file names, current default-branch identity, and check-run evidence, then invokes the same canonical Core used by the local CLI.

```yaml
name: repository-intelligence
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]

permissions:
  contents: read
  pull-requests: read
  checks: read

jobs:
  intelligence:
    runs-on: ubuntu-latest
    steps:
      - id: ri
        uses: James3014/nexus-opencli-reviewer@<immutable-commit>
      - uses: actions/upload-artifact@v4
        with:
          name: repository-intelligence
          path: ${{ steps.ri.outputs.report-path }}
```

The generated `reviewer.repository_intelligence_cloud.v1` bundle is exact-identity-bound and hash-bound, includes readiness + CFI + EIA reports, and has top-level `ADVISORY_EVIDENCE_ONLY`. Outputs include the report path/hash, readiness, CFI status, EIA decision, and claim ceiling. The action does not comment, approve, merge, dispatch workers, or execute pull-request source.

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
