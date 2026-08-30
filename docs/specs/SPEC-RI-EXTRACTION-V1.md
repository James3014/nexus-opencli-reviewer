# Repository Intelligence Extraction Contract

- **Spec ID:** `SPEC-RI-EXTRACTION-V1`
- **Status:** `READY_FOR_TASK_CARDS`
- **Mode:** `BROWNFIELD`
- **Basis repository:** `James3014/nexus-opencli-reviewer`
- **Basis branch:** `main`
- **Basis HEAD:** `06857abbd33e140fcf3d4b181e05050294ab21c1`
- **Accepted behavior baseline:** `aab512ff738650cbffcbc44532b9d99f3787d138` (Repository Intelligence V1.1 integrated subject accepted by N6)
- **Supersedes:** G10 repository timing decision only for post-V1.1 extraction timing; all V1/V1.1 behavior and claim ceilings remain binding.
- **Claim ceiling:** `MIGRATION_CONTRACT_ONLY`

## 1. Problem statement

Repository Intelligence is now a canonical deterministic advisory subsystem with multiple real consumers, but its implementation still resides inside `nexus-opencli-reviewer` and imports legacy reviewer primitives. The repository also contains semantic-review, publication, queue, receipt, runtime, service, and other application responsibilities that are not Repository Intelligence authority. Keeping both products physically co-located increases migration compatibility debt and makes future ownership unclear.

## 2. Desired outcome

Extract Repository Intelligence into a self-contained product repository/package while preserving the exact accepted V1.1 observable behavior, evidence semantics, and authority ceilings. Extraction SHALL be a behavior-preserving migration, not a redesign.

## 3. Basis, coverage, and freshness

### Verified current source

- Current `main`: `06857abbd33e140fcf3d4b181e05050294ab21c1`.
- Current package identity remains `nexus-opencli-reviewer`.
- `reviewer.intelligence.core` directly imports `reviewer.classifier`, `reviewer.models`, and `reviewer.overlap`.
- The current canonical Repository Intelligence facade is `reviewer.intelligence`.
- V1.1 operations include revision identity, readiness, overlap, CI evidence, Change Impact, CFI, and EIA.
- Current adapters include local CLI, WebMCP compatibility, and read-only GitHub Action/cloud execution.
- Semantic reviewer/publication remain separate application surfaces.

### Verified N6 evidence

The exact accepted V1.1 subject `aab512ff738650cbffcbc44532b9d99f3787d138` was replayed on a GitHub-hosted runner. Result: `467 passed, 1 skipped, 1 deselected`; the single deselected test was classified as hosted-runner variance in legacy `GhCliTransport._get_bytes()` and is not on the Repository Intelligence V1.1 cloud path. V1.1 boundary assertions passed.

### Evidence gap

The currently connected Dev MCP manifest did not expose Repository Intelligence native actions during N6 re-check. This is a runtime projection freshness gap only; it SHALL be re-proven during adapter cutover and SHALL NOT be treated as evidence that the V1.1 source baseline is absent.

## 4. Source and decision ledger

| ID | Class | Statement | Authority/location | Status |
|---|---|---|---|---|
| DEC-001 | Owner decision | Extract Repository Intelligence after V1.1 acceptance rather than before it. | N5 owner-approved campaign decision | BINDING |
| DEC-002 | Owner decision | Extraction is the next campaign after N6. | E1 request and prior N5/N6 sequence | BINDING |
| CUR-001 | Current fact | Current main is `06857abbd33e140fcf3d4b181e05050294ab21c1`. | GitHub main | EVIDENCE |
| CUR-002 | Current fact | Accepted V1.1 behavior subject is `aab512ff738650cbffcbc44532b9d99f3787d138`. | N6 exact-subject verification | EVIDENCE |
| CUR-003 | Current fact | Core imports legacy `reviewer.classifier`, `reviewer.models`, `reviewer.overlap`. | `reviewer/intelligence/core.py` | EVIDENCE |
| CUR-004 | Current fact | Package project name is `nexus-opencli-reviewer`. | `pyproject.toml` | EVIDENCE |
| CUR-005 | Current fact | Semantic/opencli/publication are separate from canonical Repository Intelligence Core. | README/current tree | EVIDENCE |
| DER-001 | Derivation | A standalone repo requires Core self-containment before physical extraction. | CUR-003 + DEC-001 | BINDING DERIVATION |
| REJ-001 | Rejected | Reimplement or redesign intelligence semantics during extraction. | N5 migration decision | REJECTED |
| REJ-002 | Rejected | Keep two independently evolving classifier/Core authorities. | N5 authority boundary | REJECTED |
| UNK-001 | Evidence gap | Dev MCP live RI native projection is not currently manifest-verified. | N6 runtime re-check | UNRESOLVED OPERATIONAL |

## 5. Canonical terminology

- **Behavior baseline:** exact observable V1.1 behavior at `aab512ff738650cbffcbc44532b9d99f3787d138`.
- **Current source baseline:** repository `main` at E1 freeze, `06857abbd33e140fcf3d4b181e05050294ab21c1`.
- **Target repository:** working name `repository-intelligence-engine`. Repository name MAY change without changing Python API.
- **Canonical Python namespace:** `repository_intelligence`.
- **Compatibility shim:** thin forwarding/import projection in the old repo; it SHALL NOT contain an independent intelligence implementation.
- **Adapter:** acquisition/transport/serialization surface that consumes the canonical Core and does not own intelligence decisions.

## 6. Change delta

### ADDED

- Standalone Repository Intelligence product repository/package.
- Canonical Python namespace `repository_intelligence`.
- Differential migration verification against the accepted V1.1 baseline.
- Temporary compatibility shim in `nexus-opencli-reviewer` where required.

### MODIFIED

- Physical ownership moves from `reviewer.intelligence` in `nexus-opencli-reviewer` to `repository_intelligence` in the target repo.
- Adapters SHALL consume the extracted canonical package instead of owning or duplicating logic.

### REMOVED

- After successful cutover, direct dependence of the canonical Core on legacy `reviewer.*` primitives.
- After compatibility retirement, duplicate Repository Intelligence implementation code in `nexus-opencli-reviewer`.

### RENAMED

- Python package authority: `reviewer.intelligence` -> `repository_intelligence` after cutover.
- This rename does not authorize semantic/schema/claim-ceiling changes.

## 7. Scope

Included:

1. Core self-containment.
2. New repo/package bootstrap.
3. Behavior-preserving migration of canonical V1.1 operations and contracts.
4. Differential parity verification.
5. Adapter cutover for CLI, GitHub Action, Dev MCP native projection, and WebMCP.
6. Compatibility shim and later cleanup.
7. Extraction acceptance and post-cutover verification.

## 8. Non-goals

Extraction SHALL NOT:

- redesign readiness, overlap, CI, Change Impact, CFI, or EIA semantics;
- change V1.1 schemas merely for aesthetic cleanup;
- increase claim ceilings;
- add comment, approval, merge, release, worker-dispatch, or production authority;
- move semantic reviewer, OpenCLI model transport, publication, queue, receipt, attempt, service, or unattended runtime into the intelligence product merely because they share the current repo;
- create a standalone MCP server by default;
- treat Dev MCP projection freshness as Repository Intelligence decision authority;
- remove legacy compatibility before all real consumers have cut over and differential verification passes.

## 9. Architecture and authority boundaries

### Target dependency direction

```text
upstream evidence producers
        |
        v
repository_intelligence
  contracts + deterministic Core
        |
        +--> CLI adapter
        +--> GitHub Action adapter
        +--> Dev MCP narrow read-only projection
        +--> WebMCP compatibility adapter

semantic reviewer / publication / governance
        |
        v
consumer of intelligence only
```

The canonical Core SHALL NOT import from `nexus-opencli-reviewer` after self-containment. The old repository MAY import the new package through compatibility projections during migration.

## 10. Requirements

### REQ-001 — Immutable behavior baseline
- **Status:** SETTLED
- **Source:** DEC-001, CUR-002, REJ-001
- **Behavior:** Every extraction Candidate SHALL be evaluated against the accepted V1.1 behavior baseline. Migration SHALL preserve observable reports, dispositions, evidence completeness, hashes/fingerprints under equivalent canonical inputs, and claim ceilings unless a separately owner-approved semantic change exists.
- **Failure behavior:** Any unexplained semantic delta blocks extraction acceptance.

### REQ-002 — Core self-containment
- **Status:** DERIVED
- **Source:** CUR-003, DER-001
- **Behavior:** The extracted canonical package SHALL NOT depend on `reviewer.models`, `reviewer.classifier`, `reviewer.overlap`, or other application-only `reviewer.*` modules. Required primitives SHALL be moved/internalized without creating a second authority.
- **Failure behavior:** Any reverse dependency on the old application repo blocks E3 bootstrap acceptance.

### REQ-003 — Stable namespace
- **Status:** SETTLED
- **Source:** DEC-001
- **Behavior:** The canonical Python namespace SHALL be `repository_intelligence`. GitHub repository naming SHALL NOT alter this namespace.
- **Failure behavior:** A second namespace migration requires a new owner decision.

### REQ-004 — Single intelligence authority
- **Status:** SETTLED
- **Source:** REJ-002
- **Behavior:** At every migration stage exactly one implementation SHALL own canonical intelligence decisions. Compatibility shims SHALL forward to that authority and SHALL NOT fork classifier/Core logic.
- **Failure behavior:** Duplicate live logic blocks cutover.

### REQ-005 — Preserve claim ceilings
- **Status:** SETTLED
- **Source:** CUR-002, REJ-001
- **Behavior:** Extraction SHALL preserve `PR_INTELLIGENCE_ONLY`, `CI_EVIDENCE_ONLY`, `AUTOMATION_ADVISORY_ONLY`, and cloud top-level `ADVISORY_EVIDENCE_ONLY` where currently applicable.
- **Failure behavior:** Any authority escalation fails closed.

### REQ-006 — Adapter ownership
- **Status:** SETTLED
- **Source:** DEC-001, current adapter contract
- **Behavior:** CLI, GitHub Action, Dev MCP, and WebMCP SHALL acquire/transport/serialize and invoke the canonical package; they SHALL NOT reimplement intelligence decisions.
- **Failure behavior:** Adapter-specific decision divergence blocks cutover.

### REQ-007 — Old application surfaces remain separate
- **Status:** SETTLED
- **Source:** CUR-005
- **Behavior:** Semantic review, OpenCLI transport, publication, attempt/receipt, queue, service, and unattended runtime SHALL remain outside the extracted Core unless a later independent contract explicitly moves them.
- **Failure behavior:** Unapproved application migration is out-of-scope contamination.

### REQ-008 — Compatibility is temporary and measurable
- **Status:** SETTLED
- **Source:** DEC-001, REJ-002
- **Behavior:** The old repo MAY contain a thin compatibility shim only while real consumers still require it. Removal SHALL occur only after consumer inventory proves cutover and post-cutover verification passes.
- **Failure behavior:** Early removal or permanent duplicate authority blocks completion.

### REQ-009 — Dev MCP live projection closure
- **Status:** DERIVED
- **Source:** UNK-001, REQ-006
- **Behavior:** Before extraction acceptance, the connected Dev MCP runtime SHALL expose and successfully invoke the intended narrow read-only Repository Intelligence actions against the extracted canonical package.
- **Failure behavior:** Source implementation without live manifest/invocation evidence remains operationally incomplete.

### REQ-010 — No extraction-time semantic cleanup
- **Status:** SETTLED
- **Source:** REJ-001
- **Behavior:** Refactors performed solely for relocation/self-containment SHALL be behavior-preserving. Semantic improvements SHALL be split into a later contract/Candidate.
- **Failure behavior:** Mixed migration+semantic diffs are rejected unless explicitly authorized.

## 11. Verification seam

Highest required seams:

1. Static dependency checks proving the new Core does not import old `reviewer.*` application modules.
2. Golden/differential replay against exact accepted V1.1 inputs and outputs.
3. Existing V1/V1.1 unit/contract tests replayed against the extracted package.
4. Real GitHub-hosted Action execution using an immutable extracted-package/action revision.
5. Live Dev MCP tool-manifest discovery and invocation.
6. WebMCP adapter conformance against the extracted Core.
7. Post-cutover old-repo tests proving compatibility forwarding and absence of duplicate decision logic.

## 12. Acceptance criteria

### AC-001 — Behavioral parity
- **Requirement:** REQ-001, REQ-010
- **Evidence level:** SIMULATION + CANARY
- **Pass:** Differential replay of accepted V1.1 witnesses is equivalent under the extracted package; no unexplained report/hash/claim-ceiling delta exists.
- **Negative control:** Deliberately altered identity/evidence/claim inputs still produce the same fail-closed behavior.
- **Fail:** Any unexplained semantic difference.

### AC-002 — Self-contained dependency graph
- **Requirement:** REQ-002
- **Evidence level:** STATIC
- **Pass:** Canonical package imports contain no dependency on old application `reviewer.*` modules.
- **Negative control:** Architecture test fails when an old-repo import is introduced.
- **Fail:** Reverse dependency remains.

### AC-003 — Single authority
- **Requirement:** REQ-004, REQ-008
- **Evidence level:** STATIC + SIMULATION
- **Pass:** Old compatibility API delegates to the new package and produces identical results; no copied classifier/Core implementation remains active.
- **Negative control:** A deliberately divergent shim implementation is detected.
- **Fail:** Two authoritative implementations can disagree.

### AC-004 — Claim ceilings preserved
- **Requirement:** REQ-005
- **Evidence level:** FIXTURE + CANARY
- **Pass:** PR, CI, EIA, and cloud outputs retain their accepted ceilings.
- **Negative control:** Forged elevated ceilings fail verification.
- **Fail:** Any migration path emits stronger authority.

### AC-005 — Adapter cutover
- **Requirement:** REQ-006
- **Evidence level:** LIVE_RUNTIME
- **Pass:** CLI, GitHub Action, Dev MCP, and WebMCP consume the extracted canonical package and return accepted intelligence semantics.
- **Negative control:** Adapter-local poisoned legacy classifications cannot override canonical Core decisions.
- **Fail:** Any adapter still owns or bypasses canonical intelligence decisions.

### AC-006 — Application boundary preserved
- **Requirement:** REQ-007
- **Evidence level:** STATIC
- **Pass:** Semantic/OpenCLI/publication/service/queue/receipt runtime remain outside the extracted Core.
- **Negative control:** Scope audit detects these modules entering the target Core package without a new contract.
- **Fail:** Application authority is silently absorbed.

### AC-007 — Dev MCP runtime bound
- **Requirement:** REQ-009
- **Evidence level:** LIVE_RUNTIME
- **Pass:** Current Dev MCP manifest exposes the intended RI narrow read-only actions and at least one real invocation is bound to the extracted package revision.
- **Negative control:** Source-only definitions without live tool discovery do not pass.
- **Fail:** Live projection remains unbound or stale.

## 13. Traceability matrix

| Requirement | Sources | Delta | Acceptance | Evidence level | Claim ceiling | Handoff |
|---|---|---|---|---|---|---|
| REQ-001 | DEC-001,CUR-002,REJ-001 | MODIFIED ownership only | AC-001 | SIMULATION/CANARY | MIGRATION_PARITY_ONLY | E4 |
| REQ-002 | CUR-003,DER-001 | ADDED | AC-002 | STATIC | SELF_CONTAINMENT_ONLY | E2 |
| REQ-003 | DEC-001 | RENAMED package | AC-002 | STATIC | PACKAGE_IDENTITY_ONLY | E2/E3 |
| REQ-004 | REJ-002 | MODIFIED ownership | AC-003 | STATIC/SIMULATION | SINGLE_AUTHORITY_ONLY | E3/E7 |
| REQ-005 | CUR-002,REJ-001 | UNCHANGED | AC-004 | FIXTURE/CANARY | EXISTING_CEILINGS_ONLY | E4/E8 |
| REQ-006 | DEC-001 | MODIFIED dependency | AC-005 | LIVE_RUNTIME | ADAPTER_ONLY | E5/E6 |
| REQ-007 | CUR-005 | UNCHANGED boundary | AC-006 | STATIC | SCOPE_ONLY | E2/E3 |
| REQ-008 | DEC-001,REJ-002 | ADDED migration rule | AC-003 | STATIC/SIMULATION | COMPATIBILITY_ONLY | E7/E9 |
| REQ-009 | UNK-001 | ADDED operational closure | AC-007 | LIVE_RUNTIME | MCP_PROJECTION_ONLY | E6/E8 |
| REQ-010 | REJ-001 | ADDED migration guard | AC-001 | SIMULATION/CANARY | MIGRATION_PARITY_ONLY | E2-E8 |

## 14. Rollback and failure handling

- Until adapter cutover is accepted, the old accepted V1.1 package remains the fallback implementation.
- A failed differential test SHALL halt cutover rather than normalize the delta as a new expected output.
- A failed Dev MCP/WebMCP/GitHub Action rebind SHALL leave the old consumer path intact until the failure is classified and repaired.
- Compatibility shims SHALL be removable independently from the new Core.
- New repo creation alone SHALL NOT establish product authority; authority transfers only after differential acceptance and consumer cutover.

## 15. Risks and unknowns

- `UNK-001`: Dev MCP current live RI projection is not manifest-verified.
- WebMCP still has legacy acquisition coupling that may require adapter-specific migration work; it must not drag `reviewer.scan` into the new Core.
- Current accepted N6 hosted-runner evidence has one known legacy `GhCliTransport` environment variance outside RI V1.1; extraction MUST NOT silently broaden scope to repair it.

## 16. Unresolved owner decisions

None required to start E2. Target GitHub repository name is explicitly non-authoritative and may be finalized during E3 without changing package/API semantics.

## 17. Task-card handoff boundary

| Task group | Requirements | Acceptance | Outcome | Dependency seam | Verification | Maximum claim | Scope | MCP |
|---|---|---|---|---|---|---|---|---|
| E2 Core Self-Containment | REQ-002,003,007,010 | AC-002,006 | Core can stand alone without old app imports | accepted V1.1 Core | static + focused parity | SELF_CONTAINED_CANDIDATE | medium | MUTATE_BOUNDED |
| E3 New Repo Bootstrap | REQ-003,004,007,010 | AC-002,003,006 | target repo/package exists without second authority | E2 | static + package tests | BOOTSTRAP_ONLY | medium | CANDIDATE |
| E4 Differential Parity | REQ-001,004,005,010 | AC-001,003,004 | old/new behavior equivalent | E3 | differential golden replay | MIGRATION_PARITY_ONLY | medium | VERIFY |
| E5 Adapter Cutover | REQ-006,008,010 | AC-005 | adapters point to canonical extracted Core | E4 | adapter tests/canary | ADAPTER_CUTOVER_ONLY | wide-mechanical | CANDIDATE |
| E6 Dev MCP Live Rebind | REQ-006,009 | AC-005,007 | live Dev MCP invokes extracted package | E5 | manifest + live invocation | MCP_PROJECTION_ONLY | medium | VERIFY |
| E7 Compatibility Shim | REQ-004,008 | AC-003 | old repo forwards without duplicate authority | E4/E5 | parity + static check | COMPATIBILITY_ONLY | medium | CANDIDATE |
| E8 Extraction Acceptance | REQ-001-010 | AC-001-007 | exact extraction Candidate accepted | E4-E7 | independent acceptance + live adapters | EXTRACTION_ACCEPTED | medium | VERIFY |
| E9 Legacy Cleanup | REQ-004,008 | AC-003 | obsolete shim/duplicates removed after cutover | E8 | consumer inventory + post-cutover tests | CLEANUP_COMPLETE | medium | CANDIDATE |

## 18. Out of scope

No semantic redesign, governance authority, automatic repair, merge/approval authority, semantic reviewer migration, independent MCP server requirement, production deployment claim, or unrelated legacy `GhCliTransport` repair is authorized by this contract.

## 19. Supersession and change history

This contract converts the N5 decision `EXTRACT_AFTER_V1_1_ACCEPTANCE` into the execution contract for E2-E9 after N6 closure. It supersedes only the earlier deferred extraction timing statement; it does not supersede Repository Intelligence V1/V1.1 behavioral contracts, evidence schemas, claim ceilings, or N6 acceptance evidence.
