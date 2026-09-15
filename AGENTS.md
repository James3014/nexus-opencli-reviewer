# Nexus OpenCLI Reviewer — Agent Contract

This file is the repository-local operating contract for AI coding agents and automated contributors. It applies to the whole repository unless a deeper `AGENTS.md` narrows rules for a subtree.

## Repository authority

`nexus-opencli-reviewer` is the retained semantic-review application and compatibility surface around the extracted canonical Repository Intelligence engine.

It owns application behavior for:

- PR/CI evidence acquisition and normalization used by this reviewer;
- deterministic eligibility/context assembly as an application consumer;
- OpenCLI/ChatGPT semantic-review transport and durable attempt/reconciliation state;
- `PRE_REVIEW_ONLY` receipts;
- optional idempotent advisory GitHub publication after fresh identity rebind;
- unattended reviewer service behavior and local service state.

It does not own:

- canonical Repository Intelligence decision semantics (`repository-intelligence-engine` owns those);
- coding/repair-worker mutation authority;
- Candidate acceptance, approval, request-changes authority, merge, release, deployment, or Nexus lifecycle promotion;
- Nexus Core, Learning, Runtime, DevSpace, or provider/model policy authority.

The maximum semantic-review claim remains `PRE_REVIEW_ONLY`. Repository Intelligence compatibility shims in this repo must forward to the canonical extracted engine and must not become a second intelligence implementation.

## Required reading before mutation

Read the smallest relevant set:

- `README.md` for current application layers, claim ceilings, compatibility surfaces, and unattended-service behavior;
- `docs/specs/SPEC-RI-EXTRACTION-V1.md` only when work touches Repository Intelligence extraction/compatibility lineage; treat its historical HEADs and migration statuses as provenance, not current repository identity;
- relevant evidence/contract files when changing a previously accepted migration or compatibility boundary.

Do not import `Nexus-new` governance wholesale. Cross-repository docs do not authorize mutation here unless this repository explicitly adopts them.

## Change rules

1. Bind the current repository root, default branch, HEAD, and dirty state before editing. Never treat a historical extraction SHA as current truth.
2. Preserve the product split: canonical Repository Intelligence decisions live in `repository-intelligence-engine`; this repo is a consumer/compatibility application plus semantic-review sidecar.
3. Do not reintroduce duplicate classifier, readiness, overlap, CI, impact, CFI, or EIA logic in reviewer compatibility modules.
4. Semantic review remains advisory. `PASS`, `FINDINGS`, `BLOCKED`, or `PRE_REVIEW_ONLY` receipts do not grant approval, request-changes, Candidate acceptance, merge, release, or deployment authority.
5. Treat semantic model invocation as an external effect. Preserve durable attempt identity, exact conversation/effect identity when available, idempotent publication, and reconciliation-before-replay semantics. Timeout or local uncertainty does not authorize blind resend.
6. Preserve fresh PR/head/base/main identity checks before advisory publication. Do not publish evidence bound to a stale or substituted review identity.
7. Unattended service changes must preserve bounded concurrency/backpressure and must not convert transport health failures into repository or semantic correctness claims.
8. Cross-repository mutation requires separate explicit authority in the target repository and must follow the target repo's local contract.
9. Do not self-authorize merge, release, deployment, service activation outside the bounded task, or production claims.

## Verification

Use the smallest meaningful verification for the changed surface and report only commands actually run.

- Documentation-only: inspect the physical diff and run `git diff --check` when a local checkout is available.
- Reviewer application logic: run targeted tests for the affected module, then the broader test suite when practical.
- Repository Intelligence compatibility changes: prove compatibility modules still forward to the canonical engine and do not carry independent decision logic.
- Semantic transport/reconciliation changes: verify timeout, crash/unknown outcome, exact conversation/effect identity, no-blind-replay, and parser/receipt binding paths.
- Publication changes: include stale-identity and duplicate-publication negative tests.
- Service/scheduler changes: verify bounded work per cycle and that degraded transport remains fail-closed/advisory rather than escalating authority.

A skipped, unavailable, or not-run check is not a pass. Record the exact verification gap.

## Completion and stop boundary

A semantic-review result is advisory evidence only. Source changes and green tests do not independently prove external transport health, unattended service activation, Candidate acceptance, merge readiness, deployment, or production state.

Stop and rebind authority when a task would:

- move canonical Repository Intelligence decision ownership back into this repo;
- grant this reviewer coding-worker, Candidate-acceptance, approval, request-changes, merge, release, deployment, or lifecycle authority;
- replay an external semantic effect whose outcome is still unknown;
- mutate another repository without separate target-repo authority;
- perform merge, release, deployment, or another irreversible external effect without explicit authorization.
