# Issue #70 Nexus Core signed-receipt migration candidate

Status: remote draft PR #71 `CANDIDATE_READY` with verified pre-activation
negative controls and isolation tests. Activation remains
`BLOCKED_MIGRATION_AUTHORITY`.

Parent: James3014/Nexus-new#1452.

Bound local identity when prepared:

- repository: James3014/nexus-opencli-reviewer
- default branch: main
- base HEAD: 4c8f4271d8d80f62b0f7524782c7437308a6236c
- trusted Core commit: 076845b3c69dfb90256a422449fb6318522104ba (action identity
  and interface verified read-only by the coordinator, not by this implementer)

This is a local candidate. It is not merge, activation, ruleset, release, or
Candidate-acceptance authority.

## Remaining blocker: old-base self-protection

The workflow on `main` at the base HEAD runs under `pull_request_target`, so
GitHub executes the base-branch bytes. Its "Protect trusted Core governance
inputs" step fails with `NEXUS_CORE_GOVERNANCE_INPUT_CHANGED` when the PR head
differs from base for `.github/workflows/nexus-core-issue-completion.yml` or
`.nexus-core/config.toml`. This candidate changes both files, so the PR that
carries it cannot turn `Nexus Core issue completion` green through the
protected path, and the candidate cannot self-bootstrap.

That guard is intentional and is not weakened here. Landing the candidate needs a
separately authorized, Owner-controlled trusted-generation transition, so this
migration remains `BLOCKED_MIGRATION_AUTHORITY`.

## Protected-input guard is preserved after activation

Core `--require-trusted-config` only requires `config_source.kind == 'base-ref'`
(coordinator reading of `product/clients/local_golden_path.py` at the Core
commit). It does not prove the candidate's workflow and config bytes are
unchanged. The first two-job draft dropped the old guard, and a coordinator RED
probe caught it. The candidate now keeps the guard as the first step of `run`,
before `issue-gate`:

- same protected paths: `.github/workflows/nexus-core-issue-completion.yml` and
  `.nexus-core/config.toml`
- same denial: `NEXUS_CORE_GOVERNANCE_INPUT_CHANGED: <paths>`, non-zero exit
- validates the event `head.sha` and `base.sha` as exactly 40 lowercase hex
  characters (`NEXUS_CORE_TRUSTED_INPUT_SHA_INVALID`)
- creates a scratch bare repository under `$RUNNER_TEMP` and fetches only those
  two exact SHAs (`--depth=1 --no-tags`) from
  `$GITHUB_SERVER_URL/$GITHUB_REPOSITORY.git`, with no token and no branch names
- compares `git ls-tree` entries (mode, type, blob id) for each path, so content
  changes, deletion, rename-away, mode change, and file→tree replacement are all
  denied
- base missing a protected path → `NEXUS_CORE_TRUSTED_INPUT_BASE_MISSING`; a
  fetch or `ls-tree` failure aborts via `set -euo pipefail`

Why this method was chosen: the old guard checked out the PR head into the
workspace and compared file bytes. This version never materializes or executes
candidate files. It reads only git objects in a bare repository. Comparing
committed tree entries is at least as strict as comparing checked-out bytes,
because it is unaffected by checkout filters or line-ending conversion. No safer
source-grounded method was found in this repository. Core has no input that
pins arbitrary paths.

Limitations:
- Without a token, the fetch works only while the repository is public. If it
  becomes private, the guard fails closed rather than passing.
- `base.sha` is the event's base. If `main` moves after the event, the guard
  compares against the event base, the same as the old guard and as Core
  `--expect-config-commit`.
- The guard runs in the `id-token: write` job. It is base-defined trusted code
  and never runs candidate code, but it shares that job.

## Candidate

`.github/workflows/nexus-core-issue-completion.yml`

| Job | Check name | Condition | Permissions | Steps |
| --- | --- | --- | --- | --- |
| `run` | `Nexus Core issue run` | same repository and not fork | contents/issues/pull-requests read, `id-token: write` | protected-input guard, then `issue-gate@076845b…` |
| `verify` | `Nexus Core issue completion` | `needs: run`, `if: always()` | contents read, actions read | fail-closed precondition, then `receipt-verify@076845b…` |

The `receipt-verify` inputs are the artifact name and Issue number from `run`
outputs, the expected identity
`https://github.com/James3014/nexus-opencli-reviewer/.github/workflows/nexus-core-issue-completion.yml@refs/heads/main`,
`github.repository`, the event head and base SHAs, and `nexus-certify-ref` at the
same Core commit.

Deliberate deviation from the nexus-runtime consumer: there, `verify` uses
`if: always() && same-repository && !fork`. GitHub reports a skipped job as
success for a required check, so a fork PR would show `Nexus Core issue
completion` as passing without verification. This candidate instead always runs
`verify` and fails it in a small precondition step when the PR comes from a fork
or another repository, or when `needs.run.result != 'success'`. That step only
checks preconditions. It does not verify signatures or receipts.

Concurrency is grouped per PR with `cancel-in-progress: false`, so an in-flight
signing run is not cancelled mid-effect. nexus-runtime's value for this setting
was not reported to this implementer.

`.nexus-core/config.toml`

- Adds `[isolation]` with `mode = "container"`, the digest-pinned
  `ghcr.io/astral-sh/uv:python3.11-bookworm@sha256:5868…26cf` image, and
  `network = "bridge"`, matching nexus-runtime.
- The `pytest` verifier now prepares its own environment. `issue-gate` has no
  equivalent of the old workflow's "Bootstrap verifier environment" step, and
  the bare image has no pytest. The command creates a venv under `mktemp -d`,
  outside the subject tree, installs `pytest==8.3.3` and `pyyaml==6.0.2`, installs
  the vendored `repository_intelligence_engine` wheel with `--no-deps --no-index`
  (the same as the old workflow and `ci.yml`), then runs `python -m pytest -q`.
- Dependency assessment: the only third-party imports in `tests/` and `reviewer/`
  are `pytest`, `yaml`, and `repository_intelligence` (vendored wheel). The only
  tests that shell out are the new protected-input guard tests, which need `git`
  and `bash`. The `diff-check` verifier already requires `git` in the same
  isolation. The one OpenCLI test skips when `opencli` is absent, which is the
  existing behavior. Pytest caches are gitignored.
- The material, the `diff-check` verifier, `deletion_policy = "FORBID"`, `version`,
  and `universe_generation` are unchanged.

## Trust boundary

- Trusted: base-branch workflow bytes, Core actions and `nexus-certify` at
  `076845b…`, the digest-pinned isolation image, and the GitHub OIDC/Sigstore
  workflow identity.
- Untrusted: PR body, PR head tree, vendored wheel, tests, and everything the
  verifiers execute inside isolation.
- The `id-token: write` job contains only the base-defined protected-input guard
  and the Core `issue-gate` step. The guard reads git objects only and never
  checks out or executes candidate code. The job is skipped for fork and
  cross-repository PRs.
- `verify` checks out no code and has no write or `id-token` permission. Signed
  receipt acceptance is decided only by Core `receipt-verify`.
- A verified receipt is evidence that the check passed. It carries no approval,
  merge, release, deployment, or Candidate-acceptance authority.

## Tests

Local structural tests (`tests/test_nexus_core_issue_completion_workflow.py`):

- the required status name exists exactly once across all workflows, on `verify`
- exactly the jobs `run` and `verify`, with no matrix fan-out or
  `continue-on-error`
- only the `pull_request_target` trigger, on `main`, with per-PR concurrency
- read-only top-level permissions
- the issuer signs only through `issue-gate@CORE_SHA` with exact permissions,
  exact outputs, and a same-repository/non-fork condition
- the consumer has `needs: run`, `if: always()`, exactly contents/actions read,
  and no checkout
- the consumer fails closed on fork, cross-repository, or unsuccessful issuer
- `receipt-verify@CORE_SHA` gets exactly the expected inputs and expected identity
- every `uses:` is pinned to the single Core commit, with no `${{ }}` inside
  `run:` scripts and no `secrets.`
- config isolation is exact, and the verifiers stay REQUIRED and not weakened
- RED witness: exactly one unconditional guard step before `issue-gate`, with
  `NEXUS_CORE_GOVERNANCE_INPUT_CHANGED`, both protected paths, and env bound to the
  event head and base SHAs
- the guard script uses only a scratch bare repository, exact SHAs, no
  checkout/clone/worktree, no token or branch refs, and no Python/pip/uv
- behavioural: the guard script is taken from the workflow YAML and run under
  `bash --noprofile --norc -eo pipefail` against a local `file://` origin.
  - allows an unrelated change
  - denies a changed workflow, changed config, deleted config, renamed config, a
    workflow mode change, and both paths changed (exact message)
  - rejects empty, ref-name, uppercase, short, or newline-suffixed SHAs
  - fails closed when the head cannot be fetched or the base lacks a protected
    path

These tests need Python ≥ 3.11 (`tomllib`), which matches CI, the old workflow,
and the isolation image. The behavioural tests also need `git` and `bash`, and
the mode-change case needs a filesystem that honors the executable bit.

Signed-receipt behaviour belongs in Core conformance tests, then in live canary
PRs after Owner-authorized activation:

| Case | Expected `Nexus Core issue completion` |
| --- | --- |
| P1 same-repo PR, one Issue marker, verifiers pass, valid receipt | success |
| N1 receipt signed by another workflow, ref, or repository | failure |
| N2 receipt Issue ≠ PR marker | failure |
| N3 receipt repository ≠ `github.repository` | failure |
| N4 / N5 / N6 receipt head / base / tree mismatch | failure |
| N7 receipt or bundle missing, or more than one present | failure |
| N8 receipt or bundle altered after signing | failure |
| N9 receipt status not `VERIFIED` | failure |
| N10 `run` failed, cancelled, or skipped | failure (precondition), not skipped |
| N11 fork or cross-repository PR | failure (precondition), not skipped |
| N12 zero or multiple Issue markers | `run` fails → N10 |
| N13 PR changes the workflow or `.nexus-core/config.toml` after activation | `run` guard fails with `NEXUS_CORE_GOVERNANCE_INPUT_CHANGED` before `issue-gate` signs anything → N10 |

## Gaps not proven by this repository

- Static inspection of the pinned Core `issue-gate` and `receipt-verify`
  action sources at `076845b…` confirms their advertised receipt/identity
  input contracts, including rejecting empty artifact/Issue inputs. Their
  **live** N1–N9 signature, substitution and identity behavior is unverified.
- The protected-input guard's exact base/head SHA fetch succeeded against
  **github.com**, and committed tree entries detected both protected path
  changes. A real `pull_request_target` live canary remains unrun.
- Digest-pinned `ghcr.io/astral-sh/uv:python3.11-bookworm` worked locally
  under Docker Desktop linux/arm64 with `uv`, Python 3.11, Git and PyPI.
  The full verifier pytest command passed 518 tests (one skipped); the
  pinned Core's own detached-clone Docker executor also passed pytest.
- A real RED found Docker Desktop mount ownership making Git reject
  `/sandbox/repo` as dubious. The `diff-check` verifier's original
  `git diff --cached --check HEAD` returned 129. Binding
  `git -c safe.directory=/sandbox/repo diff --cached --check HEAD`
  to the exact isolated subject passed via the pinned Core executor,
  without a global safe.directory exception. A config regression test
  now asserts this bounded command. Re-check it on the exact new commit.
- Pinned Core `_validate_config` accepted v2, `universe_generation = 1`,
  digest-pinned container isolation and both verifier command definitions.
  The Github-hosted linux/amd64 image/container and signed OIDC jobs
  remain unverified. Core `issue-check --require-trusted-config` against
  the old base correctly used the **old** config and failed its pytest
  verifier; it is not positive evidence for the new config.
- Actual [security-negative PR #72](https://github.com/James3014/nexus-opencli-reviewer/pull/72)
  made an unrelated GitHub Actions job report an identical
  `Nexus Core issue completion` success while the real protected check failed.
  The PR stayed `BLOCKED`; it was closed without merge and its remote
  test branch deleted. This is an exact negative witness, not a proof
  against every possible spoof. Main ruleset requires strict up-to-date
  checks, helping prevent reuse of old-generation green checks.
- That the expected identity matches the OIDC `job_workflow_ref` for this
  repository's `pull_request_target` runs is inferred from nexus-runtime. It is
  unverified here.
- Python packages are version-pinned but not hash-pinned.

## Next authorized gate

An Owner-controlled trusted-generation transition that lands this candidate past
the self-protecting base workflow. The current base guard forbids this migration
PR, so the transition is `BLOCKED_MIGRATION_AUTHORITY`. After that come live
P1/N10/N11/N13 canaries on this repository. These gates require distinct Owner exception and independent verification
authorities; preactivation local tests cannot substitute for signed live CI.
