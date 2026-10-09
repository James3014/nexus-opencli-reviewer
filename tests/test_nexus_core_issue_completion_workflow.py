"""Structural invariants for the two-job ``Nexus Core issue completion`` check (Issue #70).

The ``run`` job issues a Sigstore-signed receipt through the trusted Core
``issue-gate`` action; the ``verify`` job owns the required status name and
checks that receipt through the trusted Core ``receipt-verify`` action. These
tests prove the wiring in this repository and execute the base-defined
protected-input guard against local ``file://`` repositories (requires ``git``
and ``bash``). Signature, binding and trusted-config behaviour live in
nexus-core and are listed as gaps in
docs/ISSUE-70-NEXUS-CORE-SIGNED-RECEIPT-MIGRATION.md.
"""
from __future__ import annotations

import os
import re
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
WORKFLOW = WORKFLOWS / "nexus-core-issue-completion.yml"
CONFIG = ROOT / ".nexus-core" / "config.toml"
REQUIRED_STATUS = "Nexus Core issue completion"
CORE_SHA = "076845b3c69dfb90256a422449fb6318522104ba"
ISSUE_GATE = f"James3014/nexus-core/.github/actions/issue-gate@{CORE_SHA}"
RECEIPT_VERIFY = f"James3014/nexus-core/.github/actions/receipt-verify@{CORE_SHA}"
SAME_REPOSITORY = (
    "github.event.pull_request.head.repo.full_name == github.repository"
    " && !github.event.pull_request.head.repo.fork"
)
EXPECTED_IDENTITY = (
    "https://github.com/James3014/nexus-opencli-reviewer/.github/workflows/"
    "nexus-core-issue-completion.yml@refs/heads/main"
)
ISOLATION_IMAGE = (
    "ghcr.io/astral-sh/uv:python3.11-bookworm@sha256:"
    "58683a39536f1f4ed2e1dd79cf155edccfb47731aba8964bd0312aac942126cf"
)
PROTECTED = (".github/workflows/nexus-core-issue-completion.yml", ".nexus-core/config.toml")
GUARD_CODE = "NEXUS_CORE_GOVERNANCE_INPUT_CHANGED"
PINNED_USES = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$")


def _load(path: Path) -> dict:
    # BaseLoader keeps the YAML 1.2 ``on`` key as a string and every scalar as text.
    value = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(value, dict)
    return value


def _workflow() -> dict:
    return _load(WORKFLOW)


def _config() -> dict:
    return tomllib.loads(CONFIG.read_text(encoding="utf-8"))


def _all_steps(workflow: dict) -> list[dict]:
    return [step for job in workflow["jobs"].values() for step in job.get("steps", [])]


def test_required_status_name_is_unique_across_all_workflows() -> None:
    owners = []
    for path in sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")]):
        for job_id, job in (_load(path).get("jobs") or {}).items():
            if job.get("name", job_id) == REQUIRED_STATUS:
                owners.append((path.name, job_id))
    assert owners == [(WORKFLOW.name, "verify")]


def test_workflow_is_exactly_one_issuer_and_one_consumer_without_matrix_fanout() -> None:
    jobs = _workflow()["jobs"]
    assert set(jobs) == {"run", "verify"}
    assert jobs["run"]["name"] == "Nexus Core issue run"
    for job in jobs.values():
        assert "strategy" not in job
        assert "continue-on-error" not in job


def test_triggers_and_concurrency_are_base_defined_and_per_pull_request() -> None:
    workflow = _workflow()
    triggers = workflow["on"]
    assert set(triggers) == {"pull_request_target"}
    assert triggers["pull_request_target"]["branches"] == ["main"]
    assert "${{ github.event.pull_request.number }}" in workflow["concurrency"]["group"]


def test_top_level_permissions_are_read_only() -> None:
    assert _workflow()["permissions"] == {"contents": "read", "issues": "read", "pull-requests": "read"}


def test_issuer_signs_only_through_trusted_issue_gate_for_same_repository_pull_requests() -> None:
    job = _workflow()["jobs"]["run"]
    assert job["if"] == SAME_REPOSITORY
    assert job["permissions"] == {
        "contents": "read",
        "issues": "read",
        "pull-requests": "read",
        "id-token": "write",
    }
    # Besides the base-defined governance guard, the id-token job carries no
    # repository-authored step; signing happens only inside issue-gate.
    steps = job["steps"]
    assert len(steps) == 2
    assert "uses" not in steps[0]
    assert steps[1] == {
        "name": "Issue signed Nexus Core receipt",
        "id": "gate",
        "uses": ISSUE_GATE,
        "with": {"nexus-certify-ref": CORE_SHA},
    }
    assert job["outputs"] == {
        "artifact-name": "${{ steps.gate.outputs.artifact-name }}",
        "issue-number": "${{ steps.gate.outputs.issue-number }}",
    }


def _guard_script() -> str:
    return _workflow()["jobs"]["run"]["steps"][0]["run"]


def test_issuer_keeps_protected_input_guard_before_issue_gate() -> None:
    # RED witness: the first two-job candidate dropped this guard, and Core
    # --require-trusted-config does not replace it.
    steps = _workflow()["jobs"]["run"]["steps"]
    gate_index = next(index for index, step in enumerate(steps) if step.get("uses") == ISSUE_GATE)
    guards = [index for index, step in enumerate(steps) if GUARD_CODE in step.get("run", "")]
    assert len(guards) == 1
    assert guards[0] < gate_index
    guard = steps[guards[0]]
    assert "if" not in guard
    assert "continue-on-error" not in guard
    assert guard["shell"] == "bash"
    assert guard["env"] == {
        "HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
        "BASE_SHA": "${{ github.event.pull_request.base.sha }}",
    }
    for path in PROTECTED:
        assert path in guard["run"]


def test_protected_input_guard_reads_exact_shas_into_scratch_bare_repository_only() -> None:
    script = _guard_script()
    assert script.startswith("set -euo pipefail\n")
    # Explicit class: bracket ranges can be locale-dependent.
    assert "^[0123456789abcdef]{40}$" in script
    assert 'git init --quiet --bare "$scratch"' in script
    assert 'scratch="$RUNNER_TEMP/' in script
    assert '"$GITHUB_SERVER_URL/$GITHUB_REPOSITORY.git" "$BASE_SHA" "$HEAD_SHA"' in script
    assert '"$BASE_SHA^{commit}"' in script and '"$HEAD_SHA^{commit}"' in script
    lowered = script.lower()
    for forbidden in (
        "checkout", "clone", "work-tree", "worktree", "token", "authorization",
        "pull_request.head.ref", "refs/heads", "python", "pytest", "pip ", "uv ", "|| true",
    ):
        assert forbidden not in lowered, forbidden


_GIT_ENV_KEYS = ("PATH", "SYSTEMROOT", "TMPDIR")


def _git_env(home: Path) -> dict[str, str]:
    env = {key: os.environ[key] for key in _GIT_ENV_KEYS if key in os.environ}
    env.update(
        HOME=str(home),
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_AUTHOR_NAME="guard-test",
        GIT_AUTHOR_EMAIL="guard-test@example.invalid",
        GIT_COMMITTER_NAME="guard-test",
        GIT_COMMITTER_EMAIL="guard-test@example.invalid",
    )
    return env


def _git(repo: Path, env: dict[str, str], *args: str) -> str:
    completed = subprocess.run(
        ["git", "-c", "commit.gpgsign=false", *args],
        cwd=repo, env=env, check=True, capture_output=True, text=True, timeout=60,
    )
    return completed.stdout.strip()


def _write(repo: Path, relative: str, content: str) -> None:
    target = repo / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _mutate(repo: Path, env: dict[str, str], case: str) -> None:
    if case == "unrelated-change":
        _write(repo, "README.md", "changed\n")
    elif case == "workflow-changed":
        _write(repo, PROTECTED[0], "candidate workflow\n")
    elif case == "config-changed":
        _write(repo, PROTECTED[1], "candidate config\n")
    elif case == "config-deleted":
        _git(repo, env, "rm", "--quiet", PROTECTED[1])
    elif case == "config-renamed":
        _git(repo, env, "mv", PROTECTED[1], ".nexus-core/config.renamed.toml")
    elif case == "workflow-mode-changed":
        (repo / PROTECTED[0]).chmod(0o755)
    else:
        raise AssertionError(case)


def _run_guard(tmp_path: Path, env: dict[str, str], base_sha: str, head_sha: str):
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir(exist_ok=True)
    guard_env = dict(env)
    guard_env.update(
        RUNNER_TEMP=str(runner_temp),
        GITHUB_SERVER_URL="file://" + str(tmp_path / "server"),
        GITHUB_REPOSITORY="owner/repo",
        BASE_SHA=base_sha,
        HEAD_SHA=head_sha,
    )
    # Mirrors the GitHub Actions ``shell: bash`` invocation.
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", _guard_script()],
        cwd=runner_temp, env=guard_env, capture_output=True, text=True, timeout=120,
    )


def _origin(tmp_path: Path, *, with_config: bool = True) -> tuple[Path, dict[str, str], str]:
    home = tmp_path / "home"
    home.mkdir()
    env = _git_env(home)
    repo = tmp_path / "server" / "owner" / "repo.git"
    repo.mkdir(parents=True)
    _git(repo, env, "init", "--quiet")
    _git(repo, env, "config", "uploadpack.allowAnySHA1InWant", "true")
    _write(repo, PROTECTED[0], "trusted workflow\n")
    if with_config:
        _write(repo, PROTECTED[1], "trusted config\n")
    _write(repo, "README.md", "base\n")
    _git(repo, env, "add", "-A")
    _git(repo, env, "commit", "--quiet", "-m", "base")
    _git(repo, env, "branch", "trusted-base")
    return repo, env, _git(repo, env, "rev-parse", "HEAD")


def _candidate(repo: Path, env: dict[str, str], case: str) -> str:
    _git(repo, env, "checkout", "--quiet", "-b", f"candidate-{case}", "trusted-base")
    _mutate(repo, env, case)
    _git(repo, env, "add", "-A")
    _git(repo, env, "commit", "--quiet", "--allow-empty", "-m", case)
    return _git(repo, env, "rev-parse", "HEAD")


def test_protected_input_guard_allows_unchanged_governance_inputs(tmp_path: Path) -> None:
    repo, env, base_sha = _origin(tmp_path)
    head_sha = _candidate(repo, env, "unrelated-change")
    result = _run_guard(tmp_path, env, base_sha, head_sha)
    assert result.returncode == 0, result.stderr
    assert GUARD_CODE not in result.stderr


@pytest.mark.parametrize(
    ("case", "paths"),
    [
        ("workflow-changed", PROTECTED[0]),
        ("config-changed", PROTECTED[1]),
        ("config-deleted", PROTECTED[1]),
        ("config-renamed", PROTECTED[1]),
        ("workflow-mode-changed", PROTECTED[0]),
    ],
)
def test_protected_input_guard_denies_changed_governance_inputs(tmp_path: Path, case: str, paths: str) -> None:
    repo, env, base_sha = _origin(tmp_path)
    head_sha = _candidate(repo, env, case)
    result = _run_guard(tmp_path, env, base_sha, head_sha)
    assert result.returncode != 0
    assert f"{GUARD_CODE}: {paths}" in result.stderr


def test_protected_input_guard_reports_both_changed_paths(tmp_path: Path) -> None:
    repo, env, base_sha = _origin(tmp_path)
    _git(repo, env, "checkout", "--quiet", "-b", "candidate-both", "trusted-base")
    _write(repo, PROTECTED[0], "candidate workflow\n")
    _write(repo, PROTECTED[1], "candidate config\n")
    _git(repo, env, "commit", "--quiet", "-am", "both")
    result = _run_guard(tmp_path, env, base_sha, _git(repo, env, "rev-parse", "HEAD"))
    assert result.returncode != 0
    assert f"{GUARD_CODE}: {PROTECTED[0]}, {PROTECTED[1]}" in result.stderr


@pytest.mark.parametrize("bad", ["", "trusted-base", "A" * 40, "0" * 39, "0" * 40 + "\n"])
def test_protected_input_guard_rejects_non_exact_shas(tmp_path: Path, bad: str) -> None:
    repo, env, base_sha = _origin(tmp_path)
    for base, head in ((bad, base_sha), (base_sha, bad)):
        result = _run_guard(tmp_path, env, base, head)
        assert result.returncode != 0
        assert "NEXUS_CORE_TRUSTED_INPUT_SHA_INVALID" in result.stderr


def test_protected_input_guard_fails_closed_when_head_cannot_be_fetched(tmp_path: Path) -> None:
    _, env, base_sha = _origin(tmp_path)
    result = _run_guard(tmp_path, env, base_sha, "0" * 40)
    assert result.returncode != 0


def test_protected_input_guard_fails_closed_when_base_lacks_protected_input(tmp_path: Path) -> None:
    repo, env, base_sha = _origin(tmp_path, with_config=False)
    head_sha = _candidate(repo, env, "unrelated-change")
    result = _run_guard(tmp_path, env, base_sha, head_sha)
    assert result.returncode != 0
    assert f"NEXUS_CORE_TRUSTED_INPUT_BASE_MISSING: {PROTECTED[1]}" in result.stderr


def test_consumer_always_runs_and_is_read_only_without_code_checkout() -> None:
    job = _workflow()["jobs"]["verify"]
    assert job["needs"] == "run"
    assert job["if"] == "always()"
    assert job["permissions"] == {"contents": "read", "actions": "read"}
    for step in job["steps"]:
        assert not str(step.get("uses", "")).startswith("actions/checkout@")


def test_consumer_fails_closed_on_fork_cross_repository_or_unsuccessful_issuer() -> None:
    # A skipped required job reports success, so these cases must fail here.
    steps = _workflow()["jobs"]["verify"]["steps"]
    assert len(steps) == 2
    gate = steps[0]
    assert "if" not in gate
    assert gate["env"] == {
        "HEAD_REPOSITORY": "${{ github.event.pull_request.head.repo.full_name }}",
        "HEAD_IS_FORK": "${{ github.event.pull_request.head.repo.fork }}",
        "RUN_RESULT": "${{ needs.run.result }}",
    }
    script = gate["run"]
    assert "set -euo pipefail" in script
    assert '"$HEAD_REPOSITORY" != "$GITHUB_REPOSITORY"' in script
    assert '"$HEAD_IS_FORK" != "false"' in script
    assert '"$RUN_RESULT" != "success"' in script
    assert script.count("exit 1") == 2


def test_consumer_verifies_with_trusted_receipt_verify_and_exact_bindings() -> None:
    step = _workflow()["jobs"]["verify"]["steps"][-1]
    assert "if" not in step
    assert step["uses"] == RECEIPT_VERIFY
    assert step["with"] == {
        "artifact-name": "${{ needs.run.outputs.artifact-name }}",
        "expected-identity": EXPECTED_IDENTITY,
        "github-repository": "${{ github.repository }}",
        "head-sha": "${{ github.event.pull_request.head.sha }}",
        "base-sha": "${{ github.event.pull_request.base.sha }}",
        "issue-number": "${{ needs.run.outputs.issue-number }}",
        "nexus-certify-ref": CORE_SHA,
    }


def test_actions_are_immutably_pinned_to_one_core_commit() -> None:
    uses = [step["uses"] for step in _all_steps(_workflow()) if "uses" in step]
    assert uses == [ISSUE_GATE, RECEIPT_VERIFY]
    for ref in uses:
        assert PINNED_USES.match(ref), ref


def test_workflow_has_no_soft_failure_secrets_or_expression_injection_into_scripts() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "continue-on-error" not in text
    assert "secrets." not in text
    for step in _all_steps(_workflow()):
        assert "${{" not in step.get("run", "")
        assert "continue-on-error" not in step


def test_config_isolates_verifiers_in_digest_pinned_container() -> None:
    assert _config()["isolation"] == {"mode": "container", "image": ISOLATION_IMAGE, "network": "bridge"}


def test_config_verifiers_remain_required_and_unweakened() -> None:
    config = _config()
    assert config["deletion_policy"] == "FORBID"
    verifiers = {item["id"]: item for item in config["verifiers"]}
    assert set(verifiers) == {"pytest", "diff-check"}
    for verifier in verifiers.values():
        assert verifier["requirement_mode"] == "REQUIRED"
        assert verifier["applicability"] == "APPLICABLE"
        assert verifier["required_material_ids"] == ["repository-intelligence-revision"]
    assert verifiers["diff-check"]["command"] == ["git", "-c", "safe.directory=/sandbox/repo", "diff", "--cached", "--check", "HEAD"]

    command = verifiers["pytest"]["command"]
    assert command[:2] == ["sh", "-ec"]
    script = command[2]
    assert "$(mktemp -d)" in script
    assert (
        "--no-deps --no-index ./vendor/repository_intelligence_engine-0.1.0-py3-none-any.whl" in script
    )
    assert script.endswith('/bin/python" -m pytest -q')
    for forbidden in ("--deselect", " -k ", "|| true", "xfail", "--continue-on-collection-errors"):
        assert forbidden not in script, forbidden
