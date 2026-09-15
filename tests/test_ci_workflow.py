"""Contract tests for the current-head, read-only GitHub Actions workflow."""
from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
CURRENT_HEAD = "${{ github.event.pull_request.head.sha || github.sha }}"


def _workflow() -> dict:
    # BaseLoader keeps the YAML 1.2 ``on`` key as a string on PyYAML versions
    # whose default resolver still applies YAML 1.1 boolean rules.
    value = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(value, dict)
    return value


def _steps(workflow: dict) -> list[dict]:
    steps = workflow["jobs"]["test"]["steps"]
    assert isinstance(steps, list)
    return steps


def test_events_run_for_pull_requests_and_pushes_to_main() -> None:
    triggers = _workflow()["on"]
    assert set(triggers) == {"pull_request", "push"}
    assert triggers["push"]["branches"] == ["main"]


def test_checkout_and_binding_use_the_actual_event_subject() -> None:
    workflow = _workflow()
    job = workflow["jobs"]["test"]
    assert job["env"]["EXPECTED_SHA"] == CURRENT_HEAD

    checkout = next(step for step in _steps(workflow) if step.get("uses") == "actions/checkout@v4")
    assert checkout["with"]["ref"] == CURRENT_HEAD
    assert checkout["with"]["persist-credentials"] == "false"

    binding = next(step for step in _steps(workflow) if step.get("name") == "Bind current checkout")
    script = binding["run"]
    assert 'git rev-parse HEAD' in script
    assert '"$EXPECTED_SHA"' in script
    assert "git diff --check" in script


def test_permissions_are_read_only() -> None:
    assert _workflow()["permissions"] == {"contents": "read"}


def test_install_is_pinned_and_service_publication_and_full_tests_are_gates() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "pip install --no-deps --no-index ./vendor/repository_intelligence_engine-0.1.0-py3-none-any.whl" in text
    assert "python -m pytest -q tests/test_service.py tests/test_service_cli.py tests/test_publication.py" in text
    assert "python -m pytest -q\n" in text
    assert "--deselect" not in text
    assert "continue-on-error" not in text
    assert "xfail" not in text
    assert "pytest.skip" not in text


def test_workflow_has_no_live_browser_or_github_write_paths() -> None:
    text = WORKFLOW.read_text(encoding="utf-8").lower()
    for forbidden in (
        "pull_request_target",
        "secrets.",
        "browser",
        "playwright",
        "gh pr",
        "git push",
        "create_comment",
        "curl ",
    ):
        assert forbidden not in text, forbidden
