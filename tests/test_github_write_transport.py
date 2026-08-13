import json
import subprocess

import pytest

from reviewer.github import GhCliTransport, GitHubError


def test_create_comment_is_exact_issue_comment_post(monkeypatch):
    calls = []

    class Result:
        returncode = 0
        stdout = '{"id": 42, "html_url": "https://github.test/c"}'
        stderr = ""

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return Result()

    monkeypatch.setattr("reviewer.github.subprocess.run", run)
    result = GhCliTransport(gh="gh-test").create_comment("owner/repo", 17, "Automated PRE_REVIEW")
    assert result["id"] == 42
    args, kwargs = calls[0]
    assert args == ["gh-test", "api", "repos/owner/repo/issues/17/comments", "--method", "POST", "--input", "-"]
    assert json.loads(kwargs["input"]) == {"body": "Automated PRE_REVIEW"}
    assert kwargs["timeout"] == 30
    assert "review" not in args[2].split("/")[-1]
    assert "labels" not in args[2]


def test_comment_rejects_unsafe_repository_before_write(monkeypatch):
    monkeypatch.setattr("reviewer.github.subprocess.run", lambda *a, **k: pytest.fail("must not invoke gh"))
    with pytest.raises(ValueError):
        GhCliTransport().create_comment("owner/repo?state=open", 1, "body")
    with pytest.raises(ValueError):
        GhCliTransport().list_comments("owner/repo;touch /tmp/x", 1)


def test_post_timeout_is_normalized(monkeypatch):
    def run(*args, **kwargs):
        raise subprocess.TimeoutExpired(kwargs.get("args", args[0]), kwargs["timeout"])

    monkeypatch.setattr("reviewer.github.subprocess.run", run)
    with pytest.raises(GitHubError, match="timed out|Timeout"):
        GhCliTransport().create_comment("owner/repo", 1, "body")


def test_list_comments_collects_all_pages(monkeypatch):
    transport = GhCliTransport()
    seen = []

    def page(endpoint, **params):
        seen.append((endpoint, params))
        return [{"id": i} for i in (range(100) if params["page"] == 1 else range(100, 103))]

    monkeypatch.setattr(transport, "_get", page)
    comments = transport.list_comments("owner/repo", 1)
    assert [x["id"] for x in comments] == list(range(103))
    assert [p["page"] for _, p in seen] == [1, 2]
    assert all(p["per_page"] == 100 for _, p in seen)


def test_comment_list_failure_fails_closed(monkeypatch):
    transport = GhCliTransport()

    def page(endpoint, **params):
        if params["page"] == 2:
            raise GitHubError("page unavailable")
        return [{"id": i} for i in range(100)]

    monkeypatch.setattr(transport, "_get", page)
    with pytest.raises(GitHubError, match="page unavailable"):
        transport.list_comments("owner/repo", 1)
