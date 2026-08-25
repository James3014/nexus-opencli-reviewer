import json
import socket
import subprocess
import urllib.error

import pytest

from reviewer.github import GhCliTransport, GitHubError


class Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return self.payload


def test_auth_preflight_caches_token_in_memory(monkeypatch):
    calls = []

    class Result:
        returncode = 0
        stdout = "secret-token\n"
        stderr = ""

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return Result()

    monkeypatch.setattr("reviewer.github.subprocess.run", run)
    transport = GhCliTransport(gh="gh-test")

    transport.auth_preflight()
    transport.auth_preflight()

    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args == ["gh-test", "auth", "token", "--hostname", "github.com"]
    assert kwargs["timeout"] == 30
    assert transport._token == "secret-token"


def test_auth_preflight_retries_one_timeout_then_caches(monkeypatch):
    calls = []
    sleeps = []

    class Result:
        returncode = 0
        stdout = "secret-token\n"
        stderr = ""

    def run(args, **kwargs):
        calls.append(kwargs["timeout"])
        if len(calls) == 1:
            raise subprocess.TimeoutExpired(args, kwargs["timeout"])
        return Result()

    monkeypatch.setattr("reviewer.github.subprocess.run", run)
    monkeypatch.setattr("reviewer.github.time.sleep", lambda value: sleeps.append(value))

    transport = GhCliTransport(gh="gh-test")
    transport.auth_preflight()

    assert calls == [30, 15]
    assert sleeps == [0.25]
    assert transport._token == "secret-token"


def test_read_api_uses_cached_token_and_retries_one_timeout(monkeypatch):
    calls = []
    sleeps = []

    def urlopen(request, *, timeout):
        calls.append((request, timeout))
        if len(calls) == 1:
            raise socket.timeout("slow")
        return Response(json.dumps({"object": {"sha": "abc"}}).encode())

    monkeypatch.setattr("reviewer.github.urllib.request.urlopen", urlopen)
    monkeypatch.setattr("reviewer.github.time.sleep", lambda value: sleeps.append(value))

    transport = GhCliTransport(gh="gh-test")
    transport._token = "cached-token"
    result = transport.get_ref("owner/repo", "main")

    assert result == {"object": {"sha": "abc"}}
    assert [timeout for _, timeout in calls] == [30, 15]
    assert sleeps == [0.25]
    for request, _ in calls:
        assert request.full_url == "https://api.github.com/repos/owner/repo/git/ref/heads/main"
        assert request.get_header("Authorization") == "Bearer cached-token"
        assert request.get_header("Accept") == "application/vnd.github+json"


def test_read_api_second_timeout_fails_closed(monkeypatch):
    calls = []

    def urlopen(request, *, timeout):
        calls.append(timeout)
        raise socket.timeout("still slow")

    monkeypatch.setattr("reviewer.github.urllib.request.urlopen", urlopen)
    monkeypatch.setattr("reviewer.github.time.sleep", lambda _: None)

    transport = GhCliTransport(gh="gh-test")
    transport._token = "cached-token"
    with pytest.raises(GitHubError, match="still slow"):
        transport.get_ref("owner/repo", "main")

    assert calls == [30, 15]


def test_read_api_http_error_is_not_retried(monkeypatch):
    calls = []

    def urlopen(request, *, timeout):
        calls.append(timeout)
        raise urllib.error.HTTPError(request.full_url, 401, "unauthorized", {}, None)

    monkeypatch.setattr("reviewer.github.urllib.request.urlopen", urlopen)

    transport = GhCliTransport(gh="gh-test")
    transport._token = "cached-token"
    with pytest.raises(GitHubError, match="GitHub HTTP 401"):
        transport.get_ref("owner/repo", "main")

    assert calls == [30]


def test_patch_uses_direct_http_and_patch_accept(monkeypatch):
    seen = []

    def urlopen(request, *, timeout):
        seen.append((request, timeout))
        return Response(b"diff --git a/a b/a\n")

    monkeypatch.setattr("reviewer.github.urllib.request.urlopen", urlopen)
    transport = GhCliTransport(gh="gh-test")
    transport._token = "cached-token"

    patch = transport.get_patch("owner/repo", 17)

    assert patch.startswith("diff --git")
    request, timeout = seen[0]
    assert timeout == 30
    assert request.get_header("Accept") == "application/vnd.github.v3.patch"
    assert request.get_header("Authorization") == "Bearer cached-token"


def test_post_uses_cached_token_but_keeps_single_attempt(monkeypatch):
    calls = []

    class Result:
        returncode = 0
        stdout = '{"id": 42}'
        stderr = ""

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return Result()

    monkeypatch.setattr("reviewer.github.subprocess.run", run)
    transport = GhCliTransport(gh="gh-test")
    transport._token = "cached-token"

    result = transport.create_comment("owner/repo", 17, "body")

    assert result["id"] == 42
    assert len(calls) == 1
    assert calls[0][1]["env"]["GH_TOKEN"] == "cached-token"
    assert calls[0][1]["timeout"] == 30
