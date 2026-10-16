"""Issue #79: receipt history per identity and default-branch resolution."""
import copy
import json

import pytest

from reviewer.github import GhCliTransport, GitHubError
from reviewer.receipt import persist_receipt, reusable_receipt, receipt_path, compute_receipt_id
from reviewer.scan import scan, review_ready
from reviewer.publication import _fresh_identity

IDENTITY = ["o/r", 7, "head", "base", "main"]


def _receipt(ctx="ctx-a", prompt="prompt-a"):
    semantic = {"schema": "reviewer.semantic_response.v1", "status": "PASS",
                "summary": "ok", "findings": [], "evidence_gaps": []}
    return {
        "schema": "reviewer.pre_review.v1",
        "receipt_id": compute_receipt_id(IDENTITY, ctx, prompt, None, semantic, "PARSED", "REVIEW_COMPLETED"),
        "review_identity": list(IDENTITY),
        "context_pack_sha256": ctx, "prompt_sha256": prompt,
        "transport_result": "REVIEW_COMPLETED", "parse_result": "PARSED",
        "claim_ceiling": "PRE_REVIEW_ONLY", "outcome_unknown": False, "retry_safe": False,
        "semantic_result": {"schema": "reviewer.semantic_response.v1", "status": "PASS",
                            "summary": "ok", "findings": [], "evidence_gaps": []},
    }


def _history(tmp_path):
    return sorted((tmp_path / "reviews" / "history").rglob("*.json"))


def test_two_receipts_same_identity_both_survive_and_latest_is_newest(tmp_path):
    first, second = _receipt("ctx-a", "prompt-a"), _receipt("ctx-b", "prompt-b")
    persist_receipt(tmp_path, first)
    persist_receipt(tmp_path, second)
    contents = [json.loads(p.read_text()) for p in _history(tmp_path)]
    assert len(contents) == 2
    assert {c["context_pack_sha256"] for c in contents} == {"ctx-a", "ctx-b"}
    value, path = reusable_receipt(tmp_path, IDENTITY)
    assert value["context_pack_sha256"] == "ctx-b"
    assert path == receipt_path(tmp_path, IDENTITY)


def test_persisting_same_receipt_twice_creates_one_history_file(tmp_path):
    persist_receipt(tmp_path, _receipt())
    persist_receipt(tmp_path, _receipt())
    assert len(_history(tmp_path)) == 1


def test_legacy_latest_file_is_archived_not_lost(tmp_path):
    legacy = _receipt("ctx-old", "prompt-old")
    latest = receipt_path(tmp_path, IDENTITY)
    legacy_bytes = (json.dumps(legacy, indent=2, sort_keys=True) + "\n").encode()
    latest.write_bytes(legacy_bytes)  # written the old way, no history
    assert reusable_receipt(tmp_path, IDENTITY)  # still readable
    persist_receipt(tmp_path, _receipt("ctx-new", "prompt-new"))
    blobs = [p.read_bytes() for p in _history(tmp_path)]
    assert legacy_bytes in blobs
    assert len(blobs) == 2
    assert reusable_receipt(tmp_path, IDENTITY)[0]["context_pack_sha256"] == "ctx-new"


def test_history_files_are_never_replaced(tmp_path):
    persist_receipt(tmp_path, _receipt())
    (hist,) = _history(tmp_path)
    before = hist.read_bytes()
    persist_receipt(tmp_path, _receipt("ctx-b", "prompt-b"))
    assert hist.read_bytes() == before


def test_status_inventory_does_not_double_count_history(tmp_path):
    from reviewer.status import inventory
    persist_receipt(tmp_path, _receipt())
    persist_receipt(tmp_path, _receipt("ctx-b", "prompt-b"))
    assert len(inventory(tmp_path)["pre_review_receipts"]) == 1


class _DevelopTransport:
    """Default branch is 'develop'; any ref lookup for 'main' fails."""
    def __init__(self):
        self.refs = []

    def auth_preflight(self):
        return None

    def get_default_branch(self, repo):
        return "develop"

    def get_ref(self, repo, branch):
        self.refs.append(branch)
        if branch != "develop":
            raise GitHubError("no such ref " + branch)
        return {"object": {"sha": "m"}}

    def list_open_prs(self, repo):
        return [{"number": 1, "title": "ready", "base": {"sha": "m"}, "head": {"sha": "h"},
                 "body": "", "labels": [], "draft": False, "mergeable": True}]

    def list_files(self, repo, n):
        return [{"filename": "x.py"}]

    def list_checks(self, repo, sha):
        return []

    def get_patch(self, repo, n):
        return "diff --git a/x.py b/x.py"

    def get_pr(self, repo, n):
        return {"number": n, "base": {"sha": "m"}, "head": {"sha": "h"}}


def test_scan_uses_repository_default_branch():
    t = _DevelopTransport()
    main_sha, _, items, _ = scan("o/r", t)
    assert main_sha == "m" and len(items) == 1
    assert set(t.refs) == {"develop"}


def test_review_ready_rebind_uses_default_branch_once_per_call(tmp_path):
    from reviewer.opencli import TransportResult
    good = json.dumps({"schema": "reviewer.semantic_response.v1", "status": "PASS",
                       "summary": "ok", "findings": [], "evidence_gaps": []})

    class S:
        def invoke(self, p):
            return TransportResult("REVIEW_COMPLETED", good, version="fake")

    t = _DevelopTransport()
    calls = []
    orig = t.get_default_branch
    t.get_default_branch = lambda repo: (calls.append(repo), orig(repo))[1]
    receipt, path = review_ready("o/r", t, 1, S(), state_root=tmp_path)
    assert path.exists() and set(t.refs) == {"develop"}
    assert len(calls) == 1


def test_publication_fresh_identity_uses_default_branch():
    t = _DevelopTransport()
    assert _fresh_identity(t, ("o/r", 1, "h", "m", "m")) == ("o/r", 1, "h", "m", "m")
    assert set(t.refs) == {"develop"}


def test_default_branch_helper_falls_back_to_main_for_fakes():
    from reviewer.github import default_branch
    class Bare:
        pass
    assert default_branch(Bare(), "o/r") == "main"


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self.payload


def _http(monkeypatch, payload):
    urls = []

    def urlopen(request, *, timeout):
        urls.append(request.full_url)
        return _Response(json.dumps(payload).encode())
    monkeypatch.setattr("reviewer.github.urllib.request.urlopen", urlopen)
    return urls


def test_real_transport_get_default_branch_parses_and_caches(monkeypatch):
    urls = _http(monkeypatch, {"default_branch": "develop", "name": "r"})
    t = GhCliTransport(gh="gh-test")
    t._token = "tok"
    assert t.get_default_branch("o/r") == "develop"
    assert t.get_default_branch("o/r") == "develop"
    assert urls == ["https://api.github.com/repos/o/r"]
    from reviewer.github import default_branch
    assert default_branch(t, "o/r") == "develop"


@pytest.mark.parametrize("payload", [{}, {"default_branch": ""}, {"default_branch": 3}, [], {"default_branch": None}])
def test_real_transport_get_default_branch_rejects_invalid(monkeypatch, payload):
    _http(monkeypatch, payload)
    t = GhCliTransport(gh="gh-test")
    t._token = "tok"
    with pytest.raises(GitHubError):
        t.get_default_branch("o/r")
