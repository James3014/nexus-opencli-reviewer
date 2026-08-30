from __future__ import annotations

import copy
import json
from pathlib import Path

import reviewer.github_action as gha


class FakeGitHubAPI:
    def __init__(self):
        self.calls: list[tuple[str, dict | None]] = []

    def get_json(self, path: str, params=None):
        self.calls.append((path, dict(params) if params else None))
        if path == "/repos/owner/repo/pulls/7":
            return {
                "number": 7,
                "title": "fix: core",
                "state": "open",
                "draft": False,
                "mergeable": True,
                "head": {"sha": "b" * 40, "ref": "fix/core"},
                "base": {"sha": "a" * 40, "ref": "main"},
                "labels": [{"name": "bug"}],
                "created_at": "2026-08-30T00:00:00Z",
                "updated_at": "2026-08-30T01:00:00Z",
            }
        if path == "/repos/owner/repo":
            return {"default_branch": "main"}
        if path == "/repos/owner/repo/git/ref/heads/main":
            return {"object": {"sha": "a" * 40}}
        if path == "/repos/owner/repo/pulls/7/files":
            if params and params.get("page") == 1:
                return [{"filename": "src/core.ts"}, {"filename": "tests/core.test.ts"}]
            return []
        if path == "/repos/owner/repo/commits/" + "b" * 40 + "/check-runs":
            if params and params.get("page") == 1:
                return {
                    "check_runs": [
                        {
                            "id": 101,
                            "name": "ci/test",
                            "status": "completed",
                            "conclusion": "failure",
                            "head_sha": "b" * 40,
                            "details_url": "https://example.invalid/check/101",
                            "check_suite": {"id": 201},
                            "app": {"slug": "github-actions"},
                            "output": {"annotations_count": 1},
                            "started_at": "2026-08-30T01:00:00Z",
                            "completed_at": "2026-08-30T01:01:00Z",
                        }
                    ]
                }
            return {"check_runs": []}
        raise AssertionError(f"unexpected API call: {path} {params}")


def test_cloud_acquisition_reads_metadata_files_and_checks_without_source_content():
    api = FakeGitHubAPI()
    snapshot = gha.collect_pr_snapshot(api, "owner/repo", 7)

    assert snapshot["head_sha"] == "b" * 40
    assert snapshot["base_sha"] == snapshot["current_main_sha"] == "a" * 40
    assert snapshot["changed_files"] == ["src/core.ts", "tests/core.test.ts"]
    assert snapshot["checks"][0]["check_run_id"] == 101
    assert snapshot["checks"][0]["head_sha"] == "b" * 40
    assert snapshot["collection_complete"] is True
    assert snapshot["source_identity"] == "github_action_rest_v1"

    paths = [path for path, _ in api.calls]
    assert not any("/contents/" in path for path in paths)
    assert not any("/git/blobs/" in path for path in paths)
    assert not any("/zipball" in path or "/tarball" in path for path in paths)


def test_cloud_bundle_is_exact_identity_bound_and_eia_ready():
    snapshot = gha.collect_pr_snapshot(FakeGitHubAPI(), "owner/repo", 7)
    bundle = gha.run_cloud_bundle(snapshot)

    assert bundle["schema"] == "reviewer.repository_intelligence_cloud.v1"
    assert bundle["claim_ceiling"] == "ADVISORY_EVIDENCE_ONLY"
    assert bundle["review_identity"] == ["owner/repo", 7, "b" * 40, "a" * 40, "a" * 40]
    assert bundle["reports"]["readiness"]["result"]["disposition"] == "REVIEW_READY"
    assert bundle["reports"]["cfi"]["result"]["status"] == "UNEXPECTED_FAILURE_OBSERVED"
    assert bundle["reports"]["eia"]["result"]["decision"] == "READY"
    assert gha.verify_cloud_bundle(bundle) is True


def test_cloud_bundle_rejects_rehashed_cross_report_identity_substitution():
    snapshot = gha.collect_pr_snapshot(FakeGitHubAPI(), "owner/repo", 7)
    bundle = gha.run_cloud_bundle(snapshot)
    tampered = copy.deepcopy(bundle)
    tampered["reports"]["cfi"]["result"]["identity"]["head_sha"] = "f" * 40
    tampered["content_sha256"] = gha._hash_payload(tampered)
    assert gha.verify_cloud_bundle(tampered) is False


def test_action_metadata_never_checks_out_or_executes_pull_request_code():
    text = (Path(__file__).resolve().parent.parent / "action.yml").read_text(encoding="utf-8")
    assert "actions/checkout" not in text
    assert "pull_request_target" not in text
    assert "python3 -m reviewer.github_action" in text
    assert 'PYTHONPATH="$GITHUB_ACTION_PATH' in text


def test_main_writes_report_summary_and_outputs_without_github_mutation(tmp_path, monkeypatch):
    class FakeClientFactory:
        def __init__(self, *args, **kwargs):
            self.api = FakeGitHubAPI()

        def get_json(self, path, params=None):
            return self.api.get_json(path, params)

    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"number": 7}}), encoding="utf-8")
    summary = tmp_path / "summary.md"
    outputs = tmp_path / "outputs.txt"
    report = tmp_path / "ri.json"

    monkeypatch.setattr(gha, "GitHubReadClient", FakeClientFactory)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))

    code = gha.main(["--output", str(report)])
    assert code == 0
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert gha.verify_cloud_bundle(payload) is True
    assert "Repository Intelligence" in summary.read_text(encoding="utf-8")
    output_text = outputs.read_text(encoding="utf-8")
    assert "eia-decision=READY" in output_text
    assert "claim-ceiling=ADVISORY_EVIDENCE_ONLY" in output_text
