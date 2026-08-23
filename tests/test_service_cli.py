import base64
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from reviewer import service_cli
from reviewer.config import ReviewerConfig, save_config
from reviewer.opencli import TransportResult
from reviewer.preflight import PreflightResult


def config(tmp_path):
    return ReviewerConfig(poll_interval_seconds=5, state_root=tmp_path/"state", log_path=tmp_path/"service.log", opencli_executable="opencli")


def test_launch_agent_is_user_level_and_independent(tmp_path, monkeypatch):
    monkeypatch.setattr(Path,"home",classmethod(lambda cls: tmp_path))
    cfg=config(tmp_path); path=tmp_path/"config.json";save_config(cfg,path)
    plist=service_cli.install(path); text=plist.read_text()
    assert service_cli.SERVICE_LABEL in text and "<key>KeepAlive</key><true/>" in text
    assert "sudo" not in text and "reviewer.service_cli" in text and "daemon" in text
    assert "/opt/homebrew/bin" in text


def test_launch_agent_path_uses_current_environment_and_escapes_deduplicated_entries(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "/custom/bin:/custom/bin:/path&with<markup>")
    monkeypatch.setattr(service_cli.shutil, "which", lambda executable: None)
    text = service_cli._plist_xml(tmp_path / "config&.json")
    assert "/custom/bin:/path&amp;with&lt;markup&gt;" in text
    assert text.count("/custom/bin") == 1


def test_run_once_delegates_without_manual_pr(monkeypatch,tmp_path):
    cfg=config(tmp_path); seen=[]
    class S:
        def run_once(self):seen.append("run");return {"status":"IDLE"}
    monkeypatch.setattr(service_cli,"build_service",lambda config,repository,bootstrap_canary=False:S())
    value=service_cli.run_once(cfg)
    assert seen==["run"] and value["semantic_concurrency"]==1


def test_bounded_bootstrap_config_admits_exactly_one_canary(monkeypatch,tmp_path):
    from reviewer.config import BootstrapPolicy
    cfg=ReviewerConfig(poll_interval_seconds=5,state_root=tmp_path/"state",log_path=tmp_path/"log",bootstrap=BootstrapPolicy("bounded",1))
    captured={}
    monkeypatch.setattr(service_cli,"UnattendedReviewService",lambda **kwargs:captured.update(kwargs) or object())
    service_cli.build_service(cfg,"James3014/Nexus-new")
    assert captured["policy"].bootstrap_canary is True


def test_metadata_canary_is_get_only_and_rejects_artifact_head_mismatch(monkeypatch):
    head = "f" * 40
    calls = []

    class FakeGh:
        def _get(self, endpoint):
            calls.append(endpoint)
            if endpoint.endswith("check-suites/11"):
                return {"id": 11, "head_sha": head}
            if endpoint.endswith("check-runs/12"):
                return {"id": 12, "head_sha": head, "conclusion": "failure"}
            if endpoint.endswith("actions/runs/13"):
                return {"id": 13, "head_sha": head, "conclusion": "failure"}
            if endpoint.endswith("jobs?per_page=100&page=1"):
                return {"jobs": [{"id": 14, "head_sha": head}]}
            if endpoint.endswith("artifacts?per_page=100&page=1"):
                return {"artifacts": [{"id": 15, "name": "exact-base-impact-" + "a" * 40}]}
            if endpoint.endswith("actions/artifacts/15"):
                return {"id": 15, "name": "exact-base-impact-" + "a" * 40,
                        "expired": False, "workflow_run": {"id": 13, "head_sha": head}}
            raise AssertionError(endpoint)

        def get_pr(self, repo, number):
            return {
                "number": number,
                "base": {"sha": "b" * 40, "repo": {"full_name": repo}},
                "head": {"sha": head, "repo": {"full_name": repo}},
            }

        def get_job_log(self, *args):
            raise AssertionError("job logs are forbidden")

        def get_artifact_archive(self, *args):
            raise AssertionError("artifact archives are forbidden")

    monkeypatch.setattr(service_cli, "GhCliTransport", FakeGh)
    value = service_cli.run_metadata_canary(
        repository="James3014/Nexus-new", pr_number=380, head_sha=head,
        check_suite_id=11, check_run_id=12, run_id=13, job_id=14, artifact_id=15)
    assert value["status"] == "CANARY_REJECTED"
    assert "CANARY_ARTIFACT_NAME_HEAD_MISMATCH" in value["evidence_gaps"]
    assert len(calls) == 6 and all("logs" not in call and not call.endswith("/zip") for call in calls)


def test_metadata_canary_valid_binds_six_endpoints_without_side_effects(monkeypatch):
    repository = "James3014/Nexus-new"
    pr_number = 380
    head = "f" * 40
    base = "b" * 40
    artifact_name = "exact-base-impact-" + head
    calls = []
    forbidden = {"logs": 0, "archives": 0, "providers": 0, "config": 0, "runtime": 0}

    class FakeGh:
        def _get(self, endpoint):
            calls.append(endpoint)
            if endpoint.endswith("check-suites/11"):
                return {"id": 11, "head_sha": head}
            if endpoint.endswith("check-runs/12"):
                return {"id": 12, "head_sha": head, "conclusion": "failure"}
            if endpoint.endswith("actions/runs/13"):
                return {"id": 13, "head_sha": head, "conclusion": "failure"}
            if endpoint.endswith("jobs?per_page=100&page=1"):
                return {"jobs": [{"id": 14, "head_sha": head, "run_id": 13}]}
            if endpoint.endswith("artifacts?per_page=100&page=1"):
                return {"artifacts": [{"id": 15, "name": artifact_name}]}
            if endpoint.endswith("actions/artifacts/15"):
                return {
                    "id": 15,
                    "name": artifact_name,
                    "expired": False,
                    "workflow_run": {"id": 13, "head_sha": head},
                }
            raise AssertionError(endpoint)

        def get_pr(self, repo, number):
            return {
                "number": number,
                "base": {"sha": base, "repo": {"full_name": repo}},
                "head": {"sha": head, "repo": {"full_name": repo}},
            }

        def get_job_log(self, *args):
            forbidden["logs"] += 1
            raise AssertionError("job logs are forbidden")

        def get_artifact_archive(self, *args):
            forbidden["archives"] += 1
            raise AssertionError("artifact archives are forbidden")

        def invoke_provider(self, *args):
            forbidden["providers"] += 1
            raise AssertionError("provider calls are forbidden")

        def load_config(self, *args):
            forbidden["config"] += 1
            raise AssertionError("config calls are forbidden")

        def start_runtime(self, *args):
            forbidden["runtime"] += 1
            raise AssertionError("runtime calls are forbidden")

    monkeypatch.setattr(service_cli, "GhCliTransport", FakeGh)
    value = service_cli.run_metadata_canary(
        repository=repository, pr_number=pr_number, head_sha=head,
        check_suite_id=11, check_run_id=12, run_id=13, job_id=14,
        artifact_id=15, max_bytes=65536, max_records=100)

    assert value == {
        "status": "CANARY_METADATA_BOUND",
        "schema": "reviewer.ci_failure_evidence.v1",
        "repository": repository,
        "pr_number": pr_number,
        "head_sha": head,
        "base_sha": base,
        "check_suite_id": 11,
        "check_run_id": 12,
        "run_id": 13,
        "job_id": 14,
        "artifact_id": 15,
        "evidence_gaps": [],
        "claim_ceiling": "CI_EVIDENCE_ONLY",
    }
    assert calls == [
        f"repos/{repository}/check-suites/11",
        f"repos/{repository}/check-runs/12",
        f"repos/{repository}/actions/runs/13",
        f"repos/{repository}/actions/runs/13/jobs?per_page=100&page=1",
        f"repos/{repository}/actions/runs/13/artifacts?per_page=100&page=1",
        f"repos/{repository}/actions/artifacts/15",
    ]
    assert len(calls) == 6
    assert forbidden == {
        "logs": 0, "archives": 0, "providers": 0, "config": 0, "runtime": 0,
    }


def test_metadata_canary_rejects_pagination_limit(monkeypatch):
    head = "a" * 40
    class FakeGh:
        def get_pr(self, repo, number):
            return {
                "number": number,
                "base": {"sha": "b" * 40, "repo": {"full_name": repo}},
                "head": {"sha": head, "repo": {"full_name": repo}},
            }

        def _get(self, endpoint):
            if endpoint.endswith("check-suites/11"):
                return {"id": 11, "head_sha": head}
            if endpoint.endswith("check-runs/12"):
                return {"id": 12, "head_sha": head}
            if endpoint.endswith("actions/runs/13"):
                return {"id": 13, "head_sha": head, "conclusion": "failure"}
            if endpoint.endswith("jobs?per_page=1&page=1"):
                return {"jobs": [{"id": 14}]}
            return {"artifacts": []}

    monkeypatch.setattr(service_cli, "GhCliTransport", FakeGh)
    value = service_cli.run_metadata_canary(
        repository="o/r", pr_number=1, head_sha=head, check_suite_id=11,
        check_run_id=12, run_id=13, job_id=14, artifact_id=15, max_records=1)
    assert value["status"] == "CANARY_REJECTED"
    assert "CANARY_PAGINATION_OR_RECORD_LIMIT" in value["evidence_gaps"]


def test_metadata_canary_rejects_huge_byte_budget_without_transport(monkeypatch):
    class NoCalls:
        def __init__(self):
            self.called = False

        def get_pr(self, *args):
            self.called = True
            raise AssertionError("transport forbidden")

    fake = NoCalls()
    monkeypatch.setattr(service_cli, "GhCliTransport", lambda: fake)
    value = service_cli.run_metadata_canary(
        repository="o/r", pr_number=1, head_sha="a" * 40,
        check_suite_id=1, check_run_id=2, run_id=3, job_id=4, artifact_id=5,
        max_bytes=service_cli.MAX_CANARY_BYTES + 1)
    assert value["reason"] == "CANARY_INPUT_INVALID" and fake.called is False


@pytest.mark.parametrize("head", ["A" * 40, "a" * 39, "a" * 41, "not-a-sha"])
def test_metadata_canary_rejects_malformed_head_sha(monkeypatch, head):
    monkeypatch.setattr(
        service_cli,
        "GhCliTransport",
        lambda: (_ for _ in ()).throw(AssertionError("transport forbidden")),
    )
    value = service_cli.run_metadata_canary(
        repository="o/r", pr_number=1, head_sha=head,
        check_suite_id=1, check_run_id=2, run_id=3, job_id=4, artifact_id=5)
    assert value["reason"] == "CANARY_INPUT_INVALID"


def test_metadata_canary_rejects_pr_number_and_head_mismatch(monkeypatch):
    head = "a" * 40

    class FakeGh:
        def get_pr(self, repo, number):
            return {
                "number": number + 1,
                "base": {"sha": "b" * 40, "repo": {"full_name": repo}},
                "head": {"sha": "c" * 40, "repo": {"full_name": repo}},
            }

    monkeypatch.setattr(service_cli, "GhCliTransport", FakeGh)
    value = service_cli.run_metadata_canary(
        repository="o/r", pr_number=1, head_sha=head,
        check_suite_id=1, check_run_id=2, run_id=3, job_id=4, artifact_id=5)
    assert value["status"] == "CANARY_REJECTED"
    assert {"CANARY_PR_NUMBER_MISMATCH", "CANARY_PR_HEAD_MISMATCH"} <= set(
        value["evidence_gaps"]
    )


def test_metadata_canary_rejects_foreign_pr_repository(monkeypatch):
    head = "a" * 40

    class FakeGh:
        def get_pr(self, repo, number):
            return {
                "number": number,
                "base": {
                    "sha": "b" * 40,
                    "repo": {"full_name": "foreign/repo"},
                },
                "head": {
                    "sha": head,
                    "repo": {"full_name": "foreign/repo"},
                },
            }

    monkeypatch.setattr(service_cli, "GhCliTransport", FakeGh)
    value = service_cli.run_metadata_canary(
        repository="o/r", pr_number=1, head_sha=head,
        check_suite_id=1, check_run_id=2, run_id=3, job_id=4, artifact_id=5)
    assert value["evidence_gaps"] == ["CANARY_PR_REPOSITORY_MISMATCH"]


def test_metadata_canary_redacts_long_secret_like_transport_error(monkeypatch):
    head = "a" * 40
    secret = "token_" + "x" * 5000

    class FakeGh:
        def get_pr(self, *args): raise RuntimeError(secret)

    monkeypatch.setattr(service_cli, "GhCliTransport", FakeGh)
    value = service_cli.run_metadata_canary(
        repository="o/r", pr_number=1, head_sha=head,
        check_suite_id=1, check_run_id=2, run_id=3, job_id=4, artifact_id=5)
    assert value["evidence_gaps"] == ["CANARY_METADATA_READ_FAILED"]
    assert secret not in json.dumps(value)


def test_metadata_canary_rejection_is_a_failed_cli_exit(monkeypatch):
    monkeypatch.setattr(service_cli, "run_metadata_canary", lambda **_: {
        "status": "CANARY_REJECTED", "claim_ceiling": "CI_EVIDENCE_ONLY"
    })
    assert service_cli.main(["ci-metadata-canary", "--json"]) == 2


def test_github_binary_read_rejects_oversized_archive_before_materializing(monkeypatch):
    import tempfile
    from reviewer.github import GhCliTransport, GitHubError

    payload = tempfile.TemporaryFile()
    payload.write(b"x" * 17)
    payload.seek(0)

    class Process:
        stdout = payload
        stderr = tempfile.TemporaryFile()

        def wait(self, **_):
            return 0

        def kill(self):
            return None

    monkeypatch.setattr("reviewer.github.subprocess.Popen", lambda *a, **k: Process())
    with pytest.raises(GitHubError, match="byte limit"):
        GhCliTransport("gh")._get_bytes("repos/o/r/actions/artifacts/1/zip", max_bytes=16)


def test_status_reports_launch_and_durable_queue(monkeypatch,tmp_path):
    cfg=config(tmp_path)
    monkeypatch.setattr(service_cli,"_launchctl",lambda *a:SimpleNamespace(returncode=0))
    class S:
        def status(self):return {"status":"IDLE","queued":0}
    monkeypatch.setattr(service_cli,"build_service",lambda *a,**k:S())
    value=service_cli.service_status(cfg)
    assert value["running"] is True and value["repositories"][0]["queued"]==0


def test_bounded_log_rotation(tmp_path):
    path=tmp_path/"service.log";path.write_bytes(b"x"*service_cli.MAX_LOG_BYTES)
    service_cli._append_log(path,{"status":"IDLE"})
    assert path.with_suffix(".log.1").exists()


def test_start_retries_launchctl_bootstrap_race(monkeypatch,tmp_path):
    monkeypatch.setattr(service_cli,"install",lambda p:tmp_path/"agent.plist")
    monkeypatch.setattr(service_cli.time,"sleep",lambda n:None)
    calls=[]
    def launch(*args):
        calls.append(args)
        code=5 if args[0]=="bootstrap" and sum(1 for x in calls if x[0]=="bootstrap")==1 else 0
        return SimpleNamespace(returncode=code,stderr="")
    monkeypatch.setattr(service_cli,"_launchctl",launch)
    assert service_cli.start(tmp_path/"config.json").returncode==0
    assert sum(1 for x in calls if x[0]=="bootstrap")==2


def test_stop_requires_label_readback_to_disappear(monkeypatch):
    calls = []
    def launch(*args):
        calls.append(args)
        if args[0] == "bootout":
            return SimpleNamespace(returncode=0, stderr="", stdout="")
        return SimpleNamespace(returncode=1 if len(calls) >= 3 else 0, stderr="", stdout="")
    monkeypatch.setattr(service_cli, "_launchctl", launch)
    result = service_cli.stop()
    assert result.returncode == 0
    assert calls[0][0] == "bootout" and calls[1][0] == "print"


def test_stop_fails_when_label_stays_present(monkeypatch):
    monkeypatch.setattr(service_cli, "STOP_READBACK_TIMEOUT_SECONDS", 0)
    monkeypatch.setattr(service_cli, "_launchctl",
                        lambda *args: SimpleNamespace(returncode=0, stderr="", stdout=""))
    assert service_cli.stop().returncode != 0


def test_history_reconciliation_requires_exact_prompt_hash(monkeypatch,tmp_path):
    from reviewer.attempt import prepare_attempt,mark_dispatching
    cfg=config(tmp_path); identity=["James3014/Nexus-new",7,"h","b","m"]
    _,path=prepare_attempt(cfg.state_root,identity,"context","expected",{},attempt_id="a",browser_profile="p")
    mark_dispatching(path)
    monkeypatch.setattr(service_cli,"_opencli_json",lambda *a,**k:[{"Id":"c"}] if "history" in a[2] else [{"Role":"User","Text":"different"},{"Role":"Assistant","Text":"{}","Generating":False}])
    monkeypatch.setattr(service_cli,"_browser_exact_response",lambda *a,**k:None)
    assert service_cli.reconcile_semantic_history(cfg,"James3014/Nexus-new")==[]
    assert json.loads(path.read_text())["state"]=="DISPATCHING"


def test_browser_reconciliation_requires_exact_dom_hash(monkeypatch):
    calls=[]
    def browser(executable,profile,args):
        calls.append(args)
        return {} if "open" in args else {"response_b64":base64.b64encode(b'{"schema":"reviewer.semantic_response.v1"}').decode()}
    monkeypatch.setattr(service_cli,"_opencli_browser",browser)
    value=service_cli._browser_exact_response("opencli","profile","conversation","a"*64)
    assert value=='{"schema":"reviewer.semantic_response.v1"}'
    assert calls[0][0:3]==["reviewer-reconcile","open","https://chatgpt.com/c/conversation"]
    assert "a"*64 in calls[1][-1]


def test_history_reconciliation_uses_bounded_ephemeral_session(monkeypatch,tmp_path):
    cfg=config(tmp_path); seen=[]
    def read(*args):
        seen.append(args[2]); return []
    monkeypatch.setattr(service_cli,"_opencli_json",read)
    assert service_cli.reconcile_semantic_history(cfg,"James3014/Nexus-new")==[]
    # No attempt means no transport call; this assertion documents the helper
    # command shape through source-level behavior in the recovery test below.
    assert seen==[]


def test_history_reconciliation_accepts_exact_dom_response(monkeypatch,tmp_path):
    from reviewer.attempt import prepare_attempt,mark_dispatching
    cfg=config(tmp_path); identity=["James3014/Nexus-new",7,"h","b","m"]
    _,path=prepare_attempt(cfg.state_root,identity,"context","expected",{},attempt_id="a",browser_profile="p")
    mark_dispatching(path)
    semantic=json.dumps({"schema":"reviewer.semantic_response.v1","status":"PASS","summary":"ok","findings":[],"evidence_gaps":[]})
    seen=[]
    def read(*a,**k):
        seen.append(a[2]); return [{"Id":"c"}] if "history" in a[2] else [{"Role":"User","Text":"truncated"}]
    monkeypatch.setattr(service_cli,"_opencli_json",read)
    monkeypatch.setattr(service_cli,"_browser_exact_response",lambda *a,**k:semantic)
    class Item:
        review_identity=tuple(identity); findings=[]; risk="LOW"; snapshot=SimpleNamespace(source_identity="github",changed_files=())
    monkeypatch.setattr(service_cli,"scan",lambda *a,**k:(None,"observed",[Item()],None))
    recovered=service_cli.reconcile_semantic_history(cfg,"James3014/Nexus-new")
    assert len(recovered)==1 and recovered[0]["receipt"]["semantic_result"]["status"]=="PASS"
    assert all("ephemeral" in command for command in seen)
    assert json.loads(path.read_text())["state"]=="COMPLETED"


def test_detail_failure_still_uses_exact_dom_response(monkeypatch,tmp_path):
    from reviewer.attempt import prepare_attempt,mark_dispatching
    cfg=config(tmp_path); identity=["James3014/Nexus-new",7,"h","b","m"]
    _,path=prepare_attempt(cfg.state_root,identity,"context","expected",{},attempt_id="a",browser_profile="p")
    mark_dispatching(path)
    semantic=json.dumps({"schema":"reviewer.semantic_response.v1","status":"PASS","summary":"ok","findings":[],"evidence_gaps":[]})
    def read(*a,**k):
        if "history" in a[2]: return [{"Id":"c"}]
        raise RuntimeError("detail unavailable")
    monkeypatch.setattr(service_cli,"_opencli_json",read)
    monkeypatch.setattr(service_cli,"_browser_exact_response",lambda *a,**k:semantic)
    class Item:
        review_identity=tuple(identity); findings=[]; risk="LOW"; snapshot=SimpleNamespace(source_identity="github",changed_files=())
    monkeypatch.setattr(service_cli,"scan",lambda *a,**k:(None,"observed",[Item()],None))
    assert len(service_cli.reconcile_semantic_history(cfg,"James3014/Nexus-new"))==1
    assert json.loads(path.read_text())["state"]=="COMPLETED"


def test_exact_response_with_drifted_context_finishes_failed(monkeypatch,tmp_path):
    from reviewer.attempt import prepare_attempt,mark_dispatching
    cfg=config(tmp_path); identity=["James3014/Nexus-new",7,"h","b","old-main"]
    _,path=prepare_attempt(cfg.state_root,identity,"context","expected",{},attempt_id="a",browser_profile="p")
    mark_dispatching(path)
    semantic=json.dumps({"schema":"reviewer.semantic_response.v1","status":"PASS","summary":"ok","findings":[],"evidence_gaps":[]})
    monkeypatch.setattr(service_cli,"_opencli_json",lambda *a,**k:[{"Id":"c"}] if "history" in a[2] else [])
    monkeypatch.setattr(service_cli,"_browser_exact_response",lambda *a,**k:semantic)
    monkeypatch.setattr(service_cli,"scan",lambda *a,**k:(None,"observed",[],None))
    recovered=service_cli.reconcile_semantic_history(cfg,"James3014/Nexus-new")
    assert recovered[0]["terminal"]=="STALE_CONTEXT_AFTER_COMPLETION"
    record=json.loads(path.read_text())
    assert record["state"]=="FAILED" and record["retry_safe"] is False


def test_explicit_conversation_id_bypasses_broken_history(monkeypatch,tmp_path):
    from reviewer.attempt import prepare_attempt,mark_dispatching
    cfg=config(tmp_path); identity=["James3014/Nexus-new",7,"h","b","m"]
    _,path=prepare_attempt(cfg.state_root,identity,"context","expected",{},attempt_id="a",browser_profile="p")
    mark_dispatching(path)
    semantic=json.dumps({"schema":"reviewer.semantic_response.v1","status":"PASS","summary":"ok","findings":[],"evidence_gaps":[]})
    commands=[]
    def read(*a,**k):
        commands.append(a[2]); return []
    monkeypatch.setattr(service_cli,"_opencli_json",read)
    monkeypatch.setattr(service_cli,"_browser_exact_response",lambda executable,profile,conversation,prompt: semantic if conversation=="known" else None)
    class Item:
        review_identity=tuple(identity); findings=[]; risk="LOW"; snapshot=SimpleNamespace(source_identity="github",changed_files=())
    monkeypatch.setattr(service_cli,"scan",lambda *a,**k:(None,"observed",[Item()],None))
    assert len(service_cli.reconcile_semantic_history(cfg,"James3014/Nexus-new",["known"]))==1
    assert not any("history" in command for command in commands)


def test_apply_terminal_reconciliation_unblocks_scheduler(tmp_path):
    cfg=config(tmp_path); service=service_cli.build_service
    class Store:
        def __init__(self): self.value={"queue":{"k":{"review_identity":["r",1,"h","b","m"],"state":"outcome_unknown"}}}
        def load(self): return self.value
        def save(self,value): self.value=value
    fake=SimpleNamespace(store=Store())
    service_cli._apply_recovered(fake,[{"identity":["r",1,"h","b","m"],"receipt":None,"terminal":"STALE_CONTEXT_AFTER_COMPLETION"}])
    item=fake.store.value["queue"]["k"]
    assert item["state"]=="semantic_failed" and item["retry_safe"] is False


def test_build_service_end_to_end_persists_receipts_and_deduplicates(monkeypatch, tmp_path):
    from reviewer.config import BootstrapPolicy

    class FakeGitHub:
        def __init__(self):
            self.comments = []
            self.comment_writes = 0
            self.main = "m"
            self.pr = {"number": 1, "title": "ready", "body": "", "draft": False,
                       "mergeable": True, "state": "OPEN",
                       "base": {"ref": "main", "sha": "m"},
                       "head": {"ref": "feature", "sha": "h"}, "labels": []}
        def auth_preflight(self): return None
        def get_ref(self, repo, branch): return {"object": {"sha": self.main}}
        def list_open_prs(self, repo): return [self.pr]
        def get_pr(self, repo, number): return self.pr
        def list_files(self, repo, number): return [{"filename": "src/example.py"}]
        def list_checks(self, repo, sha): return []
        def get_patch(self, repo, number): return "diff --git a/src/example.py b/src/example.py\n+1"
        def list_comments(self, repo, number): return list(self.comments)
        def create_comment(self, repo, number, body):
            self.comment_writes += 1
            comment = {"id": self.comment_writes, "body": body,
                       "html_url": f"https://example.test/comments/{self.comment_writes}"}
            self.comments.append(comment)
            return comment

    class FakeSemanticTransport:
        calls = 0
        def __init__(self, executable="opencli", profile=None):
            self.executable, self.profile = executable, profile
            self.session_mode = "ephemeral"
        def version(self): return "fake-1"
        def safe_argv(self):
            return [self.executable, "chatgpt", "ask", "<prompt>", "--site-session", "ephemeral", "-f", "json"]
        def invoke(self, prompt):
            type(self).calls += 1
            raw = json.dumps({"schema": "reviewer.semantic_response.v1", "status": "PASS",
                              "summary": "ok", "findings": [], "evidence_gaps": []})
            return TransportResult("REVIEW_COMPLETED", raw, executable=self.executable,
                                   profile=self.profile, version="fake-1", argv=self.safe_argv())

    gh = FakeGitHub()
    monkeypatch.setattr(service_cli, "GhCliTransport", lambda: gh)
    monkeypatch.setattr(service_cli, "OpenCLITransport", FakeSemanticTransport)
    monkeypatch.setattr(service_cli, "preflight_opencli",
                        lambda executable: PreflightResult("READY", profile={"id": "profile-1"}))
    monkeypatch.setattr(service_cli, "_daemon_restart", lambda executable: True)
    cfg = ReviewerConfig(repositories=("owner/repo",), poll_interval_seconds=5,
                         state_root=tmp_path / "state", log_path=tmp_path / "service.log",
                         bootstrap=BootstrapPolicy("bounded", 1))

    first = service_cli.run_once(cfg, bootstrap_canary=True)
    assert first["results"][0]["status"] == "COMPLETE"
    assert FakeSemanticTransport.calls == 1 and gh.comment_writes == 1
    receipts = list((cfg.state_root / "reviews").glob("*.json"))
    publications = list((cfg.state_root / "publication-receipts").glob("*.json"))
    assert len(receipts) == 1 and json.loads(receipts[0].read_text())["schema"] == "reviewer.pre_review.v1"
    assert len(publications) == 1 and json.loads(publications[0].read_text())["schema"] == "reviewer.publication_receipt.v1"

    assert service_cli.run_once(cfg)["results"][0]["status"] == "IDLE"
    assert service_cli.run_once(cfg)["results"][0]["status"] == "IDLE"
    assert FakeSemanticTransport.calls == 1 and gh.comment_writes == 1


def test_reconcile_recovers_failed_opencli_process_failure_with_exact_prompt(monkeypatch, tmp_path):
    import hashlib
    from reviewer.attempt import prepare_attempt, mark_dispatching, finish_attempt
    from reviewer.receipt import persist_failure
    cfg = config(tmp_path)
    identity = ["James3014/Nexus-new", 7, "h", "b", "m"]
    prompt = "exact user prompt for review"
    prompt_sha = hashlib.sha256(prompt.encode()).hexdigest()
    _, path = prepare_attempt(cfg.state_root, identity, "context-pack", prompt_sha, {},
                              attempt_id="failed-attempt-1", browser_profile="profile-p")
    mark_dispatching(path)
    finish_attempt(path, "FAILED", result={"transport_result": "OPENCLI_PROCESS_FAILURE", "parse_result": "NOT_ATTEMPTED"}, retry_safe=False)
    fail_path = persist_failure(cfg.state_root, "failed-attempt-1", {
        "review_identity": identity, "context_pack_sha256": "context-pack",
        "prompt_sha256": prompt_sha, "transport_result": "OPENCLI_PROCESS_FAILURE",
        "parse_result": "NOT_ATTEMPTED", "claim_ceiling": "PRE_REVIEW_ONLY", "retry_safe": False,
    })
    assert fail_path.exists()

    semantic = json.dumps({"schema": "reviewer.semantic_response.v1", "status": "PASS", "summary": "ok", "findings": [], "evidence_gaps": []})
    monkeypatch.setattr(service_cli, "_opencli_json", lambda *a, **k: [{"Id": "conv-1"}] if "history" in a[2] else [
        {"Role": "User", "Text": prompt},
        {"Role": "Assistant", "Text": semantic, "Generating": False},
    ])
    class Item:
        review_identity = tuple(identity); findings = []; risk = "LOW"; snapshot = SimpleNamespace(source_identity="github", changed_files=())
    monkeypatch.setattr(service_cli, "scan", lambda *a, **k: (None, "observed", [Item()], None))

    recovered = service_cli.reconcile_semantic_history(cfg, "James3014/Nexus-new")
    assert len(recovered) == 1
    assert recovered[0]["attempt_id"] == "failed-attempt-1"
    assert recovered[0]["receipt"]["semantic_result"]["status"] == "PASS"
    assert recovered[0]["receipt"]["transport_result"] == "REVIEW_COMPLETED"
    assert recovered[0]["receipt"]["reconciliation"] == "opencli_history_exact_prompt_sha256"

    attempt_record = json.loads(path.read_text())
    assert attempt_record["state"] == "COMPLETED"
    assert attempt_record["reconciled"] is True

    # Durable first-pass failure JSON is preserved
    assert fail_path.exists()
    fail_record = json.loads(fail_path.read_text())
    assert fail_record["transport_result"] == "OPENCLI_PROCESS_FAILURE"


def test_reconcile_uses_journaled_conversation_id_when_history_is_empty(monkeypatch, tmp_path):
    import hashlib
    from reviewer.attempt import prepare_attempt, mark_dispatching, finish_attempt
    cfg = config(tmp_path)
    identity = ["James3014/Nexus-new", 7, "h", "b", "m"]
    prompt = "exact user prompt for journal recovery"
    prompt_sha = hashlib.sha256(prompt.encode()).hexdigest()
    _, path = prepare_attempt(cfg.state_root, identity, "context-pack", prompt_sha, {},
                              attempt_id="journal-conversation-attempt", browser_profile="profile-p")
    mark_dispatching(path)
    finish_attempt(path, "FAILED", result={
        "transport_result": "OPENCLI_PROCESS_FAILURE",
        "parse_result": "NOT_ATTEMPTED",
        "conversation_id": "conv-journaled",
    }, retry_safe=False)

    semantic = json.dumps({"schema": "reviewer.semantic_response.v1", "status": "PASS", "summary": "ok", "findings": [], "evidence_gaps": []})
    calls = []
    def read_opencli(*a, **k):
        calls.append(a[2])
        assert "history" not in a[2]
        assert "conv-journaled" in a[2]
        return [
            {"Role": "User", "Text": prompt},
            {"Role": "Assistant", "Text": semantic, "Generating": False},
        ]
    monkeypatch.setattr(service_cli, "_opencli_json", read_opencli)
    class Item:
        review_identity = tuple(identity); findings = []; risk = "LOW"; snapshot = SimpleNamespace(source_identity="github", changed_files=())
    monkeypatch.setattr(service_cli, "scan", lambda *a, **k: (None, "observed", [Item()], None))

    recovered = service_cli.reconcile_semantic_history(cfg, "James3014/Nexus-new")
    assert len(recovered) == 1
    assert recovered[0]["receipt"]["conversation_id"] == "conv-journaled"
    assert recovered[0]["receipt"]["semantic_result"]["status"] == "PASS"
    assert all("history" not in call for call in calls)
    assert json.loads(path.read_text())["state"] == "COMPLETED"


def test_reconcile_negative_cases_for_failed_attempts(monkeypatch, tmp_path):
    import hashlib
    from reviewer.attempt import prepare_attempt, mark_dispatching, finish_attempt
    cfg = config(tmp_path)
    identity = ["James3014/Nexus-new", 7, "h", "b", "m"]
    prompt = "user prompt"
    prompt_sha = hashlib.sha256(prompt.encode()).hexdigest()

    # Case 1: Unrelated FAILED transport result (e.g. OPENCLI_TIMEOUT or REVIEW_PARSE_FAILED)
    _, p1 = prepare_attempt(cfg.state_root, identity, "c", prompt_sha, {}, attempt_id="timeout-1", browser_profile="p")
    mark_dispatching(p1)
    finish_attempt(p1, "FAILED", result={"transport_result": "OPENCLI_TIMEOUT", "parse_result": "NOT_ATTEMPTED"}, retry_safe=False)

    # Case 2: Mismatched prompt
    _, p2 = prepare_attempt(cfg.state_root, identity, "c", prompt_sha, {}, attempt_id="mismatch-prompt", browser_profile="p")
    mark_dispatching(p2)
    finish_attempt(p2, "FAILED", result={"transport_result": "OPENCLI_PROCESS_FAILURE", "parse_result": "NOT_ATTEMPTED"}, retry_safe=False)

    # Case 3: Generating/incomplete assistant response
    _, p3 = prepare_attempt(cfg.state_root, identity, "c", "different_prompt_sha", {}, attempt_id="generating-1", browser_profile="p")
    mark_dispatching(p3)
    finish_attempt(p3, "FAILED", result={"transport_result": "OPENCLI_PROCESS_FAILURE", "parse_result": "NOT_ATTEMPTED"}, retry_safe=False)

    semantic = json.dumps({"schema": "reviewer.semantic_response.v1", "status": "PASS", "summary": "ok", "findings": [], "evidence_gaps": []})
    def read_opencli(*a, **k):
        if "history" in a[2]:
            return [{"Id": "conv-mismatch"}]
        return [
            {"Role": "User", "Text": "completely different prompt text"},
            {"Role": "Assistant", "Text": semantic, "Generating": False},
        ]
    monkeypatch.setattr(service_cli, "_opencli_json", read_opencli)
    monkeypatch.setattr(service_cli, "_browser_exact_response", lambda *a, **k: None)

    recovered = service_cli.reconcile_semantic_history(cfg, "James3014/Nexus-new")
    assert recovered == []
    assert json.loads(p1.read_text())["state"] == "FAILED"
    assert json.loads(p2.read_text())["state"] == "FAILED"
    assert json.loads(p3.read_text())["state"] == "FAILED"


def test_apply_recovered_exact_key_hostile_cfi_lineage(tmp_path):
    from reviewer.receipt import build_ci_failure_evidence
    from reviewer.unattended import UnattendedReviewService
    identity = ["James3014/Nexus-new", 7, "h", "b", "m"]
    ci = build_ci_failure_evidence(
        repository="James3014/Nexus-new", pr_number=7, base_sha="b", head_sha="h",
        current_main_sha="m", canonical_disposition="NEW_REGRESSION",
        expected_check_run_id=1, expected_run_id=2, expected_artifact_identity="art-1",
        checks=[{"name": "check1", "status": "failure", "check_run_id": 1,
                 "run_id": 2, "external_id": "art-1", "head_sha": "h"}],
    )
    cfi_receipt = {
        "schema": "reviewer.pre_review.v1",
        "review_identity": identity,
        "semantic_result": {
            "schema": "reviewer.semantic_response.v1",
            "status": "BLOCKED",
            "summary": "cfi blocked",
            "findings": [],
            "evidence_gaps": [],
        },
        "ci_failure_evidence": ci,
    }
    old_key = "old-generic-failed-key"
    current_cfi_key = "current-cfi-fingerprint-key"

    calls = []
    current_item = {"review_identity": identity, "disposition": "REVIEW_READY",
                    "checks": [{"name": "check1", "status": "failure", "check_run_id": 1, "run_id": 2}]}
    service = UnattendedReviewService(
        repository="James3014/Nexus-new",
        discover=lambda: [current_item],
        review=lambda i: None,
        publish=lambda i, r: calls.append(("publish", i, r)) or {"status": "PUBLISHED"},
        root=tmp_path / "state",
    )
    # Prime baseline
    assert service.run_once()["status"] == "IDLE"

    # Setup 2 queue entries with the SAME 5-field identity
    state = service.store.load()
    state["queue"] = {
        old_key: {
            "review_identity": list(identity),
            "state": "semantic_failed",
            "last_error": "OPENCLI_PROCESS_FAILURE",
            "retry_safe": False,
        },
        current_cfi_key: {
            "review_identity": list(identity),
            "state": "outcome_unknown",
            "retry_safe": False,
        },
    }
    service.store.save(state)

    # Recovered result specifies the exact current_cfi_key
    recovered = [{"identity": identity, "identity_key": current_cfi_key, "receipt": cfi_receipt}]
    service_cli._apply_recovered(service, recovered)

    # Old lineage remains strictly untouched
    saved = service.store.load()["queue"]
    assert saved[old_key]["state"] == "semantic_failed"
    assert saved[old_key]["last_error"] == "OPENCLI_PROCESS_FAILURE"
    assert saved[old_key]["retry_safe"] is False

    # Current CFI item moved to publication_pending
    assert saved[current_cfi_key]["state"] == "publication_pending"
    assert saved[current_cfi_key]["semantic_result"] == cfi_receipt

    # Scheduler publishes the current CFI item exactly once
    result = service.run_once()
    assert result["status"] == "PUBLISHED"
    assert len(calls) == 1

    # Second run deduplicates
    assert service.run_once()["status"] == "IDLE"
    assert len(calls) == 1
    assert service.store.load()["queue"][old_key]["state"] == "semantic_failed"


def test_apply_recovered_legacy_ambiguity_fails_closed(tmp_path):
    identity = ["James3014/Nexus-new", 7, "h", "b", "m"]
    class Store:
        def __init__(self):
            self.value = {
                "queue": {
                    "k1": {"review_identity": list(identity), "state": "semantic_failed", "last_error": "ERR1"},
                    "k2": {"review_identity": list(identity), "state": "outcome_unknown", "last_error": "ERR2"},
                }
            }
        def load(self): return self.value
        def save(self, v): self.value = v

    fake = SimpleNamespace(store=Store())
    # Legacy recovered without identity_key when multiple items share identity -> fail closed
    service_cli._apply_recovered(fake, [{"identity": identity, "receipt": {"dummy": "receipt"}}])
    assert fake.store.value["queue"]["k1"]["state"] == "semantic_failed"
    assert fake.store.value["queue"]["k2"]["state"] == "outcome_unknown"
