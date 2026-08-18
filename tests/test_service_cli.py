import json
import base64
from pathlib import Path
from types import SimpleNamespace

from reviewer.config import ReviewerConfig, save_config
from reviewer import service_cli
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


def test_metadata_canary_rejects_pagination_limit(monkeypatch):
    class FakeGh:
        def _get(self, endpoint):
            if endpoint.endswith("check-suites/11"):
                return {"id": 11, "head_sha": "h"}
            if endpoint.endswith("check-runs/12"):
                return {"id": 12, "head_sha": "h"}
            if endpoint.endswith("actions/runs/13"):
                return {"id": 13, "head_sha": "h", "conclusion": "failure"}
            if endpoint.endswith("jobs?per_page=1&page=1"):
                return {"jobs": [{"id": 14}]}
            return {"artifacts": []}

    monkeypatch.setattr(service_cli, "GhCliTransport", FakeGh)
    value = service_cli.run_metadata_canary(
        repository="o/r", pr_number=1, head_sha="h", check_suite_id=11,
        check_run_id=12, run_id=13, job_id=14, artifact_id=15, max_records=1)
    assert value["status"] == "CANARY_REJECTED"
    assert "CANARY_PAGINATION_OR_RECORD_LIMIT" in value["evidence_gaps"]


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
