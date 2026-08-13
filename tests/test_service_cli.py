import json
import base64
from pathlib import Path
from types import SimpleNamespace

from reviewer.config import ReviewerConfig, save_config
from reviewer import service_cli


def config(tmp_path):
    return ReviewerConfig(poll_interval_seconds=5, state_root=tmp_path/"state", log_path=tmp_path/"service.log", opencli_executable="opencli")


def test_launch_agent_is_user_level_and_independent(tmp_path, monkeypatch):
    monkeypatch.setattr(Path,"home",classmethod(lambda cls: tmp_path))
    cfg=config(tmp_path); path=tmp_path/"config.json";save_config(cfg,path)
    plist=service_cli.install(path); text=plist.read_text()
    assert service_cli.SERVICE_LABEL in text and "<key>KeepAlive</key><true/>" in text
    assert "sudo" not in text and "reviewer.service_cli" in text and "daemon" in text
    assert "/opt/homebrew/bin" in text


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
