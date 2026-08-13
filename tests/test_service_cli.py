import json
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


def test_run_once_delegates_without_manual_pr(monkeypatch,tmp_path):
    cfg=config(tmp_path); seen=[]
    class S:
        def run_once(self):seen.append("run");return {"status":"IDLE"}
    monkeypatch.setattr(service_cli,"build_service",lambda config,repository,bootstrap_canary=False:S())
    value=service_cli.run_once(cfg)
    assert seen==["run"] and value["semantic_concurrency"]==1


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
