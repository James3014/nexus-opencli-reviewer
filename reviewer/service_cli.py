"""Installed, user-level unattended Reviewer service operator surface."""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

from .attempt import COMPLETED, DISPATCHING, discover_unfinished, finish_attempt
from .config import DEFAULT_CONFIG_PATH, ReviewerConfig, load_config, save_config
from .github import GhCliTransport
from .opencli import OpenCLITransport
from .preflight import preflight_opencli
from .publication import publish_review
from .receipt import persist_receipt
from .runtime import RuntimeSupervisor
from .scan import review_ready, scan
from .semantic import parse_response, SemanticParseError
from .unattended import ServicePolicy, UnattendedReviewService

SERVICE_LABEL = "com.nexus.opencli-reviewer"
MAX_LOG_BYTES = 2 * 1024 * 1024
REPO_ROOT = Path(__file__).resolve().parents[1]


def _safe_repo(repo: str) -> str:
    return repo.replace("/", "_")


def _append_log(path: Path, event: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size >= MAX_LOG_BYTES:
        rotated = path.with_suffix(path.suffix + ".1")
        rotated.unlink(missing_ok=True)
        path.replace(rotated)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")


def _daemon_restart(executable: str) -> bool:
    try:
        result = subprocess.run([executable, "daemon", "restart"], check=False,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=20)
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _opencli_json(executable: str, profile: str, args: list[str]) -> Any:
    env=os.environ.copy();env["OPENCLI_PROFILE"]=profile
    result=subprocess.run([executable,*args,"-f","json"],check=False,capture_output=True,
                          text=True,timeout=45,env=env)
    if result.returncode:
        raise RuntimeError("OPENCLI_READ_FAILURE")
    return json.loads(result.stdout)


def reconcile_semantic_history(config: ReviewerConfig, repository: str) -> list[dict[str, Any]]:
    """Recover exact dispatched responses from read-only ChatGPT history.

    A conversation is accepted only when SHA-256 of its complete User message
    equals the journaled prompt hash. No fuzzy title/time matching is allowed.
    """
    recovered=[]
    for attempt in discover_unfinished(config.state_root):
        if attempt.get("state") != DISPATCHING or attempt.get("review_identity", [None])[0] != repository:
            continue
        profile=str(attempt.get("browser_profile") or "")
        if not profile:
            continue
        try:
            history=_opencli_json(config.opencli_executable,profile,
                                  ["chatgpt","history","--limit","20","--site-session","persistent"])
        except Exception:
            continue
        match=None
        for row in history if isinstance(history,list) else []:
            conversation=row.get("Id") or row.get("id")
            if not conversation: continue
            try: detail=_opencli_json(config.opencli_executable,profile,["chatgpt","detail",str(conversation),"--site-session","persistent"])
            except Exception: continue
            user=next((x.get("Text") for x in detail if x.get("Role")=="User"),None) if isinstance(detail,list) else None
            assistant=next((x.get("Text") for x in reversed(detail) if x.get("Role")=="Assistant" and not x.get("Generating")),None) if isinstance(detail,list) else None
            if (isinstance(user,str) and isinstance(assistant,str)
                    and hashlib.sha256(user.encode()).hexdigest()==attempt.get("prompt_sha256")):
                match=(str(conversation),assistant);break
        if match is None: continue
        try: parsed=parse_response(match[1])
        except SemanticParseError: continue
        identity=attempt["review_identity"]
        _,observed,items,_=scan(repository,GhCliTransport())
        item=next((x for x in items if list(x.review_identity)==identity),None)
        if item is None: continue
        raw_sha=hashlib.sha256(match[1].encode()).hexdigest()
        receipt_id=hashlib.sha256(json.dumps({"identity":identity,"context":attempt["context_pack_sha256"],"prompt":attempt["prompt_sha256"],"raw":raw_sha},sort_keys=True,separators=(",",":" )).encode()).hexdigest()
        receipt={"schema":"reviewer.pre_review.v1","receipt_id":receipt_id,"repository":repository,
                 "pr_number":identity[1],"head_sha":identity[2],"base_sha":identity[3],"current_main_sha":identity[4],
                 "review_identity":identity,"source_observed_at":observed,"source_identity":item.snapshot.source_identity,
                 "deterministic_findings":item.findings,"risk":item.risk,"changed_files":list(item.snapshot.changed_files),
                 "context_pack_sha256":attempt["context_pack_sha256"],"prompt_sha256":attempt["prompt_sha256"],
                 "opencli_executable":attempt.get("opencli_executable"),"opencli_version":attempt.get("opencli_version"),
                 "browser_profile":profile,"session_mode":attempt.get("session_mode","ephemeral"),"safe_argv":attempt.get("safe_argv",[]),
                 "invocation_started_at":attempt.get("dispatching_at"),"invocation_finished_at":datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z"),
                 "transport_result":"REVIEW_COMPLETED","outcome_unknown":False,"retry_safe":False,
                 "raw_response_sha256":raw_sha,"parse_result":"PARSED","semantic_result":parsed,
                 "conversation_id":match[0],"reconciliation":"opencli_history_exact_prompt_sha256","claim_ceiling":"PRE_REVIEW_ONLY"}
        receipt_path=persist_receipt(config.state_root,receipt)
        attempt_path=config.state_root/"reviews"/"attempts"/f"{attempt['attempt_id']}.json"
        finish_attempt(attempt_path,COMPLETED,result={"transport_result":"REVIEW_COMPLETED","parse_result":"PARSED","reconciled":True})
        recovered.append({"attempt_id":attempt["attempt_id"],"identity":identity,"receipt":receipt,"path":str(receipt_path)})
    return recovered


def build_service(config: ReviewerConfig, repository: str, *, bootstrap_canary: bool = False) -> UnattendedReviewService:
    gh = GhCliTransport()
    service_root = config.state_root / "unattended" / _safe_repo(repository)

    def discover():
        _, _, items, _ = scan(repository, gh, persist_state=True, state_root=config.state_root)
        return items

    def review(identity):
        supervisor = RuntimeSupervisor(
            lambda: preflight_opencli(config.opencli_executable),
            lambda: _daemon_restart(config.opencli_executable),
            base_backoff=30, max_backoff=1800,
        )
        health = supervisor.recover()
        if not health.ready:
            raise RuntimeError(health.status)
        profile = (health.profile or {}).get("id") or (health.profile or {}).get("contextId") or (health.profile or {}).get("name")
        if not profile:
            raise RuntimeError("PROFILE_SELECTION_AMBIGUOUS")
        transport = OpenCLITransport(executable=config.opencli_executable, profile=str(profile))
        receipt, path = review_ready(
            repository, gh, int(identity[1]), semantic_transport=transport,
            state_root=config.state_root, profile_resolver=lambda: str(profile),
        )
        value = dict(receipt)
        value["evidence_path"] = str(path)
        return value

    def publish(identity, receipt):
        if not config.publication_enabled:
            return {"status": "COMPLETE", "publication": "DISABLED"}
        path = publish_review(config.state_root, gh, dict(receipt))
        return {"status": "PUBLISHED", "evidence_path": str(path)}

    return UnattendedReviewService(
        repository=repository, discover=discover, review=review, publish=publish,
        root=service_root,
        policy=ServicePolicy(
            poll_interval_seconds=config.poll_interval_seconds,
            bootstrap_canary=(bootstrap_canary or (config.bootstrap.mode == "bounded" and config.bootstrap.max_reviews == 1)),
            max_retries=1000000,
            backoff_seconds=30,
        ),
    )


def run_once(config: ReviewerConfig, *, bootstrap_canary: bool = False) -> dict[str, Any]:
    results = []
    for repository in config.repositories:
        service = build_service(config, repository, bootstrap_canary=bootstrap_canary)
        recovered=reconcile_semantic_history(config,repository)
        if recovered:
            state=service.store.load()
            for value in recovered:
                for item in state.get("queue",{}).values():
                    if item.get("review_identity")==value["identity"]:
                        item["semantic_result"]=value["receipt"]
                        item["state"]="publication_pending"
                        item["retry_safe"]=False
            service.store.save(state)
        result = service.run_once()
        results.append({"repository": repository, **result})
        # One semantic/publication path across all repositories per cycle.
        if result.get("status") not in {"IDLE", "DISCOVERY_FAILED", "RETRY_WAIT", "PUBLICATION_RETRY_WAIT"}:
            break
    value = {"schema": "reviewer.unattended_run.v1", "results": results,
             "semantic_concurrency": 1, "state_root": str(config.state_root)}
    _append_log(config.log_path, value)
    return value


def service_status(config: ReviewerConfig) -> dict[str, Any]:
    launch = _launchctl("print", f"gui/{os.getuid()}/{SERVICE_LABEL}")
    repos = []
    for repository in config.repositories:
        service = build_service(config, repository)
        repos.append(service.status())
    return {
        "schema": "reviewer.unattended_status.v1", "service": SERVICE_LABEL,
        "running": launch.returncode == 0, "repositories": repos,
        "semantic_concurrency": 1, "config_path": str(DEFAULT_CONFIG_PATH),
        "state_root": str(config.state_root), "log_path": str(config.log_path),
        "unfinished_semantic_attempts": discover_unfinished(config.state_root),
    }


def launch_agent_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{SERVICE_LABEL}.plist"


def _plist_xml(config_path: Path) -> str:
    args = [sys.executable, "-m", "reviewer.service_cli", "daemon", "--config", str(config_path)]
    arg_xml = "".join(f"<string>{html.escape(value)}</string>" for value in args)
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{SERVICE_LABEL}</string>
<key>ProgramArguments</key><array>{arg_xml}</array>
<key>WorkingDirectory</key><string>{html.escape(str(REPO_ROOT))}</string>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>ProcessType</key><string>Background</string><key>ThrottleInterval</key><integer>30</integer>
<key>StandardOutPath</key><string>/dev/null</string><key>StandardErrorPath</key><string>/dev/null</string>
<key>EnvironmentVariables</key><dict><key>PYTHONDONTWRITEBYTECODE</key><string>1</string><key>PYTHONPATH</key><string>{html.escape(str(REPO_ROOT))}</string><key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/Users/jameschen/.npm-global/bin:/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
</dict></plist>\n'''


def install(config_path: str | Path) -> Path:
    path = Path(config_path).expanduser()
    config = load_config(path)
    save_config(config, path)
    target = launch_agent_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(_plist_xml(path), encoding="utf-8")
    target.chmod(0o600)
    return target


def _launchctl(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["launchctl", *args], check=False, capture_output=True, text=True, timeout=20)


def start(config_path: str | Path) -> subprocess.CompletedProcess[str]:
    plist = install(config_path)
    domain = f"gui/{os.getuid()}"
    _launchctl("bootout", f"{domain}/{SERVICE_LABEL}")
    result = _launchctl("bootstrap", domain, str(plist))
    if result.returncode != 0:
        time.sleep(1)
        result = _launchctl("bootstrap", domain, str(plist))
    return result


def stop() -> subprocess.CompletedProcess[str]:
    return _launchctl("bootout", f"gui/{os.getuid()}/{SERVICE_LABEL}")


def daemon(config: ReviewerConfig) -> None:
    stopping = False
    def halt(_sig, _frame):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, halt)
    signal.signal(signal.SIGINT, halt)
    while not stopping:
        run_once(config)
        deadline = time.monotonic() + config.poll_interval_seconds
        while not stopping and time.monotonic() < deadline:
            time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="reviewer-service")
    parser.add_argument("command", choices=("install", "start", "stop", "restart", "status", "run-once", "daemon", "logs", "reconcile"))
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    parser.add_argument("--bootstrap-canary", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    config = load_config(args.config)
    if args.command == "install": value = {"status": "INSTALLED", "path": str(install(args.config))}
    elif args.command == "start":
        result = start(args.config); value = {"status": "STARTED" if result.returncode == 0 else "START_FAILED", "detail": result.stderr.strip()}
    elif args.command == "stop":
        result = stop(); value = {"status": "STOPPED" if result.returncode == 0 else "STOP_FAILED", "detail": result.stderr.strip()}
    elif args.command == "restart":
        stop(); result = start(args.config); value = {"status": "RESTARTED" if result.returncode == 0 else "RESTART_FAILED", "detail": result.stderr.strip()}
    elif args.command == "status": value = service_status(config)
    elif args.command == "run-once": value = run_once(config, bootstrap_canary=args.bootstrap_canary)
    elif args.command == "logs": value = {"path": str(config.log_path), "recent": config.log_path.read_text(encoding="utf-8")[-12000:] if config.log_path.exists() else ""}
    elif args.command == "reconcile":
        # Semantic uncertainty is never guessed away by an unattended command.
        value = {"status": "RECONCILIATION_REQUIRED", "attempts": discover_unfinished(config.state_root)}
    else:
        daemon(config); return 0
    print(json.dumps(value, indent=2, sort_keys=True) if args.json else json.dumps(value, sort_keys=True))
    return 0 if value.get("status") not in {"START_FAILED", "STOP_FAILED", "RESTART_FAILED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
