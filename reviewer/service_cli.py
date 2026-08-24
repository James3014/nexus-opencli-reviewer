"""Installed, user-level unattended Reviewer service operator surface."""
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .attempt import COMPLETED, DISPATCHING, discover_unfinished, finish_attempt
from .config import DEFAULT_CONFIG_PATH, ReviewerConfig, load_config, save_config
from .github import REPO_RE, GhCliTransport
from .opencli import OpenCLITransport
from .preflight import preflight_opencli
from .publication import publish_review
from .receipt import persist_receipt
from .runtime import RuntimeSupervisor
from .scan import review_ready, scan, _ci_evidence_for
from .semantic import SemanticParseError, parse_response
from .unattended import ServicePolicy, UnattendedReviewService

SERVICE_LABEL = "com.nexus.opencli-reviewer"
MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_CANARY_BYTES = 1024 * 1024
MAX_EVIDENCE_GAPS = 32
STOP_READBACK_TIMEOUT_SECONDS = 5.0
STOP_READBACK_INTERVAL_SECONDS = 0.1
# Live transport evidence: successful ChatGPT responses regularly need more
# than the previous 120s default, and aborted asks cluster at ~127-138s.
SEMANTIC_TIMEOUT_SECONDS = 240
REPO_ROOT = Path(__file__).resolve().parents[1]
SHA_RE = re.compile(r"[0-9a-f]{40}")


def _safe_repo(repo: str) -> str:
    return repo.replace("/", "_")


def _canary_get(transport: GhCliTransport, endpoint: str, *, max_bytes: int) -> Any:
    """Read one bounded JSON metadata response; never follows redirects."""
    if hasattr(transport, "gh"):
        try:
            result = subprocess.run([transport.gh, "api", endpoint], check=False,
                                    capture_output=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("CANARY_GET_FAILED") from exc
        if result.returncode:
            raise ValueError("CANARY_GET_FAILED")
        if len(result.stdout) > max_bytes:
            raise ValueError("CANARY_RESPONSE_BYTE_LIMIT")
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ValueError("CANARY_JSON_INVALID") from exc
    value = transport._get(endpoint)  # noqa: SLF001 - metadata-only test seam
    if len(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()) > max_bytes:
        raise ValueError("CANARY_RESPONSE_BYTE_LIMIT")
    return value


def _redacted_gap(exc: BaseException) -> str:
    """Return only a bounded typed gap; never expose transport exception text."""
    known = {
        "CANARY_GET_FAILED",
        "CANARY_RESPONSE_BYTE_LIMIT",
        "CANARY_JSON_INVALID",
    }
    message = exc.args[0] if len(exc.args) == 1 else None
    return (
        message
        if isinstance(message, str) and message in known
        else "CANARY_METADATA_READ_FAILED"
    )


def _pr_identity_gaps(
    pr: Any, repository: str, pr_number: int, head_sha: str
) -> tuple[list[str], str | None]:
    if not isinstance(pr, dict):
        return ["CANARY_PR_METADATA_SHAPE_INVALID"], None
    gaps: list[str] = []
    if pr.get("number") != pr_number:
        gaps.append("CANARY_PR_NUMBER_MISMATCH")
    base = pr.get("base")
    head = pr.get("head")
    if not isinstance(base, dict) or not isinstance(head, dict):
        return [*gaps, "CANARY_PR_BINDING_FIELDS_MISSING"], None
    base_repo = (
        (base.get("repo") or {}).get("full_name")
        if isinstance(base.get("repo"), dict)
        else None
    )
    head_repo = (
        (head.get("repo") or {}).get("full_name")
        if isinstance(head.get("repo"), dict)
        else None
    )
    if base_repo != repository or head_repo != repository:
        gaps.append("CANARY_PR_REPOSITORY_MISMATCH")
    base_sha = base.get("sha")
    if not isinstance(base_sha, str) or not SHA_RE.fullmatch(base_sha):
        gaps.append("CANARY_PR_BASE_SHA_INVALID")
        base_sha = None
    if head.get("sha") != head_sha:
        gaps.append("CANARY_PR_HEAD_MISMATCH")
    return gaps, base_sha


def run_metadata_canary(*, repository: str, pr_number: int, head_sha: str,
                        check_suite_id: int, check_run_id: int, run_id: int,
                        job_id: int, artifact_id: int, max_bytes: int = 65536,
                        max_records: int = 100) -> dict[str, Any]:
    """Acquire only exact GitHub check/run/job/artifact metadata."""
    if (not isinstance(repository, str) or not REPO_RE.fullmatch(repository)
            or type(pr_number) is not int or pr_number <= 0
            or not isinstance(head_sha, str) or not SHA_RE.fullmatch(head_sha)
            or any(type(value) is not int or value <= 0 for value in
                   (check_suite_id, check_run_id, run_id, job_id, artifact_id))
            or type(max_bytes) is not int or not 0 < max_bytes <= MAX_CANARY_BYTES
            or type(max_records) is not int or max_records <= 0 or max_records > 100):
        return {"status": "CANARY_REJECTED", "reason": "CANARY_INPUT_INVALID",
                "claim_ceiling": "CI_EVIDENCE_ONLY"}
    transport = GhCliTransport()
    gaps: list[str] = []
    metadata: dict[str, Any] = {}
    base_sha: str | None = None
    get_pr = getattr(transport, "get_pr", None)
    if not callable(get_pr):
        gaps.append("CANARY_PR_BINDING_UNAVAILABLE")
    else:
        try:
            pr_gaps, base_sha = _pr_identity_gaps(
                get_pr(repository, pr_number), repository, pr_number, head_sha
            )
            gaps.extend(pr_gaps)
        except Exception as exc:
            gaps.append(_redacted_gap(exc))
    if gaps:
        return {
            "status": "CANARY_REJECTED",
            "schema": "reviewer.ci_failure_evidence.v1",
            "repository": repository,
            "pr_number": pr_number,
            "head_sha": head_sha,
            "base_sha": base_sha,
            "check_suite_id": check_suite_id,
            "check_run_id": check_run_id,
            "run_id": run_id,
            "job_id": job_id,
            "artifact_id": artifact_id,
            "evidence_gaps": sorted(set(gaps))[:MAX_EVIDENCE_GAPS],
            "claim_ceiling": "CI_EVIDENCE_ONLY",
        }
    try:
        suite = _canary_get(transport, f"repos/{repository}/check-suites/{check_suite_id}", max_bytes=max_bytes)
        check = _canary_get(transport, f"repos/{repository}/check-runs/{check_run_id}", max_bytes=max_bytes)
        run = _canary_get(transport, f"repos/{repository}/actions/runs/{run_id}", max_bytes=max_bytes)
        jobs_page = _canary_get(transport, f"repos/{repository}/actions/runs/{run_id}/jobs?per_page={max_records}&page=1", max_bytes=max_bytes)
        artifacts_page = _canary_get(transport, f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page={max_records}&page=1", max_bytes=max_bytes)
        artifact = _canary_get(transport, f"repos/{repository}/actions/artifacts/{artifact_id}", max_bytes=max_bytes)
        metadata = {"check_suite": suite, "check_run": check, "workflow_run": run,
                    "jobs": jobs_page, "artifacts": artifacts_page, "artifact": artifact}
    except Exception as exc:
        gaps.append(_redacted_gap(exc))
    if metadata:
        suite, check, run = metadata["check_suite"], metadata["check_run"], metadata["workflow_run"]
        jobs_page, artifacts_page, artifact = metadata["jobs"], metadata["artifacts"], metadata["artifact"]
        jobs = jobs_page.get("jobs") if isinstance(jobs_page, dict) else None
        artifacts = artifacts_page.get("artifacts") if isinstance(artifacts_page, dict) else None
        if not isinstance(jobs, list) or not isinstance(artifacts, list):
            gaps.append("CANARY_METADATA_SHAPE_INVALID")
        else:
            if len(jobs) >= max_records or len(artifacts) >= max_records:
                gaps.append("CANARY_PAGINATION_OR_RECORD_LIMIT")
            if sum(isinstance(row, dict) and row.get("id") == job_id
                   and row.get("head_sha") == head_sha
                   and row.get("run_id") in (None, run_id) for row in jobs) != 1:
                gaps.append("CANARY_JOB_ID_MISMATCH_OR_AMBIGUOUS")
            if sum(isinstance(row, dict) and row.get("id") == artifact_id for row in artifacts) != 1:
                gaps.append("CANARY_ARTIFACT_ID_MISMATCH_OR_AMBIGUOUS")
        if not isinstance(suite, dict) or suite.get("id") != check_suite_id:
            gaps.append("CANARY_CHECK_SUITE_ID_MISMATCH")
        if not isinstance(check, dict) or check.get("id") != check_run_id:
            gaps.append("CANARY_CHECK_RUN_ID_MISMATCH")
        if not isinstance(run, dict) or run.get("id") != run_id:
            gaps.append("CANARY_WORKFLOW_RUN_ID_MISMATCH")
        for label, value in (("CHECK_SUITE", suite), ("CHECK_RUN", check), ("WORKFLOW_RUN", run)):
            if not isinstance(value, dict) or value.get("head_sha") != head_sha:
                gaps.append(f"CANARY_{label}_HEAD_MISMATCH")
        if isinstance(run, dict) and run.get("conclusion") not in {"failure", "cancelled", "timed_out"}:
            gaps.append("CANARY_RUN_NOT_TERMINAL_FAILURE")
        if isinstance(check, dict) and check.get("conclusion") not in {"failure", "cancelled", "timed_out", "action_required"}:
            gaps.append("CANARY_CHECK_NOT_TERMINAL_FAILURE")
        if isinstance(artifact, dict):
            if artifact.get("id") != artifact_id:
                gaps.append("CANARY_ARTIFACT_METADATA_ID_MISMATCH")
            if artifact.get("expired") is True:
                gaps.append("CANARY_ARTIFACT_EXPIRED")
            binding = artifact.get("workflow_run")
            if not isinstance(binding, dict) or binding.get("id") != run_id or binding.get("head_sha") != head_sha:
                gaps.append("CANARY_ARTIFACT_WORKFLOW_BINDING_MISMATCH")
            name = artifact.get("name")
            if isinstance(name, str) and name.startswith("exact-base-impact-"):
                suffix = name.removeprefix("exact-base-impact-")
                if len(suffix) == 40 and suffix != head_sha:
                    gaps.append("CANARY_ARTIFACT_NAME_HEAD_MISMATCH")
    return {"status": "CANARY_REJECTED" if gaps else "CANARY_METADATA_BOUND",
            "schema": "reviewer.ci_failure_evidence.v1", "repository": repository,
            "pr_number": pr_number, "head_sha": head_sha, "base_sha": base_sha,
            "check_suite_id": check_suite_id,
            "check_run_id": check_run_id, "run_id": run_id, "job_id": job_id,
            "artifact_id": artifact_id, "evidence_gaps": sorted(set(gaps))[:MAX_EVIDENCE_GAPS],
            "claim_ceiling": "CI_EVIDENCE_ONLY"}


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


def _opencli_browser(executable: str, profile: str, args: list[str]) -> Any:
    """Run one bounded, read-only Browser Bridge command."""
    env = os.environ.copy()
    env["OPENCLI_PROFILE"] = profile
    result = subprocess.run(
        [executable, "browser", *args], check=False, capture_output=True,
        text=True, timeout=45, env=env,
    )
    if result.returncode:
        raise RuntimeError("OPENCLI_BROWSER_READ_FAILURE")
    return json.loads(result.stdout)


def _browser_exact_response(executable: str, profile: str, conversation: str,
                            expected_prompt_sha256: str) -> str | None:
    """Recover a response only when a rendered User node hashes exactly.

    ChatGPT's history/detail surface can truncate long messages.  The Browser
    Bridge DOM retains the complete rendered message, but its outer container
    may add UI labels.  Hash every User container/descendant and return the
    Assistant text only after an exact journal-bound SHA-256 match.
    """
    session = "reviewer-reconcile"
    _opencli_browser(executable, profile, [
        session, "open", f"https://chatgpt.com/c/{conversation}",
        "--window", "background",
    ])
    expected = json.dumps(str(expected_prompt_sha256))
    script = f'''(async()=>{{
      const user=document.querySelector('[data-message-author-role="user"]');
      const assistant=document.querySelector('[data-message-author-role="assistant"]');
      if(!user||!assistant)return null;
      const candidates=[user,...user.querySelectorAll('*')];
      for(const node of candidates){{
        const text=node.textContent||'';
        const bytes=new TextEncoder().encode(text);
        const digest=await crypto.subtle.digest('SHA-256',bytes);
        const sha=Array.from(new Uint8Array(digest)).map(x=>x.toString(16).padStart(2,'0')).join('');
        if(sha==={expected}){{
          const response=new TextEncoder().encode(assistant.textContent||'');
          return {{response_b64:btoa(String.fromCharCode(...response))}};
        }}
      }}
      return null;
    }})()'''
    value = _opencli_browser(executable, profile, [session, "eval", script])
    if not isinstance(value, dict) or not isinstance(value.get("response_b64"), str):
        return None
    try:
        return base64.b64decode(value["response_b64"], validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        try:
            dfd = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


RECONCILE_MAX_MISSES = 3
# Automatic reconciliation is wall-time bounded per service cycle so read-only
# recovery of old attempts can never starve actionable scheduler work.
RECONCILE_CYCLE_BUDGET_SECONDS = 150.0


def _has_journal_conversation(record: dict[str, Any]) -> bool:
    res = record.get("result")
    conv = res.get("conversation_id") if isinstance(res, dict) else record.get("conversation_id")
    return bool(isinstance(conv, str) and conv)


def _attempt_timestamp(record: dict[str, Any]) -> str:
    return str(
        record.get("dispatching_at")
        or record.get("started_at")
        or record.get("created_at")
        or ""
    )


def _order_reconcilable_attempts(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Journaled-conversation attempts first, then newest failures first.

    A live failure must never starve behind old attempts whose conversation
    no longer exists; recency is the best available recovery prior.
    """
    records.sort(key=_attempt_timestamp, reverse=True)
    records.sort(key=lambda record: 0 if _has_journal_conversation(record) else 1)
    return records


def _discover_reconcilable_attempts(root: Path, repository: str) -> list[dict[str, Any]]:
    directory = root / "reviews" / "attempts"
    if not directory.exists():
        return []
    records: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(record, dict) or record.get("schema") != "reviewer.semantic_attempt.v1":
            continue
        if record.get("review_identity", [None])[0] != repository:
            continue
        state = record.get("state")
        if state == DISPATCHING:
            records.append(record)
        elif state == "FAILED":
            result = record.get("result")
            if (
                record.get("retry_safe") is False
                and isinstance(result, dict)
                and result.get("transport_result") in {"OPENCLI_PROCESS_FAILURE", "OPENCLI_STABLE_READ_FAILURE"}
                and not record.get("reconciled")
            ):
                records.append(record)
    return _order_reconcilable_attempts(records)


def _record_reconcile_miss(root: Path, attempt: dict[str, Any]) -> None:
    """Count one bounded read-only recovery pass that found no exact match."""
    if attempt.get("reconciled"):
        return
    attempt["reconcile_misses"] = int(attempt.get("reconcile_misses", 0)) + 1
    attempt["last_reconcile_at"] = datetime.now(timezone.utc).replace(
        microsecond=0).isoformat().replace("+00:00", "Z")
    path = Path(root) / "reviews" / "attempts" / f"{attempt['attempt_id']}.json"
    try:
        current = json.loads(path.read_text(encoding="utf-8"))
        if current.get("attempt_id") != attempt.get("attempt_id"):
            return
        current.update({key: attempt[key] for key in ("reconcile_misses", "last_reconcile_at")})
        _atomic_json(path, current)
    except (OSError, ValueError):
        pass


def reconcile_semantic_history(config: ReviewerConfig, repository: str,
                               conversation_ids: list[str] | None = None,
                               *, max_attempts: int | None = None,
                               budget_seconds: float | None = RECONCILE_CYCLE_BUDGET_SECONDS) -> list[dict[str, Any]]:
    """Recover exact dispatched responses from read-only ChatGPT history.

    A conversation is accepted only when SHA-256 of its complete User message
    equals the journaled prompt hash. No fuzzy title/time matching is allowed.
    Automatic passes are wall-time bounded so recovery of old attempts can
    never starve actionable scheduler work; unreconciled attempts simply stay
    pending for later cycles.
    """
    deadline = (time.monotonic() + budget_seconds) if budget_seconds else None

    def expired() -> bool:
        return deadline is not None and time.monotonic() > deadline

    effective_limit = max_attempts if max_attempts is not None else (None if conversation_ids else 1)
    attempts = _discover_reconcilable_attempts(config.state_root, repository)
    if not conversation_ids:
        # Automatic reconciliation retires attempts after a bounded number of
        # full read-only passes found nothing; an explicit operator-provided
        # conversation id always overrides the retirement.
        attempts = [a for a in attempts
                    if int(a.get("reconcile_misses") or 0) < RECONCILE_MAX_MISSES]
    if effective_limit is not None and effective_limit >= 0:
        attempts = attempts[:effective_limit]

    recovered = []
    for attempt in attempts:
        if expired():
            break
        profile = str(attempt.get("browser_profile") or "")
        if not profile:
            continue
        journal_conversation = ((attempt.get("result") or {}).get("conversation_id")
                                if isinstance(attempt.get("result"), dict) else attempt.get("conversation_id"))
        if conversation_ids:
            history = [{"Id": value} for value in conversation_ids]
        elif isinstance(journal_conversation, str) and journal_conversation:
            history = [{"Id": journal_conversation}]
        else:
            try:
                history = _opencli_json(config.opencli_executable, profile,
                                      ["chatgpt", "history", "--limit", "20", "--site-session", "ephemeral"])
            except Exception:
                continue
        match = None
        for row in history if isinstance(history, list) else []:
            if expired():
                break
            conversation = row.get("Id") or row.get("id")
            if not conversation:
                continue
            try:
                detail = _opencli_json(config.opencli_executable, profile, ["chatgpt", "detail", str(conversation), "--site-session", "ephemeral"])
            except Exception:
                detail = []
            user = next((x.get("Text") for x in detail if x.get("Role") == "User"), None) if isinstance(detail, list) else None
            assistant = next((x.get("Text") for x in reversed(detail) if x.get("Role") == "Assistant" and not x.get("Generating")), None) if isinstance(detail, list) else None
            if (isinstance(user, str) and isinstance(assistant, str)
                    and hashlib.sha256(user.encode()).hexdigest() == attempt.get("prompt_sha256")):
                match = (str(conversation), assistant)
                break
            try:
                assistant = _browser_exact_response(
                    config.opencli_executable, profile, str(conversation),
                    str(attempt.get("prompt_sha256") or ""),
                )
            except Exception:
                assistant = None
            if isinstance(assistant, str):
                match = (str(conversation), assistant)
                break
        if match is None:
            _record_reconcile_miss(config.state_root, attempt)
            continue
        try:
            parsed = parse_response(match[1])
        except SemanticParseError:
            continue
        identity = attempt["review_identity"]
        _, observed, items, _ = scan(repository, GhCliTransport())
        item = next((x for x in items if list(x.review_identity) == identity), None)
        attempt_path = config.state_root / "reviews" / "attempts" / f"{attempt['attempt_id']}.json"
        if item is None:
            if attempt.get("state") == DISPATCHING:
                finish_attempt(
                    attempt_path, "FAILED",
                    result={"transport_result": "REVIEW_COMPLETED", "parse_result": "PARSED",
                            "reconciled": True, "context_result": "STALE_CONTEXT_AFTER_COMPLETION"},
                    retry_safe=False,
                )
            else:
                attempt["reconciled"] = True
                attempt["reconciled_result"] = {
                    "transport_result": "REVIEW_COMPLETED",
                    "parse_result": "PARSED",
                    "reconciled": True,
                    "context_result": "STALE_CONTEXT_AFTER_COMPLETION",
                }
                _atomic_json(attempt_path, attempt)
            recovered.append({"attempt_id": attempt["attempt_id"], "identity": identity,
                              "terminal": "STALE_CONTEXT_AFTER_COMPLETION", "receipt": None,
                              "path": str(attempt_path)})
            continue
        raw_sha = hashlib.sha256(match[1].encode()).hexdigest()
        receipt_id = hashlib.sha256(json.dumps({"identity": identity, "context": attempt["context_pack_sha256"], "prompt": attempt["prompt_sha256"], "raw": raw_sha}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        ci_evidence = None
        if hasattr(getattr(item, "snapshot", None), "checks") and getattr(item.snapshot, "checks", None):
            try:
                ci_evidence = _ci_evidence_for(item)
            except Exception:
                ci_evidence = None
        receipt = {"schema": "reviewer.pre_review.v1", "receipt_id": receipt_id, "repository": repository,
                   "pr_number": identity[1], "head_sha": identity[2], "base_sha": identity[3], "current_main_sha": identity[4],
                   "review_identity": identity, "source_observed_at": observed, "source_identity": item.snapshot.source_identity,
                   "deterministic_findings": item.findings, "risk": item.risk, "changed_files": list(item.snapshot.changed_files),
                   "context_pack_sha256": attempt["context_pack_sha256"], "prompt_sha256": attempt["prompt_sha256"],
                   "opencli_executable": attempt.get("opencli_executable"), "opencli_version": attempt.get("opencli_version"),
                   "browser_profile": profile, "session_mode": attempt.get("session_mode", "ephemeral"), "safe_argv": attempt.get("safe_argv", []),
                   "invocation_started_at": attempt.get("dispatching_at") or attempt.get("started_at"),
                   "invocation_finished_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                   "transport_result": "REVIEW_COMPLETED", "outcome_unknown": False, "retry_safe": False,
                   "raw_response_sha256": raw_sha, "parse_result": "PARSED", "semantic_result": parsed,
                   "ci_failure_evidence": ci_evidence,
                   "conversation_id": match[0], "reconciliation": "opencli_history_exact_prompt_sha256", "claim_ceiling": "PRE_REVIEW_ONLY"}
        service_record = UnattendedReviewService._record(item)
        queue_key = service_record.get("identity_key")
        receipt_path = persist_receipt(config.state_root, receipt)
        if attempt.get("state") == DISPATCHING:
            finish_attempt(attempt_path, COMPLETED, result={"transport_result": "REVIEW_COMPLETED", "parse_result": "PARSED", "reconciled": True})
        else:
            attempt["state"] = COMPLETED
            attempt["reconciled"] = True
            attempt["reconciled_result"] = {"transport_result": "REVIEW_COMPLETED", "parse_result": "PARSED", "reconciled": True}
            _atomic_json(attempt_path, attempt)
        recovered.append({"attempt_id": attempt["attempt_id"], "identity": identity, "identity_key": queue_key, "receipt": receipt, "path": str(receipt_path)})
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
        transport = OpenCLITransport(executable=config.opencli_executable, profile=str(profile),
                                     timeout=SEMANTIC_TIMEOUT_SECONDS)
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


def _apply_recovered(service: UnattendedReviewService, recovered: list[dict[str, Any]]) -> None:
    if not recovered:
        return
    state = service.store.load()
    queue = state.get("queue", {})
    for value in recovered:
        target_item = None
        key = value.get("identity_key")
        if key and key in queue:
            target_item = queue[key]
        elif value.get("identity"):
            matching = [item for item in queue.values() if item.get("review_identity") == value["identity"]]
            if len(matching) == 1:
                target_item = matching[0]
        if target_item is not None:
            if value.get("receipt") is not None:
                target_item["semantic_result"] = value["receipt"]
                target_item["state"] = "publication_pending"
            else:
                target_item["state"] = "semantic_failed"
                target_item["last_error"] = value.get("terminal", "RECONCILIATION_FAILED")
            target_item["retry_safe"] = False
    service.store.save(state)


def run_once(config: ReviewerConfig, *, bootstrap_canary: bool = False) -> dict[str, Any]:
    results = []
    for repository in config.repositories:
        service = build_service(config, repository, bootstrap_canary=bootstrap_canary)
        recovered=reconcile_semantic_history(config,repository)
        _apply_recovered(service,recovered)
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
    path_entries = _launch_agent_path_entries()
    path_xml = html.escape(":".join(path_entries))
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{SERVICE_LABEL}</string>
<key>ProgramArguments</key><array>{arg_xml}</array>
<key>WorkingDirectory</key><string>{html.escape(str(REPO_ROOT))}</string>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>ProcessType</key><string>Background</string><key>ThrottleInterval</key><integer>30</integer>
<key>StandardOutPath</key><string>/dev/null</string><key>StandardErrorPath</key><string>/dev/null</string>
<key>EnvironmentVariables</key><dict><key>PYTHONDONTWRITEBYTECODE</key><string>1</string><key>PYTHONPATH</key><string>{html.escape(str(REPO_ROOT))}</string><key>PATH</key><string>{path_xml}</string></dict>
</dict></plist>\n'''


def _launch_agent_path_entries(executable: str = "opencli") -> list[str]:
    """Build a portable, deterministic PATH for the user LaunchAgent."""
    entries: list[str] = []
    resolved = shutil.which(executable)
    if resolved:
        entries.append(str(Path(resolved).resolve().parent))
    entries.extend(os.environ.get("PATH", "").split(os.pathsep))
    entries.extend(("/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"))
    return list(dict.fromkeys(entry for entry in entries if entry))


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
    target = f"gui/{os.getuid()}/{SERVICE_LABEL}"
    bootout = _launchctl("bootout", target)
    command = getattr(bootout, "args", ("launchctl", "bootout", target))
    deadline = time.monotonic() + STOP_READBACK_TIMEOUT_SECONDS
    last = bootout
    while True:
        last = _launchctl("print", target)
        # launchctl print fails once the service label is actually gone.  A
        # successful bootout alone is not sufficient because the process may
        # still be alive during the unload race.
        if last.returncode != 0:
            return subprocess.CompletedProcess(
                command, 0, stdout=getattr(last, "stdout", ""),
                stderr=getattr(bootout, "stderr", "") or getattr(last, "stderr", ""),
            )
        if time.monotonic() >= deadline:
            detail = getattr(last, "stderr", "") or "SERVICE_LABEL_STILL_PRESENT"
            return subprocess.CompletedProcess(
                command, 1, stdout=getattr(last, "stdout", ""), stderr=detail,
            )
        time.sleep(STOP_READBACK_INTERVAL_SECONDS)


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
    parser.add_argument("command", choices=("install", "start", "stop", "restart", "status", "run-once", "daemon", "logs", "reconcile", "ci-metadata-canary"))
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    parser.add_argument("--bootstrap-canary", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--conversation-id", action="append", default=[])
    parser.add_argument("--repository")
    parser.add_argument("--pr-number", type=int)
    parser.add_argument("--head-sha")
    parser.add_argument("--check-suite-id", type=int)
    parser.add_argument("--check-run-id", type=int)
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--job-id", type=int)
    parser.add_argument("--artifact-id", type=int)
    parser.add_argument("--max-bytes", type=int, default=65536)
    parser.add_argument("--max-records", type=int, default=100)
    args = parser.parse_args(argv)
    if args.command == "ci-metadata-canary":
        value = run_metadata_canary(repository=args.repository, pr_number=args.pr_number,
                                    head_sha=args.head_sha, check_suite_id=args.check_suite_id,
                                    check_run_id=args.check_run_id, run_id=args.run_id,
                                    job_id=args.job_id, artifact_id=args.artifact_id,
                                    max_bytes=args.max_bytes, max_records=args.max_records)
        print(json.dumps(value, indent=2, sort_keys=True) if args.json else json.dumps(value, sort_keys=True))
        return 0 if value.get("status") == "CANARY_METADATA_BOUND" else 2
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
        recovered=[]
        for repository in config.repositories:
            values=reconcile_semantic_history(config,repository,args.conversation_id or None)
            _apply_recovered(build_service(config,repository),values)
            recovered.extend(values)
        value = {"status": "RECONCILED" if recovered else "RECONCILIATION_REQUIRED",
                 "recovered": recovered, "attempts": discover_unfinished(config.state_root)}
    else:
        daemon(config); return 0
    print(json.dumps(value, indent=2, sort_keys=True) if args.json else json.dumps(value, sort_keys=True))
    return 0 if value.get("status") not in {"START_FAILED", "STOP_FAILED", "RESTART_FAILED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
