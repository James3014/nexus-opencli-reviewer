"""Read-only GitHub Actions / cloud adapter for Repository Intelligence.

The adapter acquires normalized PR evidence from GitHub REST and invokes the
canonical deterministic Core. It never checks out or executes PR code, writes
GitHub state, comments, approves, merges, or dispatches workers.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from repository_intelligence import (
    CI_EVIDENCE_CLAIM_CEILING,
    analyze_ci_failure_intelligence,
    plan_external_intelligence_automation,
    verify_ci_failure_intelligence_report,
    verify_external_intelligence_automation_envelope,
)
from repository_intelligence.cli import execute_operation

CLOUD_SCHEMA = "reviewer.repository_intelligence_cloud.v1"
CLOUD_CLAIM_CEILING = "ADVISORY_EVIDENCE_ONLY"
DEFAULT_API_URL = "https://api.github.com"
DEFAULT_MAX_PAGES = 50


class GitHubReadAPI(Protocol):
    def get_json(self, path: str, params: Mapping[str, Any] | None = None) -> Any: ...


class GitHubReadClient:
    def __init__(self, token: str, *, api_url: str = DEFAULT_API_URL, timeout: float = 20.0):
        if not token:
            raise ValueError("GITHUB_TOKEN is required")
        if not api_url.startswith("https://"):
            raise ValueError("GitHub API URL must use https")
        self.token = token
        self.api_url = api_url.rstrip("/")
        self.timeout = timeout

    def get_json(self, path: str, params: Mapping[str, Any] | None = None) -> Any:
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            raise ValueError("GitHub API path must be absolute and host-relative")
        query = urllib.parse.urlencode(params or {})
        url = f"{self.api_url}{path}{'?' + query if query else ''}"
        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "repository-intelligence-action",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as exc:
            detail = exc.read(8192).decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"GitHub HTTP {exc.code}: {detail or exc.reason}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RuntimeError(f"GitHub read failed: {exc}") from exc
        if len(raw) > 4 * 1024 * 1024:
            raise RuntimeError("GitHub response exceeded 4 MiB bound")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("GitHub returned invalid JSON") from exc


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _validate_repo(repo: str) -> str:
    if not isinstance(repo, str):
        raise ValueError("repository must be owner/name")
    parts = repo.split("/")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")
    if len(parts) != 2 or any(not part or any(ch not in allowed for ch in part) for part in parts):
        raise ValueError("repository must be owner/name")
    return repo


def _paginate_list(api: GitHubReadAPI, path: str, *, key: str | None = None) -> list[Mapping[str, Any]]:
    out: list[Mapping[str, Any]] = []
    for page in range(1, DEFAULT_MAX_PAGES + 1):
        value = api.get_json(path, {"per_page": 100, "page": page})
        rows = value.get(key) if key is not None and isinstance(value, Mapping) else value
        if not isinstance(rows, list):
            raise RuntimeError(f"GitHub pagination shape invalid for {path}")
        for row in rows:
            if not isinstance(row, Mapping):
                raise RuntimeError(f"GitHub pagination row invalid for {path}")
            out.append(row)
        if len(rows) < 100:
            return out
    raise RuntimeError(f"GitHub pagination exceeded {DEFAULT_MAX_PAGES} pages for {path}")


def collect_pr_snapshot(api: GitHubReadAPI, repository: str, pr_number: int) -> dict[str, Any]:
    """Collect one normalized PR snapshot without reading or executing PR file content."""
    repository = _validate_repo(repository)
    if not isinstance(pr_number, int) or pr_number <= 0:
        raise ValueError("pr_number must be a positive integer")

    owner, repo = repository.split("/", 1)
    prefix = f"/repos/{owner}/{repo}"
    pr = api.get_json(f"{prefix}/pulls/{pr_number}")
    if not isinstance(pr, Mapping):
        raise RuntimeError("pull request response is invalid")
    default_branch_data = api.get_json(prefix)
    if not isinstance(default_branch_data, Mapping):
        raise RuntimeError("repository response is invalid")
    default_branch = str(default_branch_data.get("default_branch") or "main")
    ref = api.get_json(f"{prefix}/git/ref/heads/{urllib.parse.quote(default_branch, safe='')}")
    try:
        current_main_sha = str(ref["object"]["sha"])
        head = pr["head"]
        base = pr["base"]
        head_sha = str(head["sha"])
        base_sha = str(base["sha"])
    except (KeyError, TypeError) as exc:
        raise RuntimeError("pull request identity evidence is incomplete") from exc

    files = _paginate_list(api, f"{prefix}/pulls/{pr_number}/files")
    check_rows = _paginate_list(api, f"{prefix}/commits/{urllib.parse.quote(head_sha, safe='')}/check-runs", key="check_runs")

    changed_files: list[str] = []
    collection_errors: list[str] = []
    for row in files:
        filename = row.get("filename")
        if isinstance(filename, str) and filename:
            changed_files.append(filename)
        else:
            collection_errors.append("changed_files: missing filename")

    checks: list[dict[str, Any]] = []
    for row in check_rows:
        name = row.get("name")
        status = row.get("conclusion") or row.get("status")
        if not isinstance(name, str) or not isinstance(status, str):
            collection_errors.append("checks: missing name/status")
            continue
        check_suite = row.get("check_suite") if isinstance(row.get("check_suite"), Mapping) else {}
        app = row.get("app") if isinstance(row.get("app"), Mapping) else {}
        output = row.get("output") if isinstance(row.get("output"), Mapping) else {}
        check: dict[str, Any] = {
            "name": name,
            "status": status,
            "expected_failure": False,
            "head_sha": row.get("head_sha") if isinstance(row.get("head_sha"), str) else head_sha,
        }
        optional = {
            "check_run_id": row.get("id"),
            "external_id": row.get("external_id"),
            "details_url": row.get("details_url"),
            "html_url": row.get("html_url"),
            "node_id": row.get("node_id"),
            "check_suite_id": check_suite.get("id"),
            "started_at": row.get("started_at"),
            "completed_at": row.get("completed_at"),
            "annotation_count": output.get("annotations_count"),
            "app_slug": app.get("slug"),
        }
        for key, value in optional.items():
            if value is not None:
                check[key] = value
        checks.append(check)

    labels = [
        str(label.get("name"))
        for label in pr.get("labels", [])
        if isinstance(label, Mapping) and isinstance(label.get("name"), str)
    ]
    snapshot = {
        "repository": repository,
        "pr_number": pr_number,
        "title": str(pr.get("title") or ""),
        "state": str(pr.get("state") or "open"),
        "draft": bool(pr.get("draft", False)),
        "mergeable": pr.get("mergeable") if isinstance(pr.get("mergeable"), bool) else None,
        "base_branch": str(base.get("ref") or default_branch),
        "base_sha": base_sha,
        "head_branch": str(head.get("ref") or ""),
        "head_sha": head_sha,
        "current_main_sha": current_main_sha,
        "changed_files": sorted(set(changed_files)),
        "issue_numbers": [],
        "labels": sorted(set(labels)),
        "checks": checks,
        "observed_at": _utc_now(),
        "source_identity": "github_action_rest_v1",
        "collection_complete": not collection_errors,
        "collection_errors": collection_errors,
        "created_at": str(pr.get("created_at") or ""),
        "updated_at": str(pr.get("updated_at") or ""),
    }
    return snapshot


def _hash_payload(payload: Mapping[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned.pop("content_sha256", None)
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def run_cloud_bundle(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Run canonical deterministic cloud-safe operations over one acquired snapshot."""
    revision = execute_operation("revision", dict(snapshot))
    readiness = execute_operation("readiness", dict(snapshot))
    cfi_report = analyze_ci_failure_intelligence(dict(snapshot))
    cfi = {
        "operation": "cfi",
        "claim_ceiling": CI_EVIDENCE_CLAIM_CEILING,
        "result": cfi_report.to_dict(),
    }
    eia_report = plan_external_intelligence_automation({"cfi_report": cfi["result"]})
    eia = {
        "operation": "eia",
        "claim_ceiling": "AUTOMATION_ADVISORY_ONLY",
        "result": eia_report.to_dict(),
    }
    bundle: dict[str, Any] = {
        "schema": CLOUD_SCHEMA,
        "claim_ceiling": CLOUD_CLAIM_CEILING,
        "review_identity": revision["result"]["review_identity"],
        "snapshot_source_identity": snapshot.get("source_identity"),
        "snapshot_observed_at": snapshot.get("observed_at"),
        "reports": {
            "revision": revision,
            "readiness": readiness,
            "cfi": cfi,
            "eia": eia,
        },
        "content_sha256": "",
    }
    bundle["content_sha256"] = _hash_payload(bundle)
    return bundle


def verify_cloud_bundle(payload: Mapping[str, Any]) -> bool:
    if not isinstance(payload, Mapping):
        return False
    if payload.get("schema") != CLOUD_SCHEMA or payload.get("claim_ceiling") != CLOUD_CLAIM_CEILING:
        return False
    supplied = payload.get("content_sha256")
    if not isinstance(supplied, str) or len(supplied) != 64 or supplied != _hash_payload(payload):
        return False
    reports = payload.get("reports")
    if not isinstance(reports, Mapping):
        return False
    expected = {
        "revision": "PR_INTELLIGENCE_ONLY",
        "readiness": "PR_INTELLIGENCE_ONLY",
        "cfi": "CI_EVIDENCE_ONLY",
        "eia": "AUTOMATION_ADVISORY_ONLY",
    }
    for name, ceiling in expected.items():
        report = reports.get(name)
        if not isinstance(report, Mapping) or report.get("operation") != name or report.get("claim_ceiling") != ceiling:
            return False
        result = report.get("result")
        if not isinstance(result, Mapping):
            return False
    top_identity = payload.get("review_identity")
    if not isinstance(top_identity, list) or len(top_identity) != 5:
        return False

    def identity_consistent(identity: Any) -> bool:
        if not isinstance(identity, Mapping):
            return False
        rebuilt = [
            identity.get("repository"),
            identity.get("pr_number"),
            identity.get("head_sha"),
            identity.get("base_sha"),
            identity.get("current_main_sha"),
        ]
        return rebuilt == top_identity and identity.get("review_identity") == top_identity

    revision_result = reports["revision"]["result"]
    if not isinstance(revision_result, Mapping):
        return False
    rebuilt_revision = [
        revision_result.get("repository"),
        revision_result.get("pr_number"),
        revision_result.get("head_sha"),
        revision_result.get("base_sha"),
        revision_result.get("current_main_sha"),
    ]
    if rebuilt_revision != top_identity or revision_result.get("review_identity") != top_identity:
        return False

    for name in ("readiness", "cfi", "eia"):
        result = reports[name]["result"]
        if not isinstance(result, Mapping) or not identity_consistent(result.get("identity")):
            return False

    if not verify_ci_failure_intelligence_report(reports["cfi"]["result"]):
        return False
    if not verify_external_intelligence_automation_envelope(reports["eia"]["result"]):
        return False
    return True


def _write_step_summary(bundle: Mapping[str, Any], path: str | None) -> None:
    if not path:
        return
    reports = bundle["reports"]
    readiness = reports["readiness"]["result"]
    cfi = reports["cfi"]["result"]
    eia = reports["eia"]["result"]
    text = (
        "## Repository Intelligence\n\n"
        f"- Review identity: `{json.dumps(bundle['review_identity'], separators=(',', ':'))}`\n"
        f"- Readiness: `{readiness.get('disposition')}`\n"
        f"- CI failure intelligence: `{cfi.get('status')}`\n"
        f"- External automation advisory: `{eia.get('decision')}`\n"
        f"- Claim ceiling: `{bundle['claim_ceiling']}`\n"
        f"- Bundle SHA-256: `{bundle['content_sha256']}`\n\n"
        "This action is read-only advisory evidence. It does not approve, merge, or execute pull-request code.\n"
    )
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(text)


def _write_github_outputs(bundle: Mapping[str, Any], path: str | None, report_path: str) -> None:
    if not path:
        return
    reports = bundle["reports"]
    values = {
        "report-path": report_path,
        "content-sha256": bundle["content_sha256"],
        "readiness": reports["readiness"]["result"].get("disposition", ""),
        "cfi-status": reports["cfi"]["result"].get("status", ""),
        "eia-decision": reports["eia"]["result"].get("decision", ""),
        "claim-ceiling": bundle["claim_ceiling"],
    }
    with open(path, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def _resolve_pr_number(explicit: int | None, event_path: str | None) -> int:
    if explicit is not None:
        return explicit
    if not event_path:
        raise ValueError("pr-number is required outside pull_request events")
    event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    pr = event.get("pull_request") if isinstance(event, Mapping) else None
    if isinstance(pr, Mapping) and isinstance(pr.get("number"), int):
        return int(pr["number"])
    raise ValueError("unable to derive pull request number from GITHUB_EVENT_PATH")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="repository-intelligence-action")
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--pr-number", type=int)
    parser.add_argument("--output", default=os.environ.get("RI_OUTPUT_FILE", "repository-intelligence.json"))
    args = parser.parse_args(argv)
    try:
        repository = _validate_repo(args.repository)
        pr_number = _resolve_pr_number(args.pr_number, os.environ.get("GITHUB_EVENT_PATH"))
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
        api = GitHubReadClient(token, api_url=os.environ.get("GITHUB_API_URL", DEFAULT_API_URL))
        snapshot = collect_pr_snapshot(api, repository, pr_number)
        bundle = run_cloud_bundle(snapshot)
        if not verify_cloud_bundle(bundle):
            raise RuntimeError("cloud bundle failed self-verification")
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        _write_step_summary(bundle, os.environ.get("GITHUB_STEP_SUMMARY"))
        _write_github_outputs(bundle, os.environ.get("GITHUB_OUTPUT"), str(output))
        print(json.dumps(bundle, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc), "claim_ceiling": CLOUD_CLAIM_CEILING}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
