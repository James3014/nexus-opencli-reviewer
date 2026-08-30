from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any
import re


class Disposition(str, Enum):
    REVIEW_READY = "REVIEW_READY"
    WAIT_REBIND = "WAIT_REBIND"
    NEEDS_ATTENTION = "NEEDS_ATTENTION"
    EVIDENCE_ONLY = "EVIDENCE_ONLY"
    STALE = "STALE"
    EXCLUDED = "EXCLUDED"


@dataclass(frozen=True)
class CheckObservation:
    name: str
    status: str
    expected_failure: bool = False
    check_run_id: int | None = None
    run_id: int | None = None
    external_id: str | None = None
    details_url: str | None = None
    html_url: str | None = None
    node_id: str | None = None
    workflow_name: str | None = None
    head_sha: str | None = None
    check_suite_id: int | None = None
    started_at: str | None = None
    completed_at: str | None = None
    artifact_identity: str | None = None
    annotation_count: int | None = None
    app_slug: str | None = None
    job_identity: str | None = None
    log_sha256: str | None = None
    log_truncated: bool = False
    artifact_sha256: str | None = None
    artifact_truncated: bool = False
    run_attempt: int | None = None


@dataclass(frozen=True)
class PRSnapshot:
    repository: str
    pr_number: int
    title: str
    state: str
    draft: bool
    mergeable: bool | None
    base_branch: str
    base_sha: str
    head_branch: str
    head_sha: str
    current_main_sha: str
    changed_files: tuple[str, ...] = ()
    issue_numbers: tuple[int, ...] = ()
    labels: tuple[str, ...] = ()
    body: str = ""
    checks: tuple[CheckObservation, ...] = ()
    observed_at: str = ""
    source_identity: str = "fixture"
    declared_base_sha: str | None = None
    declared_head_sha: str | None = None
    declared_main_sha: str | None = None
    expected_failure: bool = False
    do_not_merge: bool = False
    collection_complete: bool = True
    collection_errors: tuple[str, ...] = ()
    created_at: str = ""
    updated_at: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any], main: str):
        body = d.get("body", "") or ""

        def declared(key: str):
            if d.get("declared_" + key) is not None:
                return d["declared_" + key]
            match = re.search(
                rf"(?:exact\s+)?{key}\s*[:=]\s*[` ]*([0-9a-f]{{40}}|[0-9a-f]{{64}})\b",
                body,
                re.I,
            )
            return match.group(1) if match else None

        return cls(
            d["repository"],
            int(d["pr_number"]),
            d.get("title", ""),
            d.get("state", "OPEN"),
            bool(d.get("draft", False)),
            d.get("mergeable"),
            d.get("base_branch", "main"),
            d["base_sha"],
            d.get("head_branch", ""),
            d["head_sha"],
            main,
            tuple(d.get("changed_files", [])),
            tuple(d.get("issue_numbers", [])),
            tuple(d.get("labels", [])),
            body,
            tuple(CheckObservation(**item) for item in d.get("checks", [])),
            d.get("observed_at", ""),
            d.get("source_identity", "fixture"),
            declared("base"),
            declared("head"),
            declared("main"),
            bool(d.get("expected_failure", False)),
            bool(d.get("do_not_merge", False)),
            bool(d.get("collection_complete", True)),
            tuple(d.get("collection_errors", [])),
            d.get("created_at", ""),
            d.get("updated_at", ""),
        )


@dataclass
class Classification:
    snapshot: PRSnapshot
    findings: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    disposition: Disposition = Disposition.REVIEW_READY
    risk: str = "MED"
    overlaps: dict[int, list[str]] = field(default_factory=dict)

    @property
    def review_identity(self):
        snapshot = self.snapshot
        return (
            snapshot.repository,
            snapshot.pr_number,
            snapshot.head_sha,
            snapshot.base_sha,
            snapshot.current_main_sha,
        )

    def to_dict(self):
        snapshot = self.snapshot
        return {
            "pr_number": snapshot.pr_number,
            "repository": snapshot.repository,
            "title": snapshot.title,
            "disposition": self.disposition.value,
            "findings": self.findings,
            "reasons": self.reasons,
            "risk": self.risk,
            "overlaps": self.overlaps,
            "review_identity": list(self.review_identity),
            "base_sha": snapshot.base_sha,
            "head_sha": snapshot.head_sha,
            "current_main_sha": snapshot.current_main_sha,
            "changed_files": list(snapshot.changed_files),
            "issue_numbers": list(snapshot.issue_numbers),
            "labels": list(snapshot.labels),
            "checks": [asdict(check) for check in snapshot.checks],
            "observed_at": snapshot.observed_at,
            "source_identity": snapshot.source_identity,
            "collection_complete": snapshot.collection_complete,
            "collection_errors": list(snapshot.collection_errors),
            "declared_base_sha": snapshot.declared_base_sha,
            "declared_head_sha": snapshot.declared_head_sha,
            "declared_main_sha": snapshot.declared_main_sha,
        }
