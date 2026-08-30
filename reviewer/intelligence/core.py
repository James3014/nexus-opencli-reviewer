"""Repository Intelligence Core V1 Operations.

Pure, deterministic, transport-neutral operations for repository intelligence:
1) revision_identity
2) classify_readiness
3) analyze_cross_pr_overlap
4) fingerprint_ci_failures
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import Any, Mapping, Sequence

from .classifier import classify
from .models import CheckObservation, Classification, Disposition, PRSnapshot
from .overlap import detect

from .contracts import (
    CLAIM_CEILING,
    CI_EVIDENCE_CLAIM_CEILING,
    TERMINAL_FAILURE_STATUSES,
    CIFailureFingerprint,
    CrossPROverlapResult,
    EvidenceCompleteness,
    NormalizedCheckEvidence,
    ReadinessClassification,
    RepositoryIntelligencePolicyV1,
    RepositoryIntelligenceReportV1,
    RevisionIdentity,
)


def _validate_repo_format(repo: str) -> bool:
    if not isinstance(repo, str) or not repo:
        return False
    parts = repo.split("/")
    return len(parts) == 2 and all(bool(p.strip()) for p in parts)


def revision_identity(snapshot: PRSnapshot | Mapping[str, Any] | Any) -> RevisionIdentity:
    """Extract and validate deterministic revision identity and stale markers."""
    gaps: list[str] = []

    if isinstance(snapshot, PRSnapshot):
        repository = snapshot.repository
        pr_number = snapshot.pr_number
        head_sha = snapshot.head_sha
        base_sha = snapshot.base_sha
        current_main_sha = snapshot.current_main_sha
        declared_base = snapshot.declared_base_sha
        declared_head = snapshot.declared_head_sha
        declared_main = snapshot.declared_main_sha
    elif isinstance(snapshot, Mapping):
        repository = snapshot.get("repository", "")
        pr_number = snapshot.get("pr_number", 0)
        head_sha = snapshot.get("head_sha", "")
        base_sha = snapshot.get("base_sha", "")
        current_main_sha = snapshot.get("current_main_sha", "")
        declared_base = snapshot.get("declared_base_sha") or snapshot.get("declared_base")
        declared_head = snapshot.get("declared_head_sha") or snapshot.get("declared_head")
        declared_main = snapshot.get("declared_main_sha") or snapshot.get("declared_main")
    else:
        repository = getattr(snapshot, "repository", "")
        pr_number = getattr(snapshot, "pr_number", 0)
        head_sha = getattr(snapshot, "head_sha", "")
        base_sha = getattr(snapshot, "base_sha", "")
        current_main_sha = getattr(snapshot, "current_main_sha", "")
        declared_base = getattr(snapshot, "declared_base_sha", None) or getattr(snapshot, "declared_base", None)
        declared_head = getattr(snapshot, "declared_head_sha", None) or getattr(snapshot, "declared_head", None)
        declared_main = getattr(snapshot, "declared_main_sha", None) or getattr(snapshot, "declared_main", None)

    if not _validate_repo_format(repository):
        gaps.append("repository domain or format invalid")
    if not isinstance(pr_number, int) or pr_number <= 0:
        gaps.append("pr_number must be a positive integer")
    if not isinstance(head_sha, str) or not head_sha:
        gaps.append("head_sha missing or invalid")
    if not isinstance(base_sha, str) or not base_sha:
        gaps.append("base_sha missing or invalid")
    if not isinstance(current_main_sha, str) or not current_main_sha:
        gaps.append("current_main_sha missing or invalid")

    stale_base = bool(base_sha and current_main_sha and base_sha != current_main_sha)
    stale_declared_base = bool(declared_base and declared_base != base_sha)
    stale_declared_head = bool(declared_head and declared_head != head_sha)
    stale_declared_main = bool(declared_main and declared_main != current_main_sha)
    stale_evidence = bool(stale_declared_base or stale_declared_head or stale_declared_main)

    is_valid = len(gaps) == 0

    return RevisionIdentity(
        repository=repository if isinstance(repository, str) else str(repository),
        pr_number=pr_number if isinstance(pr_number, int) else 0,
        head_sha=head_sha if isinstance(head_sha, str) else "",
        base_sha=base_sha if isinstance(base_sha, str) else "",
        current_main_sha=current_main_sha if isinstance(current_main_sha, str) else "",
        declared_base_sha=declared_base,
        declared_head_sha=declared_head,
        declared_main_sha=declared_main,
        stale_base=stale_base,
        stale_declared_base=stale_declared_base,
        stale_declared_head=stale_declared_head,
        stale_declared_main=stale_declared_main,
        stale_evidence=stale_evidence,
        evidence_gaps=tuple(gaps),
        is_valid=is_valid,
    )


def _coerce_snapshot(snapshot: PRSnapshot | Mapping[str, Any] | Any) -> PRSnapshot:
    if isinstance(snapshot, PRSnapshot):
        return snapshot
    if isinstance(snapshot, Mapping):
        data = dict(snapshot)
        # Canonical V1 names use declared_*_sha; the legacy PRSnapshot loader
        # accepts declared_base/head/main. Bridge explicitly without parsing prose.
        for key in ("base", "head", "main"):
            canonical_key = f"declared_{key}_sha"
            legacy_key = f"declared_{key}"
            if data.get(canonical_key) is not None:
                data[legacy_key] = data[canonical_key]
        data["body"] = ""
        main_sha = data.get("current_main_sha") or data.get("base_sha", "")
        return PRSnapshot.from_dict(data, main=main_sha)
    if all(hasattr(snapshot, name) for name in ("repository", "pr_number", "base_sha", "head_sha", "current_main_sha")):
        return snapshot
    raise TypeError("snapshot must be a PRSnapshot, mapping, or compatible object")


def _resolve_policy(
    authority_patterns: Sequence[str] | None,
    policy: RepositoryIntelligencePolicyV1 | None,
) -> RepositoryIntelligencePolicyV1:
    if authority_patterns is not None and policy is not None:
        raise ValueError("use policy or authority_patterns, not both")
    if policy is not None:
        return policy
    if authority_patterns is not None:
        return RepositoryIntelligencePolicyV1(
            protected_path_patterns=tuple(authority_patterns)
        )
    return RepositoryIntelligencePolicyV1()


def _recompute_disposition(classification: Classification) -> None:
    findings = set(classification.findings)
    blockers = {
        "STALE_BASE",
        "STALE_EVIDENCE",
        "DRAFT",
        "NON_MERGEABLE",
        "DO_NOT_MERGE",
        "STALE_LONG_LIVED",
        "COLLECTION_INCOMPLETE",
    }
    if not (findings & blockers):
        classification.disposition = Disposition.REVIEW_READY
    elif "DO_NOT_MERGE" in findings:
        classification.disposition = Disposition.EVIDENCE_ONLY
    elif "DRAFT" in findings or "NON_MERGEABLE" in findings:
        classification.disposition = Disposition.EXCLUDED
    elif findings & {"STALE_LONG_LIVED", "STALE_BASE", "STALE_EVIDENCE"}:
        classification.disposition = Disposition.STALE
    else:
        classification.disposition = Disposition.NEEDS_ATTENTION


def _classify_snapshot(
    snapshot: PRSnapshot | Mapping[str, Any] | Any,
    *,
    policy: RepositoryIntelligencePolicyV1,
) -> tuple[Classification, RevisionIdentity, EvidenceCompleteness, tuple[str, ...]]:
    pr_snap = _coerce_snapshot(snapshot)
    legacy_stale_labels = {"long-lived", "stale-long-lived"}
    sanitized_labels = tuple(
        label for label in pr_snap.labels if label.lower() not in legacy_stale_labels
    )
    core_snapshot = replace(pr_snap, body="", labels=sanitized_labels)
    classification = classify(
        core_snapshot,
        authority_patterns=tuple(policy.protected_path_patterns),
    )

    configured_stale_labels = {label.lower() for label in policy.stale_labels}
    if any(label.lower() in configured_stale_labels for label in pr_snap.labels):
        if "STALE_LONG_LIVED" not in classification.findings:
            classification.findings.append("STALE_LONG_LIVED")
            classification.reasons.append("STALE_LONG_LIVED")
    _recompute_disposition(classification)

    rev_id = revision_identity(pr_snap)
    gaps = list(rev_id.evidence_gaps)
    gaps.extend(str(error) for error in pr_snap.collection_errors)
    if not rev_id.is_valid:
        if "INVALID_IDENTITY" not in classification.findings:
            classification.findings.append("INVALID_IDENTITY")
            classification.reasons.append("invalid five-part review identity")
        classification.disposition = Disposition.NEEDS_ATTENTION
        completeness = EvidenceCompleteness.INCOMPLETE
    elif not pr_snap.collection_complete:
        completeness = EvidenceCompleteness.INCOMPLETE
    elif pr_snap.collection_errors:
        completeness = EvidenceCompleteness.PARTIAL
    else:
        completeness = EvidenceCompleteness.COMPLETE

    deduped_gaps = tuple(dict.fromkeys(gaps))
    return classification, rev_id, completeness, deduped_gaps


def classify_readiness(
    snapshot: PRSnapshot | Mapping[str, Any] | Any,
    authority_patterns: Sequence[str] | None = None,
    *,
    policy: RepositoryIntelligencePolicyV1 | None = None,
) -> ReadinessClassification:
    """Pure advisory readiness projection over normalized structured evidence."""
    effective_policy = _resolve_policy(authority_patterns, policy)
    raw_classification, rev_id, completeness, gaps = _classify_snapshot(
        snapshot,
        policy=effective_policy,
    )
    overlaps_frozen: dict[int, tuple[str, ...]] = {
        pr_num: tuple(sorted(paths))
        for pr_num, paths in raw_classification.overlaps.items()
    }
    return ReadinessClassification(
        identity=rev_id,
        disposition=raw_classification.disposition,
        findings=tuple(raw_classification.findings),
        reasons=tuple(raw_classification.reasons),
        risk=raw_classification.risk,
        overlaps=overlaps_frozen,
        evidence_completeness=completeness,
        evidence_gaps=gaps,
        claim_ceiling=CLAIM_CEILING,
    )


def analyze_cross_pr_overlap(
    snapshots: Sequence[PRSnapshot | Mapping[str, Any] | Any],
    authority_patterns: Sequence[str] | None = None,
    *,
    policy: RepositoryIntelligencePolicyV1 | None = None,
) -> CrossPROverlapResult:
    """Deterministic immutable projection of cross-PR overlap semantics."""
    effective_policy = _resolve_policy(authority_patterns, policy)
    items: list[Classification] = []
    metadata: dict[int, tuple[RevisionIdentity, EvidenceCompleteness, tuple[str, ...]]] = {}
    for snapshot in snapshots:
        classification, rev_id, completeness, gaps = _classify_snapshot(
            snapshot,
            policy=effective_policy,
        )
        items.append(classification)
        metadata[id(classification)] = (rev_id, completeness, gaps)

    detect(items)

    classifications_list: list[ReadinessClassification] = []
    for classification in items:
        rev_id, completeness, gaps = metadata[id(classification)]
        overlaps_frozen: dict[int, tuple[str, ...]] = {
            pr_num: tuple(sorted(paths))
            for pr_num, paths in classification.overlaps.items()
        }
        classifications_list.append(
            ReadinessClassification(
                identity=rev_id,
                disposition=classification.disposition,
                findings=tuple(classification.findings),
                reasons=tuple(classification.reasons),
                risk=classification.risk,
                overlaps=overlaps_frozen,
                evidence_completeness=completeness,
                evidence_gaps=gaps,
                claim_ceiling=CLAIM_CEILING,
            )
        )

    seen_pairs: set[tuple[int, int]] = set()
    overlap_pairs_list: list[tuple[int, int, tuple[str, ...]]] = []
    for index, left in enumerate(items):
        for right in items[index + 1 :]:
            shared = sorted(set(left.snapshot.changed_files) & set(right.snapshot.changed_files))
            if shared:
                pair_key = (
                    min(left.snapshot.pr_number, right.snapshot.pr_number),
                    max(left.snapshot.pr_number, right.snapshot.pr_number),
                )
                if pair_key not in seen_pairs:
                    seen_pairs.add(pair_key)
                    overlap_pairs_list.append((pair_key[0], pair_key[1], tuple(shared)))

    overlap_pairs_list.sort(key=lambda pair: (pair[0], pair[1]))
    return CrossPROverlapResult(
        classifications=tuple(classifications_list),
        overlap_pairs=tuple(overlap_pairs_list),
        claim_ceiling=CLAIM_CEILING,
    )


def _normalize_check(
    check: CheckObservation | Mapping[str, Any] | Any,
    expected_failure_override: bool = False,
    head_sha: str | None = None,
) -> tuple[NormalizedCheckEvidence | None, list[str]]:
    gaps: list[str] = []
    if isinstance(check, CheckObservation):
        name = check.name
        status = check.status
        expected_failure = bool(check.expected_failure or expected_failure_override)
        check_run_id = check.check_run_id
        run_id = check.run_id
        external_id = check.external_id
        details_url = check.details_url
        html_url = check.html_url
        node_id = check.node_id
        workflow_name = check.workflow_name
        check_head_sha = check.head_sha
        check_suite_id = check.check_suite_id
        started_at = check.started_at
        completed_at = check.completed_at
        artifact_identity = check.artifact_identity
        annotation_count = check.annotation_count
        app_slug = check.app_slug
        job_identity = check.job_identity
        log_sha256 = check.log_sha256
        log_truncated = check.log_truncated
        artifact_sha256 = check.artifact_sha256
        artifact_truncated = check.artifact_truncated
        run_attempt = check.run_attempt
    elif isinstance(check, Mapping):
        name = check.get("name")
        status = check.get("status")
        expected_failure = bool(check.get("expected_failure", False) or expected_failure_override)
        check_run_id = check.get("check_run_id")
        run_id = check.get("run_id")
        external_id = check.get("external_id")
        details_url = check.get("details_url")
        html_url = check.get("html_url")
        node_id = check.get("node_id")
        workflow_name = check.get("workflow_name")
        check_head_sha = check.get("head_sha")
        check_suite_id = check.get("check_suite_id")
        started_at = check.get("started_at")
        completed_at = check.get("completed_at")
        artifact_identity = check.get("artifact_identity")
        annotation_count = check.get("annotation_count")
        app_slug = check.get("app_slug")
        job_identity = check.get("job_identity")
        log_sha256 = check.get("log_sha256")
        log_truncated = check.get("log_truncated")
        artifact_sha256 = check.get("artifact_sha256")
        artifact_truncated = check.get("artifact_truncated")
        run_attempt = check.get("run_attempt")
    else:
        name = getattr(check, "name", None)
        status = getattr(check, "status", None)
        expected_failure = bool(getattr(check, "expected_failure", False) or expected_failure_override)
        check_run_id = getattr(check, "check_run_id", None)
        run_id = getattr(check, "run_id", None)
        external_id = getattr(check, "external_id", None)
        details_url = getattr(check, "details_url", None)
        html_url = getattr(check, "html_url", None)
        node_id = getattr(check, "node_id", None)
        workflow_name = getattr(check, "workflow_name", None)
        check_head_sha = getattr(check, "head_sha", None)
        check_suite_id = getattr(check, "check_suite_id", None)
        started_at = getattr(check, "started_at", None)
        completed_at = getattr(check, "completed_at", None)
        artifact_identity = getattr(check, "artifact_identity", None)
        annotation_count = getattr(check, "annotation_count", None)
        app_slug = getattr(check, "app_slug", None)
        job_identity = getattr(check, "job_identity", None)
        log_sha256 = getattr(check, "log_sha256", None)
        log_truncated = getattr(check, "log_truncated", None)
        artifact_sha256 = getattr(check, "artifact_sha256", None)
        artifact_truncated = getattr(check, "artifact_truncated", None)
        run_attempt = getattr(check, "run_attempt", None)

    if not isinstance(name, str) or not name:
        gaps.append("check name missing or invalid")
        return None, gaps
    if not isinstance(status, str) or not status:
        gaps.append("check status missing or invalid")
        return None, gaps

    status_lower = status.lower()
    is_terminal = status_lower in TERMINAL_FAILURE_STATUSES
    is_unexpected = is_terminal and not expected_failure

    if is_terminal:
        if not check_head_sha:
            gaps.append(f"terminal check '{name}' missing head_sha")
        elif head_sha and check_head_sha != head_sha:
            gaps.append(f"check head_sha '{check_head_sha}' mismatches PR head_sha '{head_sha}'")
        elif not head_sha:
            gaps.append(f"terminal check '{name}' cannot anchor to missing PR head_sha")

        has_locator = any(
            val is not None and (not isinstance(val, str) or bool(val.strip()))
            for val in (
                check_run_id,
                run_id,
                external_id,
                job_identity,
                log_sha256,
                artifact_identity,
                artifact_sha256,
                details_url,
                html_url,
            )
        )
        if not has_locator:
            gaps.append(f"terminal check '{name}' missing material execution/evidence locator")
    else:
        if check_head_sha and head_sha and check_head_sha != head_sha:
            gaps.append(f"check head_sha '{check_head_sha}' mismatches PR head_sha '{head_sha}'")

    norm = NormalizedCheckEvidence(
        name=name,
        status=status,
        expected_failure=expected_failure,
        is_unexpected=is_unexpected,
        check_run_id=check_run_id if isinstance(check_run_id, int) else None,
        run_id=run_id if isinstance(run_id, int) else None,
        external_id=external_id if isinstance(external_id, str) else None,
        details_url=details_url if isinstance(details_url, str) else None,
        html_url=html_url if isinstance(html_url, str) else None,
        node_id=node_id if isinstance(node_id, str) else None,
        workflow_name=workflow_name if isinstance(workflow_name, str) else None,
        head_sha=check_head_sha if isinstance(check_head_sha, str) else None,
        check_suite_id=check_suite_id if isinstance(check_suite_id, int) else None,
        started_at=started_at if isinstance(started_at, str) else None,
        completed_at=completed_at if isinstance(completed_at, str) else None,
        artifact_identity=artifact_identity if isinstance(artifact_identity, str) else None,
        annotation_count=annotation_count if isinstance(annotation_count, int) else None,
        app_slug=app_slug if isinstance(app_slug, str) else None,
        job_identity=job_identity if isinstance(job_identity, str) else None,
        log_sha256=log_sha256 if isinstance(log_sha256, str) else None,
        log_truncated=log_truncated if isinstance(log_truncated, bool) else None,
        artifact_sha256=artifact_sha256 if isinstance(artifact_sha256, str) else None,
        artifact_truncated=artifact_truncated if isinstance(artifact_truncated, bool) else None,
        run_attempt=run_attempt if isinstance(run_attempt, int) else None,
    )
    return norm, gaps


def _content_hash(payload: Mapping[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned.pop("content_sha256", None)
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def fingerprint_ci_failures(
    snapshot: PRSnapshot | Mapping[str, Any] | Any | None = None,
    *,
    repository: str | None = None,
    pr_number: int | None = None,
    base_sha: str | None = None,
    head_sha: str | None = None,
    current_main_sha: str | None = None,
    checks: Sequence[Any] | None = None,
    collection_complete: bool = True,
    collection_errors: Sequence[str] = (),
    expected_failure: bool = False,
    expected_check_run_id: int | None = None,
    expected_run_id: int | None = None,
    expected_job_identity: str | None = None,
    expected_artifact_identity: str | None = None,
) -> CIFailureFingerprint:
    """Build deterministic, identity-bound CI failure evidence."""
    gaps: list[str] = list(collection_errors)

    if snapshot is not None:
        if isinstance(snapshot, PRSnapshot):
            rev_id = revision_identity(snapshot)
            raw_checks = snapshot.checks
            collection_complete = snapshot.collection_complete
            gaps.extend(snapshot.collection_errors)
            expected_failure = expected_failure or snapshot.expected_failure
        elif isinstance(snapshot, Mapping):
            rev_id = revision_identity(snapshot)
            raw_checks = snapshot.get("checks", ())
            collection_complete = snapshot.get("collection_complete", True)
            gaps.extend(snapshot.get("collection_errors", ()))
            expected_failure = expected_failure or snapshot.get("expected_failure", False)
        else:
            rev_id = revision_identity(snapshot)
            raw_checks = getattr(snapshot, "checks", ())
            collection_complete = getattr(snapshot, "collection_complete", True)
            gaps.extend(getattr(snapshot, "collection_errors", ()))
            expected_failure = expected_failure or getattr(snapshot, "expected_failure", False)
    else:
        rev_id = revision_identity({
            "repository": repository,
            "pr_number": pr_number,
            "base_sha": base_sha,
            "head_sha": head_sha,
            "current_main_sha": current_main_sha,
        })
        raw_checks = checks or ()

    gaps.extend(rev_id.evidence_gaps)
    if not collection_complete:
        gaps.append("collection_incomplete")
    if not raw_checks:
        gaps.append("no_check_evidence_provided")

    unexpected_failures: list[NormalizedCheckEvidence] = []
    expected_failures: list[NormalizedCheckEvidence] = []
    total_valid_checks = 0

    for chk in raw_checks:
        norm, chk_gaps = _normalize_check(
            chk,
            expected_failure_override=expected_failure,
            head_sha=rev_id.head_sha if rev_id.is_valid else None,
        )
        gaps.extend(chk_gaps)
        if norm is None:
            continue
        total_valid_checks += 1
        status_lower = norm.status.lower()
        if status_lower not in TERMINAL_FAILURE_STATUSES:
            continue
        if expected_check_run_id is not None and norm.check_run_id != expected_check_run_id:
            gaps.append("foreign check identity")
        if expected_run_id is not None and norm.run_id != expected_run_id:
            gaps.append("foreign check run identity")
        if expected_job_identity is not None and norm.job_identity != expected_job_identity:
            gaps.append("foreign check job identity")
        if expected_artifact_identity is not None and norm.artifact_identity != expected_artifact_identity:
            gaps.append("foreign check artifact identity")
        if norm.is_unexpected:
            unexpected_failures.append(norm)
        else:
            expected_failures.append(norm)

    def _sort_key(check: NormalizedCheckEvidence) -> str:
        return json.dumps(check.to_dict(), sort_keys=True, separators=(",", ":"))

    unexpected_failures.sort(key=_sort_key)
    expected_failures.sort(key=_sort_key)

    fingerprint_payload = {
        "review_identity": list(rev_id.review_identity),
        "unexpected_failures": [check.to_dict() for check in unexpected_failures],
        "expected_failures": [check.to_dict() for check in expected_failures],
        "expected_check_run_id": expected_check_run_id,
        "expected_run_id": expected_run_id,
        "expected_job_identity": expected_job_identity,
        "expected_artifact_identity": expected_artifact_identity,
        "total_checks_count": total_valid_checks,
        "unexpected_count": len(unexpected_failures),
        "expected_count": len(expected_failures),
    }
    fp_hash = hashlib.sha256(
        json.dumps(fingerprint_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    deduped_gaps = tuple(dict.fromkeys(str(gap) for gap in gaps))
    is_complete = not deduped_gaps and collection_complete and rev_id.is_valid
    completeness = (
        EvidenceCompleteness.COMPLETE
        if is_complete
        else EvidenceCompleteness.INCOMPLETE
    )
    result = CIFailureFingerprint(
        identity=rev_id,
        fingerprint=fp_hash,
        has_unexpected_failures=bool(unexpected_failures),
        unexpected_failures=tuple(unexpected_failures),
        expected_failures=tuple(expected_failures),
        total_checks_count=total_valid_checks,
        unexpected_count=len(unexpected_failures),
        expected_count=len(expected_failures),
        terminal_failure_count=len(unexpected_failures) + len(expected_failures),
        evidence_gaps=deduped_gaps,
        is_complete=is_complete,
        evidence_completeness=completeness,
        content_sha256="",
        expected_check_run_id=expected_check_run_id,
        expected_run_id=expected_run_id,
        expected_job_identity=expected_job_identity,
        expected_artifact_identity=expected_artifact_identity,
        claim_ceiling=CI_EVIDENCE_CLAIM_CEILING,
    )
    return replace(result, content_sha256=_content_hash(result.to_dict()))


def verify_ci_failure_evidence(payload: Mapping[str, Any]) -> bool:
    if not isinstance(payload, Mapping):
        return False
    if payload.get("schema") != "reviewer.ci_failure_evidence.v1":
        return False
    if payload.get("claim_ceiling") != CI_EVIDENCE_CLAIM_CEILING:
        return False
    supplied = payload.get("content_sha256")
    if not (isinstance(supplied, str) and len(supplied) == 64 and supplied == _content_hash(payload)):
        return False

    identity = payload.get("identity")
    if not isinstance(identity, Mapping):
        return False
    expected_review_identity = [
        identity.get("repository"),
        identity.get("pr_number"),
        identity.get("head_sha"),
        identity.get("base_sha"),
        identity.get("current_main_sha"),
    ]
    if identity.get("review_identity") != expected_review_identity:
        return False

    gaps = payload.get("evidence_gaps")
    if not isinstance(gaps, list) or any(not isinstance(gap, str) for gap in gaps):
        return False
    completeness = payload.get("evidence_completeness")
    is_complete = payload.get("is_complete") is True
    if is_complete != (completeness == EvidenceCompleteness.COMPLETE.value):
        return False
    if is_complete and gaps:
        return False

    failure_groups = (
        (payload.get("unexpected_failures"), True),
        (payload.get("expected_failures"), False),
    )
    for failures, should_be_unexpected in failure_groups:
        if not isinstance(failures, list):
            return False
        for check in failures:
            if not isinstance(check, Mapping):
                return False
            if bool(check.get("is_unexpected")) is not should_be_unexpected:
                return False
            if is_complete and check.get("head_sha") != identity.get("head_sha"):
                return False
            if is_complete and payload.get("expected_check_run_id") is not None:
                if check.get("check_run_id") != payload.get("expected_check_run_id"):
                    return False
            if is_complete and payload.get("expected_run_id") is not None:
                if check.get("run_id") != payload.get("expected_run_id"):
                    return False
            if is_complete and payload.get("expected_job_identity") is not None:
                if check.get("job_identity") != payload.get("expected_job_identity"):
                    return False
            if is_complete and payload.get("expected_artifact_identity") is not None:
                if check.get("artifact_identity") != payload.get("expected_artifact_identity"):
                    return False
    return True


def build_repository_intelligence_report(
    snapshots: Sequence[PRSnapshot | Mapping[str, Any] | Any],
    authority_patterns: Sequence[str] | None = None,
    *,
    policy: RepositoryIntelligencePolicyV1 | None = None,
) -> RepositoryIntelligenceReportV1:
    effective_policy = _resolve_policy(authority_patterns, policy)
    normalized = tuple(_coerce_snapshot(snapshot) for snapshot in snapshots)
    overlap = analyze_cross_pr_overlap(normalized, policy=effective_policy)
    items = tuple(sorted(
        overlap.classifications,
        key=lambda item: item.identity.review_identity,
    ))

    repositories = {snapshot.repository for snapshot in normalized if snapshot.repository}
    main_shas = {snapshot.current_main_sha for snapshot in normalized if snapshot.current_main_sha}
    observed_values = sorted(snapshot.observed_at for snapshot in normalized if snapshot.observed_at)
    gaps: list[str] = []
    if not normalized:
        gaps.append("no pull request evidence")
    if len(repositories) > 1:
        gaps.append("mixed repository identity")
    if len(main_shas) > 1:
        gaps.append("mixed current main identity")
    for item in items:
        gaps.extend(f"pr:{item.identity.pr_number}:{gap}" for gap in item.evidence_gaps)

    if not normalized or len(repositories) > 1 or len(main_shas) > 1 or any(
        item.evidence_completeness == EvidenceCompleteness.INCOMPLETE for item in items
    ):
        completeness = EvidenceCompleteness.INCOMPLETE
    elif any(item.evidence_completeness == EvidenceCompleteness.PARTIAL for item in items):
        completeness = EvidenceCompleteness.PARTIAL
    else:
        completeness = EvidenceCompleteness.COMPLETE

    report = RepositoryIntelligenceReportV1(
        repository=next(iter(repositories), ""),
        current_main_sha=next(iter(main_shas), ""),
        observed_at=observed_values[-1] if observed_values else "",
        items=items,
        evidence_completeness=completeness,
        evidence_gaps=tuple(dict.fromkeys(gaps)),
        content_sha256="",
        claim_ceiling=CLAIM_CEILING,
    )
    return replace(report, content_sha256=_content_hash(report.to_dict()))


def verify_repository_intelligence_report(payload: Mapping[str, Any]) -> bool:
    if not isinstance(payload, Mapping):
        return False
    if payload.get("schema") != "reviewer.repository_intelligence.v1":
        return False
    if payload.get("claim_ceiling") != CLAIM_CEILING:
        return False
    supplied = payload.get("content_sha256")
    if not (isinstance(supplied, str) and len(supplied) == 64 and supplied == _content_hash(payload)):
        return False
    if payload.get("evidence_completeness") not in {
        EvidenceCompleteness.COMPLETE.value,
        EvidenceCompleteness.PARTIAL.value,
        EvidenceCompleteness.INCOMPLETE.value,
    }:
        return False
    items = payload.get("items")
    if not isinstance(items, list):
        return False
    for item in items:
        if not isinstance(item, Mapping) or item.get("claim_ceiling") != CLAIM_CEILING:
            return False
        identity = item.get("identity")
        if not isinstance(identity, Mapping):
            return False
        expected_review_identity = [
            identity.get("repository"),
            identity.get("pr_number"),
            identity.get("head_sha"),
            identity.get("base_sha"),
            identity.get("current_main_sha"),
        ]
        if identity.get("review_identity") != expected_review_identity:
            return False
    return True
