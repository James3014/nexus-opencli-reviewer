from .models import *

DEFAULT_AUTHORITY_PATTERNS = ("AGENTS.md", "docs/agents/", "docs/governance/", "policy/")


def classify(pr, authority_patterns=DEFAULT_AUTHORITY_PATTERNS):
    classification = Classification(pr)

    def add(finding, reason=None):
        classification.findings.append(finding)
        classification.reasons.append(reason or finding)

    if pr.base_sha != pr.current_main_sha:
        add("STALE_BASE")
    if (
        (pr.declared_base_sha and pr.declared_base_sha != pr.base_sha)
        or (pr.declared_head_sha and pr.declared_head_sha != pr.head_sha)
        or (pr.declared_main_sha and pr.declared_main_sha != pr.current_main_sha)
    ):
        add("STALE_EVIDENCE")
    if pr.draft:
        add("DRAFT")
    if pr.mergeable is False:
        add("NON_MERGEABLE")
    if (
        pr.do_not_merge
        or any(label.lower() in ("do-not-merge", "do not merge") for label in pr.labels)
        or "do not merge" in pr.body.lower()
    ):
        add("DO_NOT_MERGE")
    if pr.expected_failure or any(check.expected_failure for check in pr.checks):
        add("EXPECTED_FAILURE")
    if any(
        check.status.lower() in ("failure", "failed", "red") and not check.expected_failure
        for check in pr.checks
    ):
        add("UNEXPECTED_FAILURE")
    if any(
        any(
            changed_file == pattern
            or (pattern.endswith("/") and changed_file.startswith(pattern))
            for pattern in authority_patterns
        )
        for changed_file in pr.changed_files
    ):
        add("AUTHORITY_OVERLAP")
        classification.risk = "HIGH"
    if any(label.lower() in ("long-lived", "stale-long-lived") for label in pr.labels):
        add("STALE_LONG_LIVED")
    if not pr.collection_complete:
        add("COLLECTION_INCOMPLETE")

    blockers = {
        "STALE_BASE",
        "STALE_EVIDENCE",
        "DRAFT",
        "NON_MERGEABLE",
        "DO_NOT_MERGE",
        "STALE_LONG_LIVED",
        "COLLECTION_INCOMPLETE",
    }
    if not (set(classification.findings) & blockers):
        classification.disposition = Disposition.REVIEW_READY
    elif "DO_NOT_MERGE" in classification.findings:
        classification.disposition = Disposition.EVIDENCE_ONLY
    elif "DRAFT" in classification.findings or "NON_MERGEABLE" in classification.findings:
        classification.disposition = Disposition.EXCLUDED
    elif (
        "STALE_LONG_LIVED" in classification.findings
        or "STALE_BASE" in classification.findings
        or "STALE_EVIDENCE" in classification.findings
    ):
        classification.disposition = Disposition.STALE
    else:
        classification.disposition = Disposition.NEEDS_ATTENTION
    return classification
