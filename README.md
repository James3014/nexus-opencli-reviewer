# Nexus OpenCLI Reviewer Sidecar V1

Local advisory reviewer for GitHub pull requests. It collects physical PR state,
classifies deterministic eligibility, builds a SHA-bound semantic context, invokes
ChatGPT through OpenCLI, persists crash-safe attempt and PRE_REVIEW evidence, and
can publish one idempotent GitHub issue comment after a fresh identity rebind.

The Sidecar never approves, requests changes, merges, accepts a Candidate, or
changes Nexus lifecycle state. Its maximum claim is `PRE_REVIEW_ONLY`; published
results are explicitly marked automated and advisory.

Runtime state is stored below `.reviewer-state/` and is intentionally ignored by
Git. Use `python -m reviewer.cli --help` for scan, review, status, reconciliation,
and publication operations.
