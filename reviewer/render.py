"""Safe rendering of bounded, advisory publication comments.

Only the validated semantic result is accepted.  Prompt, transport envelopes,
and private metadata are intentionally not part of this API.
"""
from __future__ import annotations

import re
from typing import Any, Mapping

MAX_FIELD = 2_000
MAX_BODY = 12_000
_MARKDOWN = re.compile(r"([\\`*_{}\[\]()#+.!|>~<])")
_HTML_COMMENT = re.compile(r"<!--|-->", re.IGNORECASE)


def _safe(value: Any, limit: int = MAX_FIELD) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\x00", "").replace("\r", "")
    # Prevent HTML comments from hiding the fixed disclaimer or swallowing
    # subsequent fields.  Escape markdown metacharacters independently.
    text = _HTML_COMMENT.sub("", text)
    text = _MARKDOWN.sub(r"\\\1", text)
    text = text.replace("\n", "\n  ")
    return text[:limit]


def render_advisory(
    semantic_result: Mapping[str, Any],
    *,
    reviewed_head: str,
    attempt_id: str,
    content_hash: str = "pending",
) -> str:
    """Render an advisory-only comment from parser-validated semantic data."""
    if not isinstance(semantic_result, Mapping):
        raise ValueError("SEMANTIC_RESULT_REQUIRED")
    status = _safe(semantic_result.get("status", ""), 64)
    summary = _safe(semantic_result.get("summary", ""))
    lines = [
        "Automated PRE_REVIEW",
        "ADVISORY ONLY — NOT APPROVAL, ACCEPTANCE, VERIFICATION, OR MERGE AUTHORIZATION.",
        f"Reviewed exact head: {_safe(reviewed_head, 128)}",
        f"Result: {status}",
        f"Summary: {summary}",
    ]
    findings = semantic_result.get("findings") or []
    if findings:
        lines.append("Findings:")
        for finding in findings[:50]:
            if not isinstance(finding, Mapping):
                continue
            lines.append(
                "- " + " ".join([
                    _safe(finding.get("severity", ""), 32),
                    _safe(finding.get("category", ""), 128),
                    f"[{_safe(finding.get('path') or '(no path)', 256)}]:",
                    _safe(finding.get("reason", "")),
                ])
            )
    # Repeat the claim boundary after all untrusted text, so it cannot be
    # visually displaced by a field containing markdown/HTML controls.
    lines.extend([
        "",
        "ADVISORY ONLY — NOT APPROVAL, ACCEPTANCE, VERIFICATION, OR MERGE AUTHORIZATION.",
        f"Publication identity: {_safe(attempt_id, 128)}",
        f"Publication marker: reviewer-publication-v1:{_safe(attempt_id, 128)}:{_safe(content_hash, 128)}",
    ])
    body = "\n".join(lines) + "\n"
    return body[:MAX_BODY]


__all__ = ["render_advisory", "MAX_BODY", "MAX_FIELD"]
