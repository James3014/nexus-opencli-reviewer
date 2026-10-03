"""Canonical query-evidence assist + paired economics experiment (#45)."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping

QUERY_ASSIST_SCHEMA = "reviewer.query_assist_context.v1"
QUERY_ASSIST_EXPERIMENT_SCHEMA = "reviewer.query_assist_paired_experiment.v1"
QUERY_ASSIST_CLAIM_CEILING = "REVIEWER_QUERY_ASSIST_ECONOMICS_EXPERIMENT_ONLY"
CANONICAL_RETRIEVAL_SCHEMA = "reviewer.repository_query_evidence.v1"
CANONICAL_RETRIEVAL_CLAIM_CEILING = "REPOSITORY_QUERY_EVIDENCE_ONLY"


def _text(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _hash(payload):
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def validate_query_evidence(evidence):
    blockers = []
    if not isinstance(evidence, Mapping):
        return ["query_evidence_not_mapping"]
    for key in ("repository", "query_evidence_hash", "head_sha", "base_sha"):
        if not isinstance(evidence.get(key), str) or not evidence[key].strip():
            blockers.append(f"query_evidence_missing_{key}")
    for key in ("head_sha", "base_sha", "main_sha"):
        value = evidence.get(key)
        if value is not None and not str(value).strip():
            blockers.append(f"query_evidence_invalid_{key}")
    return sorted(set(blockers))


def assemble_assisted_context(
    *,
    pr_identity,
    critical_evidence,
    query_evidence=None,
    retrieved_candidates=(),
    widened_candidates=(),
):
    pr_identity = {str(k): str(v).strip() for k, v in dict(pr_identity or {}).items()}
    for key in ("repository", "head_sha", "base_sha"):
        if not pr_identity.get(key):
            raise ValueError(f"pr_identity missing {key}")
    critical = [str(c) for c in (critical_evidence or []) if str(c).strip()]
    if query_evidence is None:
        return {
            "schema": QUERY_ASSIST_SCHEMA,
            "mode": "O_BASELINE",
            "pr_identity": pr_identity,
            "critical_preserved": list(critical),
            "candidates": [],
            "widened": [],
            "blockers": ["query_evidence_unavailable_baseline_fallback"],
            "query_identity": {},
            "claim_ceiling": QUERY_ASSIST_CLAIM_CEILING,
        }
    blockers = validate_query_evidence(query_evidence)
    evidence = dict(query_evidence) if isinstance(query_evidence, Mapping) else {}
    if not blockers:
        if str(evidence.get("repository") or "").strip() != pr_identity["repository"]:
            blockers.append("query_evidence_foreign_repository")
        if (
            str(evidence.get("head_sha") or "").strip()
            and str(evidence["head_sha"]).strip() != pr_identity["head_sha"]
        ):
            blockers.append("query_evidence_stale_head")
        for key in ("base_sha", "main_sha"):
            if key in pr_identity and evidence.get(key) != pr_identity[key]:
                blockers.append(f"query_evidence_stale_{key}")
    if blockers:
        return {
            "schema": QUERY_ASSIST_SCHEMA,
            "mode": "O_BASELINE",
            "pr_identity": pr_identity,
            "critical_preserved": list(critical),
            "candidates": [],
            "widened": [],
            "blockers": sorted(set(blockers)),
            "query_identity": {},
            "claim_ceiling": QUERY_ASSIST_CLAIM_CEILING,
        }
    candidates = [
        str(c).strip() for c in (retrieved_candidates or []) if str(c).strip()
    ]
    widened = [str(c).strip() for c in (widened_candidates or []) if str(c).strip()]
    identity = {
        "repository": str(evidence.get("repository")),
        "query_evidence_hash": str(evidence.get("query_evidence_hash")),
        "retriever_policy": str(evidence.get("retriever_policy") or ""),
    }
    identity["binding_hash"] = _hash(identity)
    identity["revision_binding"] = dict(pr_identity)
    identity["candidate_hash"] = _hash(candidates)
    narrowed = [c for c in candidates if c not in widened]
    return {
        "schema": QUERY_ASSIST_SCHEMA,
        "mode": "D_ASSISTED",
        "pr_identity": pr_identity,
        "critical_preserved": list(critical),
        "candidates": narrowed,
        "widened": list(widened),
        "blockers": [],
        "query_identity": identity,
        "claim_ceiling": QUERY_ASSIST_CLAIM_CEILING,
    }


def consume_canonical_query_evidence(
    report,
    *,
    critical_evidence=(),
    pr_identity=None,
    widened_candidates=(),
):
    """Consume canonical Repository Intelligence query output without forked retrieval."""
    if hasattr(report, "to_dict") and callable(report.to_dict):
        report_data = report.to_dict()
    elif isinstance(report, Mapping):
        report_data = dict(report)
    elif isinstance(report, str):
        try:
            report_data = json.loads(report)
        except (json.JSONDecodeError, TypeError, ValueError):
            return assemble_assisted_context(
                pr_identity=pr_identity or {},
                critical_evidence=critical_evidence,
                query_evidence=None,
            )
    else:
        return assemble_assisted_context(
            pr_identity=pr_identity or {},
            critical_evidence=critical_evidence,
            query_evidence=None,
        )

    blockers = []
    if report_data.get("schema") != CANONICAL_RETRIEVAL_SCHEMA:
        blockers.append("query_evidence_invalid_schema")
    if report_data.get("claim_ceiling") != CANONICAL_RETRIEVAL_CLAIM_CEILING:
        blockers.append("query_evidence_invalid_claim_ceiling")

    raw_ident = report_data.get("identity")
    if hasattr(raw_ident, "to_dict") and callable(raw_ident.to_dict):
        ident_dict = raw_ident.to_dict()
    elif isinstance(raw_ident, Mapping):
        ident_dict = dict(raw_ident)
    else:
        ident_dict = {}

    target_pr = (
        dict(pr_identity)
        if pr_identity
        else {
            "repository": str(ident_dict.get("repository") or ""),
            "head_sha": str(ident_dict.get("head_sha") or ""),
            "base_sha": str(ident_dict.get("base_sha") or ""),
            "main_sha": str(ident_dict.get("current_main_sha") or ""),
        }
    )

    supplied_hash = report_data.get("content_sha256")
    if not isinstance(supplied_hash, str) or not supplied_hash.strip():
        blockers.append("query_evidence_missing_content_sha256")

    if (
        report_data.get("is_complete") is False
        or report_data.get("evidence_completeness") == "INCOMPLETE"
    ):
        blockers.append("query_evidence_incomplete")

    candidates = []
    for item in report_data.get("fused_candidates", ()):
        ref = (
            item.get("candidate_ref")
            if isinstance(item, Mapping)
            else getattr(item, "candidate_ref", str(item))
        )
        if ref:
            path_part = str(ref).split("::")[0].strip()
            if path_part and path_part not in candidates:
                candidates.append(path_part)

    query_evidence = {
        "repository": str(
            ident_dict.get("repository") or target_pr.get("repository") or ""
        ),
        "head_sha": str(ident_dict.get("head_sha") or target_pr.get("head_sha") or ""),
        "base_sha": str(ident_dict.get("base_sha") or target_pr.get("base_sha") or ""),
        "main_sha": str(
            ident_dict.get("current_main_sha") or target_pr.get("main_sha") or ""
        ),
        "query_evidence_hash": str(supplied_hash or ""),
        "retriever_policy": str(
            report_data.get("retriever_policy") or "rrf_k60_deterministic_fusion"
        ),
        "query_id": str(report_data.get("query_id") or ""),
        "resolution": str(report_data.get("resolution") or ""),
    }

    if blockers:
        result = assemble_assisted_context(
            pr_identity=target_pr,
            critical_evidence=critical_evidence,
            query_evidence=None,
        )
        result["blockers"] = sorted(set(result.get("blockers", []) + blockers))
        return result

    return assemble_assisted_context(
        pr_identity=target_pr,
        critical_evidence=critical_evidence,
        query_evidence=query_evidence,
        retrieved_candidates=candidates,
        widened_candidates=widened_candidates,
    )


def build_paired_experiment(*, population_id, oracle_id, pairs):
    population_id = _text(population_id, "population_id")
    oracle_id = _text(oracle_id, "oracle_id")
    if not isinstance(pairs, (list, tuple)) or not pairs:
        raise ValueError("pairs must be a non-empty list")
    rows = []
    for entry in pairs:
        if not isinstance(entry, Mapping):
            raise ValueError("pairs entries must be mappings")  # noqa: TRY004
        pr_id = _text(entry.get("pr_id"), "pr_id")
        for arm in ("baseline", "assisted"):
            arm_data = entry.get(arm)
            if not isinstance(arm_data, Mapping):
                raise ValueError(f"pair {pr_id} missing {arm} arm")  # noqa: TRY004
            for key in (
                "finding_recall",
                "input_tokens",
                "output_tokens",
                "call_count",
                "wall_seconds",
            ):
                value = arm_data.get(key)
                if (
                    isinstance(value, bool)
                    or not isinstance(value, (int, float))
                    or not math.isfinite(value)
                    or value < 0
                ):
                    raise ValueError(
                        f"pair {pr_id}.{arm}.{key} must be a non-negative number"
                    )
                if key == "finding_recall" and value > 1:
                    raise ValueError("finding_recall must be between zero and one")
                if (
                    key in ("input_tokens", "output_tokens", "call_count")
                    and type(value) is not int
                ):
                    raise ValueError(f"{key} must be an integer")
        rows.append(
            {
                "pr_id": pr_id,
                "baseline": dict(entry["baseline"]),
                "assisted": dict(entry["assisted"]),
                "recovery_events": int(entry.get("recovery_events") or 0),
            }
        )
    quality_ok = all(
        r["assisted"]["finding_recall"] >= r["baseline"]["finding_recall"] for r in rows
    )
    if len({row["pr_id"] for row in rows}) != len(rows):
        raise ValueError("paired population contains duplicate PR identities")
    tok_base = sum(
        r["baseline"]["input_tokens"] + r["baseline"]["output_tokens"] for r in rows
    )
    tok_asst = sum(
        r["assisted"]["input_tokens"] + r["assisted"]["output_tokens"] for r in rows
    )
    calls_base = sum(r["baseline"]["call_count"] for r in rows)
    calls_asst = sum(r["assisted"]["call_count"] for r in rows)
    body = {
        "schema": QUERY_ASSIST_EXPERIMENT_SCHEMA,
        "population_id": population_id,
        "oracle_id": oracle_id,
        "pairs": rows,
        "quality_non_inferior": bool(quality_ok),
        "token_savings": tok_base - tok_asst,
        "call_savings": calls_base - calls_asst,
        "savings_claim_allowed": bool(quality_ok),
        "claim_ceiling": QUERY_ASSIST_CLAIM_CEILING,
    }
    body["experiment_hash"] = _hash(
        {k: v for k, v in body.items() if k != "experiment_hash"}
    )
    return body


def validate_paired_experiment(body):
    if (
        not isinstance(body, Mapping)
        or body.get("schema") != QUERY_ASSIST_EXPERIMENT_SCHEMA
    ):
        return ["invalid_experiment_schema"]
    if body.get("claim_ceiling") != QUERY_ASSIST_CLAIM_CEILING:
        return ["invalid_claim_ceiling"]
    expected = dict(body)
    digest = expected.pop("experiment_hash", "")
    if _hash(expected) != digest:
        return ["experiment_hash_mismatch"]
    if not body.get("quality_non_inferior") and body.get("savings_claim_allowed"):
        return ["savings_claim_without_quality_gate"]
    try:
        recomputed = build_paired_experiment(
            population_id=body["population_id"],
            oracle_id=body["oracle_id"],
            pairs=body["pairs"],
        )
        return [] if dict(body) == recomputed else ["experiment_semantics_mismatch"]
    except (KeyError, TypeError, ValueError, OverflowError):
        return ["invalid_experiment_inputs"]
