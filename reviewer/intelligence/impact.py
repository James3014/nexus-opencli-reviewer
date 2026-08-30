"""Repository Intelligence V1.1 language-neutral Change Impact Core.

This module does not parse source code and does not own a language-specific code index.
It consumes normalized repository graph evidence and computes deterministic downstream
impact for one exact PR revision identity.
"""
from __future__ import annotations

import hashlib
import json
import posixpath
from dataclasses import replace
from typing import Any, Mapping, Sequence

from .contracts import CLAIM_CEILING, ChangeImpactReportV1, EvidenceCompleteness
from .core import revision_identity


def _content_hash(payload: Mapping[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned.pop("content_sha256", None)
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _graph_hash(
    *,
    covered_files: Sequence[str],
    dependency_edges: Sequence[tuple[str, str]],
    observed_symbols: Mapping[str, Sequence[str]],
    graph_complete: bool,
    graph_errors: Sequence[str],
) -> str:
    payload = {
        "covered_files": list(covered_files),
        "dependency_edges": [
            {"consumer": consumer, "dependency": dependency}
            for consumer, dependency in dependency_edges
        ],
        "observed_symbols": {
            path: list(symbols) for path, symbols in sorted(observed_symbols.items())
        },
        "graph_complete": graph_complete,
        "graph_errors": list(graph_errors),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _normalize_path(value: Any) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or not value:
        return None, "path must be a non-empty string"
    if "\x00" in value:
        return None, "path contains NUL"
    if "\\" in value:
        return None, f"path must use repository POSIX separators: {value!r}"
    if value.startswith("/"):
        return None, f"absolute path rejected: {value!r}"
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return None, f"path is not normalized or contains traversal: {value!r}"
    normalized = posixpath.normpath(value)
    if normalized != value or normalized.startswith("../") or normalized == "..":
        return None, f"path is not a safe normalized repository path: {value!r}"
    return value, None


def _normalize_path_sequence(
    raw: Any,
    *,
    label: str,
    gaps: list[str],
) -> tuple[str, ...]:
    if not isinstance(raw, (list, tuple)):
        gaps.append(f"{label} must be a list")
        return ()
    values: set[str] = set()
    for item in raw:
        path, error = _normalize_path(item)
        if error:
            gaps.append(f"{label}: {error}")
            continue
        values.add(path)
    return tuple(sorted(values))


def _normalize_graph_errors(raw: Any, gaps: list[str]) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, (list, tuple)):
        gaps.append("graph_errors must be a list")
        return ()
    normalized: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            gaps.append("graph_errors entries must be non-empty strings")
            continue
        value = item.strip()
        if value not in normalized:
            normalized.append(value)
    return tuple(normalized)


def _normalize_observed_symbols(
    raw: Any,
    *,
    covered_files: set[str],
    gaps: list[str],
) -> dict[str, tuple[str, ...]]:
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        gaps.append("observed_symbols must be a mapping of path to symbol list")
        return {}

    normalized: dict[str, tuple[str, ...]] = {}
    for raw_path, raw_symbols in raw.items():
        path, error = _normalize_path(raw_path)
        if error:
            gaps.append(f"observed_symbols: {error}")
            continue
        if path not in covered_files:
            gaps.append(f"observed_symbols path not covered by graph: {path}")
            continue
        if not isinstance(raw_symbols, (list, tuple)):
            gaps.append(f"observed_symbols[{path!r}] must be a list")
            continue
        symbols: set[str] = set()
        for raw_symbol in raw_symbols:
            if not isinstance(raw_symbol, str) or not raw_symbol.strip():
                gaps.append(f"observed_symbols[{path!r}] contains an invalid symbol")
                continue
            symbols.add(raw_symbol.strip())
        normalized[path] = tuple(sorted(symbols))
    return dict(sorted(normalized.items()))


def _normalize_edges(
    raw: Any,
    *,
    covered_files: set[str],
    gaps: list[str],
) -> tuple[tuple[str, str], ...]:
    if raw is None:
        return ()
    if not isinstance(raw, (list, tuple)):
        gaps.append("dependency_edges must be a list")
        return ()

    normalized: set[tuple[str, str]] = set()
    for index, edge in enumerate(raw):
        if not isinstance(edge, Mapping):
            gaps.append(f"dependency_edges[{index}] must be an object")
            continue
        consumer, consumer_error = _normalize_path(edge.get("consumer"))
        dependency, dependency_error = _normalize_path(edge.get("dependency"))
        if consumer_error:
            gaps.append(f"dependency_edges[{index}].consumer: {consumer_error}")
        if dependency_error:
            gaps.append(f"dependency_edges[{index}].dependency: {dependency_error}")
        if consumer is None or dependency is None:
            continue
        if consumer not in covered_files:
            gaps.append(f"dependency edge consumer not covered by graph: {consumer}")
            continue
        if dependency not in covered_files:
            gaps.append(f"dependency edge dependency not covered by graph: {dependency}")
            continue
        if consumer == dependency:
            continue
        normalized.add((consumer, dependency))
    return tuple(sorted(normalized))


def _compute_impact(
    changed_files: Sequence[str],
    dependency_edges: Sequence[tuple[str, str]],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    changed = set(changed_files)
    downstream: dict[str, set[str]] = {}
    for consumer, dependency in dependency_edges:
        downstream.setdefault(dependency, set()).add(consumer)

    direct: set[str] = set()
    for changed_file in changed:
        direct.update(downstream.get(changed_file, ()))
    direct.difference_update(changed)

    transitive: set[str] = set()
    visited = set(changed) | set(direct)
    queue = list(sorted(direct))
    cursor = 0
    while cursor < len(queue):
        current = queue[cursor]
        cursor += 1
        for consumer in sorted(downstream.get(current, ())):
            if consumer in visited:
                continue
            visited.add(consumer)
            transitive.add(consumer)
            queue.append(consumer)

    all_impacted = changed | direct | transitive
    return tuple(sorted(direct)), tuple(sorted(transitive)), tuple(sorted(all_impacted))


def analyze_change_impact(data: Mapping[str, Any]) -> ChangeImpactReportV1:
    """Compute language-neutral downstream impact from normalized graph evidence.

    Required input shape::

        {
          "snapshot": {repository/pr_number/base_sha/head_sha/current_main_sha/...},
          "covered_files": ["src/a.ts", ...],
          "dependency_edges": [{"consumer": "src/b.ts", "dependency": "src/a.ts"}],
          # changed files are authoritative inside snapshot.changed_files
          # an optional top-level changed_files copy must match exactly
          "observed_symbols": {"src/a.ts": ["A"]},  # optional upstream evidence
          "graph_complete": true,
          "graph_errors": []
        }

    Dependency edges mean "consumer depends on dependency". A change to dependency
    therefore directly impacts consumer; the inverse graph is followed transitively.
    """
    if not isinstance(data, Mapping):
        raise TypeError("change impact input must be a mapping")

    gaps: list[str] = []
    snapshot = data.get("snapshot")
    if not isinstance(snapshot, Mapping):
        gaps.append("snapshot must be a mapping")
        snapshot = {}
    identity = revision_identity(snapshot)
    gaps.extend(identity.evidence_gaps)
    if identity.stale_evidence:
        gaps.append("stale identity evidence")

    covered_files = _normalize_path_sequence(
        data.get("covered_files", ()), label="covered_files", gaps=gaps
    )
    covered_set = set(covered_files)
    if not covered_files:
        gaps.append("no covered_files provided")

    snapshot_changed_raw = (
        snapshot.get("changed_files") if isinstance(snapshot, Mapping) else None
    )
    if snapshot_changed_raw is None:
        gaps.append("snapshot.changed_files missing")
        snapshot_changed_files: tuple[str, ...] = ()
    else:
        snapshot_changed_files = _normalize_path_sequence(
            snapshot_changed_raw, label="snapshot.changed_files", gaps=gaps
        )

    explicit_changed_raw = data.get("changed_files")
    if explicit_changed_raw is None:
        changed_files = snapshot_changed_files
    else:
        changed_files = _normalize_path_sequence(
            explicit_changed_raw, label="changed_files", gaps=gaps
        )
        if changed_files != snapshot_changed_files:
            gaps.append("changed_files do not match snapshot.changed_files")
    if not changed_files:
        gaps.append("no changed_files provided")
    for path in changed_files:
        if path not in covered_set:
            gaps.append(f"changed file not covered by graph: {path}")

    graph_complete_raw = data.get("graph_complete", False)
    if not isinstance(graph_complete_raw, bool):
        gaps.append("graph_complete must be a boolean")
        graph_complete = False
    else:
        graph_complete = graph_complete_raw
    if not graph_complete:
        gaps.append("graph_incomplete")

    graph_errors = _normalize_graph_errors(data.get("graph_errors", ()), gaps)
    gaps.extend(f"graph_error: {error}" for error in graph_errors)

    dependency_edges = _normalize_edges(
        data.get("dependency_edges", ()), covered_files=covered_set, gaps=gaps
    )
    observed_symbols = _normalize_observed_symbols(
        data.get("observed_symbols", {}), covered_files=covered_set, gaps=gaps
    )

    direct, transitive, all_impacted = _compute_impact(changed_files, dependency_edges)

    graph_sha256 = _graph_hash(
        covered_files=covered_files,
        dependency_edges=dependency_edges,
        observed_symbols=observed_symbols,
        graph_complete=graph_complete,
        graph_errors=graph_errors,
    )

    deduped_gaps = tuple(dict.fromkeys(str(gap) for gap in gaps))
    hard_gap_prefixes = (
        "repository domain or format invalid",
        "pr_number must be a positive integer",
        "head_sha missing or invalid",
        "base_sha missing or invalid",
        "current_main_sha missing or invalid",
        "snapshot must be a mapping",
        "covered_files",
        "no covered_files provided",
        "snapshot.changed_files",
        "snapshot.changed_files missing",
        "changed_files",
        "changed_files do not match snapshot.changed_files",
        "no changed_files provided",
        "changed file not covered by graph",
        "dependency_edges",
        "dependency edge consumer not covered by graph",
        "dependency edge dependency not covered by graph",
        "observed_symbols",
        "stale identity evidence",
    )
    hard_gap = any(gap.startswith(hard_gap_prefixes) for gap in deduped_gaps)
    if not deduped_gaps and identity.is_valid and graph_complete:
        completeness = EvidenceCompleteness.COMPLETE
    elif identity.is_valid and covered_files and changed_files and not hard_gap:
        completeness = EvidenceCompleteness.PARTIAL
    else:
        completeness = EvidenceCompleteness.INCOMPLETE

    result = ChangeImpactReportV1(
        identity=identity,
        covered_files=covered_files,
        changed_files=changed_files,
        dependency_edges=dependency_edges,
        observed_symbols=observed_symbols,
        direct_impacted_files=direct,
        transitive_impacted_files=transitive,
        all_impacted_files=all_impacted,
        graph_complete=graph_complete,
        graph_errors=graph_errors,
        edge_count=len(dependency_edges),
        graph_sha256=graph_sha256,
        evidence_gaps=deduped_gaps,
        evidence_completeness=completeness,
        is_complete=completeness == EvidenceCompleteness.COMPLETE,
        content_sha256="",
        claim_ceiling=CLAIM_CEILING,
    )
    return replace(result, content_sha256=_content_hash(result.to_dict()))


def verify_change_impact_report(payload: Mapping[str, Any]) -> bool:
    """Verify hash binding plus deterministic graph/impact invariants."""
    if not isinstance(payload, Mapping):
        return False
    if payload.get("schema") != "reviewer.change_impact.v1":
        return False
    if payload.get("claim_ceiling") != CLAIM_CEILING:
        return False
    supplied_hash = payload.get("content_sha256")
    if not (
        isinstance(supplied_hash, str)
        and len(supplied_hash) == 64
        and supplied_hash == _content_hash(payload)
    ):
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

    covered_files = payload.get("covered_files")
    changed_files = payload.get("changed_files")
    edges_raw = payload.get("dependency_edges")
    symbols_raw = payload.get("observed_symbols")
    graph_errors = payload.get("graph_errors")
    if not isinstance(covered_files, list) or any(not isinstance(v, str) for v in covered_files):
        return False
    if not isinstance(changed_files, list) or any(not isinstance(v, str) for v in changed_files):
        return False
    if covered_files != sorted(set(covered_files)) or changed_files != sorted(set(changed_files)):
        return False
    if not isinstance(edges_raw, list):
        return False
    dependency_edges: list[tuple[str, str]] = []
    for edge in edges_raw:
        if not isinstance(edge, Mapping):
            return False
        consumer = edge.get("consumer")
        dependency = edge.get("dependency")
        if not isinstance(consumer, str) or not isinstance(dependency, str):
            return False
        dependency_edges.append((consumer, dependency))
    if dependency_edges != sorted(set(dependency_edges)):
        return False
    if payload.get("edge_count") != len(dependency_edges):
        return False
    if not isinstance(symbols_raw, Mapping):
        return False
    observed_symbols: dict[str, tuple[str, ...]] = {}
    for path, symbols in symbols_raw.items():
        if not isinstance(path, str) or not isinstance(symbols, list):
            return False
        if any(not isinstance(symbol, str) for symbol in symbols):
            return False
        if symbols != sorted(set(symbols)):
            return False
        observed_symbols[path] = tuple(symbols)
    if not isinstance(graph_errors, list) or any(not isinstance(error, str) for error in graph_errors):
        return False

    covered_set = set(covered_files)
    if any(path not in covered_set for path in changed_files):
        return False
    if any(consumer not in covered_set or dependency not in covered_set for consumer, dependency in dependency_edges):
        return False
    if any(path not in covered_set for path in observed_symbols):
        return False

    expected_graph_hash = _graph_hash(
        covered_files=tuple(covered_files),
        dependency_edges=tuple(dependency_edges),
        observed_symbols=observed_symbols,
        graph_complete=payload.get("graph_complete") is True,
        graph_errors=tuple(graph_errors),
    )
    if payload.get("graph_sha256") != expected_graph_hash:
        return False

    direct, transitive, all_impacted = _compute_impact(changed_files, dependency_edges)
    if payload.get("direct_impacted_files") != list(direct):
        return False
    if payload.get("transitive_impacted_files") != list(transitive):
        return False
    if payload.get("all_impacted_files") != list(all_impacted):
        return False
    if payload.get("direct_impacted_count") != len(direct):
        return False
    if payload.get("transitive_impacted_count") != len(transitive):
        return False
    if payload.get("total_impacted_count") != len(all_impacted):
        return False

    gaps = payload.get("evidence_gaps")
    completeness = payload.get("evidence_completeness")
    if not isinstance(gaps, list) or any(not isinstance(gap, str) for gap in gaps):
        return False
    if completeness not in {item.value for item in EvidenceCompleteness}:
        return False
    is_complete = payload.get("is_complete") is True
    if is_complete != (completeness == EvidenceCompleteness.COMPLETE.value):
        return False
    if is_complete and (
        gaps
        or graph_errors
        or payload.get("graph_complete") is not True
        or identity.get("is_valid") is not True
        or identity.get("stale_evidence") is True
        or bool(identity.get("evidence_gaps"))
    ):
        return False
    return True
