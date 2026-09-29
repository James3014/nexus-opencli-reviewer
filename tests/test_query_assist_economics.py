"""Issue #45: canonical query evidence assist + paired economics."""
from __future__ import annotations

from reviewer.query_assist import (
    QUERY_ASSIST_CLAIM_CEILING,
    assemble_assisted_context,
    build_paired_experiment,
    validate_paired_experiment,
)


def _pr():
    return {"repository": "owner/repo", "head_sha": "aaa", "base_sha": "bbb"}


def _evidence(**overrides):
    data = {"repository": "owner/repo", "head_sha": "aaa", "base_sha": "bbb",
            "query_evidence_hash": "q1", "retriever_policy": "rrf_k60_weighted"}
    data.update(overrides)
    return data


def test_assisted_mode_preserves_critical():
    out = assemble_assisted_context(pr_identity=_pr(),
        critical_evidence=["ci:required", "revision:head"],
        query_evidence=_evidence(), retrieved_candidates=["src/a.py", "src/b.py"])
    assert out["mode"] == "D_ASSISTED"
    assert "ci:required" in out["critical_preserved"]
    assert out["claim_ceiling"] == QUERY_ASSIST_CLAIM_CEILING


def test_stale_evidence_falls_back_to_baseline():
    out = assemble_assisted_context(pr_identity=_pr(), critical_evidence=["ci:x"],
        query_evidence=_evidence(head_sha="zzz"), retrieved_candidates=["src/a.py"])
    assert out["mode"] == "O_BASELINE"
    assert "query_evidence_stale_head" in out["blockers"]
    assert out["critical_preserved"] == ["ci:x"]


def test_low_score_never_proof_of_absence():
    out = assemble_assisted_context(pr_identity=_pr(), critical_evidence=["ci:x"],
        query_evidence=_evidence(), retrieved_candidates=[])
    assert out["mode"] == "D_ASSISTED"
    assert out["critical_preserved"] == ["ci:x"]


def test_widening_observable():
    out = assemble_assisted_context(pr_identity=_pr(), critical_evidence=[],
        query_evidence=_evidence(), retrieved_candidates=["src/a.py", "src/b.py"],
        widened_candidates=["src/c.py"])
    assert out["widened"] == ["src/c.py"]
    assert out["candidates"] == ["src/a.py", "src/b.py"]


def _pairs(recall_ok=True):
    assist_recall = 0.9 if recall_ok else 0.5
    return [{"pr_id": "pr-1", "baseline": {"finding_recall": 0.8, "input_tokens": 1000, "output_tokens": 200, "call_count": 2, "wall_seconds": 10}, "assisted": {"finding_recall": assist_recall, "input_tokens": 600, "output_tokens": 150, "call_count": 1, "wall_seconds": 8}, "recovery_events": 1}]


def test_paired_experiment_quality_gate():
    body = build_paired_experiment(population_id="pop-frozen-1", oracle_id="oracle-frozen-1", pairs=_pairs(True))
    assert body["quality_non_inferior"] is True
    assert body["savings_claim_allowed"] is True
    assert validate_paired_experiment(body) == []
    bad = build_paired_experiment(population_id="pop-frozen-1", oracle_id="oracle-frozen-1", pairs=_pairs(False))
    assert bad["quality_non_inferior"] is False
    assert bad["savings_claim_allowed"] is False
    assert bad["token_savings"] == 450


def test_experiment_tamper_fails():
    body = build_paired_experiment(population_id="p", oracle_id="o", pairs=_pairs(True))
    tampered = dict(body)
    tampered["token_savings"] = 999999
    assert validate_paired_experiment(tampered) == ["experiment_hash_mismatch"]
