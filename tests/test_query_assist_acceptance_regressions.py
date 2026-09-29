"""PR identity and rehashed economics semantic tampering controls."""
import hashlib
import json

from reviewer.query_assist import assemble_assisted_context, build_paired_experiment, validate_paired_experiment


def test_missing_head_stale_base_and_malformed_evidence_use_baseline():
    pr = dict(repository="o/r", head_sha="h", base_sha="b", main_sha="m")
    evidence = dict(pr, query_evidence_hash="q")
    missing = dict(evidence)
    missing.pop("head_sha")
    for value in (missing, dict(evidence, base_sha="old"), dict(evidence, main_sha="old"), 42, "bad"):
        out = assemble_assisted_context(pr_identity=pr, critical_evidence=["ci"], query_evidence=value)
        assert out["mode"] == "O_BASELINE"
        assert out["critical_preserved"] == ["ci"]


def test_rehashed_false_quality_claim_is_rejected():
    baseline = dict(finding_recall=1.0, input_tokens=100, output_tokens=10, call_count=1, wall_seconds=1.0)
    assisted = dict(baseline, finding_recall=0.5)
    body = build_paired_experiment(population_id="p", oracle_id="o", pairs=[dict(pr_id="1", baseline=baseline, assisted=assisted)])
    body["quality_non_inferior"] = body["savings_claim_allowed"] = True
    body.pop("experiment_hash")
    body["experiment_hash"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
    assert validate_paired_experiment(body)
