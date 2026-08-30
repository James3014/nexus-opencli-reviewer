from __future__ import annotations

import copy
import hashlib
import json

import reviewer.intelligence as ri


def _rehash(payload):
    unsigned = dict(payload)
    unsigned.pop("content_sha256", None)
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"))
    payload["content_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _input(**overrides):
    data = {
        "snapshot": {
            "repository": "owner/repo",
            "pr_number": 42,
            "base_sha": "a" * 40,
            "head_sha": "b" * 40,
            "current_main_sha": "a" * 40,
            "changed_files": ["src/core.ts"],
        },
        "covered_files": [
            "src/api.ts",
            "src/core.ts",
            "src/service.ts",
            "src/unrelated.ts",
        ],
        "dependency_edges": [
            {"consumer": "src/service.ts", "dependency": "src/core.ts"},
            {"consumer": "src/api.ts", "dependency": "src/service.ts"},
        ],
        "observed_symbols": {"src/core.ts": ["Core", "run"]},
        "graph_complete": True,
        "graph_errors": [],
    }
    data.update(overrides)
    return data


def test_change_impact_direct_transitive_and_unrelated_exclusion():
    report = ri.analyze_change_impact(_input())

    assert isinstance(report, ri.ChangeImpactReportV1)
    assert report.identity.review_identity == (
        "owner/repo",
        42,
        "b" * 40,
        "a" * 40,
        "a" * 40,
    )
    assert report.direct_impacted_files == ("src/service.ts",)
    assert report.transitive_impacted_files == ("src/api.ts",)
    assert report.all_impacted_files == ("src/api.ts", "src/core.ts", "src/service.ts")
    assert "src/unrelated.ts" not in report.all_impacted_files
    assert report.direct_impacted_count == 1
    assert report.transitive_impacted_count == 1
    assert report.total_impacted_count == 3
    assert report.edge_count == 2
    assert report.evidence_completeness == ri.EvidenceCompleteness.COMPLETE
    assert report.is_complete is True
    assert report.claim_ceiling == ri.CLAIM_CEILING
    assert len(report.graph_sha256) == 64
    assert len(report.content_sha256) == 64
    assert ri.verify_change_impact_report(report.to_dict()) is True


def test_change_impact_is_language_neutral_graph_evidence():
    report = ri.analyze_change_impact({
        "snapshot": {
            "repository": "owner/polyglot",
            "pr_number": 7,
            "base_sha": "1" * 40,
            "head_sha": "2" * 40,
            "current_main_sha": "1" * 40,
            "changed_files": ["pkg/model.py"],
        },
        "covered_files": ["app/main.go", "pkg/model.py", "web/view.ts"],
        "dependency_edges": [
            {"consumer": "app/main.go", "dependency": "pkg/model.py"},
            {"consumer": "web/view.ts", "dependency": "app/main.go"},
        ],
        "observed_symbols": {"pkg/model.py": ["Model"]},
        "graph_complete": True,
    })

    assert report.direct_impacted_files == ("app/main.go",)
    assert report.transitive_impacted_files == ("web/view.ts",)
    assert report.observed_symbols["pkg/model.py"] == ("Model",)
    assert report.is_complete is True


def test_change_impact_cycles_terminate_and_are_deterministic():
    data = _input(
        covered_files=["a.py", "b.py", "c.py"],
        changed_files=["a.py"],
        dependency_edges=[
            {"consumer": "b.py", "dependency": "a.py"},
            {"consumer": "a.py", "dependency": "b.py"},
            {"consumer": "c.py", "dependency": "b.py"},
        ],
        observed_symbols={},
    )
    r1 = ri.analyze_change_impact(data)
    r2 = ri.analyze_change_impact(copy.deepcopy(data))

    assert r1.direct_impacted_files == ("b.py",)
    assert r1.transitive_impacted_files == ("c.py",)
    assert json.dumps(r1.to_dict(), sort_keys=True) == json.dumps(r2.to_dict(), sort_keys=True)


def test_change_impact_graph_incomplete_is_partial_not_green_complete():
    report = ri.analyze_change_impact(_input(
        graph_complete=False,
        graph_errors=["index omitted generated subtree"],
    ))

    assert report.is_complete is False
    assert report.evidence_completeness == ri.EvidenceCompleteness.PARTIAL
    assert "graph_incomplete" in report.evidence_gaps
    assert "graph_error: index omitted generated subtree" in report.evidence_gaps
    assert ri.verify_change_impact_report(report.to_dict()) is True


def test_change_impact_changed_file_outside_coverage_fails_closed():
    report = ri.analyze_change_impact(_input(changed_files=["missing.ts"]))
    assert report.is_complete is False
    assert report.evidence_completeness == ri.EvidenceCompleteness.INCOMPLETE
    assert "changed file not covered by graph: missing.ts" in report.evidence_gaps


def test_change_impact_changed_files_must_match_snapshot_evidence():
    report = ri.analyze_change_impact(_input(
        changed_files=["src/unrelated.ts"],
    ))

    assert report.is_complete is False
    assert report.evidence_completeness == ri.EvidenceCompleteness.INCOMPLETE
    assert "changed_files do not match snapshot.changed_files" in report.evidence_gaps


def test_change_impact_stale_identity_evidence_fails_closed():
    data = _input()
    data["snapshot"] = dict(data["snapshot"], declared_head_sha="c" * 40)
    report = ri.analyze_change_impact(data)

    assert report.identity.stale_evidence is True
    assert report.evidence_completeness == ri.EvidenceCompleteness.INCOMPLETE
    assert "stale identity evidence" in report.evidence_gaps


def test_change_impact_rejects_traversal_and_foreign_edges():
    report = ri.analyze_change_impact(_input(
        covered_files=["src/core.ts", "../escape.ts"],
        changed_files=["src/core.ts"],
        dependency_edges=[
            {"consumer": "src/service.ts", "dependency": "src/core.ts"},
            {"consumer": "/abs.ts", "dependency": "src/core.ts"},
        ],
        observed_symbols={"../escape.ts": ["X"]},
    ))

    assert report.is_complete is False
    assert report.evidence_completeness == ri.EvidenceCompleteness.INCOMPLETE
    assert any("traversal" in gap for gap in report.evidence_gaps)
    assert any("consumer not covered" in gap or "absolute path rejected" in gap for gap in report.evidence_gaps)


def test_change_impact_tamper_detection_catches_graph_and_impact_mutation():
    payload = ri.analyze_change_impact(_input()).to_dict()
    assert ri.verify_change_impact_report(payload) is True

    tampered = copy.deepcopy(payload)
    tampered["direct_impacted_files"] = []
    _rehash(tampered)
    assert ri.verify_change_impact_report(tampered) is False

    tampered = copy.deepcopy(payload)
    tampered["dependency_edges"][0]["dependency"] = "src/unrelated.ts"
    _rehash(tampered)
    assert ri.verify_change_impact_report(tampered) is False

    tampered = copy.deepcopy(payload)
    tampered["claim_ceiling"] = "MERGE_READY"
    assert ri.verify_change_impact_report(tampered) is False


def test_change_impact_verifier_rejects_forged_complete_with_graph_errors():
    payload = ri.analyze_change_impact(_input(
        graph_complete=True,
        graph_errors=["provider omitted subtree"],
    )).to_dict()
    assert payload["evidence_completeness"] == ri.EvidenceCompleteness.PARTIAL.value

    payload["evidence_gaps"] = []
    payload["evidence_completeness"] = ri.EvidenceCompleteness.COMPLETE.value
    payload["is_complete"] = True
    _rehash(payload)

    assert ri.verify_change_impact_report(payload) is False


def test_change_impact_verifier_rejects_forged_complete_with_stale_identity():
    data = _input()
    data["snapshot"] = dict(data["snapshot"], declared_head_sha="c" * 40)
    payload = ri.analyze_change_impact(data).to_dict()
    assert payload["identity"]["stale_evidence"] is True

    payload["evidence_gaps"] = []
    payload["evidence_completeness"] = ri.EvidenceCompleteness.COMPLETE.value
    payload["is_complete"] = True
    _rehash(payload)

    assert ri.verify_change_impact_report(payload) is False


def test_change_impact_observed_symbols_are_not_called_modified_symbols():
    payload = ri.analyze_change_impact(_input()).to_dict()
    assert "observed_symbols" in payload
    assert "modified_symbols" not in payload
