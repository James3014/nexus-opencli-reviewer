"""Issue #45: Canonical RIE query output, attempt lineage, context integration, and paired economics."""

from __future__ import annotations

import json

from reviewer.attempt import (
    COMPLETED,
    finish_attempt,
    load_attempt,
    mark_dispatching,
    prepare_attempt,
)
from reviewer.models import CheckObservation, Classification, Disposition, PRSnapshot
from reviewer.query_assist import (
    CANONICAL_RETRIEVAL_CLAIM_CEILING,
    CANONICAL_RETRIEVAL_SCHEMA,
    QUERY_ASSIST_CLAIM_CEILING,
    QUERY_ASSIST_EXPERIMENT_SCHEMA,
    QUERY_ASSIST_SCHEMA,
    consume_canonical_query_evidence,
    validate_paired_experiment,
)
from reviewer.query_assist_evaluation import (
    FROZEN_POPULATION_V1,
    ORACLE_ID_V1,
    POPULATION_ID_V1,
    build_canonical_query_report,
    run_paired_evaluation,
    save_experiment_artifact,
)
from reviewer.receipt import (
    make_receipt,
    persist_receipt,
    reusable_receipt,
)
from reviewer.review_context import ReviewContext


def _sample_snapshot(head="head_sha_123", base="base_sha_456", main="main_sha_789"):
    return PRSnapshot(
        repository="James3014/Nexus-new",
        pr_number=1058,
        title="fix gateway",
        body="recovery",
        state="OPEN",
        draft=False,
        mergeable=True,
        base_branch="main",
        base_sha=base,
        head_branch="feature",
        head_sha=head,
        current_main_sha=main,
        checks=(
            CheckObservation(
                name="Exact-base impact gate",
                status="success",
                check_run_id=1,
                run_id=1,
                external_id="art-1",
                head_sha=head,
            ),
        ),
        changed_files=("nexus/gateway/recovery.py", "docs/recovery.md"),
    )


def test_canonical_query_evidence_consumption():
    """AC 1: Reviewer consumes canonical RIE query report without forked retrieval."""
    fixture = FROZEN_POPULATION_V1[0]
    canonical_report = build_canonical_query_report(fixture)
    assert canonical_report["schema"] == CANONICAL_RETRIEVAL_SCHEMA
    assert canonical_report["claim_ceiling"] == CANONICAL_RETRIEVAL_CLAIM_CEILING

    assisted = consume_canonical_query_evidence(
        canonical_report,
        critical_evidence=["risk:MED"],
    )
    assert assisted["schema"] == QUERY_ASSIST_SCHEMA
    assert assisted["mode"] == "D_ASSISTED"
    assert assisted["claim_ceiling"] == QUERY_ASSIST_CLAIM_CEILING
    assert "risk:MED" in assisted["critical_preserved"]
    assert "nexus/gateway/recovery.py" in assisted["candidates"]
    assert assisted["query_identity"]["repository"] == fixture.repository
    assert (
        assisted["query_identity"]["query_evidence_hash"]
        == canonical_report["content_sha256"]
    )


def test_stale_or_invalid_canonical_report_falls_back_to_baseline():
    """Rule 4: Stale or foreign query evidence falls back safely to O_BASELINE."""
    fixture = FROZEN_POPULATION_V1[0]
    canonical_report = build_canonical_query_report(fixture)

    # 1. Stale head
    bad_head_report = dict(canonical_report)
    bad_head_report["identity"] = dict(
        bad_head_report["identity"], head_sha="wrong_head_sha"
    )
    out = consume_canonical_query_evidence(
        bad_head_report,
        pr_identity={
            "repository": fixture.repository,
            "head_sha": fixture.head_sha,
            "base_sha": fixture.base_sha,
            "main_sha": fixture.current_main_sha,
        },
    )
    assert out["mode"] == "O_BASELINE"
    assert "query_evidence_stale_head" in out["blockers"]

    # 2. Foreign repository
    foreign_report = dict(canonical_report)
    foreign_report["identity"] = dict(
        foreign_report["identity"], repository="Other/foreign-repo"
    )
    out2 = consume_canonical_query_evidence(
        foreign_report,
        pr_identity={
            "repository": fixture.repository,
            "head_sha": fixture.head_sha,
            "base_sha": fixture.base_sha,
            "main_sha": fixture.current_main_sha,
        },
    )
    assert out2["mode"] == "O_BASELINE"
    assert "query_evidence_foreign_repository" in out2["blockers"]

    # 3. Incomplete evidence
    incomplete_report = dict(canonical_report, is_complete=False)
    out3 = consume_canonical_query_evidence(
        incomplete_report,
        pr_identity={
            "repository": fixture.repository,
            "head_sha": fixture.head_sha,
            "base_sha": fixture.base_sha,
            "main_sha": fixture.current_main_sha,
        },
    )
    assert out3["mode"] == "O_BASELINE"
    assert "query_evidence_incomplete" in out3["blockers"]


def test_empty_retrieval_never_proof_of_absence():
    """Rule 3: Empty retrieval never interpreted as proof of absence."""
    fixture = FROZEN_POPULATION_V1[0]
    canonical_report = build_canonical_query_report(fixture)
    empty_report = dict(
        canonical_report, fused_candidates=(), resolution="EMPTY_RETRIEVAL_NOT_ABSENCE"
    )
    out = consume_canonical_query_evidence(
        empty_report,
        critical_evidence=["ci:check:pass"],
        pr_identity={
            "repository": fixture.repository,
            "head_sha": fixture.head_sha,
            "base_sha": fixture.base_sha,
            "main_sha": fixture.current_main_sha,
        },
    )
    assert out["mode"] == "D_ASSISTED"
    assert out["candidates"] == []
    assert "ci:check:pass" in out["critical_preserved"]


def test_widening_observable_and_persisted():
    """AC 5: Widening / recovery remains possible and observable."""
    fixture = FROZEN_POPULATION_V1[7]  # pr-1350 with widened_files
    canonical_report = build_canonical_query_report(fixture)
    assisted = consume_canonical_query_evidence(
        canonical_report,
        critical_evidence=["risk:HIGH"],
        widened_candidates=fixture.widened_files,
    )
    assert assisted["mode"] == "D_ASSISTED"
    assert "tests/services/test_operation_continuity.py" in assisted["widened"]
    assert "tests/services/test_operation_continuity.py" not in assisted["candidates"]


def test_reviewer_context_integration():
    """AC 2: Reviewer context builder integrates query evidence and narrows candidates."""
    fixture = FROZEN_POPULATION_V1[0]
    snapshot = _sample_snapshot(
        head=fixture.head_sha, base=fixture.base_sha, main=fixture.current_main_sha
    )
    classification = Classification(
        snapshot=snapshot,
        disposition=Disposition.REVIEW_READY,
        findings=[
            {
                "category": "security",
                "severity": "CRITICAL",
                "path": "nexus/gateway/recovery.py",
                "reason": "auth leak",
            }
        ],
        risk="HIGH",
    )

    # 1. Unassisted baseline
    ctx_base = ReviewContext.build(classification, fixture.diff)
    assert ctx_base.query_evidence_identity == {}
    assert "query_assist_mode" not in ctx_base.payload
    assert len(ctx_base.payload["changed_files"]) == 2

    # 2. Query assisted
    report = build_canonical_query_report(fixture)
    ctx_asst = ReviewContext.build(classification, fixture.diff, query_evidence=report)
    assert ctx_asst.payload["query_assist_mode"] == "D_ASSISTED"
    assert ctx_asst.query_evidence_identity["repository"] == fixture.repository
    assert (
        ctx_asst.query_evidence_identity["query_evidence_hash"]
        == report["content_sha256"]
    )
    assert "candidate_hash" in ctx_asst.query_evidence_identity

    # Critical findings preserved unconditionally
    assert ctx_asst.payload["findings"] == classification.findings
    assert ctx_asst.payload["risk"] == "HIGH"


def test_attempt_journal_and_receipt_lineage(tmp_path):
    """AC 2: Exact revision and query-evidence identity persisted in attempt and PRE_REVIEW receipt."""
    fixture = FROZEN_POPULATION_V1[0]
    report = build_canonical_query_report(fixture)
    snapshot = _sample_snapshot(
        head=fixture.head_sha, base=fixture.base_sha, main=fixture.current_main_sha
    )
    classification = Classification(
        snapshot=snapshot, disposition=Disposition.REVIEW_READY, findings=[], risk="MED"
    )
    ctx = ReviewContext.build(classification, fixture.diff, query_evidence=report)

    # 1. Attempt journal records query_evidence_identity
    identity = list(ctx.review_identity)
    record, path = prepare_attempt(
        tmp_path,
        identity,
        ctx.context_sha256,
        "prompt_sha_abc",
        {"source": "test"},
        attempt_id="att-1058",
        query_evidence_identity=ctx.query_evidence_identity,
    )
    assert record["query_evidence_identity"] == ctx.query_evidence_identity
    assert (
        json.loads(path.read_text())["query_evidence_identity"]
        == ctx.query_evidence_identity
    )

    mark_dispatching(path)
    finish_attempt(path, COMPLETED, result={"status": "REVIEW_COMPLETED"})
    loaded, _ = load_attempt(tmp_path, "att-1058")
    assert loaded["query_evidence_identity"] == ctx.query_evidence_identity

    # 2. PRE_REVIEW receipt records query_evidence_identity
    class FakeTransport:
        raw = '{"schema":"reviewer.semantic_response.v1","status":"PASS","summary":"ok","findings":[],"evidence_gaps":[]}'
        status = "REVIEW_COMPLETED"
        version = "1.0"
        executable = "/bin/opencli"
        profile = "test-profile"
        session_mode = "ephemeral"
        argv: tuple[str, ...] = ()
        started_at = "2026-10-04T00:00:00Z"
        finished_at = "2026-10-04T00:00:01Z"
        outcome_unknown = False
        retry_safe = False

    receipt = make_receipt(
        ctx,
        classification,
        FakeTransport(),
        "prompt_text",
        "2026-10-04T00:00:00Z",
        parsed={
            "schema": "reviewer.semantic_response.v1",
            "status": "PASS",
            "summary": "ok",
            "findings": [],
            "evidence_gaps": [],
        },
        parse_result="PARSED",
    )
    assert receipt["query_evidence_identity"] == ctx.query_evidence_identity
    receipt_p = persist_receipt(tmp_path, receipt)
    assert receipt_p.exists()

    reusable, _ = reusable_receipt(
        tmp_path, ctx.review_identity, context_sha256=ctx.context_sha256
    )
    assert reusable is not None
    assert reusable["query_evidence_identity"] == ctx.query_evidence_identity
    assert reusable["claim_ceiling"] == "PRE_REVIEW_ONLY"


def test_frozen_paired_population_and_quality_oracle():
    """AC 3 & 4: Frozen paired population, quality oracle non-inferiority, and measured economics."""
    assert len(FROZEN_POPULATION_V1) == 8
    exp = run_paired_evaluation(population=FROZEN_POPULATION_V1)

    assert exp["schema"] == QUERY_ASSIST_EXPERIMENT_SCHEMA
    assert exp["population_id"] == POPULATION_ID_V1
    assert exp["oracle_id"] == ORACLE_ID_V1
    assert exp["claim_ceiling"] == QUERY_ASSIST_CLAIM_CEILING

    # Quality is strictly non-inferior
    assert exp["quality_non_inferior"] is True
    assert exp["savings_claim_allowed"] is True
    for pair in exp["pairs"]:
        assert pair["assisted"]["finding_recall"] >= pair["baseline"]["finding_recall"]
        assert pair["assisted"]["finding_recall"] == 1.0

    # Token savings measured and positive
    assert exp["token_savings"] > 0
    assert exp["token_savings"] >= 1000

    # Hash binding matches
    issues = validate_paired_experiment(exp)
    assert issues == []


def test_tampered_experiment_fails_closed():
    """Security: Tampered experiment hash or inflated savings fails closed."""
    exp = run_paired_evaluation()
    tampered = dict(exp)
    tampered["token_savings"] = 999999
    assert validate_paired_experiment(tampered) == ["experiment_hash_mismatch"]


def test_saved_artifact_persistence(tmp_path):
    """Artifact: Experiment evidence artifact is saved atomically and validates."""
    exp = run_paired_evaluation()
    target = tmp_path / "evidence" / "query_assist_paired_economics_v1.json"
    saved_path = save_experiment_artifact(exp, target_path=target)
    assert saved_path.exists()
    data = json.loads(saved_path.read_text(encoding="utf-8"))
    assert validate_paired_experiment(data) == []
    assert data["claim_ceiling"] == QUERY_ASSIST_CLAIM_CEILING


def test_unbound_report_identity_is_not_backfilled_from_pr():
    report = {
        "schema": CANONICAL_RETRIEVAL_SCHEMA,
        "claim_ceiling": CANONICAL_RETRIEVAL_CLAIM_CEILING,
        "content_sha256": "abc",
        "identity": {},
        "fused_candidates": [{"candidate_ref": "a.py::f"}],
    }
    pr = {"repository": "r/x", "head_sha": "h", "base_sha": "b", "main_sha": "m"}
    res = consume_canonical_query_evidence(report, pr_identity=pr)
    assert res["mode"] == "O_BASELINE"


def test_diff_narrowing_keeps_a_b_prefixed_paths():
    snap = _sample_snapshot()
    snap = PRSnapshot(**{**snap.__dict__, "changed_files": ("app.py", "other.py")})
    cls = Classification(
        snapshot=snap,
        disposition=Disposition.REVIEW_READY,
        findings=[],
        risk="LOW",
    )
    patch = (
        "diff --git a/app.py b/app.py\n+x\n"
        "diff --git a/other.py b/other.py\n+y\n"
    )
    ctx = ReviewContext.build(
        cls,
        patch,
        query_assist={
            "mode": "D_ASSISTED",
            "candidates": ["app.py"],
            "widened": [],
            "query_identity": {"query_evidence_hash": "h"},
        },
    )
    assert "app.py" in ctx.payload["diff"]
    assert "other.py" not in ctx.payload["diff"]
