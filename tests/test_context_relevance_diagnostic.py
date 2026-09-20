"""Comprehensive test suite for Context Relevance Diagnostic Live Contract (Tests D1 to D12).

Zero live provider calls: REAL JEV CALLS = 0, NOUL CALLS = 0, API KEY READS = 0.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import tempfile
import pytest

import concurrent.futures
import threading

from reviewer.context_economics.diagnostic_contract import (
    ContextRelevanceDiagnosticAuthorizationV1,
    ContextRelevanceDiagnosticExecutor,
    ContextRelevanceLiveDiagnosticExecutor,
    ContextRelevanceProviderStateV1,
    ContextRelevanceQuestionContractV1,
    DiagnosticExecutionJournal,
    DiagnosticJournalState,
    DiagnosticOutcomeStatus,
    DiagnosticSamplePacketV1,
    build_context_relevance_provider_request,
    generate_context_relevance_authorization_preview,
    generate_diagnostic_live_packet_artifact,
    generate_wave1_diagnostic_sample_packets,
    get_authoritative_h2b_wire_descriptor,
)
from reviewer.risk_model_adapter import F4QuestionContractV1


@pytest.fixture
def clean_journal_dir():
    temp_dir = tempfile.mkdtemp(prefix="test-diag-journal-")
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


def _make_dummy_packet(
    sample_id: str,
    semantic_input_id: str,
    stratum: str = "high_relevance",
    q_hash: str | None = None,
    s_hash: str | None = None,
) -> DiagnosticSamplePacketV1:
    q_contract = ContextRelevanceQuestionContractV1()
    qh = q_hash or q_contract.contract_hash
    sh = s_hash or ContextRelevanceProviderStateV1.compute_schema_hash()

    p_state = ContextRelevanceProviderStateV1(
        current_task=f"Task for {sample_id}",
        segment_text=f"Segment text for {sample_id}",
        source_type="TOOL_RESULT",
        age_or_stage_metadata="turn_10_admission",
    )
    return DiagnosticSamplePacketV1(
        sample_id=sample_id,
        semantic_input_id=semantic_input_id,
        stratum=stratum,
        turn_id=10,
        segment_id=f"seg-{sample_id}",
        current_task_hash=hashlib.sha256(b"task").hexdigest(),
        segment_content_hash=hashlib.sha256(b"content").hexdigest(),
        sanitized_payload_hash=p_state.compute_payload_hash(),
        question_contract_hash=qh,
        provider_state_schema_hash=sh,
        provider_state=p_state,
    )


def _make_dummy_authorization(
    sample_hash: str,
    q_hash: str,
    authorized_ids: tuple[str, ...],
    backup_ids: tuple[str, ...] = (),
    namespace_hash: str = "a" * 64,
) -> ContextRelevanceDiagnosticAuthorizationV1:
    s_hash = ContextRelevanceProviderStateV1.compute_schema_hash()
    return ContextRelevanceDiagnosticAuthorizationV1(
        candidate_sha="1a82954e0ddcf90427bbad3dd36dfbea732f1f4e",
        fixture_hash="479e7484b13118398a0ce34885d3f629ed7701a30f1bb6e94a1fc46aab116102",
        diagnostic_sample_hash=sample_hash,
        question_contract_hash=q_hash,
        provider_state_schema_hash=s_hash,
        wire_contract_hash="b" * 64,
        endpoint_host="diagnostic.provider.internal",
        authorized_semantic_input_ids=authorized_ids,
        authorized_backup_sample_ids=backup_ids,
        max_calls=len(authorized_ids) + len(backup_ids),
        journal_namespace_hash=namespace_hash,
    )


# ---------------------------------------------------------------------------
# Test D1: sample hash change -> authorization hash changes
# ---------------------------------------------------------------------------

def test_d1_sample_hash_change_modifies_authorization_hash() -> None:
    q_contract = ContextRelevanceQuestionContractV1()
    auth1 = _make_dummy_authorization(sample_hash="1" * 64, q_hash=q_contract.contract_hash, authorized_ids=("id1",))
    auth2 = _make_dummy_authorization(sample_hash="2" * 64, q_hash=q_contract.contract_hash, authorized_ids=("id1",))

    assert auth1.compute_authorization_hash() != auth2.compute_authorization_hash()


# ---------------------------------------------------------------------------
# Test D2: question contract change -> authorization hash changes
# ---------------------------------------------------------------------------

def test_d2_question_contract_change_modifies_authorization_hash() -> None:
    auth1 = _make_dummy_authorization(sample_hash="1" * 64, q_hash="a" * 64, authorized_ids=("id1",))
    auth2 = _make_dummy_authorization(sample_hash="1" * 64, q_hash="b" * 64, authorized_ids=("id1",))

    assert auth1.compute_authorization_hash() != auth2.compute_authorization_hash()


# ---------------------------------------------------------------------------
# Test D3: sample ID not in authorization -> NOT_SENT
# ---------------------------------------------------------------------------

def test_d3_sample_id_not_in_authorization_results_in_not_sent(clean_journal_dir: str) -> None:
    q_contract = ContextRelevanceQuestionContractV1()
    auth = _make_dummy_authorization(
        sample_hash="1" * 64,
        q_hash=q_contract.contract_hash,
        authorized_ids=("authorized_id_1",),
    )
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir, namespace="ns1")
    executor = ContextRelevanceDiagnosticExecutor(auth, q_contract, journal)

    # Packet with unauthorized semantic_input_id
    unauth_packet = _make_dummy_packet(sample_id="s1", semantic_input_id="unauthorized_id_999")
    res = executor.execute_dry_run_sample(unauth_packet, operation_id="op1", experiment_id="exp1")

    assert res.status == DiagnosticOutcomeStatus.NOT_SENT
    assert "not in authorization" in (res.error_message or "").lower()
    assert executor.physical_network_attempts == 0


# ---------------------------------------------------------------------------
# Test D4: same semantic_input_id different operation_id -> blocked
# ---------------------------------------------------------------------------

def test_d4_same_semantic_input_id_different_operation_id_blocked(clean_journal_dir: str) -> None:
    q_contract = ContextRelevanceQuestionContractV1()
    auth = _make_dummy_authorization(
        sample_hash="1" * 64,
        q_hash=q_contract.contract_hash,
        authorized_ids=("id_shared",),
    )
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir, namespace="ns1")
    executor = ContextRelevanceDiagnosticExecutor(auth, q_contract, journal)

    packet = _make_dummy_packet(sample_id="s1", semantic_input_id="id_shared")

    # First attempt: succeeds with OBSERVED_OK
    res1 = executor.execute_dry_run_sample(packet, operation_id="op_initial", experiment_id="exp1")
    assert res1.status == DiagnosticOutcomeStatus.OBSERVED_OK

    # Second attempt with different operation_id: blocked!
    res2 = executor.execute_dry_run_sample(packet, operation_id="op_divergent", experiment_id="exp1")
    assert res2.status == DiagnosticOutcomeStatus.NOT_SENT
    assert "replay blocked" in (res2.error_message or "").lower()
    assert executor.physical_network_attempts == 0


# ---------------------------------------------------------------------------
# Test D5: max_calls != exact sample count -> authorization invalid
# ---------------------------------------------------------------------------

def test_d5_max_calls_mismatch_raises_validation_error() -> None:
    q_contract = ContextRelevanceQuestionContractV1()
    s_hash = ContextRelevanceProviderStateV1.compute_schema_hash()

    with pytest.raises(ValueError, match="max_calls .* must exactly equal total authorized IDs"):
        ContextRelevanceDiagnosticAuthorizationV1(
            candidate_sha="1a82954e0ddcf90427bbad3dd36dfbea732f1f4e",
            fixture_hash="479e7484b13118398a0ce34885d3f629ed7701a30f1bb6e94a1fc46aab116102",
            diagnostic_sample_hash="1" * 64,
            question_contract_hash=q_contract.contract_hash,
            provider_state_schema_hash=s_hash,
            wire_contract_hash="b" * 64,
            endpoint_host="diagnostic.provider.internal",
            authorized_semantic_input_ids=("id1", "id2"),
            authorized_backup_sample_ids=(),
            max_calls=3,  # Invalid: 3 != 2
            journal_namespace_hash="c" * 64,
        )


# ---------------------------------------------------------------------------
# Test D6: different journal namespace cannot replay
# ---------------------------------------------------------------------------

def test_d6_cross_namespace_replay_blocked(clean_journal_dir: str) -> None:
    q_contract = ContextRelevanceQuestionContractV1()
    auth = _make_dummy_authorization(
        sample_hash="1" * 64,
        q_hash=q_contract.contract_hash,
        authorized_ids=("id_ns_test",),
    )

    journal_ns1 = DiagnosticExecutionJournal(root_dir=clean_journal_dir, namespace="ns_alpha")
    executor1 = ContextRelevanceDiagnosticExecutor(auth, q_contract, journal_ns1)

    packet = _make_dummy_packet(sample_id="s1", semantic_input_id="id_ns_test")
    res1 = executor1.execute_dry_run_sample(packet, operation_id="op1", experiment_id="exp1")
    assert res1.status == DiagnosticOutcomeStatus.OBSERVED_OK

    # Now attempt in a completely different namespace on the same private journal root
    journal_ns2 = DiagnosticExecutionJournal(root_dir=clean_journal_dir, namespace="ns_beta")
    executor2 = ContextRelevanceDiagnosticExecutor(auth, q_contract, journal_ns2)

    res2 = executor2.execute_dry_run_sample(packet, operation_id="op2", experiment_id="exp1")
    assert res2.status == DiagnosticOutcomeStatus.NOT_SENT
    assert "replay blocked" in (res2.error_message or "").lower()


# ---------------------------------------------------------------------------
# Test D7: OUTCOME_UNKNOWN -> entire experiment stops
# ---------------------------------------------------------------------------

def test_d7_outcome_unknown_halts_entire_batch(clean_journal_dir: str) -> None:
    q_contract = ContextRelevanceQuestionContractV1()
    auth = _make_dummy_authorization(
        sample_hash="1" * 64,
        q_hash=q_contract.contract_hash,
        authorized_ids=("id1", "id2", "id3"),
    )
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir, namespace="ns1")
    executor = ContextRelevanceDiagnosticExecutor(auth, q_contract, journal)

    p1 = _make_dummy_packet(sample_id="sample-01", semantic_input_id="id1")
    p2 = _make_dummy_packet(sample_id="sample-02", semantic_input_id="id2")
    p3 = _make_dummy_packet(sample_id="sample-03", semantic_input_id="id3")

    simulated_outcomes = {
        "sample-01": DiagnosticOutcomeStatus.OBSERVED_OK,
        "sample-02": DiagnosticOutcomeStatus.OUTCOME_UNKNOWN,
        "sample-03": DiagnosticOutcomeStatus.OBSERVED_OK,
    }

    results = executor.execute_dry_run_batch([p1, p2, p3], operation_id="op1", experiment_id="exp1", simulated_outcomes=simulated_outcomes)

    # Batch MUST stop immediately on sample-02, sample-03 never attempted!
    assert len(results) == 2
    assert results[0].status == DiagnosticOutcomeStatus.OBSERVED_OK
    assert results[1].status == DiagnosticOutcomeStatus.OUTCOME_UNKNOWN


# ---------------------------------------------------------------------------
# Test D8: second attempt on same sample -> zero network attempts
# ---------------------------------------------------------------------------

def test_d8_second_attempt_on_same_sample_zero_network(clean_journal_dir: str) -> None:
    q_contract = ContextRelevanceQuestionContractV1()
    auth = _make_dummy_authorization(
        sample_hash="1" * 64,
        q_hash=q_contract.contract_hash,
        authorized_ids=("id_double",),
    )
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir, namespace="ns1")
    executor = ContextRelevanceDiagnosticExecutor(auth, q_contract, journal)

    packet = _make_dummy_packet(sample_id="s1", semantic_input_id="id_double")

    res1 = executor.execute_dry_run_sample(packet, operation_id="op1", experiment_id="exp1")
    assert res1.status == DiagnosticOutcomeStatus.OBSERVED_OK
    assert executor.physical_network_attempts == 0

    res2 = executor.execute_dry_run_sample(packet, operation_id="op1", experiment_id="exp1")
    assert res2.status == DiagnosticOutcomeStatus.NOT_SENT
    assert executor.physical_network_attempts == 0


# ---------------------------------------------------------------------------
# Test D9: unbound extra sample -> zero network attempts
# ---------------------------------------------------------------------------

def test_d9_unbound_extra_sample_zero_network(clean_journal_dir: str) -> None:
    q_contract = ContextRelevanceQuestionContractV1()
    auth = _make_dummy_authorization(
        sample_hash="1" * 64,
        q_hash=q_contract.contract_hash,
        authorized_ids=("id_bound_1",),
    )
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir, namespace="ns1")
    executor = ContextRelevanceDiagnosticExecutor(auth, q_contract, journal)

    extra_packet = _make_dummy_packet(sample_id="s_extra", semantic_input_id="id_unbound_ghost")
    res = executor.execute_dry_run_sample(extra_packet, operation_id="op1", experiment_id="exp1")

    assert res.status == DiagnosticOutcomeStatus.NOT_SENT
    assert executor.physical_network_attempts == 0
    assert executor.api_key_reads == 0


# ---------------------------------------------------------------------------
# Test D10: risk-escalation H2 question contract cannot be used as Context Relevance contract
# ---------------------------------------------------------------------------

def test_d10_risk_escalation_question_contract_rejected_as_context_relevance() -> None:
    h2_contract = F4QuestionContractV1()
    relevance_contract = ContextRelevanceQuestionContractV1()

    # Statement must differ
    assert "risk escalation" in h2_contract.question_statement.lower()
    assert "relevant" in relevance_contract.question_statement.lower()
    assert "risk escalation" not in relevance_contract.question_statement.lower()

    # Hash must differ
    assert h2_contract.contract_hash != relevance_contract.contract_hash

    # Semantic meaning must differ
    assert "P(Noul)" in relevance_contract.output_interpretation
    assert "context relevance probability and NOT risk escalation" in relevance_contract.output_interpretation


# ---------------------------------------------------------------------------
# Test D11: zero-call dry run physical network attempts = 0
# ---------------------------------------------------------------------------

def test_d11_zero_call_dry_run_physical_network_zero(clean_journal_dir: str) -> None:
    q_contract = ContextRelevanceQuestionContractV1()
    auth = _make_dummy_authorization(
        sample_hash="1" * 64,
        q_hash=q_contract.contract_hash,
        authorized_ids=("id1", "id2"),
    )
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir, namespace="ns1")
    executor = ContextRelevanceDiagnosticExecutor(auth, q_contract, journal, allow_live_provider=False)

    p1 = _make_dummy_packet(sample_id="s1", semantic_input_id="id1")
    p2 = _make_dummy_packet(sample_id="s2", semantic_input_id="id2")

    results = executor.execute_dry_run_batch([p1, p2], operation_id="op1", experiment_id="exp1")
    assert len(results) == 2
    assert all(r.status == DiagnosticOutcomeStatus.OBSERVED_OK for r in results)

    # PHYSICAL ZERO CALL CONFIRMATION
    assert executor.physical_network_attempts == 0
    assert executor.api_key_reads == 0

    # allow_live_provider=True MUST fail closed
    with pytest.raises(RuntimeError, match="LIVE_PROVIDER_PROHIBITED_IN_THIS_GATE"):
        ContextRelevanceDiagnosticExecutor(auth, q_contract, journal, allow_live_provider=True)


# ---------------------------------------------------------------------------
# Test D12: provider-visible payload does not contain secret or private endpoint
# ---------------------------------------------------------------------------

def test_d12_provider_visible_payload_prohibits_secrets_and_private_endpoints() -> None:
    # Valid provider state
    valid_state = ContextRelevanceProviderStateV1(
        current_task="Find memory leak in connection pool",
        segment_text="Observed connection count is 42 and pool capacity is 50",
        source_type="TOOL_RESULT",
        age_or_stage_metadata="turn_15_admission",
    )
    payload = valid_state.canonical_payload()
    payload_str = json.dumps(payload)

    assert "api_key" not in payload_str
    assert "sk-" not in payload_str
    assert "Bearer" not in payload_str
    assert "https://" not in payload_str

    # Forbidden pattern: API key attempt
    with pytest.raises(ValueError, match="Forbidden value pattern 'sk-'"):
        ContextRelevanceProviderStateV1(
            current_task="Task",
            segment_text="Leak with token sk-proj-12345678",
            source_type="TOOL_RESULT",
            age_or_stage_metadata="turn_1",
        )

    # Forbidden pattern: Private endpoint attempt
    with pytest.raises(ValueError, match="Forbidden value pattern 'https://'"):
        ContextRelevanceProviderStateV1(
            current_task="Task",
            segment_text="Contact https://internal.corp/secret for details",
            source_type="TOOL_RESULT",
            age_or_stage_metadata="turn_1",
        )


# ---------------------------------------------------------------------------
# Test Real Deterministic Stratified Sample from EXP_C_WAVE1_V2
# ---------------------------------------------------------------------------

def test_real_deterministic_stratified_sample_generation() -> None:
    """Validate that real EXP_C_WAVE1_V2 generates exact 5 strata with count > 0."""
    packets, strata_counts, sample_hash, fixture_hash = generate_wave1_diagnostic_sample_packets(
        seed="EXP_C_WAVE1_V2",
        target_per_stratum=5,
    )
    assert len(fixture_hash) == 64
    assert len(sample_hash) == 64
    assert len(packets) == 25

    # Check 5 strata coverage
    expected_strata = {"high_relevance", "medium_relevance", "low_relevance", "recall_required", "stale_or_repeated_noise"}
    assert set(strata_counts.keys()) == expected_strata
    for s_name, count in strata_counts.items():
        assert count == 5, f"Stratum {s_name} expected 5, got {count}"

    # Generate physical packet artifact
    artifact = generate_diagnostic_live_packet_artifact("1a82954e0ddcf90427bbad3dd36dfbea732f1f4e", seed="EXP_C_WAVE1_V2")
    assert artifact["sample_count"] == 25
    assert artifact["max_calls"] == 25
    assert artifact["claim_ceiling"] == "REAL_JEV_RANKING_SIGNAL_MEASURED"
    assert len(artifact["packet_hash"]) == 64


# ===========================================================================
# Zero-Call Preflight & Live Executor Tests (Tests L1 to L15)
# ===========================================================================

def _make_live_authorization(
    journal: DiagnosticExecutionJournal,
    candidate_sha: str = "98e8f18a637e2aecffa45a5c225f8de50bccfe82",
    authorized_ids: tuple[str, ...] = ("id1",),
    max_calls: int | None = None,
    wire_hash: str | None = None,
    q_hash: str | None = None,
    root_hash: str | None = None,
    ns_hash: str | None = None,
    sample_hash: str = "1" * 64,
) -> ContextRelevanceDiagnosticAuthorizationV1:
    wire = get_authoritative_h2b_wire_descriptor()
    q_contract = ContextRelevanceQuestionContractV1()
    s_hash = ContextRelevanceProviderStateV1.compute_schema_hash()
    effective_max = len(authorized_ids) if max_calls is None else max_calls
    return ContextRelevanceDiagnosticAuthorizationV1(
        live_contract_revision=candidate_sha,
        sample_source_revision="1a82954e0ddcf90427bbad3dd36dfbea732f1f4e",
        fixture_hash="479e7484b13118398a0ce34885d3f629ed7701a30f1bb6e94a1fc46aab116102",
        diagnostic_sample_hash=sample_hash,
        question_contract_hash=q_hash or q_contract.contract_hash,
        provider_state_schema_hash=s_hash,
        wire_contract_hash=wire_hash or wire.canonical_wire_hash(),
        endpoint_host="diagnostic.provider.internal",
        journal_root_resolved_hash=root_hash or journal.get_root_resolved_hash(),
        journal_namespace_hash=ns_hash or journal.get_namespace_hash(),
        authorized_semantic_input_ids=authorized_ids,
        authorized_backup_sample_ids=(),
        max_calls=effective_max,
        diagnostic_packet_hash="d3120e10f83a80da9e84ed5ec4e13064a6af160fb53d6b00f8fa0f304125ea99",
    )


def test_l1_committed_packet_separates_source_revision_from_live_candidate() -> None:
    """L1: Committed packet does not confuse previous harness revision with live executor Candidate."""
    packet_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "diagnostic-live-packet.json")
    assert os.path.exists(packet_path), "diagnostic-live-packet.json must exist"
    with open(packet_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "candidate_sha" not in data, "candidate_sha must NOT be in committed packet"
    assert data["sample_source_revision"] == "1a82954e0ddcf90427bbad3dd36dfbea732f1f4e"
    assert data["schema_version"] == "context-relevance-diagnostic-live-packet-v2"
    assert len(data["packet_hash"]) == 64


def test_l2_packet_hash_distinct_from_authorization_hash(clean_journal_dir: str) -> None:
    """L2: packet_hash != authorization_hash subject semantics."""
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    auth, preview = generate_context_relevance_authorization_preview(
        live_contract_revision="98e8f18a637e2aecffa45a5c225f8de50bccfe82",
        journal_root_resolved_path=journal.resolved_root,
        authorized_semantic_input_ids=("id1",),
    )
    auth_hash = preview["authorization_hash"]
    packet_hash = auth.diagnostic_packet_hash
    assert packet_hash != auth_hash, "packet_hash and authorization_hash must have distinct subject semantics"
    assert len(packet_hash) == 64
    assert len(auth_hash) == 64


def test_l3_missing_nexus_private_eval_root_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """L3: missing NEXUS_PRIVATE_EVAL_ROOT in live mode -> fails closed."""
    monkeypatch.delenv("NEXUS_PRIVATE_EVAL_ROOT", raising=False)
    with pytest.raises(RuntimeError, match="LIVE_DIAGNOSTIC_NOT_SENT_PRIVATE_ROOT_UNAVAILABLE"):
        DiagnosticExecutionJournal(root_dir=None, is_live_executor=True)


def test_l4_different_physical_journal_root_yields_not_sent(clean_journal_dir: str) -> None:
    """L4: different physical journal root -> authorization mismatch -> NOT_SENT."""
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    auth = _make_live_authorization(journal, root_hash="f" * 64)
    wire = get_authoritative_h2b_wire_descriptor()
    q = ContextRelevanceQuestionContractV1()
    executor = ContextRelevanceLiveDiagnosticExecutor(
        auth, q, wire, journal, current_candidate_sha=auth.live_contract_revision
    )
    packet = _make_dummy_packet(sample_id="s1", semantic_input_id="id1")
    res = executor.execute_sample(packet, "op1", "exp1")
    assert res.status == DiagnosticOutcomeStatus.NOT_SENT
    assert "journal_root_resolved_hash mismatch" in (res.error_message or "")


def test_l5_different_namespace_yields_not_sent(clean_journal_dir: str) -> None:
    """L5: different namespace -> authorization mismatch -> NOT_SENT."""
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir, namespace="ns_actual")
    auth = _make_live_authorization(journal, ns_hash="e" * 64)
    wire = get_authoritative_h2b_wire_descriptor()
    q = ContextRelevanceQuestionContractV1()
    executor = ContextRelevanceLiveDiagnosticExecutor(
        auth, q, wire, journal, current_candidate_sha=auth.live_contract_revision
    )
    packet = _make_dummy_packet(sample_id="s1", semantic_input_id="id1")
    res = executor.execute_sample(packet, "op1", "exp1")
    assert res.status == DiagnosticOutcomeStatus.NOT_SENT
    assert "journal_namespace_hash mismatch" in (res.error_message or "")


def test_l6_concurrent_same_sample_attempts_exactly_one_claim_winner(clean_journal_dir: str) -> None:
    """L6: two concurrent same-sample attempts -> exactly one atomic claim winner."""
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    auth = _make_live_authorization(journal, authorized_ids=("id_concurrent",))
    wire = get_authoritative_h2b_wire_descriptor()
    q = ContextRelevanceQuestionContractV1()
    executor1 = ContextRelevanceLiveDiagnosticExecutor(
        auth, q, wire, journal, current_candidate_sha=auth.live_contract_revision
    )
    executor2 = ContextRelevanceLiveDiagnosticExecutor(
        auth, q, wire, journal, current_candidate_sha=auth.live_contract_revision
    )
    packet = _make_dummy_packet(sample_id="s1", semantic_input_id="id_concurrent")
    barrier = threading.Barrier(2)

    def run_exec(ex: ContextRelevanceLiveDiagnosticExecutor, op_id: str):
        barrier.wait()
        return ex.execute_sample(packet, op_id, "exp1")

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(run_exec, executor1, "op_worker1")
        f2 = pool.submit(run_exec, executor2, "op_worker2")
        r1 = f1.result()
        r2 = f2.result()

    results = [r1, r2]
    statuses = [r.status for r in results]
    assert statuses.count(DiagnosticOutcomeStatus.OBSERVED_OK) == 1
    assert statuses.count(DiagnosticOutcomeStatus.NOT_SENT) == 1
    loser = [r for r in results if r.status == DiagnosticOutcomeStatus.NOT_SENT][0]
    assert "ALREADY_CLAIMED" in (loser.error_message or "")
    assert executor1.physical_network_attempts + executor2.physical_network_attempts == 0


def test_l7_process_restart_from_request_attempt_started_no_second_dispatch(clean_journal_dir: str) -> None:
    """L7: process/restart from REQUEST_ATTEMPT_STARTED -> no second dispatch eligibility."""
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    auth = _make_live_authorization(journal, authorized_ids=("id_crash",))
    auth_hash = auth.compute_authorization_hash()

    # Pre-claim and write REQUEST_ATTEMPT_STARTED to simulate crash during flight
    journal.try_atomic_claim("exp1", "id_crash", auth_hash, "op_dead")
    journal.write_state_atomic(
        "id_crash",
        auth_hash,
        DiagnosticJournalState.REQUEST_ATTEMPT_STARTED,
        operation_id="op_dead",
        attempt_count=1,
    )

    wire = get_authoritative_h2b_wire_descriptor()
    q = ContextRelevanceQuestionContractV1()
    executor_restarted = ContextRelevanceLiveDiagnosticExecutor(
        auth, q, wire, journal, current_candidate_sha=auth.live_contract_revision
    )
    packet = _make_dummy_packet(sample_id="s1", semantic_input_id="id_crash")
    res = executor_restarted.execute_sample(packet, "op_restart", "exp1")

    assert res.status == DiagnosticOutcomeStatus.OUTCOME_UNKNOWN
    assert "no second dispatch eligibility" in (res.error_message or "")
    assert executor_restarted.physical_network_attempts == 0

    state = journal.read_state("id_crash", auth_hash)
    assert state is not None
    assert state["journal_state"] == DiagnosticJournalState.OUTCOME_UNKNOWN.value


def test_l8_outcome_unknown_halts_subsequent_samples(clean_journal_dir: str) -> None:
    """L8: OUTCOME_UNKNOWN -> all subsequent samples NOT_SENT."""
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    auth = _make_live_authorization(journal, authorized_ids=("id1", "id2", "id3"))
    auth_hash = auth.compute_authorization_hash()

    # Inject interrupted attempt on id2
    journal.try_atomic_claim("exp1", "id2", auth_hash, "op_dead")
    journal.write_state_atomic(
        "id2",
        auth_hash,
        DiagnosticJournalState.REQUEST_ATTEMPT_STARTED,
        operation_id="op_dead",
        attempt_count=1,
    )

    wire = get_authoritative_h2b_wire_descriptor()
    q = ContextRelevanceQuestionContractV1()
    executor = ContextRelevanceLiveDiagnosticExecutor(
        auth, q, wire, journal, current_candidate_sha=auth.live_contract_revision
    )
    p1 = _make_dummy_packet(sample_id="s1", semantic_input_id="id1")
    p2 = _make_dummy_packet(sample_id="s2", semantic_input_id="id2")
    p3 = _make_dummy_packet(sample_id="s3", semantic_input_id="id3")

    results = executor.execute_batch([p1, p2, p3], "op_batch", "exp1")
    assert len(results) == 3
    assert results[0].status == DiagnosticOutcomeStatus.OBSERVED_OK
    assert results[1].status == DiagnosticOutcomeStatus.OUTCOME_UNKNOWN
    assert results[2].status == DiagnosticOutcomeStatus.NOT_SENT
    assert "BATCH_HALTED_DUE_TO_OUTCOME_UNKNOWN" in (results[2].error_message or "")


def test_l9_unauthorized_semantic_input_id_yields_zero_dispatch(clean_journal_dir: str) -> None:
    """L9: unauthorized semantic_input_id -> zero dispatch."""
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    auth = _make_live_authorization(journal, authorized_ids=("id_valid",))
    wire = get_authoritative_h2b_wire_descriptor()
    q = ContextRelevanceQuestionContractV1()
    executor = ContextRelevanceLiveDiagnosticExecutor(
        auth, q, wire, journal, current_candidate_sha=auth.live_contract_revision
    )
    packet = _make_dummy_packet(sample_id="s1", semantic_input_id="id_unauthorized")
    res = executor.execute_sample(packet, "op1", "exp1")
    assert res.status == DiagnosticOutcomeStatus.NOT_SENT
    assert "Unauthorized" in (res.error_message or "")
    assert executor.physical_network_attempts == 0
    assert executor.total_claims_consumed == 0


def test_l10_authorization_candidate_revision_mismatch_yields_zero_dispatch(clean_journal_dir: str) -> None:
    """L10: authorization Candidate/live-contract revision mismatch -> zero dispatch."""
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    auth = _make_live_authorization(journal, candidate_sha="1" * 40)
    wire = get_authoritative_h2b_wire_descriptor()
    q = ContextRelevanceQuestionContractV1()
    executor = ContextRelevanceLiveDiagnosticExecutor(
        auth, q, wire, journal, current_candidate_sha="2" * 40
    )
    packet = _make_dummy_packet(sample_id="s1", semantic_input_id="id1")
    res = executor.execute_sample(packet, "op1", "exp1")
    assert res.status == DiagnosticOutcomeStatus.NOT_SENT
    assert "live_contract_revision mismatch" in (res.error_message or "")
    assert executor.physical_network_attempts == 0


def test_l11_wire_hash_mismatch_yields_zero_dispatch(clean_journal_dir: str) -> None:
    """L11: wire hash mismatch -> zero dispatch."""
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    auth = _make_live_authorization(journal, wire_hash="0" * 64)
    wire = get_authoritative_h2b_wire_descriptor()
    q = ContextRelevanceQuestionContractV1()
    executor = ContextRelevanceLiveDiagnosticExecutor(
        auth, q, wire, journal, current_candidate_sha=auth.live_contract_revision
    )
    packet = _make_dummy_packet(sample_id="s1", semantic_input_id="id1")
    res = executor.execute_sample(packet, "op1", "exp1")
    assert res.status == DiagnosticOutcomeStatus.NOT_SENT
    assert "wire_contract_hash mismatch" in (res.error_message or "")
    assert executor.physical_network_attempts == 0


def test_l12_question_contract_mismatch_yields_zero_dispatch(clean_journal_dir: str) -> None:
    """L12: question contract mismatch -> zero dispatch."""
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    auth = _make_live_authorization(journal, q_hash="0" * 64)
    wire = get_authoritative_h2b_wire_descriptor()
    q = ContextRelevanceQuestionContractV1()
    executor = ContextRelevanceLiveDiagnosticExecutor(
        auth, q, wire, journal, current_candidate_sha=auth.live_contract_revision
    )
    packet = _make_dummy_packet(sample_id="s1", semantic_input_id="id1")
    res = executor.execute_sample(packet, "op1", "exp1")
    assert res.status == DiagnosticOutcomeStatus.NOT_SENT
    assert "question_contract_hash mismatch" in (res.error_message or "")
    assert executor.physical_network_attempts == 0


def test_l13_zero_call_preflight_network_attempts_zero(clean_journal_dir: str) -> None:
    """L13: zero-call preflight network attempts = 0."""
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    auth = _make_live_authorization(journal, authorized_ids=("id1", "id2"))
    wire = get_authoritative_h2b_wire_descriptor()
    q = ContextRelevanceQuestionContractV1()
    executor = ContextRelevanceLiveDiagnosticExecutor(
        auth, q, wire, journal, current_candidate_sha=auth.live_contract_revision
    )
    p1 = _make_dummy_packet(sample_id="s1", semantic_input_id="id1")
    p2 = _make_dummy_packet(sample_id="s2", semantic_input_id="id2")
    results = executor.execute_batch([p1, p2], "op1", "exp1")
    assert len(results) == 2
    assert executor.physical_network_attempts == 0


def test_l14_zero_call_preflight_api_key_reads_zero(clean_journal_dir: str) -> None:
    """L14: zero-call preflight API key reads = 0."""
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    auth = _make_live_authorization(journal, authorized_ids=("id1",))
    wire = get_authoritative_h2b_wire_descriptor()
    q = ContextRelevanceQuestionContractV1()
    executor = ContextRelevanceLiveDiagnosticExecutor(
        auth, q, wire, journal, current_candidate_sha=auth.live_contract_revision
    )
    packet = _make_dummy_packet(sample_id="s1", semantic_input_id="id1")
    executor.execute_sample(packet, "op1", "exp1")
    assert executor.api_key_reads == 0


def test_l15_risk_contract_cannot_substitute_relevance_contract() -> None:
    """L15: risk contract cannot substitute relevance contract."""
    wire = get_authoritative_h2b_wire_descriptor()
    risk_contract = F4QuestionContractV1()
    p_state = ContextRelevanceProviderStateV1(
        current_task="task",
        segment_text="segment",
        source_type="TOOL_RESULT",
        age_or_stage_metadata="turn_1",
    )
    with pytest.raises(TypeError, match="must be ContextRelevanceQuestionContractV1"):
        build_context_relevance_provider_request(risk_contract, p_state, wire)  # type: ignore[arg-type]
