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
    DiagnosticTransportResponse,
    PreflightStatus,
    PreflightSampleResult,
    build_context_relevance_provider_request,
    generate_context_relevance_authorization_preview,
    generate_diagnostic_live_packet_artifact,
    generate_wave1_diagnostic_sample_packets,
    get_authoritative_h2b_wire_descriptor,
)
from reviewer.hosted_risk_config import HostedProviderConfigV1
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
    config_hash: str = "",
    endpoint_host: str = "diagnostic.provider.internal",
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
        config_hash=config_hash,
        endpoint_host=endpoint_host,
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
        config_hash="c" * 64,
        endpoint_host="diagnostic.provider.internal",
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


def test_l6_concurrent_same_sample_attempts_exactly_one_claim_winner(
    clean_journal_dir: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """L6: two concurrent live attempts have exactly one claim/transport winner."""
    monkeypatch.setenv("TEST_DIAG_API_KEY", "test-key-value")
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    config = _make_test_config()
    auth = _make_live_authorization(
        journal,
        authorized_ids=("id_concurrent",),
        config_hash=config.canonical_config_hash(),
    )
    wire = get_authoritative_h2b_wire_descriptor()
    q = ContextRelevanceQuestionContractV1()
    executor1 = ContextRelevanceLiveDiagnosticExecutor(
        auth, q, wire, journal,
        current_candidate_sha=auth.live_contract_revision,
        config=config,
        owner_runtime_authorization_granted=True,
    )
    executor2 = ContextRelevanceLiveDiagnosticExecutor(
        auth, q, wire, journal,
        current_candidate_sha=auth.live_contract_revision,
        config=config,
        owner_runtime_authorization_granted=True,
    )
    packet = _make_dummy_packet("s1", "id_concurrent")
    barrier = threading.Barrier(2)
    calls = [0]

    def transport(req: dict) -> dict:
        calls[0] += 1
        return _good_transport(req)

    def run_exec(ex: ContextRelevanceLiveDiagnosticExecutor, op_id: str):
        barrier.wait()
        return ex.execute_live_sample(packet, op_id, "exp1", transport_handler=transport)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(run_exec, executor1, "op_worker1")
        f2 = pool.submit(run_exec, executor2, "op_worker2")
        r1 = f1.result()
        r2 = f2.result()

    statuses = [r1.status, r2.status]
    assert statuses.count(DiagnosticOutcomeStatus.OBSERVED_OK) == 1
    assert statuses.count(DiagnosticOutcomeStatus.NOT_SENT) == 1
    assert calls[0] == 1


def test_l7_process_restart_from_request_attempt_started_no_second_dispatch(
    clean_journal_dir: str,
) -> None:
    """L7: live restart from REQUEST_ATTEMPT_STARTED becomes OUTCOME_UNKNOWN without dispatch."""
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    config = _make_test_config()
    auth = _make_live_authorization(
        journal,
        authorized_ids=("id_crash",),
        config_hash=config.canonical_config_hash(),
    )
    auth_hash = auth.compute_authorization_hash()
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
    executor = ContextRelevanceLiveDiagnosticExecutor(
        auth, q, wire, journal,
        current_candidate_sha=auth.live_contract_revision,
        config=config,
        owner_runtime_authorization_granted=True,
    )
    packet = _make_dummy_packet("s1", "id_crash")
    result = executor.execute_live_sample(
        packet, "op_restart", "exp1", transport_handler=_good_transport
    )
    assert result.status == DiagnosticOutcomeStatus.OUTCOME_UNKNOWN
    assert executor.physical_network_attempts == 0
    state = journal.read_state("id_crash", auth_hash)
    assert state is not None
    assert state["journal_state"] == DiagnosticJournalState.OUTCOME_UNKNOWN.value


def test_l8_outcome_unknown_halts_subsequent_samples(
    clean_journal_dir: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """L8: a live OUTCOME_UNKNOWN halts all later samples in the batch."""
    monkeypatch.setenv("TEST_DIAG_API_KEY", "test-key-value")
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    config = _make_test_config(max_canary_quota=3)
    auth = _make_live_authorization(
        journal,
        authorized_ids=("id1", "id2", "id3"),
        config_hash=config.canonical_config_hash(),
    )
    auth_hash = auth.compute_authorization_hash()
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
        auth, q, wire, journal,
        current_candidate_sha=auth.live_contract_revision,
        config=config,
        owner_runtime_authorization_granted=True,
    )
    packets = [
        _make_dummy_packet("s1", "id1"),
        _make_dummy_packet("s2", "id2"),
        _make_dummy_packet("s3", "id3"),
    ]
    results = executor.execute_live_batch(
        packets, "op_batch", "exp1", transport_handler=_good_transport
    )
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


# ===========================================================================
# Live Transport Capability Tests (Tests F1 to F20)
# REAL PROVIDER CALLS = 0, REAL NOUL CALLS = 0, API KEY SECRET READS = 0
# ===========================================================================

def _make_test_config(
    endpoint_host: str = "diagnostic.provider.internal",
    max_canary_quota: int = 50,
) -> HostedProviderConfigV1:
    """Build private-config-shaped test metadata without reading a real secret."""
    return HostedProviderConfigV1(
        endpoint_origin=f"https://{endpoint_host}",
        api_key_env_var_name="TEST_DIAG_API_KEY",
        max_canary_quota=max_canary_quota,
        allowed_hosts_whitelist=(endpoint_host,),
    )


def _make_live_executor(
    journal: DiagnosticExecutionJournal,
    authorized_ids: tuple[str, ...] = ("id1",),
    candidate_sha: str = "98e8f18a637e2aecffa45a5c225f8de50bccfe82",
    config: HostedProviderConfigV1 | None = None,
    owner_authorized: bool = True,
    wire_hash: str | None = None,
    q_hash: str | None = None,
    root_hash: str | None = None,
    ns_hash: str | None = None,
    auth_config_hash: str | None = None,
    auth_endpoint_host: str | None = None,
) -> ContextRelevanceLiveDiagnosticExecutor:
    """Build a live executor with authorization bound to its test config."""
    wire = get_authoritative_h2b_wire_descriptor()
    q_contract = ContextRelevanceQuestionContractV1()
    effective_config = config if config is not None else _make_test_config()
    endpoint_host = auth_endpoint_host or effective_config.allowed_hosts_whitelist[0]
    auth = ContextRelevanceDiagnosticAuthorizationV1(
        live_contract_revision=candidate_sha,
        sample_source_revision="1a82954e0ddcf90427bbad3dd36dfbea732f1f4e",
        fixture_hash="479e7484b13118398a0ce34885d3f629ed7701a30f1bb6e94a1fc46aab116102",
        diagnostic_sample_hash="1" * 64,
        question_contract_hash=q_hash or q_contract.contract_hash,
        provider_state_schema_hash=ContextRelevanceProviderStateV1.compute_schema_hash(),
        wire_contract_hash=wire_hash or wire.canonical_wire_hash(),
        config_hash=auth_config_hash or effective_config.canonical_config_hash(),
        endpoint_host=endpoint_host,
        journal_root_resolved_hash=root_hash or journal.get_root_resolved_hash(),
        journal_namespace_hash=ns_hash or journal.get_namespace_hash(),
        authorized_semantic_input_ids=authorized_ids,
        authorized_backup_sample_ids=(),
        max_calls=len(authorized_ids),
        diagnostic_packet_hash="d3120e10f83a80da9e84ed5ec4e13064a6af160fb53d6b00f8fa0f304125ea99",
    )
    return ContextRelevanceLiveDiagnosticExecutor(
        auth,
        q_contract,
        wire,
        journal,
        current_candidate_sha=candidate_sha,
        config=effective_config,
        owner_runtime_authorization_granted=owner_authorized,
    )


def _good_transport(req: dict) -> dict:
    """Fake transport: return valid OBSERVED_OK response."""
    return {
        "model": "jev-latest",
        "answers": {
            "decision": {
                "type": "noul",
                "noul": 0.85,
            }
        },
        "usage": {"input_tokens": 100, "output_tokens": 10},
    }


# ---------------------------------------------------------------------------
# F1: pure preflight_sample — no files, no claims
# ---------------------------------------------------------------------------

def test_f1_preflight_sample_no_files_no_claims(clean_journal_dir: str) -> None:
    """F1: preflight_sample returns READY, writes NO files, makes NO claims."""
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    executor = _make_live_executor(journal, authorized_ids=("id1",))
    packet = _make_dummy_packet("s1", "id1")

    before_files = set(os.listdir(journal.journal_dir))
    result = executor.preflight_sample(packet)
    after_files = set(os.listdir(journal.journal_dir))

    assert result.status == PreflightStatus.READY
    assert result.reason is None
    assert before_files == after_files, "preflight_sample must not create any files"
    assert executor.api_key_reads == 0
    assert executor.physical_network_attempts == 0
    assert executor.total_claims_consumed == 0


# ---------------------------------------------------------------------------
# F2: repeat preflight_sample — no consumption
# ---------------------------------------------------------------------------

def test_f2_repeat_preflight_sample_no_consumption(clean_journal_dir: str) -> None:
    """F2: calling preflight_sample multiple times must not change any state."""
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    executor = _make_live_executor(journal, authorized_ids=("id1",))
    packet = _make_dummy_packet("s1", "id1")

    for _ in range(5):
        result = executor.preflight_sample(packet)
        assert result.status == PreflightStatus.READY

    assert executor.api_key_reads == 0
    assert executor.physical_network_attempts == 0
    assert executor.total_claims_consumed == 0


# ---------------------------------------------------------------------------
# F3: Owner auth absent → NOT_SENT, 0 secret reads, 0 network
# ---------------------------------------------------------------------------

def test_f3_owner_auth_absent_not_sent_zero_reads_zero_network(clean_journal_dir: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """F3: owner_runtime_authorization_granted=False → NOT_SENT, 0 api key reads, 0 network."""
    monkeypatch.delenv("TEST_DIAG_API_KEY", raising=False)
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    executor = _make_live_executor(journal, authorized_ids=("id1",), owner_authorized=False)
    packet = _make_dummy_packet("s1", "id1")

    result = executor.execute_live_sample(packet, "op1", "exp1", transport_handler=_good_transport)

    assert result.status == DiagnosticOutcomeStatus.NOT_SENT
    assert "OWNER_AUTHORIZATION_NOT_GRANTED" in (result.error_message or "")
    assert executor.api_key_reads == 0
    assert executor.physical_network_attempts == 0


# ---------------------------------------------------------------------------
# F4: exact auth + fake transport → 1 invocation, OBSERVED_OK
# ---------------------------------------------------------------------------

def test_f4_exact_auth_fake_transport_one_invocation(clean_journal_dir: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """F4: with exact authorization and fake transport → exactly 1 invocation, OBSERVED_OK."""
    monkeypatch.setenv("TEST_DIAG_API_KEY", "test-key-value")
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    executor = _make_live_executor(journal, authorized_ids=("id1",))
    packet = _make_dummy_packet("s1", "id1")

    invocations: list[dict] = []

    def counting_transport(req: dict) -> dict:
        invocations.append(req)
        return _good_transport(req)

    result = executor.execute_live_sample(packet, "op1", "exp1", transport_handler=counting_transport)

    assert result.status == DiagnosticOutcomeStatus.OBSERVED_OK
    assert result.response_hash is not None and len(result.response_hash) == 64
    assert len(invocations) == 1, "Exactly one transport invocation expected"
    assert executor.physical_network_attempts == 1
    assert executor.api_key_reads == 1


# ---------------------------------------------------------------------------
# F5: concurrent same sample → exactly 1 fake transport invocation
# ---------------------------------------------------------------------------

def test_f5_concurrent_same_sample_one_transport_invocation(clean_journal_dir: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """F5: concurrent same-sample → atomic claim ensures exactly 1 transport call."""
    monkeypatch.setenv("TEST_DIAG_API_KEY", "test-key-value")
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    executor1 = _make_live_executor(journal, authorized_ids=("id_conc",))
    executor2 = _make_live_executor(journal, authorized_ids=("id_conc",))
    packet = _make_dummy_packet("s1", "id_conc")
    barrier = threading.Barrier(2)
    invocations: list[int] = []

    def barrier_transport(req: dict) -> dict:
        invocations.append(1)
        return _good_transport(req)

    def run_ex(ex: ContextRelevanceLiveDiagnosticExecutor) -> DiagnosticExecutionResult:
        barrier.wait()
        return ex.execute_live_sample(packet, "op1", "exp1", transport_handler=barrier_transport)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(run_ex, executor1)
        f2 = pool.submit(run_ex, executor2)
        r1 = f1.result()
        r2 = f2.result()

    statuses = {r1.status, r2.status}
    assert DiagnosticOutcomeStatus.OBSERVED_OK in statuses
    assert DiagnosticOutcomeStatus.NOT_SENT in statuses
    assert len(invocations) == 1, "Exactly 1 transport invocation across concurrent executors"


# ---------------------------------------------------------------------------
# F6: parallel batch claim winner → only one batch proceeds
# ---------------------------------------------------------------------------

def test_f6_parallel_batch_claim_exactly_one_winner(clean_journal_dir: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """F6: parallel execute_live_batch with same auth → exactly one batch wins the claim."""
    monkeypatch.setenv("TEST_DIAG_API_KEY", "test-key-value")
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    exec1 = _make_live_executor(journal, authorized_ids=("id_b1", "id_b2"))
    exec2 = _make_live_executor(journal, authorized_ids=("id_b1", "id_b2"))
    p1 = _make_dummy_packet("s1", "id_b1")
    p2 = _make_dummy_packet("s2", "id_b2")
    barrier = threading.Barrier(2)

    def run_batch(ex: ContextRelevanceLiveDiagnosticExecutor) -> list[DiagnosticExecutionResult]:
        barrier.wait()
        return ex.execute_live_batch([p1, p2], "op_batch", "exp_batch", transport_handler=_good_transport)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(run_batch, exec1)
        f2 = pool.submit(run_batch, exec2)
        res1 = f1.result()
        res2 = f2.result()

    # One of the two batches must be all BATCH_ALREADY_CLAIMED (loser)
    # The other (winner) processes samples normally
    loser_batch = None
    winner_batch = None
    for batch in (res1, res2):
        if all("BATCH_ALREADY_CLAIMED" in (r.error_message or "") for r in batch):
            loser_batch = batch
        else:
            winner_batch = batch

    assert loser_batch is not None, "Exactly one batch must be the loser (BATCH_ALREADY_CLAIMED)"
    assert winner_batch is not None, "Exactly one batch must be the winner"


# ---------------------------------------------------------------------------
# F7: different operation_id replay blocked
# ---------------------------------------------------------------------------

def test_f7_different_operation_id_replay_blocked(clean_journal_dir: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """F7: second execute_live_sample with same packet but different operation_id → replay blocked."""
    monkeypatch.setenv("TEST_DIAG_API_KEY", "test-key-value")
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    executor = _make_live_executor(journal, authorized_ids=("id1",))
    packet = _make_dummy_packet("s1", "id1")

    r1 = executor.execute_live_sample(packet, "op_initial", "exp1", transport_handler=_good_transport)
    assert r1.status == DiagnosticOutcomeStatus.OBSERVED_OK

    # Second attempt → already in terminal state
    executor2 = _make_live_executor(journal, authorized_ids=("id1",))
    r2 = executor2.execute_live_sample(packet, "op_replay", "exp1", transport_handler=_good_transport)
    assert r2.status in (
        DiagnosticOutcomeStatus.NOT_SENT,
        DiagnosticOutcomeStatus.OBSERVED_OK,
    )
    # Must not call transport again
    assert executor2.physical_network_attempts == 0


# ---------------------------------------------------------------------------
# F8: cross-root/namespace blocked
# ---------------------------------------------------------------------------

def test_f8_cross_namespace_blocked(clean_journal_dir: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """F8: wrong namespace hash → preflight_sample returns NOT_READY."""
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir, namespace="ns_correct")
    executor = _make_live_executor(journal, authorized_ids=("id1",), ns_hash="f" * 64)
    packet = _make_dummy_packet("s1", "id1")

    pf = executor.preflight_sample(packet)
    assert pf.status == PreflightStatus.NOT_READY
    assert "journal_namespace_hash mismatch" in (pf.reason or "")


# ---------------------------------------------------------------------------
# F9: transport raises exception → OUTCOME_UNKNOWN, batch halts
# ---------------------------------------------------------------------------

def test_f9_timeout_outcome_unknown_stops_batch(clean_journal_dir: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """F9: transport_handler raising exception → OUTCOME_UNKNOWN → batch halts."""
    monkeypatch.setenv("TEST_DIAG_API_KEY", "test-key-value")
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    executor = _make_live_executor(journal, authorized_ids=("id1", "id2", "id3"))
    p1 = _make_dummy_packet("s1", "id1")
    p2 = _make_dummy_packet("s2", "id2")
    p3 = _make_dummy_packet("s3", "id3")

    call_count = [0]

    def flaky_transport(req: dict) -> dict:
        call_count[0] += 1
        if call_count[0] == 1:
            raise TimeoutError("simulated timeout")
        return _good_transport(req)

    results = executor.execute_live_batch([p1, p2, p3], "op_t", "exp1", transport_handler=flaky_transport)

    assert results[0].status == DiagnosticOutcomeStatus.OUTCOME_UNKNOWN
    assert results[1].status == DiagnosticOutcomeStatus.NOT_SENT
    assert results[2].status == DiagnosticOutcomeStatus.NOT_SENT
    assert "BATCH_HALTED_DUE_TO_OUTCOME_UNKNOWN" in (results[1].error_message or "")


# ---------------------------------------------------------------------------
# F10: 4xx response → OBSERVED_CLIENT_FAILURE, no retry
# ---------------------------------------------------------------------------

def test_f10_4xx_observed_client_failure_no_retry(
    clean_journal_dir: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F10: a definitive HTTP 4xx is OBSERVED_CLIENT_FAILURE with no retry."""
    monkeypatch.setenv("TEST_DIAG_API_KEY", "test-key-value")
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    executor = _make_live_executor(journal, authorized_ids=("id1",))
    packet = _make_dummy_packet("s1", "id1")
    calls = [0]

    def transport(req: dict) -> DiagnosticTransportResponse:
        calls[0] += 1
        return DiagnosticTransportResponse(status_code=429, raw_body=b'{"error":"rate"}')

    result = executor.execute_live_sample(packet, "op1", "exp1", transport_handler=transport)
    assert result.status == DiagnosticOutcomeStatus.OBSERVED_CLIENT_FAILURE
    assert result.error_message == "HTTP 429"
    assert calls[0] == 1
    assert executor.physical_network_attempts == 1


# ---------------------------------------------------------------------------
# F11: 5xx response → OBSERVED_PROVIDER_FAILURE, no retry
# ---------------------------------------------------------------------------

def test_f11_5xx_observed_provider_failure_no_retry(
    clean_journal_dir: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F11: a definitive HTTP 5xx is OBSERVED_PROVIDER_FAILURE with no retry."""
    monkeypatch.setenv("TEST_DIAG_API_KEY", "test-key-value")
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    executor = _make_live_executor(journal, authorized_ids=("id1",))
    packet = _make_dummy_packet("s1", "id1")
    calls = [0]

    def transport(req: dict) -> DiagnosticTransportResponse:
        calls[0] += 1
        return DiagnosticTransportResponse(status_code=503, raw_body=b'{"error":"unavailable"}')

    result = executor.execute_live_sample(packet, "op1", "exp1", transport_handler=transport)
    assert result.status == DiagnosticOutcomeStatus.OBSERVED_PROVIDER_FAILURE
    assert result.error_message == "HTTP 503"
    assert calls[0] == 1
    assert executor.physical_network_attempts == 1


# ---------------------------------------------------------------------------
# F12: malformed JSON from transport → OBSERVED_PROVIDER_FAILURE
# ---------------------------------------------------------------------------

def test_f12_non_dict_response_provider_failure(clean_journal_dir: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """F12: transport returns non-dict → OBSERVED_PROVIDER_FAILURE."""
    monkeypatch.setenv("TEST_DIAG_API_KEY", "test-key-value")
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    executor = _make_live_executor(journal, authorized_ids=("id1",))
    packet = _make_dummy_packet("s1", "id1")

    def list_transport(req: dict) -> dict:
        return [1, 2, 3]  # type: ignore[return-value]  # invalid: non-dict

    result = executor.execute_live_sample(packet, "op1", "exp1", transport_handler=list_transport)
    assert result.status == DiagnosticOutcomeStatus.OBSERVED_PROVIDER_FAILURE


# ---------------------------------------------------------------------------
# F13: duplicate JSON key rejected by _reject_duplicate_diag_pairs
# ---------------------------------------------------------------------------

def test_f13_duplicate_json_key_provider_failure(clean_journal_dir: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """F13: _reject_duplicate_diag_pairs rejects duplicate response keys."""
    import io
    from reviewer.context_economics.diagnostic_contract import _reject_duplicate_diag_pairs

    raw = b'{"model":"a","model":"b"}'
    with pytest.raises(ValueError, match="duplicate JSON keys"):
        import json as _json
        _json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_diag_pairs)


# ---------------------------------------------------------------------------
# F14: oversized response → OBSERVED_PROVIDER_FAILURE (via bounded 1MB check)
# ---------------------------------------------------------------------------

def test_f14_oversized_response_provider_failure(
    clean_journal_dir: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F14: a raw body larger than 1 MiB is rejected before JSON parsing."""
    monkeypatch.setenv("TEST_DIAG_API_KEY", "test-key-value")
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    executor = _make_live_executor(journal, authorized_ids=("id1",))
    packet = _make_dummy_packet("s1", "id1")
    calls = [0]

    def transport(req: dict) -> DiagnosticTransportResponse:
        calls[0] += 1
        return DiagnosticTransportResponse(
            status_code=200,
            raw_body=b"x" * (1_048_576 + 1),
        )

    result = executor.execute_live_sample(packet, "op1", "exp1", transport_handler=transport)
    assert result.status == DiagnosticOutcomeStatus.OBSERVED_PROVIDER_FAILURE
    assert "exceeded 1MB bound" in (result.error_message or "")
    assert calls[0] == 1


# ---------------------------------------------------------------------------
# F15: invalid probability (bool, NaN, out-of-range) → OBSERVED_PROVIDER_FAILURE
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_prob,prob_id", [
    (True, "bool_true"),
    (False, "bool_false"),
    (float("nan"), "nan"),
    (-0.01, "neg"),
    (1.01, "over_one"),
    (None, "none"),
    ("high", "str"),
])
def test_f15_invalid_probability_provider_failure(
    clean_journal_dir: str,
    monkeypatch: pytest.MonkeyPatch,
    bad_prob: object,
    prob_id: str,
) -> None:
    """F15: invalid noul probability → OBSERVED_PROVIDER_FAILURE."""
    monkeypatch.setenv("TEST_DIAG_API_KEY", "test-key-value")

    def bad_prob_transport(req: dict) -> dict:
        return {
            "model": "jev-latest",
            "answers": {"decision": {"type": "noul", "noul": bad_prob}},
        }

    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    sid = f"prob_{prob_id}"
    executor = _make_live_executor(journal, authorized_ids=(sid,))
    packet = _make_dummy_packet("s1", sid)

    result = executor.execute_live_sample(packet, "op1", "exp_prob", transport_handler=bad_prob_transport)
    assert result.status == DiagnosticOutcomeStatus.OBSERVED_PROVIDER_FAILURE


# ---------------------------------------------------------------------------
# F16: revision mismatch → preflight_sample NOT_READY
# ---------------------------------------------------------------------------

def test_f16_revision_mismatch_not_ready(clean_journal_dir: str) -> None:
    """F16: live_contract_revision mismatch → preflight_sample NOT_READY."""
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    executor = _make_live_executor(
        journal, authorized_ids=("id1",), candidate_sha="1" * 40
    )
    # Override current_candidate_sha to mismatch
    executor.current_candidate_sha = "2" * 40
    packet = _make_dummy_packet("s1", "id1")
    pf = executor.preflight_sample(packet)
    assert pf.status == PreflightStatus.NOT_READY
    assert "live_contract_revision mismatch" in (pf.reason or "")


# ---------------------------------------------------------------------------
# F17: private config unavailable → NOT_SENT immediately
# ---------------------------------------------------------------------------

def test_f17_private_config_unavailable_not_sent(clean_journal_dir: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """F17: config=None → LIVE_DIAGNOSTIC_NOT_SENT_PRIVATE_CONFIG_UNAVAILABLE."""
    monkeypatch.delenv("TEST_DIAG_API_KEY", raising=False)
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)

    # Build executor without config
    wire = get_authoritative_h2b_wire_descriptor()
    q = ContextRelevanceQuestionContractV1()
    auth = ContextRelevanceDiagnosticAuthorizationV1(
        live_contract_revision="98e8f18a637e2aecffa45a5c225f8de50bccfe82",
        sample_source_revision="1a82954e0ddcf90427bbad3dd36dfbea732f1f4e",
        fixture_hash="479e7484b13118398a0ce34885d3f629ed7701a30f1bb6e94a1fc46aab116102",
        diagnostic_sample_hash="1" * 64,
        question_contract_hash=q.contract_hash,
        provider_state_schema_hash=ContextRelevanceProviderStateV1.compute_schema_hash(),
        wire_contract_hash=wire.canonical_wire_hash(),
        endpoint_host="diagnostic.provider.internal",
        journal_root_resolved_hash=journal.get_root_resolved_hash(),
        journal_namespace_hash=journal.get_namespace_hash(),
        authorized_semantic_input_ids=("id1",),
        authorized_backup_sample_ids=(),
        max_calls=1,
    )
    executor = ContextRelevanceLiveDiagnosticExecutor(
        auth, q, wire, journal,
        current_candidate_sha="98e8f18a637e2aecffa45a5c225f8de50bccfe82",
        config=None,
        owner_runtime_authorization_granted=True,
    )
    packet = _make_dummy_packet("s1", "id1")

    # preflight_sample must return NOT_READY
    pf = executor.preflight_sample(packet)
    assert pf.status == PreflightStatus.NOT_READY
    assert "PRIVATE_CONFIG_UNAVAILABLE" in (pf.reason or "")

    # execute_live_sample must NOT call transport and return NOT_SENT
    invocations: list[int] = []

    def should_not_call(req: dict) -> dict:
        invocations.append(1)
        return _good_transport(req)

    result = executor.execute_live_sample(packet, "op1", "exp1", transport_handler=should_not_call)
    assert result.status == DiagnosticOutcomeStatus.NOT_SENT
    assert "PRIVATE_CONFIG_UNAVAILABLE" in (result.error_message or "")
    assert len(invocations) == 0, "transport must never be called when config is unavailable"
    assert executor.api_key_reads == 0


# ---------------------------------------------------------------------------
# F18: wire drift → preflight_sample NOT_READY
# ---------------------------------------------------------------------------

def test_f18_wire_drift_not_ready(clean_journal_dir: str) -> None:
    """F18: authorization wire_contract_hash ≠ actual wire hash → NOT_READY."""
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    executor = _make_live_executor(journal, authorized_ids=("id1",), wire_hash="0" * 64)
    packet = _make_dummy_packet("s1", "id1")
    pf = executor.preflight_sample(packet)
    assert pf.status == PreflightStatus.NOT_READY
    assert "wire_contract_hash mismatch" in (pf.reason or "")


# ---------------------------------------------------------------------------
# F19: risk contract rejected in preflight (wrong question contract)
# ---------------------------------------------------------------------------

def test_f19_risk_contract_rejected_as_relevance_contract(clean_journal_dir: str) -> None:
    """F19: authorization has wrong question_contract_hash → preflight_sample NOT_READY."""
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    executor = _make_live_executor(journal, authorized_ids=("id1",), q_hash="0" * 64)
    packet = _make_dummy_packet("s1", "id1")
    pf = executor.preflight_sample(packet)
    assert pf.status == PreflightStatus.NOT_READY
    assert "question_contract_hash mismatch" in (pf.reason or "")


# ---------------------------------------------------------------------------
# F20: external provider calls = 0, secret reads = 0 (zero-call invariant)
# ---------------------------------------------------------------------------

def test_f20_zero_external_calls_zero_secret_reads(clean_journal_dir: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """F20: pure preflight_sample calls = 0 external calls, 0 secret reads ever."""
    monkeypatch.delenv("TEST_DIAG_API_KEY", raising=False)
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    executor = _make_live_executor(journal, authorized_ids=("id1", "id2", "id3"))

    packets = [
        _make_dummy_packet("s1", "id1"),
        _make_dummy_packet("s2", "id2"),
        _make_dummy_packet("s3", "id3"),
    ]

    for p in packets:
        result = executor.preflight_sample(p)
        assert result.status == PreflightStatus.READY

    # Zero external state-machine effects after preflight
    assert executor.physical_network_attempts == 0, "REAL PROVIDER CALLS MUST BE 0"
    assert executor.api_key_reads == 0, "API KEY SECRET READS MUST BE 0"
    assert executor.total_claims_consumed == 0, "No authorization consumed in preflight"


# ===========================================================================
# Runtime authorization binding regressions
# ===========================================================================

def test_r1_config_hash_mismatch_has_zero_effects(clean_journal_dir: str) -> None:
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    executor = _make_live_executor(
        journal, authorized_ids=("id1",), auth_config_hash="0" * 64
    )
    packet = _make_dummy_packet("s1", "id1")
    ready, reason = executor.preflight_live_batch([packet])
    assert not ready
    assert "CONFIG_HASH_MISMATCH" in (reason or "")
    assert os.listdir(journal.journal_dir) == []
    assert executor.api_key_reads == 0
    assert executor.physical_network_attempts == 0


def test_r2_endpoint_host_mismatch_has_zero_effects(clean_journal_dir: str) -> None:
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    config = _make_test_config(endpoint_host="actual.provider.internal")
    executor = _make_live_executor(
        journal,
        authorized_ids=("id1",),
        config=config,
        auth_endpoint_host="authorized.provider.internal",
    )
    ready, reason = executor.preflight_live_batch([_make_dummy_packet("s1", "id1")])
    assert not ready
    assert "ENDPOINT_HOST_MISMATCH" in (reason or "")
    assert os.listdir(journal.journal_dir) == []


def test_r3_quota_25_against_quota_1_fails_before_claim(clean_journal_dir: str) -> None:
    ids = tuple(f"id{i:02d}" for i in range(25))
    packets = [_make_dummy_packet(f"s{i:02d}", sid) for i, sid in enumerate(ids)]
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    executor = _make_live_executor(
        journal,
        authorized_ids=ids,
        config=_make_test_config(max_canary_quota=1),
    )
    ready, reason = executor.preflight_live_batch(packets)
    assert not ready
    assert "QUOTA_EXCEEDED" in (reason or "")
    assert os.listdir(journal.journal_dir) == []
    assert executor.api_key_reads == 0
    assert executor.physical_network_attempts == 0


def test_r4_exact_25_with_quota_25_is_preflight_eligible(clean_journal_dir: str) -> None:
    ids = tuple(f"id{i:02d}" for i in range(25))
    packets = [_make_dummy_packet(f"s{i:02d}", sid) for i, sid in enumerate(ids)]
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    executor = _make_live_executor(
        journal,
        authorized_ids=ids,
        config=_make_test_config(max_canary_quota=25),
    )
    ready, reason = executor.preflight_live_batch(packets)
    assert ready
    assert reason is None
    assert os.listdir(journal.journal_dir) == []


def test_r5_owner_auth_missing_creates_no_batch_claim(clean_journal_dir: str) -> None:
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    executor = _make_live_executor(
        journal, authorized_ids=("id1",), owner_authorized=False
    )
    results = executor.execute_live_batch(
        [_make_dummy_packet("s1", "id1")],
        "op",
        "exp",
        transport_handler=_good_transport,
    )
    assert results[0].status == DiagnosticOutcomeStatus.NOT_SENT
    assert "OWNER_AUTHORIZATION_NOT_GRANTED" in (results[0].error_message or "")
    assert os.listdir(journal.journal_dir) == []


def test_r6_config_missing_creates_no_batch_claim(clean_journal_dir: str) -> None:
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    wire = get_authoritative_h2b_wire_descriptor()
    q = ContextRelevanceQuestionContractV1()
    auth = ContextRelevanceDiagnosticAuthorizationV1(
        live_contract_revision="1" * 40,
        sample_source_revision="2" * 40,
        fixture_hash="3" * 64,
        diagnostic_sample_hash="4" * 64,
        question_contract_hash=q.contract_hash,
        provider_state_schema_hash=ContextRelevanceProviderStateV1.compute_schema_hash(),
        wire_contract_hash=wire.canonical_wire_hash(),
        config_hash="5" * 64,
        endpoint_host="diagnostic.provider.internal",
        authorized_semantic_input_ids=("id1",),
        journal_root_resolved_hash=journal.get_root_resolved_hash(),
        journal_namespace_hash=journal.get_namespace_hash(),
        max_calls=1,
    )
    executor = ContextRelevanceLiveDiagnosticExecutor(
        auth, q, wire, journal,
        current_candidate_sha="1" * 40,
        config=None,
        owner_runtime_authorization_granted=True,
    )
    results = executor.execute_live_batch(
        [_make_dummy_packet("s1", "id1")],
        "op",
        "exp",
        transport_handler=_good_transport,
    )
    assert results[0].status == DiagnosticOutcomeStatus.NOT_SENT
    assert "PRIVATE_CONFIG_UNAVAILABLE" in (results[0].error_message or "")
    assert os.listdir(journal.journal_dir) == []


def test_r7_subset_batch_creates_no_claim(clean_journal_dir: str) -> None:
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    executor = _make_live_executor(journal, authorized_ids=("id1", "id2"))
    results = executor.execute_live_batch(
        [_make_dummy_packet("s1", "id1")],
        "op",
        "exp",
        transport_handler=_good_transport,
    )
    assert results[0].status == DiagnosticOutcomeStatus.NOT_SENT
    assert "EXACT_BATCH_REQUIRED" in (results[0].error_message or "")
    assert os.listdir(journal.journal_dir) == []


def test_r8_duplicate_semantic_id_creates_no_claim(clean_journal_dir: str) -> None:
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    executor = _make_live_executor(journal, authorized_ids=("id1", "id2"))
    packets = [
        _make_dummy_packet("s1", "id1"),
        _make_dummy_packet("s2", "id1"),
    ]
    results = executor.execute_live_batch(
        packets, "op", "exp", transport_handler=_good_transport
    )
    assert all(r.status == DiagnosticOutcomeStatus.NOT_SENT for r in results)
    assert "DUPLICATE_SEMANTIC_INPUT_ID" in (results[0].error_message or "")
    assert os.listdir(journal.journal_dir) == []


def test_r9_unauthorized_replacement_creates_no_claim(clean_journal_dir: str) -> None:
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    executor = _make_live_executor(journal, authorized_ids=("id1", "id2"))
    packets = [
        _make_dummy_packet("s1", "id1"),
        _make_dummy_packet("s2", "idX"),
    ]
    results = executor.execute_live_batch(
        packets, "op", "exp", transport_handler=_good_transport
    )
    assert all(r.status == DiagnosticOutcomeStatus.NOT_SENT for r in results)
    assert "AUTHORIZED_SET_MISMATCH" in (results[0].error_message or "")
    assert os.listdir(journal.journal_dir) == []


def test_r10_legacy_zero_call_repeated_does_not_consume_claims(clean_journal_dir: str) -> None:
    journal = DiagnosticExecutionJournal(root_dir=clean_journal_dir)
    auth = _make_live_authorization(journal, authorized_ids=("id1",))
    wire = get_authoritative_h2b_wire_descriptor()
    q = ContextRelevanceQuestionContractV1()
    executor = ContextRelevanceLiveDiagnosticExecutor(
        auth, q, wire, journal, current_candidate_sha=auth.live_contract_revision
    )
    packet = _make_dummy_packet("s1", "id1")
    first = executor.execute_sample(packet, "op1", "exp")
    second = executor.execute_sample(packet, "op2", "exp")
    assert first.status == DiagnosticOutcomeStatus.NOT_SENT
    assert second.status == DiagnosticOutcomeStatus.NOT_SENT
    assert first.error_message == "ZERO_CALL_PREFLIGHT_READY_NO_EFFECT"
    assert second.error_message == "ZERO_CALL_PREFLIGHT_READY_NO_EFFECT"
    assert os.listdir(journal.journal_dir) == []
    assert executor.api_key_reads == 0
    assert executor.physical_network_attempts == 0
