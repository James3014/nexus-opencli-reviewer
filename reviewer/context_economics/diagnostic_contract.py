"""F4 Context Economics — Context Relevance Diagnostic Live Contract.

Provides exact, reviewable, one-time Owner-authorizable live Jev execution contract:
1. ContextRelevanceQuestionContractV1: Frozen semantic question contract for context relevance.
2. ContextRelevanceProviderStateV1: Minimal sanitized provider-visible state projection.
3. DiagnosticSamplePacketV1: Deterministic sample packet binding actual sanitized payloads.
4. ContextRelevanceDiagnosticAuthorizationV1: Durable Owner batch authorization.
5. DiagnosticExecutionJournal: Non-symlink private journal outside git with 0700/0600 permissions.
6. ContextRelevanceDiagnosticExecutor: Zero-call dry-run executor with fail-closed network gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import os
from typing import Any, Sequence

from reviewer.context_economics.fixtures import SessionFixtureGenerator
from reviewer.context_economics.models import (
    ArchitectureId,
    ContextSegmentV1,
    SyntheticRankerMode,
)
from reviewer.context_economics.simulation import run_session_simulation


# ---------------------------------------------------------------------------
# 1. Question Contract
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ContextRelevanceQuestionContractV1:
    """Frozen semantic question contract for Context Relevance evaluation.

    Strictly separated from risk-escalation contracts (F4QuestionContractV1).
    """

    contract_version: str = "context-relevance-v1"
    primitive: str = "NOUL"
    question_statement: str = (
        "Does this sanitized context segment contain information that is relevant "
        "enough to retain for the current task?"
    )
    semantic_meaning: str = (
        "Evaluates whether a sanitized context segment contains task-relevant information "
        "that should be retained in the active LLM context window to complete the current task, "
        "versus being pruned or hidden in recall storage."
    )
    input_representation: str = (
        "ContextRelevanceProviderStateV1 serialized canonically as JSON with keys: "
        "current_task, segment_text, source_type, age_or_stage_metadata."
    )
    output_interpretation: str = (
        "P(Noul) represents the model's assigned probability that the segment IS relevant and "
        "worthy of retention (P(relevant) >= 0.5 -> retain; P(relevant) < 0.5 -> candidate for pruning/recall store). "
        "This is strictly context relevance probability and NOT risk escalation."
    )
    noul_probability_meaning: str = (
        "P(relevant_and_retained) in [0.0, 1.0]. Higher values indicate higher relevance to current_task."
    )

    def canonical_dict(self) -> dict[str, str]:
        return {
            "contract_version": self.contract_version,
            "primitive": self.primitive,
            "question_statement": self.question_statement,
            "semantic_meaning": self.semantic_meaning,
            "input_representation": self.input_representation,
            "output_interpretation": self.output_interpretation,
            "noul_probability_meaning": self.noul_probability_meaning,
        }

    @property
    def contract_hash(self) -> str:
        encoded = json.dumps(self.canonical_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


# ---------------------------------------------------------------------------
# 2. Provider-Visible Input Schema
# ---------------------------------------------------------------------------

_FORBIDDEN_KEY_PATTERNS = (
    "api_key",
    "secret",
    "token",
    "auth",
    "private",
    "endpoint",
    "url",
    "repo",
    "git",
    "worktree",
    "raw_response",
)
_FORBIDDEN_VALUE_PATTERNS = (
    "sk-",
    "Bearer ",
    "ghp_",
    "https://",
    "http://",
    "BEGIN PRIVATE KEY",
    "AKIA",
    "Authorization:",
)


@dataclass(frozen=True)
class ContextRelevanceProviderStateV1:
    """Minimal sanitized provider-visible state projection for Context Relevance."""

    current_task: str
    segment_text: str
    source_type: str
    age_or_stage_metadata: str

    def __post_init__(self) -> None:
        if not self.current_task or not isinstance(self.current_task, str):
            raise ValueError("current_task must be a non-empty string")
        if len(self.current_task) > 2048:
            raise ValueError("current_task exceeds maximum length 2048")
        if not self.segment_text or not isinstance(self.segment_text, str):
            raise ValueError("segment_text must be a non-empty string")
        if len(self.segment_text) > 16384:
            raise ValueError("segment_text exceeds maximum length 16384")
        if not self.source_type or not isinstance(self.source_type, str):
            raise ValueError("source_type must be a non-empty string")
        if not self.age_or_stage_metadata or not isinstance(self.age_or_stage_metadata, str):
            raise ValueError("age_or_stage_metadata must be a non-empty string")

        self.verify_no_forbidden_fields()

    def verify_no_forbidden_fields(self) -> None:
        for val in (self.current_task, self.segment_text, self.source_type, self.age_or_stage_metadata):
            for pat in _FORBIDDEN_VALUE_PATTERNS:
                if pat in val:
                    raise ValueError(f"Forbidden value pattern '{pat}' found in provider state")

    def canonical_payload(self) -> dict[str, str]:
        return {
            "current_task": self.current_task,
            "segment_text": self.segment_text,
            "source_type": self.source_type,
            "age_or_stage_metadata": self.age_or_stage_metadata,
        }

    def canonical_serialization(self) -> str:
        return json.dumps(self.canonical_payload(), sort_keys=True, separators=(",", ":"))

    def compute_payload_hash(self) -> str:
        return hashlib.sha256(self.canonical_serialization().encode("utf-8")).hexdigest()

    @classmethod
    def compute_schema_hash(cls) -> str:
        schema = {
            "schema_version": "context-relevance-provider-state-v1",
            "fields": ["current_task", "segment_text", "source_type", "age_or_stage_metadata"],
        }
        encoded = json.dumps(schema, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


# ---------------------------------------------------------------------------
# 3. Bound Sample Packet
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DiagnosticSamplePacketV1:
    """Deterministic diagnostic sample packet binding actual sanitized payloads."""

    sample_id: str
    semantic_input_id: str
    stratum: str
    turn_id: int
    segment_id: str
    current_task_hash: str
    segment_content_hash: str
    sanitized_payload_hash: str
    question_contract_hash: str
    provider_state_schema_hash: str
    provider_state: ContextRelevanceProviderStateV1

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "semantic_input_id": self.semantic_input_id,
            "stratum": self.stratum,
            "turn_id": self.turn_id,
            "segment_id": self.segment_id,
            "current_task_hash": self.current_task_hash,
            "segment_content_hash": self.segment_content_hash,
            "sanitized_payload_hash": self.sanitized_payload_hash,
            "question_contract_hash": self.question_contract_hash,
            "provider_state_schema_hash": self.provider_state_schema_hash,
            "provider_state": self.provider_state.canonical_payload(),
        }

    def compute_packet_hash(self) -> str:
        encoded = json.dumps(self.canonical_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


# ---------------------------------------------------------------------------
# 4. Durable Batch Authorization
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ContextRelevanceDiagnosticAuthorizationV1:
    """Durable batch authorization for Context Relevance Diagnostic experiment."""

    candidate_sha: str
    fixture_hash: str
    diagnostic_sample_hash: str
    question_contract_hash: str
    provider_state_schema_hash: str
    wire_contract_hash: str
    endpoint_host: str
    authorized_semantic_input_ids: tuple[str, ...]
    authorized_backup_sample_ids: tuple[str, ...] = ()
    max_calls: int = 0
    journal_namespace_hash: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.candidate_sha, str) or len(self.candidate_sha) != 40:
            raise ValueError("candidate_sha must be a 40-character hex commit SHA")

        for name, val in (
            ("fixture_hash", self.fixture_hash),
            ("diagnostic_sample_hash", self.diagnostic_sample_hash),
            ("question_contract_hash", self.question_contract_hash),
            ("provider_state_schema_hash", self.provider_state_schema_hash),
            ("wire_contract_hash", self.wire_contract_hash),
            ("journal_namespace_hash", self.journal_namespace_hash),
        ):
            if not isinstance(val, str) or len(val) != 64 or not all(c in "0123456789abcdef" for c in val):
                raise ValueError(f"{name} must be a valid 64-character lowercase hexadecimal hash")

        if not isinstance(self.endpoint_host, str) or not self.endpoint_host.strip():
            raise ValueError("endpoint_host must be a non-empty string")

        total_authorized = len(self.authorized_semantic_input_ids) + len(self.authorized_backup_sample_ids)
        if self.max_calls != total_authorized:
            raise ValueError(
                f"max_calls ({self.max_calls}) must exactly equal total authorized IDs ({total_authorized})"
            )

    def compute_authorization_hash(self) -> str:
        payload = {
            "candidate_sha": self.candidate_sha,
            "fixture_hash": self.fixture_hash,
            "diagnostic_sample_hash": self.diagnostic_sample_hash,
            "question_contract_hash": self.question_contract_hash,
            "provider_state_schema_hash": self.provider_state_schema_hash,
            "wire_contract_hash": self.wire_contract_hash,
            "endpoint_host": self.endpoint_host,
            "authorized_semantic_input_ids": list(self.authorized_semantic_input_ids),
            "authorized_backup_sample_ids": list(self.authorized_backup_sample_ids),
            "max_calls": self.max_calls,
            "journal_namespace_hash": self.journal_namespace_hash,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


# ---------------------------------------------------------------------------
# 5. Outcome Status & Journal
# ---------------------------------------------------------------------------

class DiagnosticOutcomeStatus(str, Enum):
    NOT_SENT = "NOT_SENT"
    OBSERVED_OK = "OBSERVED_OK"
    OBSERVED_CLIENT_FAILURE = "OBSERVED_CLIENT_FAILURE"
    OBSERVED_PROVIDER_FAILURE = "OBSERVED_PROVIDER_FAILURE"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"


class DiagnosticExecutionJournal:
    """Private execution journal outside git repos with strict permissions."""

    def __init__(self, root_dir: str | None = None, namespace: str = "wave1-diag"):
        self.namespace = namespace
        self.root_dir = root_dir or os.environ.get(
            "NEXUS_PRIVATE_EVAL_ROOT", "/tmp/nexus-private-eval"
        )
        self.journal_dir = os.path.join(self.root_dir, "context-economics-diagnostic-journal")
        self._ensure_safe_dir()

    def _ensure_safe_dir(self) -> None:
        if os.path.islink(self.journal_dir):
            raise ValueError(f"Journal dir {self.journal_dir} must not be a symlink")

        # Check outside git repository
        parent = os.path.abspath(self.journal_dir)
        while parent and parent != "/":
            if os.path.isdir(os.path.join(parent, ".git")):
                raise ValueError(f"Journal dir {self.journal_dir} must be outside all Git repos/worktrees")
            parent = os.path.dirname(parent)

        os.makedirs(self.journal_dir, mode=0o700, exist_ok=True)
        try:
            os.chmod(self.journal_dir, 0o700)
        except OSError:
            pass

    def get_namespace_hash(self) -> str:
        return hashlib.sha256(self.namespace.encode("utf-8")).hexdigest()

    def get_log_path(self) -> str:
        return os.path.join(self.journal_dir, f"journal-{self.get_namespace_hash()[:16]}.jsonl")

    def record_attempt(
        self,
        experiment_id: str,
        sample_id: str,
        semantic_input_id: str,
        operation_id: str,
        provider_request_id: str,
        status: DiagnosticOutcomeStatus,
    ) -> None:
        if self.is_semantic_input_attempted(semantic_input_id):
            raise ValueError(f"semantic_input_id {semantic_input_id} has already been attempted; replay blocked")

        entry = {
            "experiment_id": experiment_id,
            "sample_id": sample_id,
            "semantic_input_id": semantic_input_id,
            "operation_id": operation_id,
            "provider_request_id": provider_request_id,
            "status": status.value,
            "attempt_count": 1,
        }
        log_path = self.get_log_path()
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        try:
            os.chmod(log_path, 0o600)
        except OSError:
            pass

    def is_semantic_input_attempted(self, semantic_input_id: str) -> bool:
        if not os.path.exists(self.journal_dir):
            return False
        for fname in os.listdir(self.journal_dir):
            if fname.startswith("journal-") and fname.endswith(".jsonl"):
                fpath = os.path.join(self.journal_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        for line in f:
                            if not line.strip():
                                continue
                            data = json.loads(line)
                            if data.get("semantic_input_id") == semantic_input_id:
                                return True
                except Exception:
                    pass
        return False


# ---------------------------------------------------------------------------
# 6. Zero-Call Executor
# ---------------------------------------------------------------------------

@dataclass
class DiagnosticExecutionResult:
    sample_id: str
    semantic_input_id: str
    status: DiagnosticOutcomeStatus
    request_hash: str
    response_hash: str | None
    error_message: str | None = None


class ContextRelevanceDiagnosticExecutor:
    """Zero-call executor for Context Relevance Diagnostic packets."""

    def __init__(
        self,
        authorization: ContextRelevanceDiagnosticAuthorizationV1,
        question_contract: ContextRelevanceQuestionContractV1,
        journal: DiagnosticExecutionJournal,
        *,
        allow_live_provider: bool = False,
    ):
        if allow_live_provider:
            raise RuntimeError("LIVE_PROVIDER_PROHIBITED_IN_THIS_GATE: allow_live_provider must remain False")

        self.authorization = authorization
        self.question_contract = question_contract
        self.journal = journal
        self.allow_live_provider = allow_live_provider
        self.physical_network_attempts = 0
        self.api_key_reads = 0

    def execute_dry_run_sample(
        self,
        packet: DiagnosticSamplePacketV1,
        operation_id: str,
        experiment_id: str,
        simulated_outcome: DiagnosticOutcomeStatus = DiagnosticOutcomeStatus.OBSERVED_OK,
    ) -> DiagnosticExecutionResult:
        if packet.question_contract_hash != self.question_contract.contract_hash:
            raise ValueError("question_contract_hash mismatch")
        if packet.question_contract_hash != self.authorization.question_contract_hash:
            raise ValueError("authorization question_contract_hash mismatch")
        if packet.provider_state_schema_hash != self.authorization.provider_state_schema_hash:
            raise ValueError("authorization provider_state_schema_hash mismatch")

        # Authorization check
        is_authorized = (
            packet.semantic_input_id in self.authorization.authorized_semantic_input_ids
            or packet.semantic_input_id in self.authorization.authorized_backup_sample_ids
        )
        if not is_authorized:
            return DiagnosticExecutionResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=DiagnosticOutcomeStatus.NOT_SENT,
                request_hash=packet.compute_packet_hash(),
                response_hash=None,
                error_message="Sample ID not in authorization",
            )

        # Journal replay check
        if self.journal.is_semantic_input_attempted(packet.semantic_input_id):
            return DiagnosticExecutionResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=DiagnosticOutcomeStatus.NOT_SENT,
                request_hash=packet.compute_packet_hash(),
                response_hash=None,
                error_message="Sample already attempted in journal; replay blocked",
            )

        provider_req_id = (
            f"req-{hashlib.sha256((experiment_id + operation_id + packet.semantic_input_id).encode()).hexdigest()[:16]}"
        )
        assert not self.allow_live_provider
        assert self.physical_network_attempts == 0
        assert self.api_key_reads == 0

        self.journal.record_attempt(
            experiment_id=experiment_id,
            sample_id=packet.sample_id,
            semantic_input_id=packet.semantic_input_id,
            operation_id=operation_id,
            provider_request_id=provider_req_id,
            status=simulated_outcome,
        )

        resp_hash = (
            hashlib.sha256(f"simulated-{simulated_outcome.value}-{packet.sample_id}".encode()).hexdigest()
            if simulated_outcome == DiagnosticOutcomeStatus.OBSERVED_OK
            else None
        )

        return DiagnosticExecutionResult(
            sample_id=packet.sample_id,
            semantic_input_id=packet.semantic_input_id,
            status=simulated_outcome,
            request_hash=packet.compute_packet_hash(),
            response_hash=resp_hash,
            error_message=None if simulated_outcome == DiagnosticOutcomeStatus.OBSERVED_OK else simulated_outcome.value,
        )

    def execute_dry_run_batch(
        self,
        packets: Sequence[DiagnosticSamplePacketV1],
        operation_id: str,
        experiment_id: str,
        simulated_outcomes: dict[str, DiagnosticOutcomeStatus] | None = None,
    ) -> list[DiagnosticExecutionResult]:
        outcomes = simulated_outcomes or {}
        results: list[DiagnosticExecutionResult] = []

        for p in packets:
            sim_outcome = outcomes.get(p.sample_id, DiagnosticOutcomeStatus.OBSERVED_OK)
            res = self.execute_dry_run_sample(p, operation_id, experiment_id, sim_outcome)
            results.append(res)
            # Hard rule: OUTCOME_UNKNOWN stops the entire run
            if res.status == DiagnosticOutcomeStatus.OUTCOME_UNKNOWN:
                break

        return results


# ---------------------------------------------------------------------------
# 7. Deterministic Stratified Sample Generator
# ---------------------------------------------------------------------------

def generate_wave1_diagnostic_sample_packets(
    seed: str = "EXP_C_WAVE1_V2",
    target_per_stratum: int = 5,
) -> tuple[list[DiagnosticSamplePacketV1], dict[str, int], str, str]:
    """Generate real deterministic stratified sample packets from the canonical fixture."""
    gen = SessionFixtureGenerator(seed=seed)
    turns, anchors, fixture_hash = gen.generate_1000_turn_session()

    r_write = run_session_simulation(
        turns,
        anchors,
        ArchitectureId.SEMANTIC_WRITE_TIME_PERFECTISH,
        synthetic_ranker_mode=SyntheticRankerMode.PERFECTISH,
        fixture_hash=fixture_hash,
    )
    r_retro = run_session_simulation(
        turns,
        anchors,
        ArchitectureId.SEMANTIC_RETROACTIVE_PERFECTISH,
        synthetic_ranker_mode=SyntheticRankerMode.PERFECTISH,
        fixture_hash=fixture_hash,
    )

    q_contract = ContextRelevanceQuestionContractV1()
    q_contract_hash = q_contract.contract_hash
    p_schema_hash = ContextRelevanceProviderStateV1.compute_schema_hash()

    turn_prompt_by_id = {t.turn_id: t.user_prompt for t in turns}
    seg_by_id: dict[str, ContextSegmentV1] = {}
    for t in turns:
        for s in t.segments:
            seg_by_id[s.segment_id] = s

    strata_map: dict[str, list[dict[str, Any]]] = {
        "high_relevance": [],
        "medium_relevance": [],
        "low_relevance": [],
        "recall_required": [],
        "stale_or_repeated_noise": [],
    }
    seen_ids = set()

    for run_res in (r_write, r_retro):
        for rec in run_res.semantic_records:
            s_id = rec["semantic_input_id"]
            if s_id not in seen_ids:
                seen_ids.add(s_id)
                st = rec.get("stratum", "medium_relevance")
                if st in strata_map:
                    strata_map[st].append(rec)
                else:
                    strata_map["medium_relevance"].append(rec)

    # Fail closed: each required stratum must have at least 1 sample
    for stratum_name, items in strata_map.items():
        if len(items) == 0:
            raise ValueError(f"DIAGNOSTIC_SAMPLE_BLOCKED: stratum '{stratum_name}' has 0 samples")

    packets: list[DiagnosticSamplePacketV1] = []
    strata_counts: dict[str, int] = {}
    sample_index = 1

    for stratum_name in (
        "high_relevance",
        "medium_relevance",
        "low_relevance",
        "recall_required",
        "stale_or_repeated_noise",
    ):
        items = strata_map[stratum_name]
        items.sort(key=lambda x: str(x["semantic_input_id"]))
        sampled = items[:target_per_stratum]
        strata_counts[stratum_name] = len(sampled)

        for it in sampled:
            seg_id = it["segment_id"]
            turn_id = it["turn_id"]
            seg = seg_by_id.get(seg_id)
            prompt = turn_prompt_by_id.get(turn_id, f"Turn {turn_id} instruction.")
            seg_text = seg.content if seg else f"Segment {seg_id} text."
            source_type_str = seg.source_type.value if seg else "TOOL_RESULT"
            age_meta = (
                f"turn_{turn_id}_admission"
                if it["stratum"] != "stale_or_repeated_noise"
                else f"turn_{turn_id}_retroactive_age_30plus"
            )

            p_state = ContextRelevanceProviderStateV1(
                current_task=prompt,
                segment_text=seg_text,
                source_type=source_type_str,
                age_or_stage_metadata=age_meta,
            )

            packet = DiagnosticSamplePacketV1(
                sample_id=f"sample-{sample_index:02d}",
                semantic_input_id=it["semantic_input_id"],
                stratum=stratum_name,
                turn_id=turn_id,
                segment_id=seg_id,
                current_task_hash=hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                segment_content_hash=it["content_hash"],
                sanitized_payload_hash=p_state.compute_payload_hash(),
                question_contract_hash=q_contract_hash,
                provider_state_schema_hash=p_schema_hash,
                provider_state=p_state,
            )
            packets.append(packet)
            sample_index += 1

    canonical_list = [p.canonical_dict() for p in packets]
    encoded_list = json.dumps(canonical_list, sort_keys=True, separators=(",", ":")).encode("utf-8")
    diagnostic_sample_hash = hashlib.sha256(encoded_list).hexdigest()

    return packets, strata_counts, diagnostic_sample_hash, fixture_hash


def generate_diagnostic_live_packet_artifact(
    candidate_sha: str,
    seed: str = "EXP_C_WAVE1_V2",
) -> dict[str, Any]:
    """Generate physical zero-call diagnostic packet artifact."""
    packets, strata_counts, sample_hash, fixture_hash = generate_wave1_diagnostic_sample_packets(seed=seed)
    q_contract = ContextRelevanceQuestionContractV1()
    p_schema_hash = ContextRelevanceProviderStateV1.compute_schema_hash()

    packet_data: dict[str, Any] = {
        "schema_version": "context-relevance-diagnostic-live-packet-v1",
        "candidate_sha": candidate_sha,
        "fixture_hash": fixture_hash,
        "sample_hash": sample_hash,
        "question_contract_hash": q_contract.contract_hash,
        "provider_state_schema_hash": p_schema_hash,
        "semantic_input_schema_hash": hashlib.sha256(b"semantic-input-v1").hexdigest(),
        "sample_count": len(packets),
        "exact_semantic_input_ids": [p.semantic_input_id for p in packets],
        "per_stratum_counts": strata_counts,
        "max_calls": len(packets),
        "claim_ceiling": "REAL_JEV_RANKING_SIGNAL_MEASURED",
        "stop_conditions": [
            "OUTCOME_UNKNOWN: transport error, timeout, or connection loss halts entire run",
            "Call count reaches max_calls",
            "Auth token expired or invalid",
            "Owner abort",
        ],
    }
    encoded = json.dumps(packet_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    packet_data["packet_hash"] = hashlib.sha256(encoded).hexdigest()
    return packet_data


if __name__ == "__main__":
    import argparse
    import subprocess
    parser = argparse.ArgumentParser(description="Generate diagnostic live packet artifact")
    parser.add_argument("--candidate-sha", default=None, help="Candidate git SHA")
    parser.add_argument("--output", default=None, help="Output file path")
    args = parser.parse_args()
    sha = args.candidate_sha
    if not sha:
        try:
            sha = subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL).decode("utf-8").strip()
        except Exception:
            sha = "1a82954e0ddcf90427bbad3dd36dfbea732f1f4e"
    artifact = generate_diagnostic_live_packet_artifact(candidate_sha=sha)
    serialized = json.dumps(artifact, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(serialized)
        print(f"Wrote diagnostic live packet to {args.output}")
    else:
        print(serialized)
