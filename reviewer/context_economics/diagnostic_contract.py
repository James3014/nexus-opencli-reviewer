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
import http.client
import json
import math
import os
import re
import ssl
from typing import Any, Callable, Sequence
import urllib.error
import urllib.request

from reviewer.context_economics.fixtures import SessionFixtureGenerator
from reviewer.context_economics.models import (
    ArchitectureId,
    ContextSegmentV1,
    SyntheticRankerMode,
)
from reviewer.context_economics.simulation import run_session_simulation
from reviewer.hosted_risk_config import HostedProviderConfigV1
from reviewer.hosted_wire_contract import (
    HostedProviderWireDescriptorV1,
    load_wire_descriptor_from_dict,
)


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

    def as_payload(self) -> dict[str, str]:
        return self.canonical_payload()

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

    live_contract_revision: str = ""
    sample_source_revision: str = "1a82954e0ddcf90427bbad3dd36dfbea732f1f4e"
    fixture_hash: str = ""
    diagnostic_sample_hash: str = ""
    question_contract_hash: str = ""
    provider_state_schema_hash: str = ""
    wire_contract_hash: str = ""
    endpoint_host: str = ""
    authorized_semantic_input_ids: tuple[str, ...] = ()
    journal_root_resolved_hash: str = ""
    journal_namespace_hash: str = ""
    authorized_backup_sample_ids: tuple[str, ...] = ()
    max_calls: int = 0
    diagnostic_packet_hash: str = ""
    authorization_schema_version: str = "ContextRelevanceDiagnosticAuthorizationV1"
    candidate_sha: str = ""

    def __post_init__(self) -> None:
        if not self.live_contract_revision and self.candidate_sha:
            object.__setattr__(self, "live_contract_revision", self.candidate_sha)
        elif not self.candidate_sha and self.live_contract_revision:
            object.__setattr__(self, "candidate_sha", self.live_contract_revision)

        if not isinstance(self.live_contract_revision, str) or len(self.live_contract_revision) != 40:
            raise ValueError("live_contract_revision (or candidate_sha) must be a 40-character hex commit SHA")

        if not isinstance(self.sample_source_revision, str) or len(self.sample_source_revision) != 40:
            raise ValueError("sample_source_revision must be a 40-character hex commit SHA")

        for name, val in (
            ("fixture_hash", self.fixture_hash),
            ("diagnostic_sample_hash", self.diagnostic_sample_hash),
            ("question_contract_hash", self.question_contract_hash),
            ("provider_state_schema_hash", self.provider_state_schema_hash),
            ("wire_contract_hash", self.wire_contract_hash),
        ):
            if not isinstance(val, str) or len(val) != 64 or not all(c in "0123456789abcdef" for c in val):
                raise ValueError(f"{name} must be a valid 64-character lowercase hexadecimal hash")

        for name, val in (
            ("journal_root_resolved_hash", self.journal_root_resolved_hash),
            ("journal_namespace_hash", self.journal_namespace_hash),
            ("diagnostic_packet_hash", self.diagnostic_packet_hash),
        ):
            if val and (len(val) != 64 or not all(c in "0123456789abcdef" for c in val)):
                raise ValueError(f"{name} must be a valid 64-character lowercase hexadecimal hash")

        if not isinstance(self.endpoint_host, str) or not self.endpoint_host.strip():
            raise ValueError("endpoint_host must be a non-empty string")

        total_authorized = len(self.authorized_semantic_input_ids) + len(self.authorized_backup_sample_ids)
        if self.max_calls != total_authorized:
            raise ValueError(
                f"max_calls ({self.max_calls}) must exactly equal total authorized IDs ({total_authorized})"
            )

    def compute_authorization_hash(self) -> str:
        endpoint_host_hash = hashlib.sha256(self.endpoint_host.encode("utf-8")).hexdigest()
        payload = {
            "authorization_schema_version": self.authorization_schema_version,
            "authorized_backup_sample_ids": list(self.authorized_backup_sample_ids),
            "authorized_semantic_input_ids": list(self.authorized_semantic_input_ids),
            "diagnostic_packet_hash": self.diagnostic_packet_hash,
            "diagnostic_sample_hash": self.diagnostic_sample_hash,
            "endpoint_host_hash": endpoint_host_hash,
            "fixture_hash": self.fixture_hash,
            "journal_namespace_hash": self.journal_namespace_hash,
            "journal_root_resolved_hash": self.journal_root_resolved_hash,
            "live_contract_revision": self.live_contract_revision,
            "max_calls": self.max_calls,
            "provider_state_schema_hash": self.provider_state_schema_hash,
            "question_contract_hash": self.question_contract_hash,
            "sample_source_revision": self.sample_source_revision,
            "wire_contract_hash": self.wire_contract_hash,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def generate_public_preview(self) -> dict[str, Any]:
        endpoint_host_hash = hashlib.sha256(self.endpoint_host.encode("utf-8")).hexdigest()
        auth_hash = self.compute_authorization_hash()
        return {
            "authorization_schema_version": self.authorization_schema_version,
            "authorization_hash": auth_hash,
            "diagnostic_packet_hash": self.diagnostic_packet_hash,
            "live_contract_revision": self.live_contract_revision,
            "sample_source_revision": self.sample_source_revision,
            "fixture_hash": self.fixture_hash,
            "sample_hash": self.diagnostic_sample_hash,
            "question_contract_hash": self.question_contract_hash,
            "provider_state_schema_hash": self.provider_state_schema_hash,
            "wire_contract_hash": self.wire_contract_hash,
            "endpoint_host_hash": endpoint_host_hash,
            "journal_root_hash": self.journal_root_resolved_hash,
            "journal_namespace_hash": self.journal_namespace_hash,
            "exact_sample_count": len(self.authorized_semantic_input_ids),
            "max_calls": self.max_calls,
            "unbound_calls": 0,
        }


# ---------------------------------------------------------------------------
# 5. Preflight Types, Transport Helpers, Outcome Status & Journal State Machine
# ---------------------------------------------------------------------------

class PreflightStatus(str, Enum):
    READY = "READY"
    NOT_READY = "NOT_READY"


@dataclass(frozen=True)
class PreflightSampleResult:
    """Pure zero-effect preflight result. No disk writes, no claims, no secret reads."""
    sample_id: str
    semantic_input_id: str
    status: PreflightStatus
    reason: str | None = None


_MAX_RESPONSE_BYTES = 1_048_576


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Fail-closed redirect handler."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> urllib.request.Request | None:
        raise urllib.error.HTTPError(
            newurl, code,
            f"HTTP redirect to {newurl} forbidden by security policy",
            headers,  # type: ignore[arg-type]
            fp,
        )


class _EmptyProxyHandler(urllib.request.ProxyHandler):
    """Disable environment proxy discovery."""
    def __init__(self) -> None:
        super().__init__({})

    def http_request(self, req: urllib.request.Request) -> urllib.request.Request:
        return req

    def https_request(self, req: urllib.request.Request) -> urllib.request.Request:
        return req


def _build_secure_diag_opener() -> urllib.request.OpenerDirector:
    """Hardened HTTPS opener: no proxy, no redirect, verified TLS."""
    ssl_ctx = ssl.create_default_context()
    https_handler = urllib.request.HTTPSHandler(context=ssl_ctx)
    return urllib.request.build_opener(
        _EmptyProxyHandler,
        _NoRedirectHandler,
        https_handler,
    )


def _reject_duplicate_diag_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject ambiguous provider JSON — no silent last-write-wins."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Provider response contains duplicate JSON keys")
        result[key] = value
    return result


class DiagnosticOutcomeStatus(str, Enum):
    NOT_SENT = "NOT_SENT"
    OBSERVED_OK = "OBSERVED_OK"
    OBSERVED_CLIENT_FAILURE = "OBSERVED_CLIENT_FAILURE"
    OBSERVED_PROVIDER_FAILURE = "OBSERVED_PROVIDER_FAILURE"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"


class DiagnosticJournalState(str, Enum):
    """Lifecycle states of the durable context-relevance diagnostic journal."""

    PREPARED = "PREPARED"
    REQUEST_ATTEMPT_STARTED = "REQUEST_ATTEMPT_STARTED"
    OBSERVED_OK = "OBSERVED_OK"
    OBSERVED_CLIENT_FAILURE = "OBSERVED_CLIENT_FAILURE"
    OBSERVED_PROVIDER_FAILURE = "OBSERVED_PROVIDER_FAILURE"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
    NOT_SENT = "NOT_SENT"


class DiagnosticExecutionJournal:
    """Private execution journal outside git repos with strict permissions."""

    def __init__(
        self,
        root_dir: str | None = None,
        namespace: str = "wave1-diag",
        *,
        is_live_executor: bool = False,
    ):
        self.namespace = namespace
        self.is_live_executor = is_live_executor

        if root_dir is not None:
            raw_root = root_dir
        else:
            env_root = os.environ.get("NEXUS_PRIVATE_EVAL_ROOT")
            if not env_root:
                raise RuntimeError(
                    "LIVE_DIAGNOSTIC_NOT_SENT_PRIVATE_ROOT_UNAVAILABLE: "
                    "NEXUS_PRIVATE_EVAL_ROOT environment variable must be set; fallback to /tmp forbidden"
                )
            raw_root = env_root

        if os.path.islink(raw_root):
            raise ValueError(f"Journal root {raw_root} must not be a symlink")

        self.resolved_root = os.path.realpath(raw_root)
        self.journal_dir = os.path.join(self.resolved_root, "context-economics-diagnostic-journal")
        self._ensure_safe_dir()

    def _ensure_safe_dir(self) -> None:
        if os.path.islink(self.journal_dir):
            raise ValueError(f"Journal dir {self.journal_dir} must not be a symlink")

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

    def get_root_resolved_hash(self) -> str:
        return hashlib.sha256(self.resolved_root.encode("utf-8")).hexdigest()

    def get_namespace_hash(self) -> str:
        return hashlib.sha256(self.namespace.encode("utf-8")).hexdigest()

    def get_log_path(self) -> str:
        return os.path.join(self.journal_dir, f"journal-{self.get_namespace_hash()[:16]}.jsonl")

    def get_claim_path(self, semantic_input_id: str, authorization_hash: str) -> str:
        claim_key = hashlib.sha256(f"{semantic_input_id}:{authorization_hash}".encode("utf-8")).hexdigest()
        return os.path.join(self.journal_dir, f"claim-{claim_key}.json")

    def try_atomic_claim(
        self,
        experiment_id: str,
        semantic_input_id: str,
        authorization_hash: str,
        operation_id: str,
    ) -> bool:
        """Atomically claim a sample for execution."""
        claim_path = self.get_claim_path(semantic_input_id, authorization_hash)
        claim_data = {
            "experiment_id": experiment_id,
            "semantic_input_id": semantic_input_id,
            "authorization_hash": authorization_hash,
            "operation_id": operation_id,
        }
        encoded = json.dumps(claim_data, sort_keys=True, indent=2).encode("utf-8")
        try:
            fd = os.open(claim_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return False

        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        return True

    def get_state_path(self, semantic_input_id: str, authorization_hash: str) -> str:
        state_key = hashlib.sha256(f"{semantic_input_id}:{authorization_hash}".encode("utf-8")).hexdigest()
        return os.path.join(self.journal_dir, f"state-{state_key}.json")

    def read_state(self, semantic_input_id: str, authorization_hash: str) -> dict[str, Any] | None:
        spath = self.get_state_path(semantic_input_id, authorization_hash)
        if not os.path.exists(spath):
            return None
        try:
            with open(spath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def write_state_atomic(
        self,
        semantic_input_id: str,
        authorization_hash: str,
        state: DiagnosticJournalState,
        operation_id: str,
        attempt_count: int,
        extra_fields: dict[str, Any] | None = None,
    ) -> None:
        spath = self.get_state_path(semantic_input_id, authorization_hash)
        tmp_path = f"{spath}.tmp.{os.getpid()}"
        data = {
            "semantic_input_id": semantic_input_id,
            "authorization_hash": authorization_hash,
            "operation_id": operation_id,
            "journal_state": state.value,
            "attempt_count": attempt_count,
        }
        if extra_fields:
            data.update(extra_fields)
        encoded = json.dumps(data, sort_keys=True, indent=2).encode("utf-8")
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(encoded)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, spath)

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

    def get_batch_claim_path(self, authorization_hash: str) -> str:
        """Batch-wide durable authorization claim path (prevents parallel runs)."""
        return os.path.join(self.journal_dir, f"batch-claim-{authorization_hash[:32]}.json")

    def try_atomic_batch_claim(
        self,
        authorization_hash: str,
        experiment_id: str,
        sample_ids: Sequence[str],
        max_calls: int,
    ) -> bool:
        """Atomically claim an authorization_hash for batch execution across processes.

        Returns True if this process won the claim; False if already claimed by another.
        """
        claim_path = self.get_batch_claim_path(authorization_hash)
        data = {
            "authorization_hash": authorization_hash,
            "experiment_id": experiment_id,
            "sample_ids": list(sample_ids),
            "max_calls": max_calls,
            "claim_state": "BATCH_CLAIMED",
        }
        encoded = json.dumps(data, sort_keys=True, indent=2).encode("utf-8")
        try:
            fd = os.open(claim_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return False
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        return True


# ---------------------------------------------------------------------------
# 6. Zero-Call & Live Diagnostic Executors
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


def get_authoritative_h2b_wire_descriptor() -> HostedProviderWireDescriptorV1:
    """Return the authoritative H2B wire contract descriptor."""
    data = {
        "contract_schema_version": "f4-hosted-wire-v1",
        "http_method": "POST",
        "request_path": "/v1/systemone",
        "auth_mode": "BEARER",
        "auth_header_name": "Authorization",
        "content_type": "application/json",
        "expected_model_identifier": "jev-latest",
        "request_template_kind": "systemone_noul",
        "response_probability_path": "answers.decision.noul",
        "api_version_source": "OPENAPI_INFO_0.2.0_PATH_V1",
        "provider_schema_identity": "typesafe-openapi-0.2.0-systemone-v1",
    }
    return load_wire_descriptor_from_dict(data)


def build_context_relevance_provider_request(
    question_contract: ContextRelevanceQuestionContractV1,
    provider_state: ContextRelevanceProviderStateV1,
    wire_descriptor: HostedProviderWireDescriptorV1,
) -> dict[str, Any]:
    """Deterministic builder for Context Relevance provider request wire payload.

    Zero-network, zero-secret: serializes official SystemOne format using
    the frozen Context Relevance question instructions and sanitized provider state.
    """
    if not isinstance(question_contract, ContextRelevanceQuestionContractV1):
        raise TypeError(
            f"question_contract must be ContextRelevanceQuestionContractV1, got {type(question_contract).__name__}"
        )
    if question_contract.primitive != "NOUL":
        raise ValueError(f"Context relevance wire requires primitive='NOUL', got {question_contract.primitive!r}")

    if wire_descriptor.http_method != "POST":
        raise ValueError(f"Only POST method is supported, got {wire_descriptor.http_method!r}")
    if wire_descriptor.request_template_kind != "systemone_noul":
        raise ValueError(
            f"Requires request_template_kind='systemone_noul', got {wire_descriptor.request_template_kind!r}"
        )
    if wire_descriptor.response_probability_path != "answers.decision.noul":
        raise ValueError(
            f"Requires response_probability_path='answers.decision.noul', got {wire_descriptor.response_probability_path!r}"
        )

    body_dict: dict[str, Any] = {
        "model": wire_descriptor.expected_model_identifier,
        "questions": {
            "decision": {
                "type": "noul",
                "instructions": question_contract.question_statement,
            }
        },
        "state": provider_state.as_payload(),
    }
    encoded = json.dumps(body_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    body_payload_hash = hashlib.sha256(encoded).hexdigest()

    return {
        "method": wire_descriptor.http_method,
        "request_path": wire_descriptor.request_path,
        "auth_header_name": wire_descriptor.auth_header_name,
        "content_type": wire_descriptor.content_type,
        "body_dict": body_dict,
        "body_json": encoded.decode("utf-8"),
        "body_payload_hash": body_payload_hash,
    }


class ContextRelevanceLiveDiagnosticExecutor:
    """Live-capable diagnostic executor for Context Relevance.

    Zero external calls in this gate — physical network is routed through
    an optional transport_handler.  When transport_handler=None in execute_live_sample,
    the real HTTPS opener is used.

    Config-based identity: all private config (endpoint_origin, api_key_env_var_name)
    must come from HostedProviderConfigV1. No hardcoded defaults.
    """

    owner_live_authorization_required: bool = True

    def __init__(
        self,
        authorization: ContextRelevanceDiagnosticAuthorizationV1,
        question_contract: ContextRelevanceQuestionContractV1,
        wire_descriptor: HostedProviderWireDescriptorV1,
        journal: DiagnosticExecutionJournal,
        *,
        current_candidate_sha: str,
        config: HostedProviderConfigV1 | None = None,
        owner_runtime_authorization_granted: bool = False,
    ):
        if not isinstance(question_contract, ContextRelevanceQuestionContractV1):
            raise TypeError("question_contract must be ContextRelevanceQuestionContractV1")

        self.authorization = authorization
        self.question_contract = question_contract
        self.wire_descriptor = wire_descriptor
        self.journal = journal
        self.current_candidate_sha = current_candidate_sha
        self.config = config  # None → config unavailable → fail closed
        self.owner_runtime_authorization_granted = owner_runtime_authorization_granted

        self.physical_network_attempts = 0
        self.api_key_reads = 0
        self.total_claims_consumed = 0

    # ------------------------------------------------------------------
    # Pure preflight — zero disk writes, zero claims, zero secret reads
    # ------------------------------------------------------------------

    def preflight_sample(self, packet: DiagnosticSamplePacketV1) -> PreflightSampleResult:
        """Validate a sample packet for live execution eligibility.

        Pure zero-effect: no atomic claim, no PREPARED write, no state file,
        no journal terminal state, no authorization consumption, no API key read,
        no network.  Returns READY or NOT_READY(reason).
        """
        # Config availability (no hardcoded fallback)
        if self.config is None:
            return PreflightSampleResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=PreflightStatus.NOT_READY,
                reason="LIVE_DIAGNOSTIC_NOT_SENT_PRIVATE_CONFIG_UNAVAILABLE",
            )

        # Candidate revision
        if self.authorization.live_contract_revision != self.current_candidate_sha:
            return PreflightSampleResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=PreflightStatus.NOT_READY,
                reason=(
                    f"Authorization live_contract_revision mismatch: "
                    f"auth={self.authorization.live_contract_revision} "
                    f"current={self.current_candidate_sha}"
                ),
            )

        # Wire hash
        wire_hash = self.wire_descriptor.canonical_wire_hash()
        if self.authorization.wire_contract_hash != wire_hash:
            return PreflightSampleResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=PreflightStatus.NOT_READY,
                reason=(
                    f"Authorization wire_contract_hash mismatch: "
                    f"auth={self.authorization.wire_contract_hash} expected={wire_hash}"
                ),
            )

        # Question contract
        if self.authorization.question_contract_hash != self.question_contract.contract_hash:
            return PreflightSampleResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=PreflightStatus.NOT_READY,
                reason=(
                    f"Authorization question_contract_hash mismatch: "
                    f"auth={self.authorization.question_contract_hash} "
                    f"expected={self.question_contract.contract_hash}"
                ),
            )

        # Packet question contract hash
        if packet.question_contract_hash != self.question_contract.contract_hash:
            return PreflightSampleResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=PreflightStatus.NOT_READY,
                reason="Packet question_contract_hash does not match question_contract",
            )

        # Packet provider state schema hash
        if packet.provider_state_schema_hash != self.authorization.provider_state_schema_hash:
            return PreflightSampleResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=PreflightStatus.NOT_READY,
                reason="Packet provider_state_schema_hash mismatch with authorization",
            )

        # Journal root hash
        actual_root_hash = self.journal.get_root_resolved_hash()
        if self.authorization.journal_root_resolved_hash and \
                self.authorization.journal_root_resolved_hash != actual_root_hash:
            return PreflightSampleResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=PreflightStatus.NOT_READY,
                reason=(
                    f"Authorization journal_root_resolved_hash mismatch: "
                    f"auth={self.authorization.journal_root_resolved_hash} actual={actual_root_hash}"
                ),
            )

        # Journal namespace hash
        actual_ns_hash = self.journal.get_namespace_hash()
        if self.authorization.journal_namespace_hash and \
                self.authorization.journal_namespace_hash != actual_ns_hash:
            return PreflightSampleResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=PreflightStatus.NOT_READY,
                reason=(
                    f"Authorization journal_namespace_hash mismatch: "
                    f"auth={self.authorization.journal_namespace_hash} actual={actual_ns_hash}"
                ),
            )

        # Authorized ID check
        if packet.semantic_input_id not in self.authorization.authorized_semantic_input_ids:
            return PreflightSampleResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=PreflightStatus.NOT_READY,
                reason="semantic_input_id not in authorization.authorized_semantic_input_ids",
            )

        # Credential metadata — zero-call: verify env_var_name is non-empty, do NOT read secret
        if not self.config.api_key_env_var_name or not isinstance(self.config.api_key_env_var_name, str):
            return PreflightSampleResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=PreflightStatus.NOT_READY,
                reason="api_key_env_var_name in config must be a non-empty string",
            )

        return PreflightSampleResult(
            sample_id=packet.sample_id,
            semantic_input_id=packet.semantic_input_id,
            status=PreflightStatus.READY,
            reason=None,
        )

    # ------------------------------------------------------------------
    # Legacy batch preflight check (kept for backward compatibility)
    # ------------------------------------------------------------------

    def preflight_check(self) -> tuple[bool, str | None]:
        """Batch-level preflight check (zero-call). Does not validate per-sample.

        Note: when config is None the non-config checks still run first, so
        existing hash-mismatch tests get the expected specific error even when
        config is not set.  The config gate is checked last so callers can
        distinguish mismatch errors from config-unavailable errors.
        """
        if self.authorization.live_contract_revision != self.current_candidate_sha:
            return (
                False,
                f"Authorization live_contract_revision mismatch: "
                f"auth={self.authorization.live_contract_revision} current={self.current_candidate_sha}",
            )

        wire_hash = self.wire_descriptor.canonical_wire_hash()
        if self.authorization.wire_contract_hash != wire_hash:
            return (
                False,
                f"Authorization wire_contract_hash mismatch: "
                f"auth={self.authorization.wire_contract_hash} expected={wire_hash}",
            )

        if self.authorization.question_contract_hash != self.question_contract.contract_hash:
            return (
                False,
                f"Authorization question_contract_hash mismatch: "
                f"auth={self.authorization.question_contract_hash} expected={self.question_contract.contract_hash}",
            )

        actual_root_hash = self.journal.get_root_resolved_hash()
        if self.authorization.journal_root_resolved_hash and \
                self.authorization.journal_root_resolved_hash != actual_root_hash:
            return (
                False,
                f"Authorization journal_root_resolved_hash mismatch: "
                f"auth={self.authorization.journal_root_resolved_hash} actual={actual_root_hash}",
            )

        actual_ns_hash = self.journal.get_namespace_hash()
        if self.authorization.journal_namespace_hash and \
                self.authorization.journal_namespace_hash != actual_ns_hash:
            return (
                False,
                f"Authorization journal_namespace_hash mismatch: "
                f"auth={self.authorization.journal_namespace_hash} actual={actual_ns_hash}",
            )

        # Config gate is last: when config is None, zero-call execute_sample
        # still gives specific mismatch errors before reaching this check.
        if self.config is None:
            return False, "LIVE_DIAGNOSTIC_NOT_SENT_PRIVATE_CONFIG_UNAVAILABLE"

        if not self.config.api_key_env_var_name or not isinstance(self.config.api_key_env_var_name, str):
            return False, "api_key_env_var_name must be a non-empty string"

        return True, None

    # ------------------------------------------------------------------
    # execute_live_sample — real transport (or fake via transport_handler)
    # ------------------------------------------------------------------

    def execute_live_sample(
        self,
        packet: DiagnosticSamplePacketV1,
        operation_id: str,
        experiment_id: str,
        transport_handler: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> DiagnosticExecutionResult:
        """Execute a single live sample.

        transport_handler(request_dict) -> response_dict  (for loopback/fake tests).
        If transport_handler is None, uses real HTTPS opener.
        """
        # 1. Config gate
        if self.config is None:
            return DiagnosticExecutionResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=DiagnosticOutcomeStatus.NOT_SENT,
                request_hash=packet.compute_packet_hash(),
                response_hash=None,
                error_message="LIVE_DIAGNOSTIC_NOT_SENT_PRIVATE_CONFIG_UNAVAILABLE",
            )

        # 2. Owner authorization gate
        if not self.owner_runtime_authorization_granted:
            return DiagnosticExecutionResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=DiagnosticOutcomeStatus.NOT_SENT,
                request_hash=packet.compute_packet_hash(),
                response_hash=None,
                error_message="LIVE_DIAGNOSTIC_NOT_SENT_OWNER_AUTHORIZATION_NOT_GRANTED",
            )

        # 3. Per-sample preflight
        pf = self.preflight_sample(packet)
        if pf.status != PreflightStatus.READY:
            return DiagnosticExecutionResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=DiagnosticOutcomeStatus.NOT_SENT,
                request_hash=packet.compute_packet_hash(),
                response_hash=None,
                error_message=pf.reason,
            )

        auth_hash = self.authorization.compute_authorization_hash()

        # 4. Check existing journal state (restart / replay protection)
        existing_state = self.journal.read_state(packet.semantic_input_id, auth_hash)
        if existing_state:
            curr_j_state = existing_state.get("journal_state")
            if curr_j_state == DiagnosticJournalState.REQUEST_ATTEMPT_STARTED.value:
                self.journal.write_state_atomic(
                    packet.semantic_input_id,
                    auth_hash,
                    DiagnosticJournalState.OUTCOME_UNKNOWN,
                    operation_id=operation_id,
                    attempt_count=existing_state.get("attempt_count", 1),
                    extra_fields={"reason": "RECONCILE_ONLY_PREVIOUS_ATTEMPT_INTERRUPTED"},
                )
                return DiagnosticExecutionResult(
                    sample_id=packet.sample_id,
                    semantic_input_id=packet.semantic_input_id,
                    status=DiagnosticOutcomeStatus.OUTCOME_UNKNOWN,
                    request_hash=packet.compute_packet_hash(),
                    response_hash=None,
                    error_message="RECONCILE_ONLY: previous attempt interrupted at REQUEST_ATTEMPT_STARTED; no second dispatch eligibility",
                )
            elif curr_j_state in (
                DiagnosticJournalState.OBSERVED_OK.value,
                DiagnosticJournalState.OBSERVED_CLIENT_FAILURE.value,
                DiagnosticJournalState.OBSERVED_PROVIDER_FAILURE.value,
                DiagnosticJournalState.OUTCOME_UNKNOWN.value,
                DiagnosticJournalState.NOT_SENT.value,
            ):
                return DiagnosticExecutionResult(
                    sample_id=packet.sample_id,
                    semantic_input_id=packet.semantic_input_id,
                    status=DiagnosticOutcomeStatus(curr_j_state),
                    request_hash=packet.compute_packet_hash(),
                    response_hash=None,
                    error_message=f"Replay blocked: sample already in terminal state {curr_j_state}",
                )

        # 5. Atomic per-sample claim (first real effect)
        claimed = self.journal.try_atomic_claim(
            experiment_id=experiment_id,
            semantic_input_id=packet.semantic_input_id,
            authorization_hash=auth_hash,
            operation_id=operation_id,
        )
        if not claimed:
            return DiagnosticExecutionResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=DiagnosticOutcomeStatus.NOT_SENT,
                request_hash=packet.compute_packet_hash(),
                response_hash=None,
                error_message="ALREADY_CLAIMED: atomic sample claim exists",
            )

        self.total_claims_consumed += 1

        # 6. Call ceiling check
        if self.total_claims_consumed > self.authorization.max_calls:
            return DiagnosticExecutionResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=DiagnosticOutcomeStatus.NOT_SENT,
                request_hash=packet.compute_packet_hash(),
                response_hash=None,
                error_message="MAX_CALLS_EXHAUSTED",
            )

        # 7. PREPARED state (attempt_count=0)
        self.journal.write_state_atomic(
            packet.semantic_input_id,
            auth_hash,
            DiagnosticJournalState.PREPARED,
            operation_id=operation_id,
            attempt_count=0,
        )

        # 8. Build wire request
        req_data = build_context_relevance_provider_request(
            self.question_contract,
            packet.provider_state,
            self.wire_descriptor,
        )

        # 9. Late-bind API key secret from environment (AFTER all validations)
        secret_value = os.environ.get(self.config.api_key_env_var_name)
        self.api_key_reads += 1
        if not secret_value or not secret_value.strip():
            self.journal.write_state_atomic(
                packet.semantic_input_id,
                auth_hash,
                DiagnosticJournalState.NOT_SENT,
                operation_id=operation_id,
                attempt_count=0,
                extra_fields={"reason": f"env var {self.config.api_key_env_var_name} missing or empty"},
            )
            return DiagnosticExecutionResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=DiagnosticOutcomeStatus.NOT_SENT,
                request_hash=req_data["body_payload_hash"],
                response_hash=None,
                error_message=f"LIVE_DIAGNOSTIC_NOT_SENT_PRIVATE_CONFIG_UNAVAILABLE: "
                              f"env var {self.config.api_key_env_var_name} missing or empty",
            )

        # 10. REQUEST_ATTEMPT_STARTED (attempt_count=1) immediately before dispatch
        self.journal.write_state_atomic(
            packet.semantic_input_id,
            auth_hash,
            DiagnosticJournalState.REQUEST_ATTEMPT_STARTED,
            operation_id=operation_id,
            attempt_count=1,
        )
        self.physical_network_attempts += 1

        # 11. Dispatch (fake handler or real HTTPS)
        if transport_handler is not None:
            # Test loopback path
            try:
                resp_obj = transport_handler(req_data)
                response_code = 200
            except Exception as exc:  # noqa: BLE001
                self.journal.write_state_atomic(
                    packet.semantic_input_id,
                    auth_hash,
                    DiagnosticJournalState.OUTCOME_UNKNOWN,
                    operation_id=operation_id,
                    attempt_count=1,
                    extra_fields={"reason": f"transport_handler raised: {exc}"},
                )
                return DiagnosticExecutionResult(
                    sample_id=packet.sample_id,
                    semantic_input_id=packet.semantic_input_id,
                    status=DiagnosticOutcomeStatus.OUTCOME_UNKNOWN,
                    request_hash=req_data["body_payload_hash"],
                    response_hash=None,
                    error_message=f"OUTCOME_UNKNOWN: transport_handler raised: {exc}",
                )
        else:
            # Real HTTPS path
            from urllib.parse import urlparse as _urlparse
            parsed_origin = _urlparse(self.config.endpoint_origin)
            final_url = f"{self.config.endpoint_origin.rstrip('/')}{self.wire_descriptor.request_path}"
            encoded_body = req_data["body_json"].encode("utf-8")

            headers = {
                "Accept": "application/json",
                "Content-Type": self.wire_descriptor.content_type,
                self.wire_descriptor.auth_header_name: f"Bearer {secret_value.strip()}",
            }
            http_req = urllib.request.Request(
                url=final_url,
                data=encoded_body,
                headers=headers,
                method=self.wire_descriptor.http_method,
            )

            opener = _build_secure_diag_opener()
            raw_response_bytes: bytes | None = None
            response_code: int | None = None
            response_too_large = False

            try:
                with opener.open(http_req, timeout=10.0) as resp:
                    raw_response_bytes = resp.read(_MAX_RESPONSE_BYTES + 1)
                    response_code = resp.status
                    response_too_large = len(raw_response_bytes) > _MAX_RESPONSE_BYTES
            except urllib.error.HTTPError as exc:
                response_code = exc.code
            except (TimeoutError, urllib.error.URLError, http.client.IncompleteRead,
                    http.client.RemoteDisconnected, ConnectionResetError,
                    ConnectionError, BrokenPipeError) as exc:
                self.journal.write_state_atomic(
                    packet.semantic_input_id,
                    auth_hash,
                    DiagnosticJournalState.OUTCOME_UNKNOWN,
                    operation_id=operation_id,
                    attempt_count=1,
                    extra_fields={"reason": f"transport error: {exc}"},
                )
                return DiagnosticExecutionResult(
                    sample_id=packet.sample_id,
                    semantic_input_id=packet.semantic_input_id,
                    status=DiagnosticOutcomeStatus.OUTCOME_UNKNOWN,
                    request_hash=req_data["body_payload_hash"],
                    response_hash=None,
                    error_message=f"OUTCOME_UNKNOWN: transport error: {exc}",
                )
            except Exception as exc:  # noqa: BLE001
                self.journal.write_state_atomic(
                    packet.semantic_input_id,
                    auth_hash,
                    DiagnosticJournalState.OUTCOME_UNKNOWN,
                    operation_id=operation_id,
                    attempt_count=1,
                    extra_fields={"reason": f"unexpected: {exc}"},
                )
                return DiagnosticExecutionResult(
                    sample_id=packet.sample_id,
                    semantic_input_id=packet.semantic_input_id,
                    status=DiagnosticOutcomeStatus.OUTCOME_UNKNOWN,
                    request_hash=req_data["body_payload_hash"],
                    response_hash=None,
                    error_message=f"OUTCOME_UNKNOWN: unexpected transport failure: {exc}",
                )

            # Non-200 HTTP
            if response_code is not None and response_code != 200:
                if 400 <= response_code < 500:
                    d_status = DiagnosticOutcomeStatus.OBSERVED_CLIENT_FAILURE
                    j_state = DiagnosticJournalState.OBSERVED_CLIENT_FAILURE
                else:
                    d_status = DiagnosticOutcomeStatus.OBSERVED_PROVIDER_FAILURE
                    j_state = DiagnosticJournalState.OBSERVED_PROVIDER_FAILURE
                self.journal.write_state_atomic(
                    packet.semantic_input_id,
                    auth_hash,
                    j_state,
                    operation_id=operation_id,
                    attempt_count=1,
                )
                return DiagnosticExecutionResult(
                    sample_id=packet.sample_id,
                    semantic_input_id=packet.semantic_input_id,
                    status=d_status,
                    request_hash=req_data["body_payload_hash"],
                    response_hash=None,
                    error_message=f"HTTP {response_code}",
                )

            # Oversized body
            if response_too_large:
                self.journal.write_state_atomic(
                    packet.semantic_input_id,
                    auth_hash,
                    DiagnosticJournalState.OBSERVED_PROVIDER_FAILURE,
                    operation_id=operation_id,
                    attempt_count=1,
                )
                return DiagnosticExecutionResult(
                    sample_id=packet.sample_id,
                    semantic_input_id=packet.semantic_input_id,
                    status=DiagnosticOutcomeStatus.OBSERVED_PROVIDER_FAILURE,
                    request_hash=req_data["body_payload_hash"],
                    response_hash=None,
                    error_message="Provider response exceeded 1MB bound",
                )

            # Parse JSON
            try:
                if raw_response_bytes is None:
                    raise ValueError("Empty response body")
                resp_obj = json.loads(
                    raw_response_bytes.decode("utf-8"),
                    object_pairs_hook=_reject_duplicate_diag_pairs,
                )
                if not isinstance(resp_obj, dict):
                    raise ValueError("Response must be a JSON object")
            except Exception as exc:
                self.journal.write_state_atomic(
                    packet.semantic_input_id,
                    auth_hash,
                    DiagnosticJournalState.OBSERVED_PROVIDER_FAILURE,
                    operation_id=operation_id,
                    attempt_count=1,
                )
                return DiagnosticExecutionResult(
                    sample_id=packet.sample_id,
                    semantic_input_id=packet.semantic_input_id,
                    status=DiagnosticOutcomeStatus.OBSERVED_PROVIDER_FAILURE,
                    request_hash=req_data["body_payload_hash"],
                    response_hash=None,
                    error_message=f"Invalid response JSON: {exc}",
                )

        # 12. Validate response (shared between transport_handler and real path)
        if isinstance(resp_obj, dict):
            # Model present check
            observed_model = resp_obj.get("model")
            if not isinstance(observed_model, str) or not observed_model.strip():
                self.journal.write_state_atomic(
                    packet.semantic_input_id,
                    auth_hash,
                    DiagnosticJournalState.OBSERVED_PROVIDER_FAILURE,
                    operation_id=operation_id,
                    attempt_count=1,
                )
                return DiagnosticExecutionResult(
                    sample_id=packet.sample_id,
                    semantic_input_id=packet.semantic_input_id,
                    status=DiagnosticOutcomeStatus.OBSERVED_PROVIDER_FAILURE,
                    request_hash=req_data["body_payload_hash"],
                    response_hash=None,
                    error_message="Missing or invalid model identifier in response",
                )

            # Probability extraction
            answers = resp_obj.get("answers")
            if not isinstance(answers, dict) or "decision" not in answers:
                self.journal.write_state_atomic(
                    packet.semantic_input_id,
                    auth_hash,
                    DiagnosticJournalState.OBSERVED_PROVIDER_FAILURE,
                    operation_id=operation_id,
                    attempt_count=1,
                )
                return DiagnosticExecutionResult(
                    sample_id=packet.sample_id,
                    semantic_input_id=packet.semantic_input_id,
                    status=DiagnosticOutcomeStatus.OBSERVED_PROVIDER_FAILURE,
                    request_hash=req_data["body_payload_hash"],
                    response_hash=None,
                    error_message="Missing answers.decision in response",
                )

            decision_answer = answers["decision"]
            if not isinstance(decision_answer, dict):
                self.journal.write_state_atomic(
                    packet.semantic_input_id,
                    auth_hash,
                    DiagnosticJournalState.OBSERVED_PROVIDER_FAILURE,
                    operation_id=operation_id,
                    attempt_count=1,
                )
                return DiagnosticExecutionResult(
                    sample_id=packet.sample_id,
                    semantic_input_id=packet.semantic_input_id,
                    status=DiagnosticOutcomeStatus.OBSERVED_PROVIDER_FAILURE,
                    request_hash=req_data["body_payload_hash"],
                    response_hash=None,
                    error_message="answers.decision must be an object",
                )

            raw_prob = decision_answer.get("noul")
            if (
                raw_prob is None
                or isinstance(raw_prob, bool)
                or not isinstance(raw_prob, (int, float))
                or (isinstance(raw_prob, float) and not math.isfinite(raw_prob))
                or not (0.0 <= raw_prob <= 1.0)
            ):
                self.journal.write_state_atomic(
                    packet.semantic_input_id,
                    auth_hash,
                    DiagnosticJournalState.OBSERVED_PROVIDER_FAILURE,
                    operation_id=operation_id,
                    attempt_count=1,
                )
                return DiagnosticExecutionResult(
                    sample_id=packet.sample_id,
                    semantic_input_id=packet.semantic_input_id,
                    status=DiagnosticOutcomeStatus.OBSERVED_PROVIDER_FAILURE,
                    request_hash=req_data["body_payload_hash"],
                    response_hash=None,
                    error_message=f"Invalid noul probability value: {raw_prob!r}",
                )

        else:
            # transport_handler returned non-dict (already checked above if real path)
            self.journal.write_state_atomic(
                packet.semantic_input_id,
                auth_hash,
                DiagnosticJournalState.OBSERVED_PROVIDER_FAILURE,
                operation_id=operation_id,
                attempt_count=1,
            )
            return DiagnosticExecutionResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=DiagnosticOutcomeStatus.OBSERVED_PROVIDER_FAILURE,
                request_hash=req_data["body_payload_hash"],
                response_hash=None,
                error_message="transport_handler returned non-dict response",
            )

        # 13. OBSERVED_OK
        resp_bytes = json.dumps(resp_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        response_hash = hashlib.sha256(resp_bytes).hexdigest()
        self.journal.write_state_atomic(
            packet.semantic_input_id,
            auth_hash,
            DiagnosticJournalState.OBSERVED_OK,
            operation_id=operation_id,
            attempt_count=1,
            extra_fields={"response_hash": response_hash},
        )
        return DiagnosticExecutionResult(
            sample_id=packet.sample_id,
            semantic_input_id=packet.semantic_input_id,
            status=DiagnosticOutcomeStatus.OBSERVED_OK,
            request_hash=req_data["body_payload_hash"],
            response_hash=response_hash,
            error_message=None,
        )

    # ------------------------------------------------------------------
    # execute_live_batch
    # ------------------------------------------------------------------

    def execute_live_batch(
        self,
        packets: Sequence[DiagnosticSamplePacketV1],
        operation_id: str,
        experiment_id: str,
        transport_handler: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> list[DiagnosticExecutionResult]:
        """Execute a batch with atomic batch claim and OUTCOME_UNKNOWN halt."""
        auth_hash = self.authorization.compute_authorization_hash()
        sample_ids = [p.sample_id for p in packets]

        # Batch-wide claim (prevents parallel runs of the same authorization)
        batch_claimed = self.journal.try_atomic_batch_claim(
            authorization_hash=auth_hash,
            experiment_id=experiment_id,
            sample_ids=sample_ids,
            max_calls=self.authorization.max_calls,
        )
        if not batch_claimed:
            return [
                DiagnosticExecutionResult(
                    sample_id=p.sample_id,
                    semantic_input_id=p.semantic_input_id,
                    status=DiagnosticOutcomeStatus.NOT_SENT,
                    request_hash=p.compute_packet_hash(),
                    response_hash=None,
                    error_message="BATCH_ALREADY_CLAIMED: parallel run of same authorization blocked",
                )
                for p in packets
            ]

        results: list[DiagnosticExecutionResult] = []
        stopped_due_to_unknown = False

        for p in packets:
            if stopped_due_to_unknown:
                results.append(
                    DiagnosticExecutionResult(
                        sample_id=p.sample_id,
                        semantic_input_id=p.semantic_input_id,
                        status=DiagnosticOutcomeStatus.NOT_SENT,
                        request_hash=p.compute_packet_hash(),
                        response_hash=None,
                        error_message="BATCH_HALTED_DUE_TO_OUTCOME_UNKNOWN",
                    )
                )
                continue

            res = self.execute_live_sample(p, operation_id, experiment_id, transport_handler)
            results.append(res)
            if res.status == DiagnosticOutcomeStatus.OUTCOME_UNKNOWN:
                stopped_due_to_unknown = True

        return results

    # ------------------------------------------------------------------
    # Legacy zero-call execute_sample (kept for backward compatibility)
    # ------------------------------------------------------------------

    def _hash_preflight_check(self) -> tuple[bool, str | None]:
        """Hash/identity checks only — no config required (for zero-call path)."""
        if self.authorization.live_contract_revision != self.current_candidate_sha:
            return (
                False,
                f"Authorization live_contract_revision mismatch: "
                f"auth={self.authorization.live_contract_revision} current={self.current_candidate_sha}",
            )

        wire_hash = self.wire_descriptor.canonical_wire_hash()
        if self.authorization.wire_contract_hash != wire_hash:
            return (
                False,
                f"Authorization wire_contract_hash mismatch: "
                f"auth={self.authorization.wire_contract_hash} expected={wire_hash}",
            )

        if self.authorization.question_contract_hash != self.question_contract.contract_hash:
            return (
                False,
                f"Authorization question_contract_hash mismatch: "
                f"auth={self.authorization.question_contract_hash} expected={self.question_contract.contract_hash}",
            )

        actual_root_hash = self.journal.get_root_resolved_hash()
        if self.authorization.journal_root_resolved_hash and \
                self.authorization.journal_root_resolved_hash != actual_root_hash:
            return (
                False,
                f"Authorization journal_root_resolved_hash mismatch: "
                f"auth={self.authorization.journal_root_resolved_hash} actual={actual_root_hash}",
            )

        actual_ns_hash = self.journal.get_namespace_hash()
        if self.authorization.journal_namespace_hash and \
                self.authorization.journal_namespace_hash != actual_ns_hash:
            return (
                False,
                f"Authorization journal_namespace_hash mismatch: "
                f"auth={self.authorization.journal_namespace_hash} actual={actual_ns_hash}",
            )

        return True, None

    def execute_sample(
        self,
        packet: DiagnosticSamplePacketV1,
        operation_id: str,
        experiment_id: str,
    ) -> DiagnosticExecutionResult:
        """Legacy zero-call execute path (frozen gate).

        Does NOT consume authorization or write state — zero side-effects on
        failure paths.  On success, writes dry-run OBSERVED_OK only.
        Config is not required: zero-call path never reads secrets or makes network calls.
        """
        # Hash-only preflight (no config gate)
        ok, reason = self._hash_preflight_check()
        if not ok:
            return DiagnosticExecutionResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=DiagnosticOutcomeStatus.NOT_SENT,
                request_hash=packet.compute_packet_hash(),
                response_hash=None,
                error_message=reason,
            )

        if packet.semantic_input_id not in self.authorization.authorized_semantic_input_ids:
            return DiagnosticExecutionResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=DiagnosticOutcomeStatus.NOT_SENT,
                request_hash=packet.compute_packet_hash(),
                response_hash=None,
                error_message="Unauthorized semantic_input_id: sample not in authorized list",
            )

        auth_hash = self.authorization.compute_authorization_hash()

        existing_state = self.journal.read_state(packet.semantic_input_id, auth_hash)
        if existing_state:
            curr_j_state = existing_state.get("journal_state")
            if curr_j_state == DiagnosticJournalState.REQUEST_ATTEMPT_STARTED.value:
                self.journal.write_state_atomic(
                    packet.semantic_input_id,
                    auth_hash,
                    DiagnosticJournalState.OUTCOME_UNKNOWN,
                    operation_id=operation_id,
                    attempt_count=existing_state.get("attempt_count", 1),
                    extra_fields={"reason": "RECONCILE_ONLY_PREVIOUS_ATTEMPT_INTERRUPTED"},
                )
                return DiagnosticExecutionResult(
                    sample_id=packet.sample_id,
                    semantic_input_id=packet.semantic_input_id,
                    status=DiagnosticOutcomeStatus.OUTCOME_UNKNOWN,
                    request_hash=packet.compute_packet_hash(),
                    response_hash=None,
                    error_message="RECONCILE_ONLY: previous attempt interrupted at REQUEST_ATTEMPT_STARTED; no second dispatch eligibility",
                )
            elif curr_j_state in (
                DiagnosticJournalState.OBSERVED_OK.value,
                DiagnosticJournalState.OBSERVED_CLIENT_FAILURE.value,
                DiagnosticJournalState.OBSERVED_PROVIDER_FAILURE.value,
                DiagnosticJournalState.OUTCOME_UNKNOWN.value,
                DiagnosticJournalState.NOT_SENT.value,
            ):
                return DiagnosticExecutionResult(
                    sample_id=packet.sample_id,
                    semantic_input_id=packet.semantic_input_id,
                    status=DiagnosticOutcomeStatus(curr_j_state),
                    request_hash=packet.compute_packet_hash(),
                    response_hash=None,
                    error_message=f"Replay blocked: sample already in terminal state {curr_j_state}",
                )

        claimed = self.journal.try_atomic_claim(
            experiment_id=experiment_id,
            semantic_input_id=packet.semantic_input_id,
            authorization_hash=auth_hash,
            operation_id=operation_id,
        )
        if not claimed:
            return DiagnosticExecutionResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=DiagnosticOutcomeStatus.NOT_SENT,
                request_hash=packet.compute_packet_hash(),
                response_hash=None,
                error_message="ALREADY_CLAIMED: atomic sample claim exists",
            )

        self.total_claims_consumed += 1

        if self.total_claims_consumed > self.authorization.max_calls:
            return DiagnosticExecutionResult(
                sample_id=packet.sample_id,
                semantic_input_id=packet.semantic_input_id,
                status=DiagnosticOutcomeStatus.NOT_SENT,
                request_hash=packet.compute_packet_hash(),
                response_hash=None,
                error_message="MAX_CALLS_EXHAUSTED",
            )

        self.journal.write_state_atomic(
            packet.semantic_input_id,
            auth_hash,
            DiagnosticJournalState.PREPARED,
            operation_id=operation_id,
            attempt_count=0,
        )

        req = build_context_relevance_provider_request(
            self.question_contract,
            packet.provider_state,
            self.wire_descriptor,
        )

        # Zero-call gate: never make real network calls here
        self.journal.write_state_atomic(
            packet.semantic_input_id,
            auth_hash,
            DiagnosticJournalState.OBSERVED_OK,
            operation_id=operation_id,
            attempt_count=0,
            extra_fields={"zero_call_preflight": True, "request_payload_hash": req["body_payload_hash"]},
        )
        return DiagnosticExecutionResult(
            sample_id=packet.sample_id,
            semantic_input_id=packet.semantic_input_id,
            status=DiagnosticOutcomeStatus.OBSERVED_OK,
            request_hash=req["body_payload_hash"],
            response_hash=hashlib.sha256(b"zero_call_preflight_simulated").hexdigest(),
            error_message=None,
        )

    def execute_batch(
        self,
        packets: Sequence[DiagnosticSamplePacketV1],
        operation_id: str,
        experiment_id: str,
    ) -> list[DiagnosticExecutionResult]:
        """Legacy zero-call batch execute."""
        results: list[DiagnosticExecutionResult] = []
        stopped_due_to_unknown = False

        for p in packets:
            if stopped_due_to_unknown:
                results.append(
                    DiagnosticExecutionResult(
                        sample_id=p.sample_id,
                        semantic_input_id=p.semantic_input_id,
                        status=DiagnosticOutcomeStatus.NOT_SENT,
                        request_hash=p.compute_packet_hash(),
                        response_hash=None,
                        error_message="BATCH_HALTED_DUE_TO_OUTCOME_UNKNOWN",
                    )
                )
                continue

            res = self.execute_sample(p, operation_id, experiment_id)
            results.append(res)
            if res.status == DiagnosticOutcomeStatus.OUTCOME_UNKNOWN:
                stopped_due_to_unknown = True

        return results


def generate_context_relevance_authorization_preview(
    live_contract_revision: str,
    sample_source_revision: str = "1a82954e0ddcf90427bbad3dd36dfbea732f1f4e",
    fixture_hash: str = "479e7484b13118398a0ce34885d3f629ed7701a30f1bb6e94a1fc46aab116102",
    diagnostic_sample_hash: str = "5c0365d7d179ca233fbec0db46cc2d5698f1cce550ab69dd3d59e98eacdba8f5",
    question_contract_hash: str = "a7b75a88641668c1eb4bb460cd0f5ad8ffc3dff94e53b34bbc4791fcfff7aac9",
    provider_state_schema_hash: str = "bdfcd045b233a84618a7b26ffc963838ab41c480f3d694c989b4efa8910a70ac",
    wire_contract_hash: str = "586a75c42a22cb6f6cb03afd81cdea33695dd377384f75a1d24d3b81382cb66e",
    endpoint_host: str = "",
    journal_root_resolved_path: str = "",
    journal_namespace: str = "wave1-diag",
    authorized_semantic_input_ids: Sequence[str] = (),
    diagnostic_packet_hash: str = "d3120e10f83a80da9e84ed5ec4e13064a6af160fb53d6b00f8fa0f304125ea99",
) -> tuple[ContextRelevanceDiagnosticAuthorizationV1, dict[str, Any]]:
    """Generate exact durable ContextRelevanceDiagnosticAuthorizationV1 and preview dict.

    endpoint_host and journal_root_resolved_path must be explicitly provided
    by the Owner.  No default private endpoints or paths.
    """
    if not endpoint_host:
        raise ValueError(
            "endpoint_host must be explicitly provided; no default private endpoint allowed"
        )
    if not journal_root_resolved_path:
        raise ValueError(
            "journal_root_resolved_path must be explicitly provided; no default private path allowed"
        )
    root_resolved = os.path.realpath(journal_root_resolved_path)
    root_hash = hashlib.sha256(root_resolved.encode("utf-8")).hexdigest()
    ns_hash = hashlib.sha256(journal_namespace.encode("utf-8")).hexdigest()
    endpoint_host_hash = hashlib.sha256(endpoint_host.encode("utf-8")).hexdigest()

    auth = ContextRelevanceDiagnosticAuthorizationV1(
        authorization_schema_version="ContextRelevanceDiagnosticAuthorizationV1",
        live_contract_revision=live_contract_revision,
        sample_source_revision=sample_source_revision,
        fixture_hash=fixture_hash,
        diagnostic_sample_hash=diagnostic_sample_hash,
        question_contract_hash=question_contract_hash,
        provider_state_schema_hash=provider_state_schema_hash,
        wire_contract_hash=wire_contract_hash,
        endpoint_host=endpoint_host,
        journal_root_resolved_hash=root_hash,
        journal_namespace_hash=ns_hash,
        authorized_semantic_input_ids=tuple(authorized_semantic_input_ids),
        authorized_backup_sample_ids=(),
        max_calls=len(authorized_semantic_input_ids),
        diagnostic_packet_hash=diagnostic_packet_hash,
    )
    auth_hash = auth.compute_authorization_hash()

    preview = {
        "live_contract_revision": live_contract_revision,
        "sample_source_revision": sample_source_revision,
        "fixture_hash": fixture_hash,
        "sample_hash": diagnostic_sample_hash,
        "question_contract_hash": question_contract_hash,
        "provider_state_schema_hash": provider_state_schema_hash,
        "wire_contract_hash": wire_contract_hash,
        "endpoint_host_hash": endpoint_host_hash,
        "journal_root_hash": root_hash,
        "journal_namespace_hash": ns_hash,
        "exact_sample_count": len(authorized_semantic_input_ids),
        "max_calls": len(authorized_semantic_input_ids),
        "unbound_calls": 0,
        "authorization_hash": auth_hash,
    }
    return auth, preview


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
    sample_source_revision: str = "1a82954e0ddcf90427bbad3dd36dfbea732f1f4e",
    seed: str = "EXP_C_WAVE1_V2",
    candidate_sha: str | None = None,
) -> dict[str, Any]:
    """Generate physical zero-call diagnostic packet artifact."""
    if candidate_sha and (not sample_source_revision or sample_source_revision == "1a82954e0ddcf90427bbad3dd36dfbea732f1f4e"):
        effective_source_rev = candidate_sha
    else:
        effective_source_rev = sample_source_revision

    packets, strata_counts, sample_hash, fixture_hash = generate_wave1_diagnostic_sample_packets(seed=seed)
    q_contract = ContextRelevanceQuestionContractV1()
    p_schema_hash = ContextRelevanceProviderStateV1.compute_schema_hash()

    packet_data: dict[str, Any] = {
        "schema_version": "context-relevance-diagnostic-live-packet-v2",
        "sample_source_revision": effective_source_rev,
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
    parser.add_argument("--sample-source-revision", default="1a82954e0ddcf90427bbad3dd36dfbea732f1f4e", help="Sample source revision")
    parser.add_argument("--candidate-sha", default=None, help="Candidate git SHA (alias for source revision)")
    parser.add_argument("--output", default=None, help="Output file path")
    args = parser.parse_args()
    source_rev = args.candidate_sha or args.sample_source_revision
    artifact = generate_diagnostic_live_packet_artifact(sample_source_revision=source_rev)
    serialized = json.dumps(artifact, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(serialized)
        print(f"Wrote diagnostic live packet to {args.output}")
    else:
        print(serialized)
