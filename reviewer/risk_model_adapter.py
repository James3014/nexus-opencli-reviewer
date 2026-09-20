"""Provider-neutral H0 risk-model contract with a zero-network mock.

This module is intentionally limited to provider-facing state projection, transport
status, raw probability output, and deterministic request hashing. It owns no
family operating policy and grants no execution or governance authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
from typing import Protocol, Sequence


_MAX_EXTENSION_COUNT = 10
_MAX_ALLOWED_PATH_COUNT = 50
_MAX_SYMBOL_LENGTH = 128
_MAX_EXTENSION_LENGTH = 32


def _require_symbol(name: str, value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_SYMBOL_LENGTH:
        raise ValueError(f"{name} must be a non-empty bounded string")
    if any(char in value for char in ("\n", "\r", "\t")):
        raise ValueError(f"{name} must not contain control whitespace")
    return value


@dataclass(frozen=True)
class ProviderVisibleRiskStateV1:
    """Strict provider-visible subset of the canonical SafeRiskObservation."""

    action_type: str
    mutation_domain: str
    permission_profile: str
    is_mutation: bool
    allowed_path_extensions: Sequence[str]
    allowed_path_count: int

    def __post_init__(self) -> None:
        _require_symbol("action_type", self.action_type)
        _require_symbol("mutation_domain", self.mutation_domain)
        _require_symbol("permission_profile", self.permission_profile)

        if not isinstance(self.is_mutation, bool):
            raise ValueError("is_mutation must be bool")

        extensions = tuple(self.allowed_path_extensions)
        if len(extensions) > _MAX_EXTENSION_COUNT:
            raise ValueError(
                f"allowed_path_extensions may contain at most {_MAX_EXTENSION_COUNT} entries"
            )
        for extension in extensions:
            if (
                not isinstance(extension, str)
                or not extension.startswith(".")
                or len(extension) > _MAX_EXTENSION_LENGTH
                or "/" in extension
                or "\\" in extension
                or any(char in extension for char in ("\n", "\r", "\t"))
            ):
                raise ValueError("allowed_path_extensions contains an invalid extension")

        if (
            isinstance(self.allowed_path_count, bool)
            or not isinstance(self.allowed_path_count, int)
            or not 0 <= self.allowed_path_count <= _MAX_ALLOWED_PATH_COUNT
        ):
            raise ValueError(
                f"allowed_path_count must be an integer in [0, {_MAX_ALLOWED_PATH_COUNT}]"
            )

        object.__setattr__(self, "allowed_path_extensions", extensions)

    def as_payload(self) -> dict[str, object]:
        """Return only the provider-visible canonical subset."""

        return {
            "action_type": self.action_type,
            "mutation_domain": self.mutation_domain,
            "permission_profile": self.permission_profile,
            "is_mutation": self.is_mutation,
            "allowed_path_extensions": list(self.allowed_path_extensions),
            "allowed_path_count": self.allowed_path_count,
        }


@dataclass(frozen=True)
class F4QuestionContractV1:
    """Immutable F4 semantic question identity for the H0 contract."""

    contract_version: str = "f4-noul-v1"
    primitive: str = "NOUL"
    question_statement: str = (
        "Does this structured operation warrant additional semantic risk escalation "
        "beyond deterministic baseline policy?"
    )
    input_schema_hash: str = (
        "c74f56f34e6e6512b9d29c89456cb04c32d43be98514582f3471bbcf594fa35b"
    )
    contract_hash: str = (
        "e9124408bb39fa2799c8524458d341bcf027415e9858348bb921473be9857912"
    )


class ProviderCallStatus(str, Enum):
    """Host/transport outcome; never a model prediction."""

    OK = "OK"
    TIMEOUT = "TIMEOUT"
    RATE_LIMIT = "RATE_LIMIT"
    INVALID_RESPONSE = "INVALID_RESPONSE"
    IDENTITY_DRIFT = "IDENTITY_DRIFT"
    KILLED = "KILLED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    CLIENT_ERROR = "CLIENT_ERROR"
    NETWORK_UNAVAILABLE = "NETWORK_UNAVAILABLE"


@dataclass(frozen=True)
class RiskModelResult:
    """Typed raw provider result.

    A successful result carries only the observed probability. Any operating
    disposition belongs to a separate family policy/calibration layer.
    """

    status: ProviderCallStatus
    probability: float | None
    provider_payload_hash: str
    adapter_id: str
    adapter_revision: str
    question_contract_hash: str
    provider_schema_version: str
    api_version: str | None = None
    service_model_version: str | None = "SERVICE_MODEL_VERSION_UNEXPOSED"
    error_message: str | None = None

    def __post_init__(self) -> None:
        _require_symbol("adapter_id", self.adapter_id)
        _require_symbol("adapter_revision", self.adapter_revision)
        _require_symbol("question_contract_hash", self.question_contract_hash)
        _require_symbol("provider_schema_version", self.provider_schema_version)

        if self.status is ProviderCallStatus.OK:
            if (
                self.probability is None
                or isinstance(self.probability, bool)
                or not isinstance(self.probability, (int, float))
                or not 0.0 <= float(self.probability) <= 1.0
            ):
                raise ValueError("OK results require probability in [0.0, 1.0]")
            if self.error_message is not None:
                raise ValueError("OK results must not carry error_message")
        elif self.probability is not None:
            raise ValueError("provider failures must not carry model probability")


class RiskModelAdapter(Protocol):
    """Provider-neutral sidecar adapter contract."""

    def evaluate(
        self,
        state: ProviderVisibleRiskStateV1,
        contract: F4QuestionContractV1,
        provider_request_id: str,
    ) -> RiskModelResult:
        ...


def canonical_provider_payload_hash(
    state: ProviderVisibleRiskStateV1,
    contract: F4QuestionContractV1,
) -> str:
    """Hash the exact provider-visible H0 payload using canonical JSON."""

    payload = {
        "state": state.as_payload(),
        "question_contract": asdict(contract),
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class MockRiskModelAdapter:
    """Deterministic zero-network, zero-model H0 implementation."""

    adapter_id = "mock-risk-model-adapter"
    adapter_revision = "h0-v1"
    provider_schema_version = "mock-v1"

    def __init__(
        self,
        fixed_probability: float = 0.05,
        simulate_status: ProviderCallStatus = ProviderCallStatus.OK,
    ) -> None:
        if (
            isinstance(fixed_probability, bool)
            or not isinstance(fixed_probability, (int, float))
            or not 0.0 <= float(fixed_probability) <= 1.0
        ):
            raise ValueError("fixed_probability must be in [0.0, 1.0]")
        if not isinstance(simulate_status, ProviderCallStatus):
            raise ValueError("simulate_status must be ProviderCallStatus")
        self.fixed_probability = float(fixed_probability)
        self.simulate_status = simulate_status

    def evaluate(
        self,
        state: ProviderVisibleRiskStateV1,
        contract: F4QuestionContractV1,
        provider_request_id: str,
    ) -> RiskModelResult:
        _require_symbol("provider_request_id", provider_request_id)
        payload_hash = canonical_provider_payload_hash(state, contract)

        if self.simulate_status is not ProviderCallStatus.OK:
            return RiskModelResult(
                status=self.simulate_status,
                probability=None,
                provider_payload_hash=payload_hash,
                adapter_id=self.adapter_id,
                adapter_revision=self.adapter_revision,
                question_contract_hash=contract.contract_hash,
                provider_schema_version=self.provider_schema_version,
                error_message=f"simulated provider status: {self.simulate_status.value}",
            )

        return RiskModelResult(
            status=ProviderCallStatus.OK,
            probability=self.fixed_probability,
            provider_payload_hash=payload_hash,
            adapter_id=self.adapter_id,
            adapter_revision=self.adapter_revision,
            question_contract_hash=contract.contract_hash,
            provider_schema_version=self.provider_schema_version,
        )
