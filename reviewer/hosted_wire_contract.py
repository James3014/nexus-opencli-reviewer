"""Provider-neutral hosted wire contract descriptor, dry-run builder, and independent authorization.

This module provides generic, declarative data structures for:
1. HostedProviderWireDescriptorV1: provider-neutral wire specification (methods, relative path, auth mode, headers).
2. LiveCanaryAuthorizationV1: independent Owner-authorized grant binding config hash, wire hash, host, question contract hash, and call budget.
3. HostedCanaryDryRun: zero-network, zero-secret dry-run assembler computing request identity, hashes, and payload without remote invocation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re
from typing import Any
from urllib.parse import urlparse

from reviewer.hosted_risk_config import HostedProviderConfigV1
from reviewer.risk_model_adapter import (
    F4QuestionContractV1,
    ProviderVisibleRiskStateV1,
    canonical_provider_payload_hash,
)

_VALID_HEADER_NAME_PATTERN = re.compile(r"^[A-Za-z0-9-]+$")
_CANONICAL_DESCRIPTOR_KEYS = {
    "contract_schema_version",
    "http_method",
    "request_path",
    "auth_mode",
    "auth_header_name",
    "content_type",
    "expected_model_identifier",
    "request_template_kind",
    "response_probability_path",
    "api_version_source",
    "provider_schema_identity",
}


class HostedAuthMode(str, Enum):
    BEARER = "BEARER"
    RAW_HEADER = "RAW_HEADER"
    NONE = "NONE"


@dataclass(frozen=True)
class HostedProviderWireDescriptorV1:
    """Generic declarative descriptor for hosted provider wire protocol. DATA, NOT CODE."""

    contract_schema_version: str
    http_method: str
    request_path: str
    auth_mode: HostedAuthMode
    auth_header_name: str
    content_type: str
    expected_model_identifier: str
    request_template_kind: str
    response_probability_path: str
    api_version_source: str
    provider_schema_identity: str

    def __post_init__(self) -> None:
        if self.http_method != "POST":
            raise ValueError(f"Only POST method is currently supported, got {self.http_method!r}")

        # Path validation: must be relative path starting with '/', no scheme, no host, no //, no traversal, no CRLF
        if not isinstance(self.request_path, str) or not self.request_path.startswith("/"):
            raise ValueError("request_path must be a relative path starting with '/'")

        if (
            self.request_path.startswith("//")
            or "://" in self.request_path
            or ".." in self.request_path
            or "\\" in self.request_path
            or any(c in self.request_path for c in ("\r", "\n", "\t", " "))
            or "?" in self.request_path
            or "#" in self.request_path
        ):
            raise ValueError(f"request_path contains invalid path characters or authority injection: {self.request_path!r}")

        # Header name validation
        if not _VALID_HEADER_NAME_PATTERN.fullmatch(self.auth_header_name):
            raise ValueError(f"auth_header_name contains invalid characters: {self.auth_header_name!r}")

        # String bounds
        for field_name in (
            "contract_schema_version",
            "content_type",
            "expected_model_identifier",
            "request_template_kind",
            "response_probability_path",
            "api_version_source",
            "provider_schema_identity",
        ):
            val = getattr(self, field_name)
            if not isinstance(val, str) or not val.strip() or len(val) > 128:
                raise ValueError(f"{field_name} must be a non-empty string <= 128 characters")
            if any(c in val for c in ("\r", "\n")):
                raise ValueError(f"{field_name} must not contain newline characters")

    def canonical_wire_hash(self) -> str:
        """Compute deterministic SHA-256 hash over canonical JSON representation."""
        payload = {
            "api_version_source": self.api_version_source,
            "auth_header_name": self.auth_header_name,
            "auth_mode": self.auth_mode.value,
            "content_type": self.content_type,
            "contract_schema_version": self.contract_schema_version,
            "expected_model_identifier": self.expected_model_identifier,
            "http_method": self.http_method,
            "provider_schema_identity": self.provider_schema_identity,
            "request_path": self.request_path,
            "request_template_kind": self.request_template_kind,
            "response_probability_path": self.response_probability_path,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


def load_wire_descriptor_from_dict(data: dict[str, Any]) -> HostedProviderWireDescriptorV1:
    """Parse and validate HostedProviderWireDescriptorV1 from a dictionary."""
    if not isinstance(data, dict):
        raise ValueError("Wire descriptor must be a JSON object")

    keys = set(data.keys())
    if keys != _CANONICAL_DESCRIPTOR_KEYS:
        missing = _CANONICAL_DESCRIPTOR_KEYS - keys
        extra = keys - _CANONICAL_DESCRIPTOR_KEYS
        errs = []
        if missing:
            errs.append(f"missing required keys: {sorted(list(missing))}")
        if extra:
            errs.append(f"unknown keys forbidden: {sorted(list(extra))}")
        raise ValueError("; ".join(errs))

    auth_mode_raw = data["auth_mode"]
    try:
        auth_mode = HostedAuthMode(auth_mode_raw)
    except ValueError:
        raise ValueError(f"Invalid auth_mode: {auth_mode_raw!r}")

    return HostedProviderWireDescriptorV1(
        contract_schema_version=str(data["contract_schema_version"]),
        http_method=str(data["http_method"]),
        request_path=str(data["request_path"]),
        auth_mode=auth_mode,
        auth_header_name=str(data["auth_header_name"]),
        content_type=str(data["content_type"]),
        expected_model_identifier=str(data["expected_model_identifier"]),
        request_template_kind=str(data["request_template_kind"]),
        response_probability_path=str(data["response_probability_path"]),
        api_version_source=str(data["api_version_source"]),
        provider_schema_identity=str(data["provider_schema_identity"]),
    )


@dataclass(frozen=True)
class LiveCanaryAuthorizationV1:
    """Explicit, independent Owner authorization required for any live canary execution."""

    config_hash: str
    wire_contract_hash: str
    endpoint_host: str
    question_contract_hash: str
    max_calls: int

    def __post_init__(self) -> None:
        for name, val in (
            ("config_hash", self.config_hash),
            ("wire_contract_hash", self.wire_contract_hash),
            ("question_contract_hash", self.question_contract_hash),
        ):
            if not isinstance(val, str) or len(val) != 64 or not all(c in "0123456789abcdef" for c in val):
                raise ValueError(f"{name} must be a valid 64-character lowercase hexadecimal hash")

        if not isinstance(self.endpoint_host, str) or not self.endpoint_host.strip():
            raise ValueError("endpoint_host must be a non-empty string")

        if isinstance(self.max_calls, bool) or not isinstance(self.max_calls, int) or self.max_calls <= 0:
            raise ValueError("max_calls must be an integer > 0")


@dataclass(frozen=True)
class HostedCanaryDryRun:
    """Assembled dry-run canary request representation without network access."""

    method: str
    target_origin: str
    target_path: str
    headers: dict[str, str]
    body_payload: dict[str, Any]
    body_payload_hash: str
    config_hash: str
    wire_contract_hash: str
    question_contract_hash: str
    provider_request_id: str


def assemble_hosted_canary_dry_run(
    config: HostedProviderConfigV1,
    wire: HostedProviderWireDescriptorV1,
    authorization: LiveCanaryAuthorizationV1,
    state: ProviderVisibleRiskStateV1,
    contract: F4QuestionContractV1,
    provider_request_id: str,
    *,
    synthetic_key: str | None = None,
) -> HostedCanaryDryRun:
    """Assemble a zero-network, zero-real-secret dry run request.

    Verifies that config, wire descriptor, and Owner authorization are strictly coherent.
    """
    # 1. Authority Verification
    cfg_hash = config.canonical_config_hash()
    if authorization.config_hash != cfg_hash:
        raise ValueError(f"Authorization config_hash mismatch: {authorization.config_hash} != {cfg_hash}")

    wire_hash = wire.canonical_wire_hash()
    if authorization.wire_contract_hash != wire_hash:
        raise ValueError(f"Authorization wire_contract_hash mismatch: {authorization.wire_contract_hash} != {wire_hash}")

    parsed_origin = urlparse(config.endpoint_origin)
    if authorization.endpoint_host != parsed_origin.hostname:
        raise ValueError(
            f"Authorization endpoint_host mismatch: {authorization.endpoint_host} != {parsed_origin.hostname}"
        )

    if authorization.question_contract_hash != contract.contract_hash:
        raise ValueError(
            f"Authorization question_contract_hash mismatch: {authorization.question_contract_hash} != {contract.contract_hash}"
        )

    if authorization.max_calls <= 0:
        raise ValueError("Authorization call quota exhausted")

    # 2. Build dry-run payload
    # Semantic mapping strictly preserves ProviderVisibleRiskStateV1 + F4QuestionContractV1
    body_payload: dict[str, Any] = {
        "model": wire.expected_model_identifier,
        "provider_request_id": provider_request_id,
        "question_contract": {
            "primitive": contract.primitive,
            "contract_hash": contract.contract_hash,
            "question_statement": contract.question_statement,
        },
        "state": state.as_payload(),
    }

    encoded_bytes = json.dumps(body_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    body_payload_hash = hashlib.sha256(encoded_bytes).hexdigest()

    # 3. Assemble headers without real secrets
    headers: dict[str, str] = {
        "Content-Type": wire.content_type,
        "Accept": wire.content_type,
        "X-Provider-Request-Id": provider_request_id,
    }

    if synthetic_key:
        auth_val = f"Bearer {synthetic_key}" if wire.auth_mode == HostedAuthMode.BEARER else synthetic_key
        headers[wire.auth_header_name] = auth_val
    else:
        headers[wire.auth_header_name] = f"REDACTED_{wire.auth_mode.value}_CREDENTIAL"

    return HostedCanaryDryRun(
        method=wire.http_method,
        target_origin=config.endpoint_origin,
        target_path=wire.request_path,
        headers=headers,
        body_payload=body_payload,
        body_payload_hash=body_payload_hash,
        config_hash=cfg_hash,
        wire_contract_hash=wire_hash,
        question_contract_hash=contract.contract_hash,
        provider_request_id=provider_request_id,
    )
