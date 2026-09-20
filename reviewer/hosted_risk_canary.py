"""F4 Hosted Adapter H2C Single-Call Live Canary Executor.

This module implements a single-call live canary executor for the hosted provider
(TypeSafe SystemOne Noul). It enforces:
1. Exact authority and coherent identity bindings (config, wire, auth, question).
2. HTTPS-only URL construction with exact authorized host matching and zero query/fragment/userinfo.
3. Strict zero-proxy, zero-redirect, verified TLS transport.
4. Late-bound secret retrieval (environment variable read ONLY after all validations pass).
5. Hard replay protection and durable effect journaling:
   - PREPARED (attempt_count = 0)
   - REQUEST_ATTEMPT_STARTED (attempt_count = 1)
   - OBSERVED_OK / OBSERVED_PROVIDER_FAILURE / OUTCOME_UNKNOWN / NOT_SENT
6. Maximum exactly one network request attempt per executor invocation. Zero automatic retries.
7. Official TypeSafe SystemOne request body ({model, questions: {decision: {type: 'noul', instructions}}, state}).
8. Strict privacy preservation (exact 6-field state, no local effect IDs in request body, no secret leakage).
9. Official response parsing (answers.decision.noul, numeric, finite, [0, 1]).
10. Strict protection: ALL PROVIDER OUTPUT IS STRICTLY PROTECTED FROM TRAINING USE.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import ssl
from typing import Any
import urllib.error
from urllib.parse import urlparse
import urllib.request

from reviewer.hosted_risk_config import HostedProviderConfigV1
from reviewer.hosted_wire_contract import (
    HostedAuthMode,
    HostedProviderWireDescriptorV1,
    LiveCanaryAuthorizationV1,
)
from reviewer.risk_model_adapter import (
    F4QuestionContractV1,
    ProviderCallStatus,
    ProviderVisibleRiskStateV1,
    RiskModelResult,
)

_VALID_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_F4_PROVIDER_QUESTION_NAME = "decision"
_F4_REQUEST_TEMPLATE_KIND = "systemone_noul"
_F4_RESPONSE_PROBABILITY_PATH = "answers.decision.noul"
_F4_AUTH_HEADER_NAME = "Authorization"
_F4_CONTENT_TYPE = "application/json"
_MAX_RESPONSE_BYTES = 1_048_576
_ADAPTER_ID = "hosted-canary-adapter"
_ADAPTER_REVISION = "h2c-v2"


class CanaryJournalState(str, Enum):
    """Lifecycle states of the durable external effect journal."""

    PREPARED = "PREPARED"
    REQUEST_ATTEMPT_STARTED = "REQUEST_ATTEMPT_STARTED"
    OBSERVED_OK = "OBSERVED_OK"
    OBSERVED_PROVIDER_FAILURE = "OBSERVED_PROVIDER_FAILURE"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
    NOT_SENT = "NOT_SENT"


@dataclass(frozen=True)
class LiveCanaryObservationV1:
    """Private canary observation receipt stored only in private runtime directory."""

    operation_id: str
    provider_request_id: str
    journal_state: CanaryJournalState
    call_status: ProviderCallStatus
    config_hash: str
    wire_contract_hash: str
    question_contract_hash: str
    body_payload_hash: str
    endpoint_host_hash: str
    authorization_hash: str
    probability: float | None
    observed_model: str | None
    usage: dict[str, int] | None
    attempt_count: int
    error_message: str | None = None


class HostedNoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Fail-closed redirect handler to block redirect escape attacks."""

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
            newurl,
            code,
            f"HTTP redirect to {newurl} forbidden by security policy",
            headers,  # type: ignore[arg-type]
            fp,
        )


class HostedEmptyProxyHandler(urllib.request.ProxyHandler):
    """Explicit empty proxy handler that disables environment proxy discovery."""

    def __init__(self) -> None:
        super().__init__({})

    def http_request(self, req: urllib.request.Request) -> urllib.request.Request:
        return req

    def https_request(self, req: urllib.request.Request) -> urllib.request.Request:
        return req


def _build_secure_https_opener() -> urllib.request.OpenerDirector:
    """Build a secure, hardened OpenerDirector for HTTPS requests.

    - Urllib proxy handling disabled via empty ProxyHandler.
    - Redirects forbidden via HostedNoRedirectHandler.
    - Standard verified TLS via ssl.create_default_context().
    """
    ssl_context = ssl.create_default_context()
    https_handler = urllib.request.HTTPSHandler(context=ssl_context)
    return urllib.request.build_opener(
        HostedEmptyProxyHandler,
        HostedNoRedirectHandler,
        https_handler,
    )


def _validate_bounded_id(name: str, value: Any) -> str:
    """Validate that value is a bounded visible ASCII identifier."""
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ValueError(f"{name} must be a non-empty string <= 128 characters")
    if not _VALID_ID_PATTERN.fullmatch(value):
        raise ValueError(f"{name} contains invalid characters: {value!r}")
    return value


def _canonical_authorization_hash(authorization: LiveCanaryAuthorizationV1) -> str:
    """Bind the exact one-shot Owner authorization contents to a durable identity."""
    payload = {
        "schema": "h2c-single-call-authorization.v1",
        "config_hash": authorization.config_hash,
        "wire_contract_hash": authorization.wire_contract_hash,
        "endpoint_host": authorization.endpoint_host,
        "question_contract_hash": authorization.question_contract_hash,
        "max_calls": authorization.max_calls,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _create_json_exclusive(path: Path, data: dict[str, Any], *, conflict_code: str) -> None:
    """Atomically claim a one-shot identity before any external effect can occur."""
    encoded = json.dumps(data, sort_keys=True, indent=2).encode("utf-8")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise RuntimeError(f"{conflict_code}: durable claim already exists") from exc

    with os.fdopen(fd, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())


def _write_journal_atomic(journal_path: Path, data: dict[str, Any]) -> None:
    """Write journal data atomically via a private temp file replace."""
    tmp_path = journal_path.with_suffix(".tmp")
    encoded = json.dumps(data, sort_keys=True, indent=2).encode("utf-8")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    tmp_path.replace(journal_path)


def _reject_duplicate_response_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject ambiguous provider JSON instead of silently accepting last-write-wins."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Provider response contains duplicate JSON keys")
        result[key] = value
    return result


def execute_hosted_canary_call(
    config: HostedProviderConfigV1,
    wire: HostedProviderWireDescriptorV1,
    authorization: LiveCanaryAuthorizationV1,
    state: ProviderVisibleRiskStateV1,
    contract: F4QuestionContractV1,
    *,
    operation_id: str,
    provider_request_id: str,
    journal_dir: str | Path,
    timeout_seconds: float = 5.0,
) -> tuple[RiskModelResult, LiveCanaryObservationV1]:
    """Execute a single-call live canary request to the hosted risk provider.

    Strict invariant: At most one network request attempt per invocation. Zero retries.
    Returns (RiskModelResult, LiveCanaryObservationV1).
    """
    # Validate local effect IDs before anything else
    _validate_bounded_id("operation_id", operation_id)
    _validate_bounded_id("provider_request_id", provider_request_id)

    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or timeout_seconds <= 0
    ):
        raise ValueError("timeout_seconds must be a positive number")

    # 1. Strict Authority and Coherence Validation
    cfg_hash = config.canonical_config_hash()
    if authorization.config_hash != cfg_hash:
        raise ValueError(
            f"Authorization config_hash mismatch: {authorization.config_hash} != {cfg_hash}"
        )

    wire_hash = wire.canonical_wire_hash()
    if authorization.wire_contract_hash != wire_hash:
        raise ValueError(
            f"Authorization wire_contract_hash mismatch: {authorization.wire_contract_hash} != {wire_hash}"
        )

    parsed_origin = urlparse(config.endpoint_origin)
    if parsed_origin.scheme != "https":
        raise ValueError(f"Endpoint origin must use HTTPS scheme: {config.endpoint_origin}")

    if authorization.endpoint_host != parsed_origin.hostname:
        raise ValueError(
            f"Authorization endpoint_host mismatch: {authorization.endpoint_host} != {parsed_origin.hostname}"
        )

    if authorization.question_contract_hash != contract.contract_hash:
        raise ValueError(
            f"Authorization question_contract_hash mismatch: {authorization.question_contract_hash} != {contract.contract_hash}"
        )

    # Invariant: H2C production executor requires max_calls == 1
    if authorization.max_calls != 1:
        raise ValueError(
            f"H2C single-call canary executor requires max_calls == 1, got {authorization.max_calls}"
        )
    if config.max_canary_quota < 1:
        raise ValueError("Config max_canary_quota must be >= 1")

    # Wire schema invariants
    if wire.http_method != "POST":
        raise ValueError(f"Only POST method is supported, got {wire.http_method!r}")
    if wire.request_template_kind != _F4_REQUEST_TEMPLATE_KIND:
        raise ValueError(
            f"F4 hosted canary requires request_template_kind={_F4_REQUEST_TEMPLATE_KIND!r}"
        )
    if wire.response_probability_path != _F4_RESPONSE_PROBABILITY_PATH:
        raise ValueError(
            f"F4 hosted canary requires response_probability_path={_F4_RESPONSE_PROBABILITY_PATH!r}"
        )
    if wire.auth_mode != HostedAuthMode.BEARER:
        raise ValueError(f"F4 hosted canary requires auth_mode=BEARER, got {wire.auth_mode}")
    if wire.auth_header_name != _F4_AUTH_HEADER_NAME:
        raise ValueError(
            f"F4 hosted canary requires auth_header_name={_F4_AUTH_HEADER_NAME!r}"
        )
    if wire.content_type != _F4_CONTENT_TYPE:
        raise ValueError(
            f"F4 hosted canary requires content_type={_F4_CONTENT_TYPE!r}"
        )
    if contract.primitive != "NOUL":
        raise ValueError(f"F4 hosted canary requires primitive=NOUL, got {contract.primitive}")

    # Construct and strictly validate final request URL
    # Wire path must be a clean relative path starting with '/'
    if not wire.request_path.startswith("/") or wire.request_path.startswith("//"):
        raise ValueError(f"Invalid wire request_path: {wire.request_path!r}")

    final_url = f"{config.endpoint_origin}{wire.request_path}"
    parsed_final = urlparse(final_url)
    if parsed_final.scheme != "https":
        raise ValueError("Final URL must use https scheme")
    if parsed_final.hostname != parsed_origin.hostname:
        raise ValueError("Final URL hostname does not match authorized origin")
    if parsed_final.username or parsed_final.password:
        raise ValueError("Final URL must not contain credentials")
    if parsed_final.query or parsed_final.fragment:
        raise ValueError("Final URL must not contain query or fragment")

    # Construct the exact official SystemOneRequest body
    # Only model, questions, state. Exact 6-field state. No local IDs, no secrets.
    body_dict: dict[str, Any] = {
        "model": wire.expected_model_identifier,
        "questions": {
            _F4_PROVIDER_QUESTION_NAME: {
                "type": "noul",
                "instructions": contract.question_statement,
            }
        },
        "state": state.as_payload(),
    }
    encoded_body = json.dumps(body_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    body_payload_hash = hashlib.sha256(encoded_body).hexdigest()
    endpoint_host_hash = hashlib.sha256(parsed_origin.hostname.encode("utf-8")).hexdigest()

    # 2. Journal Setup and Replay Protection
    j_dir_input = Path(journal_dir)
    if j_dir_input.exists() and j_dir_input.is_symlink():
        raise ValueError("journal_dir must not be a symlink")
    j_dir = j_dir_input.resolve()
    j_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    journal_path = j_dir / f"{operation_id}.json"

    authorization_hash = _canonical_authorization_hash(authorization)

    # 3. Atomically claim this operation before any secret read or network attempt.
    journal_data: dict[str, Any] = {
        "operation_id": operation_id,
        "provider_request_id": provider_request_id,
        "journal_state": CanaryJournalState.PREPARED.value,
        "config_hash": cfg_hash,
        "wire_contract_hash": wire_hash,
        "question_contract_hash": contract.contract_hash,
        "body_payload_hash": body_payload_hash,
        "endpoint_host_hash": endpoint_host_hash,
        "authorization_hash": authorization_hash,
        "attempt_count": 0,
    }
    _create_json_exclusive(
        journal_path,
        journal_data,
        conflict_code="RECONCILIATION_REQUIRED",
    )

    # 4. Late-Bound Secret Retrieval
    secret_value = os.environ.get(config.api_key_env_var_name)
    if not secret_value or not secret_value.strip():
        journal_data["journal_state"] = CanaryJournalState.NOT_SENT.value
        _write_journal_atomic(journal_path, journal_data)
        observation = LiveCanaryObservationV1(
            operation_id=operation_id,
            provider_request_id=provider_request_id,
            journal_state=CanaryJournalState.NOT_SENT,
            call_status=ProviderCallStatus.CLIENT_ERROR,
            config_hash=cfg_hash,
            wire_contract_hash=wire_hash,
            question_contract_hash=contract.contract_hash,
            body_payload_hash=body_payload_hash,
            endpoint_host_hash=endpoint_host_hash,
            authorization_hash=authorization_hash,
            probability=None,
            observed_model=None,
            usage=None,
            attempt_count=0,
            error_message=f"Environment variable {config.api_key_env_var_name} missing or empty",
        )
        result = RiskModelResult(
            status=ProviderCallStatus.CLIENT_ERROR,
            probability=None,
            provider_payload_hash=body_payload_hash,
            adapter_id=_ADAPTER_ID,
            adapter_revision=_ADAPTER_REVISION,
            question_contract_hash=contract.contract_hash,
            provider_schema_version=wire.provider_schema_identity,
            api_version=wire.api_version_source,
            error_message="API key missing in environment",
        )
        return result, observation

    # 5. Consume the one-shot Owner authorization atomically before first possible effect.
    authorization_claim_path = j_dir / f"authorization-{authorization_hash}.json"
    try:
        _create_json_exclusive(
            authorization_claim_path,
            {
                "authorization_hash": authorization_hash,
                "operation_id": operation_id,
                "provider_request_id": provider_request_id,
                "config_hash": cfg_hash,
                "wire_contract_hash": wire_hash,
                "question_contract_hash": contract.contract_hash,
                "endpoint_host_hash": endpoint_host_hash,
                "max_calls": authorization.max_calls,
                "claim_state": "CONSUMED_FOR_SINGLE_CALL",
            },
            conflict_code="AUTHORIZATION_ALREADY_CONSUMED",
        )
    except RuntimeError:
        journal_data["journal_state"] = CanaryJournalState.NOT_SENT.value
        journal_data["error_code"] = "AUTHORIZATION_ALREADY_CONSUMED"
        _write_journal_atomic(journal_path, journal_data)
        raise

    # 6. Transition to REQUEST_ATTEMPT_STARTED (attempt_count = 1) immediately before send
    journal_data["journal_state"] = CanaryJournalState.REQUEST_ATTEMPT_STARTED.value
    journal_data["attempt_count"] = 1
    _write_journal_atomic(journal_path, journal_data)

    # 7. Build Request and Execute Single Attempt
    headers = {
        "Accept": "application/json",
        "Content-Type": _F4_CONTENT_TYPE,
        wire.auth_header_name: f"Bearer {secret_value.strip()}",
    }
    req = urllib.request.Request(
        url=final_url,
        data=encoded_body,
        headers=headers,
        method=wire.http_method,
    )

    opener = _build_secure_https_opener()
    raw_response_bytes: bytes | None = None
    response_code: int | None = None
    transport_error: str | None = None

    response_too_large = False
    try:
        with opener.open(req, timeout=timeout_seconds) as resp:
            raw_response_bytes = resp.read(_MAX_RESPONSE_BYTES + 1)
            response_code = resp.status
            response_too_large = len(raw_response_bytes) > _MAX_RESPONSE_BYTES
    except urllib.error.HTTPError as exc:
        response_code = exc.code
        # Error bodies are not needed for classification and are intentionally not read.
        transport_error = f"HTTP {exc.code}: {exc.reason}"
    except (TimeoutError, urllib.error.URLError) as exc:
        # Check if underlying cause is timeout
        is_timeout = isinstance(exc, TimeoutError) or "timed out" in str(exc).lower()
        if is_timeout:
            journal_data["journal_state"] = CanaryJournalState.OUTCOME_UNKNOWN.value
            _write_journal_atomic(journal_path, journal_data)
            obs = LiveCanaryObservationV1(
                operation_id=operation_id,
                provider_request_id=provider_request_id,
                journal_state=CanaryJournalState.OUTCOME_UNKNOWN,
                call_status=ProviderCallStatus.TIMEOUT,
                config_hash=cfg_hash,
                wire_contract_hash=wire_hash,
                question_contract_hash=contract.contract_hash,
                body_payload_hash=body_payload_hash,
                endpoint_host_hash=endpoint_host_hash,
                authorization_hash=authorization_hash,
                probability=None,
                observed_model=None,
                usage=None,
                attempt_count=1,
                error_message="Transport timed out waiting for response; outcome unknown",
            )
            res = RiskModelResult(
                status=ProviderCallStatus.TIMEOUT,
                probability=None,
                provider_payload_hash=body_payload_hash,
                adapter_id=_ADAPTER_ID,
                adapter_revision=_ADAPTER_REVISION,
                question_contract_hash=contract.contract_hash,
                provider_schema_version=wire.provider_schema_identity,
                api_version=wire.api_version_source,
                error_message="Transport timed out waiting for response",
            )
            return res, obs
        else:
            # Other URLError before or during connection
            journal_data["journal_state"] = CanaryJournalState.OUTCOME_UNKNOWN.value
            _write_journal_atomic(journal_path, journal_data)
            obs = LiveCanaryObservationV1(
                operation_id=operation_id,
                provider_request_id=provider_request_id,
                journal_state=CanaryJournalState.OUTCOME_UNKNOWN,
                call_status=ProviderCallStatus.NETWORK_UNAVAILABLE,
                config_hash=cfg_hash,
                wire_contract_hash=wire_hash,
                question_contract_hash=contract.contract_hash,
                body_payload_hash=body_payload_hash,
                endpoint_host_hash=endpoint_host_hash,
                authorization_hash=authorization_hash,
                probability=None,
                observed_model=None,
                usage=None,
                attempt_count=1,
                error_message=f"Network error: {exc}",
            )
            res = RiskModelResult(
                status=ProviderCallStatus.NETWORK_UNAVAILABLE,
                probability=None,
                provider_payload_hash=body_payload_hash,
                adapter_id=_ADAPTER_ID,
                adapter_revision=_ADAPTER_REVISION,
                question_contract_hash=contract.contract_hash,
                provider_schema_version=wire.provider_schema_identity,
                api_version=wire.api_version_source,
                error_message="Network transport unavailable",
            )
            return res, obs
    except (http.client.IncompleteRead, http.client.RemoteDisconnected, ConnectionResetError, ConnectionError, BrokenPipeError) as exc:
        journal_data["journal_state"] = CanaryJournalState.OUTCOME_UNKNOWN.value
        _write_journal_atomic(journal_path, journal_data)
        obs = LiveCanaryObservationV1(
            operation_id=operation_id,
            provider_request_id=provider_request_id,
            journal_state=CanaryJournalState.OUTCOME_UNKNOWN,
            call_status=ProviderCallStatus.NETWORK_UNAVAILABLE,
            config_hash=cfg_hash,
            wire_contract_hash=wire_hash,
            question_contract_hash=contract.contract_hash,
            body_payload_hash=body_payload_hash,
            endpoint_host_hash=endpoint_host_hash,
            authorization_hash=authorization_hash,
            probability=None,
            observed_model=None,
            usage=None,
            attempt_count=1,
            error_message=f"Connection terminated unexpectedly: {exc}",
        )
        res = RiskModelResult(
            status=ProviderCallStatus.NETWORK_UNAVAILABLE,
            probability=None,
            provider_payload_hash=body_payload_hash,
            adapter_id=_ADAPTER_ID,
            adapter_revision=_ADAPTER_REVISION,
            question_contract_hash=contract.contract_hash,
            provider_schema_version=wire.provider_schema_identity,
            api_version=wire.api_version_source,
            error_message="Connection terminated unexpectedly",
        )
        return res, obs
    except Exception as exc:
        journal_data["journal_state"] = CanaryJournalState.OUTCOME_UNKNOWN.value
        _write_journal_atomic(journal_path, journal_data)
        obs = LiveCanaryObservationV1(
            operation_id=operation_id,
            provider_request_id=provider_request_id,
            journal_state=CanaryJournalState.OUTCOME_UNKNOWN,
            call_status=ProviderCallStatus.CLIENT_ERROR,
            config_hash=cfg_hash,
            wire_contract_hash=wire_hash,
            question_contract_hash=contract.contract_hash,
            body_payload_hash=body_payload_hash,
            endpoint_host_hash=endpoint_host_hash,
            authorization_hash=authorization_hash,
            probability=None,
            observed_model=None,
            usage=None,
            attempt_count=1,
            error_message=f"Unexpected transport failure: {exc}",
        )
        res = RiskModelResult(
            status=ProviderCallStatus.CLIENT_ERROR,
            probability=None,
            provider_payload_hash=body_payload_hash,
            adapter_id=_ADAPTER_ID,
            adapter_revision=_ADAPTER_REVISION,
            question_contract_hash=contract.contract_hash,
            provider_schema_version=wire.provider_schema_identity,
            api_version=wire.api_version_source,
            error_message="Unexpected transport failure",
        )
        return res, obs

    # 8. Provider Response Handling (Definitive HTTP response observed)
    if response_code != 200:
        journal_data["journal_state"] = CanaryJournalState.OBSERVED_PROVIDER_FAILURE.value
        _write_journal_atomic(journal_path, journal_data)

        if response_code in (401, 403):
            call_status = ProviderCallStatus.CLIENT_ERROR
        elif response_code in (400, 422):
            call_status = ProviderCallStatus.INVALID_RESPONSE
        elif response_code == 429:
            call_status = ProviderCallStatus.RATE_LIMIT
        elif response_code and 500 <= response_code < 600:
            call_status = ProviderCallStatus.NETWORK_UNAVAILABLE
        else:
            call_status = ProviderCallStatus.CLIENT_ERROR

        obs = LiveCanaryObservationV1(
            operation_id=operation_id,
            provider_request_id=provider_request_id,
            journal_state=CanaryJournalState.OBSERVED_PROVIDER_FAILURE,
            call_status=call_status,
            config_hash=cfg_hash,
            wire_contract_hash=wire_hash,
            question_contract_hash=contract.contract_hash,
            body_payload_hash=body_payload_hash,
            endpoint_host_hash=endpoint_host_hash,
            authorization_hash=authorization_hash,
            probability=None,
            observed_model=None,
            usage=None,
            attempt_count=1,
            error_message=f"HTTP provider error {response_code}",
        )
        res = RiskModelResult(
            status=call_status,
            probability=None,
            provider_payload_hash=body_payload_hash,
            adapter_id=_ADAPTER_ID,
            adapter_revision=_ADAPTER_REVISION,
            question_contract_hash=contract.contract_hash,
            provider_schema_version=wire.provider_schema_identity,
            api_version=wire.api_version_source,
            error_message=f"HTTP provider error {response_code}",
        )
        return res, obs

    if response_too_large:
        journal_data["journal_state"] = CanaryJournalState.OBSERVED_PROVIDER_FAILURE.value
        _write_journal_atomic(journal_path, journal_data)
        obs = LiveCanaryObservationV1(
            operation_id=operation_id,
            provider_request_id=provider_request_id,
            journal_state=CanaryJournalState.OBSERVED_PROVIDER_FAILURE,
            call_status=ProviderCallStatus.INVALID_RESPONSE,
            config_hash=cfg_hash,
            wire_contract_hash=wire_hash,
            question_contract_hash=contract.contract_hash,
            body_payload_hash=body_payload_hash,
            endpoint_host_hash=endpoint_host_hash,
            authorization_hash=authorization_hash,
            probability=None,
            observed_model=None,
            usage=None,
            attempt_count=1,
            error_message="Provider response exceeded bounded size limit",
        )
        res = RiskModelResult(
            status=ProviderCallStatus.INVALID_RESPONSE,
            probability=None,
            provider_payload_hash=body_payload_hash,
            adapter_id=_ADAPTER_ID,
            adapter_revision=_ADAPTER_REVISION,
            question_contract_hash=contract.contract_hash,
            provider_schema_version=wire.provider_schema_identity,
            api_version=wire.api_version_source,
            error_message="Provider response exceeded bounded size limit",
        )
        return res, obs

    # Parse 200 response JSON
    try:
        if raw_response_bytes is None:
            raise ValueError("Empty response body")
        resp_obj = json.loads(
            raw_response_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_response_pairs,
        )
        if not isinstance(resp_obj, dict):
            raise ValueError("Response must be a JSON object")
    except Exception as exc:
        journal_data["journal_state"] = CanaryJournalState.OBSERVED_PROVIDER_FAILURE.value
        _write_journal_atomic(journal_path, journal_data)
        obs = LiveCanaryObservationV1(
            operation_id=operation_id,
            provider_request_id=provider_request_id,
            journal_state=CanaryJournalState.OBSERVED_PROVIDER_FAILURE,
            call_status=ProviderCallStatus.INVALID_RESPONSE,
            config_hash=cfg_hash,
            wire_contract_hash=wire_hash,
            question_contract_hash=contract.contract_hash,
            body_payload_hash=body_payload_hash,
            endpoint_host_hash=endpoint_host_hash,
            authorization_hash=authorization_hash,
            probability=None,
            observed_model=None,
            usage=None,
            attempt_count=1,
            error_message=f"Invalid response JSON: {exc}",
        )
        res = RiskModelResult(
            status=ProviderCallStatus.INVALID_RESPONSE,
            probability=None,
            provider_payload_hash=body_payload_hash,
            adapter_id=_ADAPTER_ID,
            adapter_revision=_ADAPTER_REVISION,
            question_contract_hash=contract.contract_hash,
            provider_schema_version=wire.provider_schema_identity,
            api_version=wire.api_version_source,
            error_message="Invalid response JSON",
        )
        return res, obs

    # Validate response schema
    observed_model = resp_obj.get("model")
    if not isinstance(observed_model, str) or not observed_model.strip():
        journal_data["journal_state"] = CanaryJournalState.OBSERVED_PROVIDER_FAILURE.value
        _write_journal_atomic(journal_path, journal_data)
        obs = LiveCanaryObservationV1(
            operation_id=operation_id,
            provider_request_id=provider_request_id,
            journal_state=CanaryJournalState.OBSERVED_PROVIDER_FAILURE,
            call_status=ProviderCallStatus.INVALID_RESPONSE,
            config_hash=cfg_hash,
            wire_contract_hash=wire_hash,
            question_contract_hash=contract.contract_hash,
            body_payload_hash=body_payload_hash,
            endpoint_host_hash=endpoint_host_hash,
            authorization_hash=authorization_hash,
            probability=None,
            observed_model=None,
            usage=None,
            attempt_count=1,
            error_message="Missing or invalid model identifier in response",
        )
        res = RiskModelResult(
            status=ProviderCallStatus.INVALID_RESPONSE,
            probability=None,
            provider_payload_hash=body_payload_hash,
            adapter_id=_ADAPTER_ID,
            adapter_revision=_ADAPTER_REVISION,
            question_contract_hash=contract.contract_hash,
            provider_schema_version=wire.provider_schema_identity,
            api_version=wire.api_version_source,
            error_message="Missing response model identifier",
        )
        return res, obs

    answers = resp_obj.get("answers")
    if not isinstance(answers, dict) or _F4_PROVIDER_QUESTION_NAME not in answers:
        journal_data["journal_state"] = CanaryJournalState.OBSERVED_PROVIDER_FAILURE.value
        _write_journal_atomic(journal_path, journal_data)
        obs = LiveCanaryObservationV1(
            operation_id=operation_id,
            provider_request_id=provider_request_id,
            journal_state=CanaryJournalState.OBSERVED_PROVIDER_FAILURE,
            call_status=ProviderCallStatus.INVALID_RESPONSE,
            config_hash=cfg_hash,
            wire_contract_hash=wire_hash,
            question_contract_hash=contract.contract_hash,
            body_payload_hash=body_payload_hash,
            endpoint_host_hash=endpoint_host_hash,
            authorization_hash=authorization_hash,
            probability=None,
            observed_model=observed_model,
            usage=None,
            attempt_count=1,
            error_message=f"Missing answers.{_F4_PROVIDER_QUESTION_NAME} in response",
        )
        res = RiskModelResult(
            status=ProviderCallStatus.INVALID_RESPONSE,
            probability=None,
            provider_payload_hash=body_payload_hash,
            adapter_id=_ADAPTER_ID,
            adapter_revision=_ADAPTER_REVISION,
            question_contract_hash=contract.contract_hash,
            provider_schema_version=wire.provider_schema_identity,
            api_version=wire.api_version_source,
            service_model_version=observed_model,
            error_message=f"Missing answer for question {_F4_PROVIDER_QUESTION_NAME!r}",
        )
        return res, obs

    decision_answer = answers[_F4_PROVIDER_QUESTION_NAME]
    if not isinstance(decision_answer, dict):
        journal_data["journal_state"] = CanaryJournalState.OBSERVED_PROVIDER_FAILURE.value
        _write_journal_atomic(journal_path, journal_data)
        obs = LiveCanaryObservationV1(
            operation_id=operation_id,
            provider_request_id=provider_request_id,
            journal_state=CanaryJournalState.OBSERVED_PROVIDER_FAILURE,
            call_status=ProviderCallStatus.INVALID_RESPONSE,
            config_hash=cfg_hash,
            wire_contract_hash=wire_hash,
            question_contract_hash=contract.contract_hash,
            body_payload_hash=body_payload_hash,
            endpoint_host_hash=endpoint_host_hash,
            authorization_hash=authorization_hash,
            probability=None,
            observed_model=observed_model,
            usage=None,
            attempt_count=1,
            error_message="Answer must be an object",
        )
        res = RiskModelResult(
            status=ProviderCallStatus.INVALID_RESPONSE,
            probability=None,
            provider_payload_hash=body_payload_hash,
            adapter_id=_ADAPTER_ID,
            adapter_revision=_ADAPTER_REVISION,
            question_contract_hash=contract.contract_hash,
            provider_schema_version=wire.provider_schema_identity,
            api_version=wire.api_version_source,
            service_model_version=observed_model,
            error_message="Answer is not an object",
        )
        return res, obs

    ans_type = decision_answer.get("type")
    if ans_type != "noul":
        journal_data["journal_state"] = CanaryJournalState.OBSERVED_PROVIDER_FAILURE.value
        _write_journal_atomic(journal_path, journal_data)
        obs = LiveCanaryObservationV1(
            operation_id=operation_id,
            provider_request_id=provider_request_id,
            journal_state=CanaryJournalState.OBSERVED_PROVIDER_FAILURE,
            call_status=ProviderCallStatus.INVALID_RESPONSE,
            config_hash=cfg_hash,
            wire_contract_hash=wire_hash,
            question_contract_hash=contract.contract_hash,
            body_payload_hash=body_payload_hash,
            endpoint_host_hash=endpoint_host_hash,
            authorization_hash=authorization_hash,
            probability=None,
            observed_model=observed_model,
            usage=None,
            attempt_count=1,
            error_message=f"Expected answer type 'noul', got {ans_type!r}",
        )
        res = RiskModelResult(
            status=ProviderCallStatus.INVALID_RESPONSE,
            probability=None,
            provider_payload_hash=body_payload_hash,
            adapter_id=_ADAPTER_ID,
            adapter_revision=_ADAPTER_REVISION,
            question_contract_hash=contract.contract_hash,
            provider_schema_version=wire.provider_schema_identity,
            api_version=wire.api_version_source,
            service_model_version=observed_model,
            error_message="Invalid answer type",
        )
        return res, obs

    raw_prob = decision_answer.get("noul")
    if (
        raw_prob is None
        or isinstance(raw_prob, bool)
        or not isinstance(raw_prob, (int, float))
        or (isinstance(raw_prob, float) and not math.isfinite(raw_prob))
        or not (0.0 <= raw_prob <= 1.0)
    ):
        journal_data["journal_state"] = CanaryJournalState.OBSERVED_PROVIDER_FAILURE.value
        _write_journal_atomic(journal_path, journal_data)
        obs = LiveCanaryObservationV1(
            operation_id=operation_id,
            provider_request_id=provider_request_id,
            journal_state=CanaryJournalState.OBSERVED_PROVIDER_FAILURE,
            call_status=ProviderCallStatus.INVALID_RESPONSE,
            config_hash=cfg_hash,
            wire_contract_hash=wire_hash,
            question_contract_hash=contract.contract_hash,
            body_payload_hash=body_payload_hash,
            endpoint_host_hash=endpoint_host_hash,
            authorization_hash=authorization_hash,
            probability=None,
            observed_model=observed_model,
            usage=None,
            attempt_count=1,
            error_message=f"Invalid noul probability value: {raw_prob!r}",
        )
        res = RiskModelResult(
            status=ProviderCallStatus.INVALID_RESPONSE,
            probability=None,
            provider_payload_hash=body_payload_hash,
            adapter_id=_ADAPTER_ID,
            adapter_revision=_ADAPTER_REVISION,
            question_contract_hash=contract.contract_hash,
            provider_schema_version=wire.provider_schema_identity,
            api_version=wire.api_version_source,
            service_model_version=observed_model,
            error_message="Invalid noul probability value",
        )
        return res, obs

    prob_value = float(raw_prob)

    # Usage parsing (optional telemetry for private receipt)
    usage_dict: dict[str, int] | None = None
    raw_usage = resp_obj.get("usage")
    if isinstance(raw_usage, dict):
        inp = raw_usage.get("input_tokens")
        out = raw_usage.get("output_tokens")
        if (
            type(inp) is int
            and type(out) is int
            and inp >= 0
            and out >= 0
        ):
            usage_dict = {"input_tokens": inp, "output_tokens": out}

    # Mark OBSERVED_OK in journal
    journal_data["journal_state"] = CanaryJournalState.OBSERVED_OK.value
    _write_journal_atomic(journal_path, journal_data)

    obs = LiveCanaryObservationV1(
        operation_id=operation_id,
        provider_request_id=provider_request_id,
        journal_state=CanaryJournalState.OBSERVED_OK,
        call_status=ProviderCallStatus.OK,
        config_hash=cfg_hash,
        wire_contract_hash=wire_hash,
        question_contract_hash=contract.contract_hash,
        body_payload_hash=body_payload_hash,
        endpoint_host_hash=endpoint_host_hash,
        authorization_hash=authorization_hash,
        probability=prob_value,
        observed_model=observed_model,
        usage=usage_dict,
        attempt_count=1,
        error_message=None,
    )

    res = RiskModelResult(
        status=ProviderCallStatus.OK,
        probability=prob_value,
        provider_payload_hash=body_payload_hash,
        adapter_id=_ADAPTER_ID,
        adapter_revision=_ADAPTER_REVISION,
        question_contract_hash=contract.contract_hash,
        provider_schema_version=wire.provider_schema_identity,
        api_version=wire.api_version_source,
        service_model_version=observed_model,
        error_message=None,
    )

    return res, obs
