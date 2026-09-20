"""Provider-neutral H1 localhost HTTP transport adapter.

This module provides an HttpRiskModelAdapter that talks ONLY to a verified
localhost loopback endpoint (127.0.0.1 or ::1 or localhost). It owns no
family operating policy, implements zero automatic retries, reads zero API
keys or environment credentials, strictly rejects non-loopback hosts, and
blocks external HTTP redirects.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
from typing import Sequence
import urllib.error
from urllib.parse import urlparse
import urllib.request

from reviewer.risk_model_adapter import (
    F4QuestionContractV1,
    ProviderCallStatus,
    ProviderVisibleRiskStateV1,
    RiskModelResult,
    canonical_provider_payload_hash,
)

_MAX_SYMBOL_LENGTH = 128


def _require_symbol(name: str, value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_SYMBOL_LENGTH:
        raise ValueError(f"{name} must be a non-empty bounded string")
    if any(char in value for char in ("\n", "\r", "\t")):
        raise ValueError(f"{name} must not contain control whitespace")
    return value


def is_loopback_host(hostname: str | None) -> bool:
    """Validate that the given hostname is strictly a local loopback address."""
    if not hostname:
        return False
    cleaned = hostname.strip().strip("[]").lower()
    if cleaned == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(cleaned)
        return ip.is_loopback
    except ValueError:
        return False


def validate_loopback_endpoint(endpoint: str) -> tuple[str, str, int]:
    """Validate and parse a loopback HTTP endpoint.

    Fails closed if the scheme is not http/https or the host is not loopback.
    Returns (scheme, host, port).
    """
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise ValueError("endpoint must be a non-empty string")

    parsed = urlparse(endpoint.strip())
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported endpoint scheme: {parsed.scheme}")

    hostname = parsed.hostname
    if not hostname or not is_loopback_host(hostname):
        raise ValueError(
            f"Endpoint host {hostname!r} is not an authorized loopback address"
        )

    # Disallow userinfo (username:password@...)
    if parsed.username or parsed.password:
        raise ValueError("Endpoint must not contain userinfo/credentials")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.scheme, hostname, port


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
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
            newurl, code, f"HTTP redirect to {newurl} forbidden by security policy", headers, fp  # type: ignore[arg-type]
        )


class HttpRiskModelAdapter:
    """Localhost HTTP transport adapter for H1 fake-server and local integration."""

    adapter_id = "http-risk-model-adapter"
    adapter_revision = "h1-v1"
    provider_schema_version = "http-v1"

    def __init__(
        self,
        endpoint: str,
        *,
        timeout_seconds: float = 2.0,
    ) -> None:
        validate_loopback_endpoint(endpoint)
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be a positive number")

        self.endpoint = endpoint.strip()
        self.timeout_seconds = float(timeout_seconds)

        # Pre-build an opener that ignores environment proxies and forbids external redirects
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirectHandler,
        )

    def evaluate(
        self,
        state: ProviderVisibleRiskStateV1,
        contract: F4QuestionContractV1,
        provider_request_id: str,
    ) -> RiskModelResult:
        _require_symbol("provider_request_id", provider_request_id)
        payload_hash = canonical_provider_payload_hash(state, contract)

        # Verify endpoint host still loopback at evaluate time (anti-tamper)
        validate_loopback_endpoint(self.endpoint)

        body = {
            "provider_request_id": provider_request_id,
            "state": state.as_payload(),
            "question_contract": {
                "contract_version": contract.contract_version,
                "primitive": contract.primitive,
                "question_statement": contract.question_statement,
                "input_schema_hash": contract.input_schema_hash,
                "contract_hash": contract.contract_hash,
            },
        }

        encoded_body = json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Provider-Request-Id": provider_request_id,
        }

        req = urllib.request.Request(
            url=self.endpoint,
            data=encoded_body,
            headers=headers,
            method="POST",
        )

        try:
            with self._opener.open(req, timeout=self.timeout_seconds) as resp:
                raw_bytes = resp.read()
                response_code = resp.status
        except urllib.error.HTTPError as exc:
            return self._map_http_error(exc, payload_hash, contract)
        except urllib.error.URLError as exc:
            return self._map_url_error(exc, payload_hash, contract)
        except TimeoutError:
            return RiskModelResult(
                status=ProviderCallStatus.TIMEOUT,
                probability=None,
                provider_payload_hash=payload_hash,
                adapter_id=self.adapter_id,
                adapter_revision=self.adapter_revision,
                question_contract_hash=contract.contract_hash,
                provider_schema_version=self.provider_schema_version,
                error_message="Transport timed out waiting for response",
            )
        except (http.client.IncompleteRead, http.client.RemoteDisconnected) as exc:
            return RiskModelResult(
                status=ProviderCallStatus.INVALID_RESPONSE,
                probability=None,
                provider_payload_hash=payload_hash,
                adapter_id=self.adapter_id,
                adapter_revision=self.adapter_revision,
                question_contract_hash=contract.contract_hash,
                provider_schema_version=self.provider_schema_version,
                error_message=f"Connection closed or truncated: {exc}",
            )
        except (ConnectionResetError, ConnectionError, BrokenPipeError) as exc:
            return RiskModelResult(
                status=ProviderCallStatus.NETWORK_UNAVAILABLE,
                probability=None,
                provider_payload_hash=payload_hash,
                adapter_id=self.adapter_id,
                adapter_revision=self.adapter_revision,
                question_contract_hash=contract.contract_hash,
                provider_schema_version=self.provider_schema_version,
                error_message=f"Connection reset by peer: {exc}",
            )
        except Exception as exc:
            return RiskModelResult(
                status=ProviderCallStatus.CLIENT_ERROR,
                probability=None,
                provider_payload_hash=payload_hash,
                adapter_id=self.adapter_id,
                adapter_revision=self.adapter_revision,
                question_contract_hash=contract.contract_hash,
                provider_schema_version=self.provider_schema_version,
                error_message=f"Unexpected transport error: {exc}",
            )

        # Parse and decode response JSON
        return self._decode_response(
            raw_bytes,
            response_code,
            payload_hash,
            contract,
        )

    def _map_http_error(
        self,
        exc: urllib.error.HTTPError,
        payload_hash: str,
        contract: F4QuestionContractV1,
    ) -> RiskModelResult:
        code = exc.code
        if code == 429:
            status = ProviderCallStatus.RATE_LIMIT
        elif code in (400, 422):
            status = ProviderCallStatus.INVALID_RESPONSE
        elif code in (401, 403):
            status = ProviderCallStatus.CLIENT_ERROR
        elif code in (500, 502, 503, 504):
            status = ProviderCallStatus.NETWORK_UNAVAILABLE
        else:
            status = ProviderCallStatus.CLIENT_ERROR

        return RiskModelResult(
            status=status,
            probability=None,
            provider_payload_hash=payload_hash,
            adapter_id=self.adapter_id,
            adapter_revision=self.adapter_revision,
            question_contract_hash=contract.contract_hash,
            provider_schema_version=self.provider_schema_version,
            error_message=f"HTTP {code}: {exc.reason}",
        )

    def _map_url_error(
        self,
        exc: urllib.error.URLError,
        payload_hash: str,
        contract: F4QuestionContractV1,
    ) -> RiskModelResult:
        reason = exc.reason
        if isinstance(reason, TimeoutError) or "timed out" in str(reason).lower():
            status = ProviderCallStatus.TIMEOUT
            msg = f"Transport timeout: {reason}"
        else:
            status = ProviderCallStatus.NETWORK_UNAVAILABLE
            msg = f"Transport network unavailable: {reason}"

        return RiskModelResult(
            status=status,
            probability=None,
            provider_payload_hash=payload_hash,
            adapter_id=self.adapter_id,
            adapter_revision=self.adapter_revision,
            question_contract_hash=contract.contract_hash,
            provider_schema_version=self.provider_schema_version,
            error_message=msg,
        )

    def _decode_response(
        self,
        raw_bytes: bytes,
        response_code: int,
        payload_hash: str,
        contract: F4QuestionContractV1,
    ) -> RiskModelResult:
        try:
            text = raw_bytes.decode("utf-8")
            data = json.loads(text)
        except Exception as exc:
            return RiskModelResult(
                status=ProviderCallStatus.INVALID_RESPONSE,
                probability=None,
                provider_payload_hash=payload_hash,
                adapter_id=self.adapter_id,
                adapter_revision=self.adapter_revision,
                question_contract_hash=contract.contract_hash,
                provider_schema_version=self.provider_schema_version,
                error_message=f"Failed to decode response JSON: {exc}",
            )

        if not isinstance(data, dict):
            return RiskModelResult(
                status=ProviderCallStatus.INVALID_RESPONSE,
                probability=None,
                provider_payload_hash=payload_hash,
                adapter_id=self.adapter_id,
                adapter_revision=self.adapter_revision,
                question_contract_hash=contract.contract_hash,
                provider_schema_version=self.provider_schema_version,
                error_message="Response payload is not a JSON object",
            )

        if "probability" not in data:
            return RiskModelResult(
                status=ProviderCallStatus.INVALID_RESPONSE,
                probability=None,
                provider_payload_hash=payload_hash,
                adapter_id=self.adapter_id,
                adapter_revision=self.adapter_revision,
                question_contract_hash=contract.contract_hash,
                provider_schema_version=self.provider_schema_version,
                error_message="Missing 'probability' field in response",
            )

        raw_prob = data["probability"]
        if (
            isinstance(raw_prob, bool)
            or not isinstance(raw_prob, (int, float))
            or not 0.0 <= float(raw_prob) <= 1.0
        ):
            return RiskModelResult(
                status=ProviderCallStatus.INVALID_RESPONSE,
                probability=None,
                provider_payload_hash=payload_hash,
                adapter_id=self.adapter_id,
                adapter_revision=self.adapter_revision,
                question_contract_hash=contract.contract_hash,
                provider_schema_version=self.provider_schema_version,
                error_message=f"Invalid probability value in response: {raw_prob!r}",
            )

        return RiskModelResult(
            status=ProviderCallStatus.OK,
            probability=float(raw_prob),
            provider_payload_hash=payload_hash,
            adapter_id=self.adapter_id,
            adapter_revision=self.adapter_revision,
            question_contract_hash=contract.contract_hash,
            provider_schema_version=self.provider_schema_version,
        )
