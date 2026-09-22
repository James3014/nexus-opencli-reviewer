from __future__ import annotations

import io
import json
import math
import os
import threading
from pathlib import Path
from typing import Any
import urllib.error
import urllib.request
import pytest

from reviewer.hosted_risk_canary import (
    CanaryJournalState,
    HostedNoRedirectHandler,
    LiveCanaryObservationV1,
    _build_secure_https_opener,
    execute_hosted_canary_call,
)
from reviewer.hosted_risk_config import HostedProviderConfigV1
from reviewer.hosted_wire_contract import (
    HostedAuthMode,
    HostedProviderWireDescriptorV1,
    LiveCanaryAuthorizationV1,
    load_wire_descriptor_from_dict,
)
from reviewer.risk_model_adapter import (
    F4QuestionContractV1,
    ProviderCallStatus,
    ProviderVisibleRiskStateV1,
)


def _valid_config() -> HostedProviderConfigV1:
    return HostedProviderConfigV1(
        endpoint_origin="https://provider.example.invalid",
        api_key_env_var_name="SYNTHETIC_API_KEY",
        max_canary_quota=1,
        allowed_hosts_whitelist=("provider.example.invalid",),
    )


def _valid_wire_descriptor() -> HostedProviderWireDescriptorV1:
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


def _valid_authorization(
    config: HostedProviderConfigV1 | None = None,
    wire: HostedProviderWireDescriptorV1 | None = None,
    contract: F4QuestionContractV1 | None = None,
    max_calls: int = 1,
) -> LiveCanaryAuthorizationV1:
    cfg = config or _valid_config()
    w = wire or _valid_wire_descriptor()
    c = contract or F4QuestionContractV1()
    return LiveCanaryAuthorizationV1(
        config_hash=cfg.canonical_config_hash(),
        wire_contract_hash=w.canonical_wire_hash(),
        endpoint_host="provider.example.invalid",
        question_contract_hash=c.contract_hash,
        max_calls=max_calls,
    )


def _valid_state() -> ProviderVisibleRiskStateV1:
    return ProviderVisibleRiskStateV1(
        action_type="TASK_RUN",
        mutation_domain="REPOSITORY",
        permission_profile="MUTATE_BOUNDED",
        is_mutation=True,
        allowed_path_extensions=(".py",),
        allowed_path_count=1,
    )


class FakeHTTPResponse:
    """Mock urllib HTTPResponse."""

    def __init__(self, status: int, body_bytes: bytes, headers: dict[str, str] | None = None):
        self.status = status
        self.code = status
        self.reason = "OK" if status == 200 else "Error"
        self._body_bytes = body_bytes
        self.headers = headers or {}

    def read(self, amt: int | None = None) -> bytes:
        if amt is None:
            return self._body_bytes
        return self._body_bytes[:amt]

    def __enter__(self) -> FakeHTTPResponse:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass


class FakeOpener:
    """Mock opener tracking calls and returning canned responses or raising errors."""

    def __init__(
        self,
        response_status: int = 200,
        response_body: bytes = b"",
        exception_to_raise: Exception | None = None,
    ):
        self.response_status = response_status
        self.response_body = response_body
        self.exception_to_raise = exception_to_raise
        self.open_call_count = 0
        self.captured_requests: list[urllib.request.Request] = []

    def open(self, req: urllib.request.Request, timeout: float = 5.0) -> FakeHTTPResponse:
        self.open_call_count += 1
        self.captured_requests.append(req)
        if self.exception_to_raise is not None:
            raise self.exception_to_raise
        if self.response_status != 200:
            fp = io.BytesIO(self.response_body)
            raise urllib.error.HTTPError(
                req.full_url,
                self.response_status,
                f"HTTP {self.response_status}",
                {},
                fp,
            )
        return FakeHTTPResponse(self.response_status, self.response_body)


# --- Tests ---


def test_successful_simulation_call(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SYNTHETIC_API_KEY", "synthetic-secret-value-xyz")

    success_body = {
        "model": "jev-latest-concrete-20260920",
        "answers": {
            "decision": {
                "type": "noul",
                "noul": 0.73,
            }
        },
        "usage": {
            "input_tokens": 100,
            "output_tokens": 10,
        },
    }
    fake_opener = FakeOpener(200, json.dumps(success_body).encode("utf-8"))
    monkeypatch.setattr(
        "reviewer.hosted_risk_canary._build_secure_https_opener",
        lambda: fake_opener,
    )

    config = _valid_config()
    wire = _valid_wire_descriptor()
    contract = F4QuestionContractV1()
    auth = _valid_authorization(config, wire, contract)
    state = _valid_state()

    res, obs = execute_hosted_canary_call(
        config,
        wire,
        auth,
        state,
        contract,
        operation_id="op-test-1",
        provider_request_id="req-test-1",
        journal_dir=tmp_path,
    )

    # Invariants
    assert fake_opener.open_call_count == 1
    assert res.status is ProviderCallStatus.OK
    assert res.probability == pytest.approx(0.73)
    assert res.service_model_version == "jev-latest-concrete-20260920"
    assert res.error_message is None

    # Observation
    assert obs.journal_state is CanaryJournalState.OBSERVED_OK
    assert obs.call_status is ProviderCallStatus.OK
    assert obs.probability == pytest.approx(0.73)
    assert obs.observed_model == "jev-latest-concrete-20260920"
    assert obs.usage == {"input_tokens": 100, "output_tokens": 10}
    assert obs.attempt_count == 1

    # Request Body Privacy Inspection
    captured_req = fake_opener.captured_requests[0]
    body = json.loads(captured_req.data.decode("utf-8"))
    assert set(body.keys()) == {"model", "questions", "state"}
    assert body["model"] == "jev-latest"
    assert set(body["questions"].keys()) == {"decision"}
    assert body["questions"]["decision"]["type"] == "noul"
    assert body["questions"]["decision"]["instructions"] == contract.question_statement
    assert set(body["state"].keys()) == {
        "action_type",
        "mutation_domain",
        "permission_profile",
        "is_mutation",
        "allowed_path_extensions",
        "allowed_path_count",
    }
    # No leaked fields
    assert "provider_request_id" not in body
    assert "operation_id" not in body
    assert "contract_hash" not in body

    # Header inspection
    assert captured_req.headers["Authorization"] == "Bearer synthetic-secret-value-xyz"
    assert captured_req.headers["Content-type"] == "application/json"
    assert captured_req.headers["Accept"] == "application/json"
    assert "X-provider-request-id" not in captured_req.headers

    # Journal on disk inspection
    journal_file = tmp_path / "op-test-1.json"
    assert journal_file.exists()
    j_data = json.loads(journal_file.read_bytes())
    assert j_data["journal_state"] == "OBSERVED_OK"
    assert j_data["attempt_count"] == 1
    # Ensure no secret in journal
    assert "synthetic-secret-value-xyz" not in journal_file.read_text()


def test_late_bound_secret_and_prevalidation_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Pre-validation failure must occur before reading os.environ."""
    secret_read = False

    def fake_getenv(key: str) -> str:
        nonlocal secret_read
        secret_read = True
        return "synthetic-key"

    monkeypatch.setattr("os.environ.get", fake_getenv)

    config = _valid_config()
    wire = _valid_wire_descriptor()
    contract = F4QuestionContractV1()
    state = _valid_state()

    # Create invalid auth with wrong config_hash
    bad_auth = LiveCanaryAuthorizationV1(
        config_hash="0" * 64,
        wire_contract_hash=wire.canonical_wire_hash(),
        endpoint_host="provider.example.invalid",
        question_contract_hash=contract.contract_hash,
        max_calls=1,
    )

    with pytest.raises(ValueError, match="Authorization config_hash mismatch"):
        execute_hosted_canary_call(
            config,
            wire,
            bad_auth,
            state,
            contract,
            operation_id="op-bad-auth",
            provider_request_id="req-bad-auth",
            journal_dir=tmp_path,
        )

    # Prove secret was NEVER read
    assert secret_read is False
    # Prove no journal created
    assert not (tmp_path / "op-bad-auth.json").exists()


def test_secret_missing_in_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("SYNTHETIC_API_KEY", raising=False)

    fake_opener = FakeOpener(200, b"{}")
    monkeypatch.setattr(
        "reviewer.hosted_risk_canary._build_secure_https_opener",
        lambda: fake_opener,
    )

    config = _valid_config()
    wire = _valid_wire_descriptor()
    contract = F4QuestionContractV1()
    auth = _valid_authorization(config, wire, contract)
    state = _valid_state()

    res, obs = execute_hosted_canary_call(
        config,
        wire,
        auth,
        state,
        contract,
        operation_id="op-no-secret",
        provider_request_id="req-no-secret",
        journal_dir=tmp_path,
    )

    assert fake_opener.open_call_count == 0
    assert res.status is ProviderCallStatus.CLIENT_ERROR
    assert res.probability is None
    assert obs.journal_state is CanaryJournalState.NOT_SENT
    assert obs.attempt_count == 0

    journal_file = tmp_path / "op-no-secret.json"
    assert journal_file.exists()
    j_data = json.loads(journal_file.read_bytes())
    assert j_data["journal_state"] == "NOT_SENT"
    assert j_data["attempt_count"] == 0


def test_authorization_max_calls_must_equal_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SYNTHETIC_API_KEY", "synthetic-key")

    config = HostedProviderConfigV1(
        endpoint_origin="https://provider.example.invalid",
        api_key_env_var_name="SYNTHETIC_API_KEY",
        max_canary_quota=5,
        allowed_hosts_whitelist=("provider.example.invalid",),
    )
    wire = _valid_wire_descriptor()
    contract = F4QuestionContractV1()
    state = _valid_state()

    # max_calls == 2 must be rejected by H2C single-call executor
    auth = _valid_authorization(config, wire, contract, max_calls=2)

    with pytest.raises(ValueError, match="requires max_calls == 1"):
        execute_hosted_canary_call(
            config,
            wire,
            auth,
            state,
            contract,
            operation_id="op-max-calls",
            provider_request_id="req-max-calls",
            journal_dir=tmp_path,
        )


@pytest.mark.parametrize(
    "status_code,expected_status",
    [
        (401, ProviderCallStatus.CLIENT_ERROR),
        (403, ProviderCallStatus.CLIENT_ERROR),
        (400, ProviderCallStatus.INVALID_RESPONSE),
        (422, ProviderCallStatus.INVALID_RESPONSE),
        (429, ProviderCallStatus.RATE_LIMIT),
        (500, ProviderCallStatus.NETWORK_UNAVAILABLE),
        (503, ProviderCallStatus.NETWORK_UNAVAILABLE),
    ],
)
def test_http_failure_status_codes(
    status_code: int,
    expected_status: ProviderCallStatus,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("SYNTHETIC_API_KEY", "synthetic-key")

    fake_opener = FakeOpener(
        response_status=status_code,
        response_body=b'{"detail": "provider error"}',
    )
    monkeypatch.setattr(
        "reviewer.hosted_risk_canary._build_secure_https_opener",
        lambda: fake_opener,
    )

    config = _valid_config()
    wire = _valid_wire_descriptor()
    contract = F4QuestionContractV1()
    auth = _valid_authorization(config, wire, contract)
    state = _valid_state()

    res, obs = execute_hosted_canary_call(
        config,
        wire,
        auth,
        state,
        contract,
        operation_id=f"op-http-{status_code}",
        provider_request_id=f"req-http-{status_code}",
        journal_dir=tmp_path,
    )

    assert fake_opener.open_call_count == 1
    assert res.status is expected_status
    assert res.probability is None
    assert obs.journal_state is CanaryJournalState.OBSERVED_PROVIDER_FAILURE
    assert obs.attempt_count == 1


def test_timeout_marks_journal_outcome_unknown(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SYNTHETIC_API_KEY", "synthetic-key")

    fake_opener = FakeOpener(
        exception_to_raise=TimeoutError("Connection timed out"),
    )
    monkeypatch.setattr(
        "reviewer.hosted_risk_canary._build_secure_https_opener",
        lambda: fake_opener,
    )

    config = _valid_config()
    wire = _valid_wire_descriptor()
    contract = F4QuestionContractV1()
    auth = _valid_authorization(config, wire, contract)
    state = _valid_state()

    res, obs = execute_hosted_canary_call(
        config,
        wire,
        auth,
        state,
        contract,
        operation_id="op-timeout",
        provider_request_id="req-timeout",
        journal_dir=tmp_path,
    )

    assert fake_opener.open_call_count == 1
    assert res.status is ProviderCallStatus.TIMEOUT
    assert res.probability is None
    assert obs.journal_state is CanaryJournalState.OUTCOME_UNKNOWN
    assert obs.attempt_count == 1

    journal_file = tmp_path / "op-timeout.json"
    j_data = json.loads(journal_file.read_bytes())
    assert j_data["journal_state"] == "OUTCOME_UNKNOWN"
    assert j_data["attempt_count"] == 1


def test_replay_protection_after_outcome_unknown(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Second invocation of same operation_id after OUTCOME_UNKNOWN must raise and send 0 calls."""
    monkeypatch.setenv("SYNTHETIC_API_KEY", "synthetic-key")

    fake_opener = FakeOpener(
        exception_to_raise=TimeoutError("timed out"),
    )
    monkeypatch.setattr(
        "reviewer.hosted_risk_canary._build_secure_https_opener",
        lambda: fake_opener,
    )

    config = _valid_config()
    wire = _valid_wire_descriptor()
    contract = F4QuestionContractV1()
    auth = _valid_authorization(config, wire, contract)
    state = _valid_state()

    # First call: times out
    execute_hosted_canary_call(
        config,
        wire,
        auth,
        state,
        contract,
        operation_id="op-replay",
        provider_request_id="req-replay-1",
        journal_dir=tmp_path,
    )
    assert fake_opener.open_call_count == 1

    # Second call with same operation_id: must block immediately with RECONCILIATION_REQUIRED
    with pytest.raises(RuntimeError, match="RECONCILIATION_REQUIRED"):
        execute_hosted_canary_call(
            config,
            wire,
            auth,
            state,
            contract,
            operation_id="op-replay",
            provider_request_id="req-replay-2",
            journal_dir=tmp_path,
        )

    # Prove zero new requests were sent
    assert fake_opener.open_call_count == 1


def test_replay_protection_after_observed_ok(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SYNTHETIC_API_KEY", "synthetic-key")

    success_body = {
        "model": "jev-latest",
        "answers": {"decision": {"type": "noul", "noul": 0.5}},
    }
    fake_opener = FakeOpener(200, json.dumps(success_body).encode("utf-8"))
    monkeypatch.setattr(
        "reviewer.hosted_risk_canary._build_secure_https_opener",
        lambda: fake_opener,
    )

    config = _valid_config()
    wire = _valid_wire_descriptor()
    contract = F4QuestionContractV1()
    auth = _valid_authorization(config, wire, contract)
    state = _valid_state()

    execute_hosted_canary_call(
        config,
        wire,
        auth,
        state,
        contract,
        operation_id="op-ok-replay",
        provider_request_id="req-ok-1",
        journal_dir=tmp_path,
    )
    assert fake_opener.open_call_count == 1

    with pytest.raises(RuntimeError, match="RECONCILIATION_REQUIRED"):
        execute_hosted_canary_call(
            config,
            wire,
            auth,
            state,
            contract,
            operation_id="op-ok-replay",
            provider_request_id="req-ok-2",
            journal_dir=tmp_path,
        )

    assert fake_opener.open_call_count == 1


@pytest.mark.parametrize(
    "corrupt_response",
    [
        b"not json at all",
        b"[]",
        json.dumps({"model": "m"}).encode("utf-8"),  # missing answers
        json.dumps({"model": "m", "answers": {}}).encode("utf-8"),  # missing decision
        json.dumps({"model": "m", "answers": {"decision": "not object"}}).encode("utf-8"),
        json.dumps({"model": "m", "answers": {"decision": {"type": "choice"}}}).encode("utf-8"),
        json.dumps({"model": "m", "answers": {"decision": {"type": "noul"}}}).encode("utf-8"),  # missing noul
        json.dumps({"model": "m", "answers": {"decision": {"type": "noul", "noul": "0.5"}}}).encode("utf-8"),  # string
        json.dumps({"model": "m", "answers": {"decision": {"type": "noul", "noul": True}}}).encode("utf-8"),  # bool
        json.dumps({"model": "m", "answers": {"decision": {"type": "noul", "noul": -0.1}}}).encode("utf-8"),  # < 0
        json.dumps({"model": "m", "answers": {"decision": {"type": "noul", "noul": 1.1}}}).encode("utf-8"),  # > 1
        json.dumps({"model": "", "answers": {"decision": {"type": "noul", "noul": 0.5}}}).encode("utf-8"),  # empty model
        json.dumps({"answers": {"decision": {"type": "noul", "noul": 0.5}}}).encode("utf-8"),  # missing model
    ],
)
def test_response_parser_failure_simulations(
    corrupt_response: bytes,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("SYNTHETIC_API_KEY", "synthetic-key")

    fake_opener = FakeOpener(200, corrupt_response)
    monkeypatch.setattr(
        "reviewer.hosted_risk_canary._build_secure_https_opener",
        lambda: fake_opener,
    )

    config = _valid_config()
    wire = _valid_wire_descriptor()
    contract = F4QuestionContractV1()
    auth = _valid_authorization(config, wire, contract)
    state = _valid_state()

    res, obs = execute_hosted_canary_call(
        config,
        wire,
        auth,
        state,
        contract,
        operation_id="op-corrupt",
        provider_request_id="req-corrupt",
        journal_dir=tmp_path,
    )

    assert fake_opener.open_call_count == 1
    assert res.status is ProviderCallStatus.INVALID_RESPONSE
    assert res.probability is None
    assert obs.journal_state is CanaryJournalState.OBSERVED_PROVIDER_FAILURE


def test_production_opener_structural_properties() -> None:
    """Verify that the production opener has no proxy and has fail-closed redirect handler."""
    opener = _build_secure_https_opener()

    has_empty_proxy = False
    has_no_redirect = False
    has_https_handler = False

    for handler in opener.handlers:
        if isinstance(handler, urllib.request.ProxyHandler):
            assert handler.proxies == {}
            has_empty_proxy = True
        elif isinstance(handler, HostedNoRedirectHandler):
            has_no_redirect = True
        elif isinstance(handler, urllib.request.HTTPSHandler):
            has_https_handler = True

    assert has_empty_proxy, "Opener must contain explicit empty ProxyHandler"
    assert has_no_redirect, "Opener must contain HostedNoRedirectHandler"
    assert has_https_handler, "Opener must contain HTTPSHandler"


def test_redirect_handler_blocks_redirects() -> None:
    handler = HostedNoRedirectHandler()
    req = urllib.request.Request("https://provider.example.invalid/v1/systemone")
    with pytest.raises(urllib.error.HTTPError, match="HTTP redirect to .* forbidden"):
        handler.redirect_request(req, None, 302, "Found", {}, "https://evil.com/leak")



def test_same_authorization_cannot_send_twice_with_different_operation_ids(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SYNTHETIC_API_KEY", "synthetic-key")
    body = b'{"model":"m","answers":{"decision":{"type":"noul","noul":0.25}}}'
    fake_opener = FakeOpener(200, body)
    monkeypatch.setattr(
        "reviewer.hosted_risk_canary._build_secure_https_opener",
        lambda: fake_opener,
    )

    config = _valid_config()
    wire = _valid_wire_descriptor()
    contract = F4QuestionContractV1()
    auth = _valid_authorization(config, wire, contract)
    state = _valid_state()

    execute_hosted_canary_call(
        config,
        wire,
        auth,
        state,
        contract,
        operation_id="op-auth-once-1",
        provider_request_id="req-auth-once-1",
        journal_dir=tmp_path,
    )
    assert fake_opener.open_call_count == 1

    with pytest.raises(RuntimeError, match="AUTHORIZATION_ALREADY_CONSUMED"):
        execute_hosted_canary_call(
            config,
            wire,
            auth,
            state,
            contract,
            operation_id="op-auth-once-2",
            provider_request_id="req-auth-once-2",
            journal_dir=tmp_path,
        )

    assert fake_opener.open_call_count == 1
    second_journal = json.loads((tmp_path / "op-auth-once-2.json").read_bytes())
    assert second_journal["journal_state"] == "NOT_SENT"
    assert second_journal["attempt_count"] == 0


def test_concurrent_same_operation_has_single_winner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SYNTHETIC_API_KEY", "synthetic-key")
    body = b'{"model":"m","answers":{"decision":{"type":"noul","noul":0.25}}}'
    fake_opener = FakeOpener(200, body)
    monkeypatch.setattr(
        "reviewer.hosted_risk_canary._build_secure_https_opener",
        lambda: fake_opener,
    )

    config = _valid_config()
    wire = _valid_wire_descriptor()
    contract = F4QuestionContractV1()
    auth = _valid_authorization(config, wire, contract)
    state = _valid_state()
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def invoke(request_id: str) -> None:
        barrier.wait()
        try:
            execute_hosted_canary_call(
                config,
                wire,
                auth,
                state,
                contract,
                operation_id="op-concurrent",
                provider_request_id=request_id,
                journal_dir=tmp_path,
            )
            outcomes.append("sent")
        except RuntimeError as exc:
            outcomes.append(str(exc))

    t1 = threading.Thread(target=invoke, args=("req-concurrent-1",))
    t2 = threading.Thread(target=invoke, args=("req-concurrent-2",))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert outcomes.count("sent") == 1
    assert sum("RECONCILIATION_REQUIRED" in item for item in outcomes) == 1
    assert fake_opener.open_call_count == 1


def test_duplicate_provider_response_keys_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SYNTHETIC_API_KEY", "synthetic-key")
    body = b'{"model":"m","answers":{"decision":{"type":"noul","noul":0.2,"noul":0.9}}}'
    fake_opener = FakeOpener(200, body)
    monkeypatch.setattr(
        "reviewer.hosted_risk_canary._build_secure_https_opener",
        lambda: fake_opener,
    )

    config = _valid_config()
    wire = _valid_wire_descriptor()
    contract = F4QuestionContractV1()
    auth = _valid_authorization(config, wire, contract)

    result, observation = execute_hosted_canary_call(
        config,
        wire,
        auth,
        _valid_state(),
        contract,
        operation_id="op-duplicate-json",
        provider_request_id="req-duplicate-json",
        journal_dir=tmp_path,
    )

    assert result.status is ProviderCallStatus.INVALID_RESPONSE
    assert result.probability is None
    assert observation.journal_state is CanaryJournalState.OBSERVED_PROVIDER_FAILURE


def test_huge_integer_probability_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SYNTHETIC_API_KEY", "synthetic-key")
    body = json.dumps(
        {
            "model": "m",
            "answers": {"decision": {"type": "noul", "noul": 10**400}},
        }
    ).encode("utf-8")
    fake_opener = FakeOpener(200, body)
    monkeypatch.setattr(
        "reviewer.hosted_risk_canary._build_secure_https_opener",
        lambda: fake_opener,
    )

    config = _valid_config()
    wire = _valid_wire_descriptor()
    contract = F4QuestionContractV1()
    auth = _valid_authorization(config, wire, contract)

    result, observation = execute_hosted_canary_call(
        config,
        wire,
        auth,
        _valid_state(),
        contract,
        operation_id="op-huge-prob",
        provider_request_id="req-huge-prob",
        journal_dir=tmp_path,
    )

    assert result.status is ProviderCallStatus.INVALID_RESPONSE
    assert result.probability is None
    assert observation.journal_state is CanaryJournalState.OBSERVED_PROVIDER_FAILURE


def test_oversized_provider_response_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SYNTHETIC_API_KEY", "synthetic-key")
    fake_opener = FakeOpener(200, b"x" * (1_048_576 + 2))
    monkeypatch.setattr(
        "reviewer.hosted_risk_canary._build_secure_https_opener",
        lambda: fake_opener,
    )

    config = _valid_config()
    wire = _valid_wire_descriptor()
    contract = F4QuestionContractV1()
    auth = _valid_authorization(config, wire, contract)

    result, observation = execute_hosted_canary_call(
        config,
        wire,
        auth,
        _valid_state(),
        contract,
        operation_id="op-large-response",
        provider_request_id="req-large-response",
        journal_dir=tmp_path,
    )

    assert result.status is ProviderCallStatus.INVALID_RESPONSE
    assert result.probability is None
    assert observation.journal_state is CanaryJournalState.OBSERVED_PROVIDER_FAILURE


@pytest.mark.parametrize(
    ("field_name", "bad_value", "message"),
    [
        ("auth_header_name", "X-Authorization", "auth_header_name='Authorization'"),
        ("content_type", "text/plain", "content_type='application/json'"),
    ],
)
def test_executor_rejects_wire_transport_drift(
    field_name: str,
    bad_value: str,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("SYNTHETIC_API_KEY", "synthetic-key")
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
    data[field_name] = bad_value
    wire = load_wire_descriptor_from_dict(data)
    config = _valid_config()
    contract = F4QuestionContractV1()
    auth = _valid_authorization(config, wire, contract)

    with pytest.raises(ValueError, match=message):
        execute_hosted_canary_call(
            config,
            wire,
            auth,
            _valid_state(),
            contract,
            operation_id="op-wire-drift",
            provider_request_id="req-wire-drift",
            journal_dir=tmp_path,
        )


# --- Negative Mutation Controls ---


def test_negative_control_automatic_retry_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Mutate: if automatic retry was attempted, fake_opener.open_call_count > 1."""
    monkeypatch.setenv("SYNTHETIC_API_KEY", "synthetic-key")

    fake_opener = FakeOpener(500, b"Internal Server Error")
    monkeypatch.setattr(
        "reviewer.hosted_risk_canary._build_secure_https_opener",
        lambda: fake_opener,
    )

    config = _valid_config()
    wire = _valid_wire_descriptor()
    contract = F4QuestionContractV1()
    auth = _valid_authorization(config, wire, contract)
    state = _valid_state()

    res, obs = execute_hosted_canary_call(
        config,
        wire,
        auth,
        state,
        contract,
        operation_id="op-no-retry",
        provider_request_id="req-no-retry",
        journal_dir=tmp_path,
    )

    # Invariant: open_call_count MUST be exactly 1, not 2
    assert fake_opener.open_call_count == 1


def test_negative_control_provider_request_id_not_in_body(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SYNTHETIC_API_KEY", "synthetic-key")

    fake_opener = FakeOpener(
        200,
        b'{"model":"m","answers":{"decision":{"type":"noul","noul":0.1}}}',
    )
    monkeypatch.setattr(
        "reviewer.hosted_risk_canary._build_secure_https_opener",
        lambda: fake_opener,
    )

    config = _valid_config()
    wire = _valid_wire_descriptor()
    contract = F4QuestionContractV1()
    auth = _valid_authorization(config, wire, contract)
    state = _valid_state()

    execute_hosted_canary_call(
        config,
        wire,
        auth,
        state,
        contract,
        operation_id="op-privacy",
        provider_request_id="req-privacy-id-must-not-leak",
        journal_dir=tmp_path,
    )

    req_data = fake_opener.captured_requests[0].data.decode("utf-8")
    assert "req-privacy-id-must-not-leak" not in req_data
    assert "op-privacy" not in req_data


def test_negative_control_timeout_journal_marked_safe_to_retry_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Mutate: journal after timeout must NOT be safe to retry (must be OUTCOME_UNKNOWN, requiring reconciliation)."""
    monkeypatch.setenv("SYNTHETIC_API_KEY", "synthetic-key")

    fake_opener = FakeOpener(
        exception_to_raise=TimeoutError("timed out"),
    )
    monkeypatch.setattr(
        "reviewer.hosted_risk_canary._build_secure_https_opener",
        lambda: fake_opener,
    )

    config = _valid_config()
    wire = _valid_wire_descriptor()
    contract = F4QuestionContractV1()
    auth = _valid_authorization(config, wire, contract)
    state = _valid_state()

    execute_hosted_canary_call(
        config,
        wire,
        auth,
        state,
        contract,
        operation_id="op-mut-timeout",
        provider_request_id="req-mut-timeout",
        journal_dir=tmp_path,
    )

    # Inspect journal
    j_data = json.loads((tmp_path / "op-mut-timeout.json").read_bytes())
    assert j_data["journal_state"] == "OUTCOME_UNKNOWN"
    assert j_data["journal_state"] != "PREPARED"
    assert j_data["journal_state"] != "NOT_SENT"
    assert j_data["attempt_count"] == 1


def test_negative_control_environment_proxy_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutate: if environment proxy is set, production opener must still have empty proxies."""
    monkeypatch.setenv("http_proxy", "http://evil-proxy.example.invalid:8080")
    monkeypatch.setenv("HTTP_PROXY", "http://evil-proxy.example.invalid:8080")
    monkeypatch.setenv("https_proxy", "http://evil-proxy.example.invalid:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://evil-proxy.example.invalid:8080")

    opener = _build_secure_https_opener()
    for handler in opener.handlers:
        if isinstance(handler, urllib.request.ProxyHandler):
            assert handler.proxies == {}, f"ProxyHandler must be empty even with env vars, got {handler.proxies}"


def test_negative_control_redirect_follow_disabled() -> None:
    """Mutate: redirect handler must fail closed on 301, 302, 303, 307, 308."""
    handler = HostedNoRedirectHandler()
    req = urllib.request.Request("https://provider.example.invalid/v1/systemone")
    for code in (301, 302, 303, 307, 308):
        with pytest.raises(urllib.error.HTTPError, match="forbidden by security policy"):
            handler.redirect_request(req, None, code, "Redirect", {}, "https://provider.example.invalid/v1/other")


def test_negative_control_historical_choice_payload_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Mutate: if wire descriptor specifies Choice request_template_kind, execution must fail."""
    monkeypatch.setenv("SYNTHETIC_API_KEY", "synthetic-key")

    wire_data = {
        "contract_schema_version": "f4-hosted-wire-v1",
        "http_method": "POST",
        "request_path": "/v1/systemone",
        "auth_mode": "BEARER",
        "auth_header_name": "Authorization",
        "content_type": "application/json",
        "expected_model_identifier": "jev-latest",
        "request_template_kind": "systemone_choice",
        "response_probability_path": "answers.decision.probabilities.ESCALATE",
        "api_version_source": "HEADER_OR_PAYLOAD",
        "provider_schema_identity": "typesafe-systemone-v1",
    }
    choice_wire = load_wire_descriptor_from_dict(wire_data)
    config = _valid_config()
    contract = F4QuestionContractV1()
    auth = _valid_authorization(config, choice_wire, contract)
    state = _valid_state()

    with pytest.raises(ValueError, match="requires request_template_kind='systemone_noul'"):
        execute_hosted_canary_call(
            config,
            choice_wire,
            auth,
            state,
            contract,
            operation_id="op-choice-mut",
            provider_request_id="req-choice-mut",
            journal_dir=tmp_path,
        )


def test_negative_control_real_secret_not_in_receipt_or_journal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Mutate: real secret must never appear in LiveCanaryObservationV1, RiskModelResult, or journal."""
    secret = "SUPER_SECRET_VALUE_999888777"
    monkeypatch.setenv("SYNTHETIC_API_KEY", secret)

    fake_opener = FakeOpener(
        200,
        b'{"model":"jev-latest","answers":{"decision":{"type":"noul","noul":0.42}}}',
    )
    monkeypatch.setattr(
        "reviewer.hosted_risk_canary._build_secure_https_opener",
        lambda: fake_opener,
    )

    config = _valid_config()
    wire = _valid_wire_descriptor()
    contract = F4QuestionContractV1()
    auth = _valid_authorization(config, wire, contract)
    state = _valid_state()

    res, obs = execute_hosted_canary_call(
        config,
        wire,
        auth,
        state,
        contract,
        operation_id="op-secret-check",
        provider_request_id="req-secret-check",
        journal_dir=tmp_path,
    )

    # Check repr and str of result and observation
    assert secret not in repr(res)
    assert secret not in str(res)
    assert secret not in repr(obs)
    assert secret not in str(obs)

    # Check journal text
    journal_text = (tmp_path / "op-secret-check.json").read_text()
    assert secret not in journal_text


def test_negative_control_authorization_max_calls_gt_1_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Mutate: authorization with max_calls > 1 must be rejected by H2C executor."""
    monkeypatch.setenv("SYNTHETIC_API_KEY", "synthetic-key")

    config = _valid_config()
    wire = _valid_wire_descriptor()
    contract = F4QuestionContractV1()
    state = _valid_state()

    for invalid_calls in (2, 5, 10):
        auth = _valid_authorization(config, wire, contract, max_calls=invalid_calls)
        with pytest.raises(ValueError, match="requires max_calls == 1"):
            execute_hosted_canary_call(
                config,
                wire,
                auth,
                state,
                contract,
                operation_id=f"op-max-{invalid_calls}",
                provider_request_id=f"req-max-{invalid_calls}",
                journal_dir=tmp_path,
            )
