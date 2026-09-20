from __future__ import annotations

import json
import urllib.request
import pytest

from reviewer.http_risk_model_adapter import (
    HttpRiskModelAdapter,
    is_loopback_host,
    validate_loopback_endpoint,
)
from reviewer.risk_model_adapter import (
    F4QuestionContractV1,
    ProviderCallStatus,
    ProviderVisibleRiskStateV1,
)
from reviewer.risk_policy import (
    FamilyCalibrationPolicy,
    FamilyPolicyOutcome,
    apply_family_policy,
)
from tests.fake_risk_server import LocalRiskModelFakeServer


def _state() -> ProviderVisibleRiskStateV1:
    return ProviderVisibleRiskStateV1(
        action_type="TASK_RUN",
        mutation_domain="REPOSITORY",
        permission_profile="MUTATE_BOUNDED",
        is_mutation=True,
        allowed_path_extensions=(".py", ".json"),
        allowed_path_count=2,
    )


@pytest.mark.parametrize("prob", [0.0, 0.49, 0.5, 0.51, 1.0])
def test_http_adapter_success_raw_probability(prob: float) -> None:
    body = json.dumps({"probability": prob}).encode("utf-8")
    with LocalRiskModelFakeServer(response_body=body) as server:
        adapter = HttpRiskModelAdapter(server.endpoint)
        res = adapter.evaluate(_state(), F4QuestionContractV1(), f"req-prob-{prob}")

        assert res.status is ProviderCallStatus.OK
        assert res.probability == pytest.approx(prob)
        assert not hasattr(res, "decision")
        assert not hasattr(res, "outcome")
        assert not hasattr(res, "threshold")


def test_http_adapter_connection_unavailable() -> None:
    # Use a loopback port where no server is listening
    adapter = HttpRiskModelAdapter("http://127.0.0.1:65432", timeout_seconds=1.0)
    res = adapter.evaluate(_state(), F4QuestionContractV1(), "req-no-server")

    assert res.status is ProviderCallStatus.NETWORK_UNAVAILABLE
    assert res.probability is None
    assert res.error_message is not None


def test_http_adapter_timeout() -> None:
    # Fake server delays longer than client timeout
    with LocalRiskModelFakeServer(delay_seconds=1.0) as server:
        adapter = HttpRiskModelAdapter(server.endpoint, timeout_seconds=0.2)
        res = adapter.evaluate(_state(), F4QuestionContractV1(), "req-timeout")

        assert res.status is ProviderCallStatus.TIMEOUT
        assert res.probability is None
        assert res.error_message is not None


def test_http_adapter_invalid_json() -> None:
    with LocalRiskModelFakeServer(response_body=b"not a valid json payload") as server:
        adapter = HttpRiskModelAdapter(server.endpoint)
        res = adapter.evaluate(_state(), F4QuestionContractV1(), "req-invalid-json")

        assert res.status is ProviderCallStatus.INVALID_RESPONSE
        assert res.probability is None


def test_http_adapter_missing_probability() -> None:
    with LocalRiskModelFakeServer(response_body=b'{"other_key": 123}') as server:
        adapter = HttpRiskModelAdapter(server.endpoint)
        res = adapter.evaluate(_state(), F4QuestionContractV1(), "req-missing-prob")

        assert res.status is ProviderCallStatus.INVALID_RESPONSE
        assert res.probability is None


def test_http_adapter_wrong_probability_type() -> None:
    with LocalRiskModelFakeServer(response_body=b'{"probability": "high"}') as server:
        adapter = HttpRiskModelAdapter(server.endpoint)
        res = adapter.evaluate(_state(), F4QuestionContractV1(), "req-wrong-type")

        assert res.status is ProviderCallStatus.INVALID_RESPONSE
        assert res.probability is None


@pytest.mark.parametrize("bad_prob", [-0.2, 1.4, True, False])
def test_http_adapter_out_of_range_probability(bad_prob: object) -> None:
    body = json.dumps({"probability": bad_prob}).encode("utf-8")
    with LocalRiskModelFakeServer(response_body=body) as server:
        adapter = HttpRiskModelAdapter(server.endpoint)
        res = adapter.evaluate(_state(), F4QuestionContractV1(), "req-bad-range")

        assert res.status is ProviderCallStatus.INVALID_RESPONSE
        assert res.probability is None


def test_http_adapter_huge_integer_probability_fails_closed() -> None:
    body = json.dumps({"probability": 10**400}).encode("utf-8")
    with LocalRiskModelFakeServer(response_body=body) as server:
        adapter = HttpRiskModelAdapter(server.endpoint)
        res = adapter.evaluate(
            _state(),
            F4QuestionContractV1(),
            "req-huge-probability",
        )

        assert res.status is ProviderCallStatus.INVALID_RESPONSE
        assert res.probability is None


def test_http_adapter_rate_limit_429() -> None:
    with LocalRiskModelFakeServer(response_code=429, response_body=b'{"error": "rate limited"}') as server:
        adapter = HttpRiskModelAdapter(server.endpoint)
        res = adapter.evaluate(_state(), F4QuestionContractV1(), "req-429")

        assert res.status is ProviderCallStatus.RATE_LIMIT
        assert res.probability is None


def test_http_adapter_http_400() -> None:
    with LocalRiskModelFakeServer(response_code=400, response_body=b'{"error": "bad request"}') as server:
        adapter = HttpRiskModelAdapter(server.endpoint)
        res = adapter.evaluate(_state(), F4QuestionContractV1(), "req-400")

        assert res.status is ProviderCallStatus.INVALID_RESPONSE
        assert res.probability is None


def test_http_adapter_http_500() -> None:
    with LocalRiskModelFakeServer(response_code=500, response_body=b'{"error": "internal error"}') as server:
        adapter = HttpRiskModelAdapter(server.endpoint)
        res = adapter.evaluate(_state(), F4QuestionContractV1(), "req-500")

        assert res.status is ProviderCallStatus.NETWORK_UNAVAILABLE
        assert res.probability is None


def test_http_adapter_truncated_connection() -> None:
    with LocalRiskModelFakeServer(truncate_connection=True) as server:
        adapter = HttpRiskModelAdapter(server.endpoint)
        res = adapter.evaluate(_state(), F4QuestionContractV1(), "req-truncate")

        assert res.status in (ProviderCallStatus.INVALID_RESPONSE, ProviderCallStatus.NETWORK_UNAVAILABLE)
        assert res.probability is None


@pytest.mark.parametrize(
    "invalid_endpoint",
    [
        "https://example.com",
        "http://8.8.8.8",
        "http://192.168.1.10",
        "http://10.0.0.1",
        "http://localhost.evil.com",
        "http://127.0.0.1.evil.com",
        "ftp://127.0.0.1",
        "http://user:pass@127.0.0.1:8080",
    ],
)
def test_http_adapter_rejects_non_loopback_endpoints(invalid_endpoint: str) -> None:
    with pytest.raises(ValueError):
        validate_loopback_endpoint(invalid_endpoint)

    with pytest.raises(ValueError):
        HttpRiskModelAdapter(invalid_endpoint)


def test_http_adapter_redirect_escape_blocked() -> None:
    def redirect_handler(handler: object) -> None:
        handler.send_response(302)  # type: ignore[attr-defined]
        handler.send_header("Location", "https://example.com/steal")  # type: ignore[attr-defined]
        handler.end_headers()  # type: ignore[attr-defined]

    with LocalRiskModelFakeServer(custom_handler=redirect_handler) as server:
        adapter = HttpRiskModelAdapter(server.endpoint)
        res = adapter.evaluate(_state(), F4QuestionContractV1(), "req-redirect")

        assert res.status is not ProviderCallStatus.OK
        assert res.probability is None


def test_failure_through_family_policy_never_same_or_escalate() -> None:
    policy = FamilyCalibrationPolicy(
        family_id="completion_reflex",
        calibration_id="synth-calib-1",
        escalation_threshold=0.50,
    )

    with LocalRiskModelFakeServer(response_code=429) as server:
        adapter = HttpRiskModelAdapter(server.endpoint)
        raw = adapter.evaluate(_state(), F4QuestionContractV1(), "req-policy-fail")

        assert raw.status is ProviderCallStatus.RATE_LIMIT
        assert raw.probability is None

        pol_res = apply_family_policy(raw, policy)
        assert pol_res.outcome is FamilyPolicyOutcome.PROVIDER_UNAVAILABLE
        assert pol_res.outcome is not FamilyPolicyOutcome.SAME
        assert pol_res.outcome is not FamilyPolicyOutcome.ESCALATE
        assert pol_res.probability is None


def test_opener_contains_no_environment_proxy_handler() -> None:
    adapter = HttpRiskModelAdapter("http://127.0.0.1:8080")
    for handler in adapter._opener.handlers:
        if isinstance(handler, urllib.request.ProxyHandler):
            assert handler.proxies == {}, f"ProxyHandler must be empty, got {handler.proxies}"


def test_env_proxy_egress_bypass_regression(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression test for ENV_PROXY_EGRESS_BYPASS defect.

    Ensures that when process-level proxy environment variables are set to an
    unauthorized proxy trap, the adapter ignores them completely and connects
    directly to the requested target (failing closed as NETWORK_UNAVAILABLE
    if the target port has no listener, with 0 requests sent to the proxy trap).
    """
    with (
        LocalRiskModelFakeServer(
            response_body=b'{"probability": 0.42}'
        ) as target_server,
        LocalRiskModelFakeServer() as proxy_trap,
    ):
        monkeypatch.setenv("http_proxy", proxy_trap.endpoint)
        monkeypatch.setenv("HTTP_PROXY", proxy_trap.endpoint)
        monkeypatch.setenv("https_proxy", proxy_trap.endpoint)
        monkeypatch.setenv("HTTPS_PROXY", proxy_trap.endpoint)
        monkeypatch.setenv("no_proxy", "")
        monkeypatch.setenv("NO_PROXY", "")

        adapter = HttpRiskModelAdapter(target_server.endpoint, timeout_seconds=1.0)
        res = adapter.evaluate(_state(), F4QuestionContractV1(), "req-proxy-regression")

        assert len(proxy_trap.received_requests) == 0
        assert len(target_server.received_requests) == 1
        assert res.status is ProviderCallStatus.OK
        assert res.probability == pytest.approx(0.42)


def test_synthetic_proxy_credentials_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure synthetic proxy credentials in env vars are ignored and never leaked."""
    with (
        LocalRiskModelFakeServer(
            response_body=b'{"probability": 0.24}'
        ) as target_server,
        LocalRiskModelFakeServer() as proxy_trap,
    ):
        host_port = proxy_trap.endpoint.replace("http://", "")
        credentialed_proxy = f"http://fake-user:fake-password@{host_port}"

        monkeypatch.setenv("http_proxy", credentialed_proxy)
        monkeypatch.setenv("HTTP_PROXY", credentialed_proxy)
        monkeypatch.setenv("no_proxy", "")
        monkeypatch.setenv("NO_PROXY", "")

        adapter = HttpRiskModelAdapter(target_server.endpoint, timeout_seconds=1.0)
        res = adapter.evaluate(_state(), F4QuestionContractV1(), "req-proxy-creds")

        assert len(proxy_trap.received_requests) == 0
        assert len(target_server.received_requests) == 1
        assert res.status is ProviderCallStatus.OK
        assert res.probability == pytest.approx(0.24)

