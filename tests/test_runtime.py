from types import SimpleNamespace

from reviewer.runtime import RuntimeSupervisor, classify_preflight


def result(status, detail="", profile=None, profiles=None):
    return SimpleNamespace(status=status, detail=detail, profile=profile, profiles=profiles)


def test_health_classes_cover_bridge_profiles_login_challenge_quota_and_transport():
    cases = {
        "READY": "READY",
        "BROWSER_BRIDGE_REQUIRED": "BROWSER_BRIDGE_REQUIRED",
        "PROFILE_SELECTION_AMBIGUOUS": "PROFILE_SELECTION_AMBIGUOUS",
        "CHATGPT_NOT_LOGGED_IN": "CHATGPT_LOGIN_REQUIRED",
        "CHATGPT_CHALLENGE": "CHATGPT_CHALLENGE",
        "CHATGPT_QUOTA_OR_RATE_LIMIT": "CHATGPT_QUOTA_OR_RATE_LIMIT",
        "OPENCLI_TRANSPORT_FAILURE": "OPENCLI_TRANSPORT_FAILURE",
        "OPENCLI_NOT_FOUND": "OPENCLI_DAEMON_UNAVAILABLE",
    }
    assert {key: classify_preflight(result(key)) for key in cases} == cases


def test_stale_profile_is_distinct_from_bridge_absence():
    assert classify_preflight(result("OPENCLI_TRANSPORT_FAILURE", "profile not found: old")) == "STALE_PROFILE"


def test_daemon_unavailable_restarts_once_then_rechecks():
    checks = iter([
        result("OPENCLI_TRANSPORT_FAILURE", "daemon connection refused"),
        result("READY", profile={"id": "current"}, profiles=[{"id": "current", "connected": True}]),
    ])
    restarts = []
    health = RuntimeSupervisor(lambda: next(checks), lambda: restarts.append(True) or True, base_backoff=2).recover()
    assert health.ready
    assert health.profile["id"] == "current"
    assert restarts == [True]
    assert health.restart_attempted and health.restart_succeeded


def test_non_daemon_failure_never_restarts_or_mutates_profile():
    restarts = []
    health = RuntimeSupervisor(lambda: result("BROWSER_BRIDGE_REQUIRED"), lambda: restarts.append(True) or True).recover()
    assert health.status == "BROWSER_BRIDGE_REQUIRED"
    assert not health.restart_attempted
    assert restarts == []


def test_recovery_failure_is_bounded_and_backoff_friendly():
    health = RuntimeSupervisor(lambda: result("OPENCLI_NOT_FOUND"), lambda: False, base_backoff=3, max_backoff=10).recover()
    assert health.status == "OPENCLI_DAEMON_UNAVAILABLE"
    assert health.restart_attempted and health.restart_succeeded is False
    assert health.retry_after == 6


def test_check_is_read_only_and_does_not_restart():
    calls = []
    health = RuntimeSupervisor(lambda: calls.append("preflight") or result("CHATGPT_QUOTA_OR_RATE_LIMIT"),
                               lambda: calls.append("restart") or True).check()
    assert health.status == "CHATGPT_QUOTA_OR_RATE_LIMIT"
    assert calls == ["preflight"]
    assert health.to_dict()["restart_attempted"] is False
