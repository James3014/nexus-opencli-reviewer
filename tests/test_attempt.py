import json

import pytest

from reviewer.attempt import (
    COMPLETED,
    DISPATCHING,
    OUTCOME_UNKNOWN,
    PREPARED,
    discover_unfinished,
    finish_attempt,
    mark_dispatching,
    prepare_attempt,
    reconcile_unfinished,
)


def test_prepare_dispatch_finish_is_bound_and_atomic(tmp_path):
    record, path = prepare_attempt(
        tmp_path, ["o/r", 7, "head", "base", "main"], "ctx", "prompt",
        {"source": "unit", "executable": "fake"}, attempt_id="a1", now="t1",
        safe_argv=["opencli", "chatgpt", "ask", "<prompt>", "-f", "json"],
        executable="/bin/opencli", version="1.2", browser_profile="default",
    )
    assert record["state"] == PREPARED
    assert record["safe_argv"][-2:] == ["-f", "json"]
    assert record["opencli_executable"] == "/bin/opencli"
    assert record["opencli_version"] == "1.2"
    assert record["browser_profile"] == "default"
    assert record["session_mode"] == "ephemeral"
    assert json.loads(path.read_text())["retry_safe"] is True
    dispatched = mark_dispatching(path, now="t2")
    assert dispatched["state"] == DISPATCHING and dispatched["retry_safe"] is False
    finished = finish_attempt(path, COMPLETED, result={"status": "PASS"}, now="t3")
    assert finished["state"] == COMPLETED and finished["finished_at"] == "t3"
    assert discover_unfinished(tmp_path) == []


def test_transitions_are_fail_closed(tmp_path):
    _, path = prepare_attempt(tmp_path, ["r", 1], "c", "p", {}, attempt_id="a2")
    with pytest.raises(ValueError, match="INVALID_ATTEMPT_TRANSITION"):
        finish_attempt(path, COMPLETED)
    mark_dispatching(path)
    with pytest.raises(ValueError, match="INVALID_ATTEMPT_TRANSITION"):
        mark_dispatching(path)
    with pytest.raises(ValueError, match="INVALID_FINAL_STATE"):
        finish_attempt(path, "PASS")


def test_restart_reconciliation_marks_prepared_and_dispatching_unknown(tmp_path):
    _, p1 = prepare_attempt(tmp_path, ["r", 1], "c1", "p1", {}, attempt_id="p1")
    _, p2 = prepare_attempt(tmp_path, ["r", 2], "c2", "p2", {}, attempt_id="p2")
    mark_dispatching(p2, now="dispatch")
    found = discover_unfinished(tmp_path)
    assert {x["attempt_id"] for x in found} == {"p1", "p2"}
    done = reconcile_unfinished(tmp_path, now="reconciled")
    assert {x["state"] for x in done} == {OUTCOME_UNKNOWN}
    assert all(x["retry_safe"] is False for x in done)
    assert discover_unfinished(tmp_path) == []
