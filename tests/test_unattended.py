from __future__ import annotations

import json

from reviewer.unattended import ServicePolicy, UnattendedReviewService


def item(head="h1", disposition="REVIEW_READY", number=1):
    return {"review_identity": ["repo", number, head, "base", "main"], "disposition": disposition}


def test_bootstrap_persists_baseline_without_historical_storm(tmp_path):
    discovered = [item("old", number=1), item("old2", number=2)]
    calls = []
    service = UnattendedReviewService(
        repository="repo", discover=lambda: discovered,
        review=lambda identity: calls.append(("review", identity)),
        publish=lambda identity, result: calls.append(("publish", identity)),
        root=tmp_path / "state",
    )
    assert service.run_once()["status"] == "IDLE"
    assert calls == []
    saved = json.loads((tmp_path / "state" / "service-state.json").read_text())
    assert saved["bootstrapped"] is True
    assert saved["queue"] == {}


def test_allow_one_bootstrap_canary_is_serial_and_published(tmp_path):
    discovered = [item("a", number=1), item("b", number=2)]
    calls = []
    service = UnattendedReviewService(
        repository="repo", discover=lambda: discovered,
        review=lambda identity: calls.append(("review", identity)) or {"receipt": "r"},
        publish=lambda identity, result: calls.append(("publish", identity)) or {"status": "PUBLISHED"},
        root=tmp_path / "state", policy=ServicePolicy(bootstrap_canary=True),
    )
    result = service.run_once()
    assert result["status"] == "COMPLETE"
    assert [kind for kind, _ in calls] == ["review", "publish"]
    assert calls[0][1][1] == 1  # deterministic identity-key order
    assert service.run_once()["status"] == "IDLE"
    assert [kind for kind, _ in calls] == ["review", "publish"]


def test_new_identity_and_head_update_are_discovered_automatically(tmp_path):
    current = [item("h1")]
    calls = []
    service = UnattendedReviewService(
        repository="repo", discover=lambda: current,
        review=lambda identity: calls.append(("review", identity)) or {"receipt": identity},
        publish=lambda identity, result: calls.append(("publish", identity)) or True,
        root=tmp_path / "state",
    )
    assert service.run_once()["status"] == "IDLE"
    current[0] = item("h2")
    assert service.run_once()["status"] == "COMPLETE"
    assert calls[0][0] == "review" and calls[0][1][2] == "h2"


def test_draft_to_ready_transition_is_queued(tmp_path):
    current = [item("h1", disposition="DRAFT")]
    calls = []
    service = UnattendedReviewService(
        repository="repo", discover=lambda: current,
        review=lambda identity: calls.append("review") or {"receipt": "r"},
        publish=lambda identity, result: calls.append("publish") or True,
        root=tmp_path / "state",
    )
    assert service.run_once()["status"] == "IDLE"
    current[0] = item("h1", disposition="REVIEW_READY")
    assert service.run_once()["status"] == "COMPLETE"
    assert calls == ["review", "publish"]


def test_uncertain_review_is_durable_and_never_replayed(tmp_path):
    calls = []

    class Unknown(Exception):
        outcome_unknown = True

    service = UnattendedReviewService(
        repository="repo", discover=lambda: [item()],
        review=lambda identity: calls.append("review") or (_ for _ in ()).throw(Unknown()),
        publish=lambda identity, result: calls.append("publish") or True,
        root=tmp_path / "state", policy=ServicePolicy(bootstrap_canary=True),
    )
    assert service.run_once()["status"] == "RECONCILIATION_REQUIRED"
    assert service.run_once()["status"] == "RECONCILIATION_REQUIRED"
    assert calls == ["review"]
    saved = json.loads((tmp_path / "state" / "service-state.json").read_text())
    assert next(iter(saved["queue"].values()))["state"] == "outcome_unknown"


def test_restart_reads_durable_queue_and_deduplicates(tmp_path):
    current = [item()]
    calls = []
    kwargs = dict(
        repository="repo", discover=lambda: current,
        review=lambda identity: calls.append("review") or {"receipt": "r"},
        publish=lambda identity, result: calls.append("publish") or True,
        root=tmp_path / "state", policy=ServicePolicy(bootstrap_canary=True),
    )
    first = UnattendedReviewService(**kwargs)
    assert first.run_once()["status"] == "COMPLETE"
    second = UnattendedReviewService(**kwargs)
    assert second.run_once()["status"] == "IDLE"
    assert calls == ["review", "publish"]


def test_restart_with_interrupted_scheduler_state_blocks_replay(tmp_path):
    root=tmp_path/"state"; service=UnattendedReviewService(repository="repo",discover=lambda:[item()],review=lambda i:None,publish=lambda i,r:None,root=root)
    state=service.store.load();state["bootstrapped"]=True;state["queue"]={"x":{"review_identity":["repo",1,"h","b","m"],"state":"semantic_prepared"}};service.store.save(state)
    assert service.run_once()["status"]=="RECONCILIATION_REQUIRED"
