from reviewer.models import CheckObservation, Classification, Disposition, PRSnapshot
from reviewer.unattended import UnattendedReviewService


def _classification(*, checks=()):
    snapshot = PRSnapshot(
        repository="repo",
        pr_number=1,
        title="CFI trigger",
        state="OPEN",
        draft=False,
        mergeable=True,
        base_branch="main",
        base_sha="base_sha",
        head_branch="feature",
        head_sha="h1",
        current_main_sha="main_sha",
        checks=tuple(checks),
    )
    return Classification(snapshot=snapshot, disposition=Disposition.REVIEW_READY)


def test_real_classification_same_head_terminal_failure_enqueues_once(tmp_path):
    current = [_classification()]
    calls = []
    service = UnattendedReviewService(
        repository="repo",
        discover=lambda: current,
        review=lambda identity: calls.append(("review", identity)) or {"receipt": identity},
        publish=lambda identity, result: calls.append(("publish", identity)) or {"status": "PUBLISHED"},
        root=tmp_path / "state",
    )

    initial = service._record(current[0])
    assert initial["failure_fingerprint"] == ""
    assert service.run_once()["status"] == "IDLE"

    expected = _classification(checks=[
        CheckObservation(
            name="CI", status="failure", expected_failure=True,
            check_run_id=7, run_id=9,
        )
    ])
    assert service._record(expected)["failure_fingerprint"] == ""
    current[0] = expected
    assert service.run_once()["status"] == "IDLE"

    failed = _classification(checks=[
        CheckObservation(
            name="CI", status="failure", expected_failure=False,
            check_run_id=7, run_id=9,
        )
    ])
    failed_record = service._record(failed)
    assert failed_record["failure_fingerprint"]
    current[0] = failed

    assert service.run_once()["status"] == "COMPLETE"
    assert calls == [
        ("review", ("repo", 1, "h1", "base_sha", "main_sha")),
        ("publish", ("repo", 1, "h1", "base_sha", "main_sha")),
    ]
    lineage = service.store.load()["queue"][failed_record["identity_key"]]
    assert lineage["reason"] == "ci_failure_fingerprint"
    assert lineage["state"] == "complete"

    assert service.run_once()["status"] == "IDLE"
    assert len(calls) == 2

    rerun = _classification(checks=[
        CheckObservation(
            name="CI", status="failure", expected_failure=False,
            check_run_id=7, run_id=10,
        )
    ])
    rerun_record = service._record(rerun)
    assert rerun_record["failure_fingerprint"]
    assert rerun_record["failure_fingerprint"] != failed_record["failure_fingerprint"]
    current[0] = rerun
    assert service.run_once()["status"] == "COMPLETE"
    assert len(calls) == 4
    assert service.run_once()["status"] == "IDLE"
    assert len(calls) == 4
