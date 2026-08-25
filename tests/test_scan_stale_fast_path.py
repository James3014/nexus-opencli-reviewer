from reviewer.models import Disposition
from reviewer.scan import scan


class _BaseTransport:
    def __init__(self, *, base_sha):
        self.base_sha = base_sha
        self.files_calls = 0
        self.check_calls = 0

    def auth_preflight(self):
        return None

    def get_ref(self, repo, branch):
        return {"object": {"sha": "current-main"}}

    def list_open_prs(self, repo):
        return [{
            "number": 17,
            "title": "fixture",
            "state": "open",
            "draft": False,
            "mergeable": True,
            "base": {"ref": "main", "sha": self.base_sha},
            "head": {"ref": "candidate", "sha": "head-sha"},
            "body": "Implements Issue #17",
            "labels": [],
        }]

    def list_files(self, repo, number):
        self.files_calls += 1
        return [{"filename": "src/example.py"}]


class StaleTransport(_BaseTransport):
    def __init__(self):
        super().__init__(base_sha="old-main")

    def list_checks(self, repo, sha):
        self.check_calls += 1
        raise AssertionError("stale base must not collect CI checks")


class CurrentTransport(_BaseTransport):
    def __init__(self):
        super().__init__(base_sha="current-main")

    def list_checks(self, repo, sha):
        self.check_calls += 1
        return [{
            "name": "Exact-base impact gate",
            "conclusion": "failure",
            "id": 42,
            "check_suite": {"id": 11},
            "head_sha": "head-sha",
        }]

    def list_check_annotations(self, repo, check_run_id):
        return []

    def list_workflow_runs_for_suite(self, repo, check_suite_id):
        return [{"id": 99, "head_sha": "head-sha"}]

    def get_workflow_run(self, repo, run_id):
        return {"id": 99, "name": "Nexus Pytest CI", "head_sha": "head-sha", "run_attempt": 1}

    def list_workflow_artifacts(self, repo, run_id):
        return [{"id": 7, "name": "exact-base-impact-head-sha"}]

    def list_workflow_jobs(self, repo, run_id):
        return [{"id": 77, "name": "Exact-base impact gate", "run_id": 99, "head_sha": "head-sha"}]


def test_stale_base_preserves_changed_files_but_skips_ci_collection():
    transport = StaleTransport()

    _, _, items, queue = scan("owner/repo", transport)

    assert transport.files_calls == 1
    assert transport.check_calls == 0
    assert items[0].disposition is Disposition.STALE
    assert items[0].snapshot.changed_files == ("src/example.py",)
    assert items[0].snapshot.issue_numbers == (17,)
    assert items[0].snapshot.checks == ()
    assert queue.semantic_review() == []


def test_current_main_still_collects_ci_failure_evidence():
    transport = CurrentTransport()

    _, _, items, _ = scan("owner/repo", transport)

    assert transport.files_calls == 1
    assert transport.check_calls == 1
    assert items[0].disposition is Disposition.REVIEW_READY
    assert "UNEXPECTED_FAILURE" in items[0].findings
    assert items[0].snapshot.checks[0].check_run_id == 42
    assert items[0].snapshot.checks[0].status == "failure"
