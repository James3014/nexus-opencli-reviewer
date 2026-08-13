import json
from pathlib import Path

from reviewer import cli
from reviewer.preflight import PreflightResult


def run(monkeypatch, *args):
    monkeypatch.setattr("sys.argv", ["reviewer", *args])
    return cli.main()


def test_status_and_missing_args_json(monkeypatch, capsys, tmp_path):
    assert run(monkeypatch, "--status", "--json", "--state-root", str(tmp_path)) is None
    assert json.loads(capsys.readouterr().out)["schema"] == "reviewer.status.v1"
    assert run(monkeypatch, "--json", "--state-root", str(tmp_path)) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "ERROR"


def test_reconcile_semantic_json(monkeypatch, capsys, tmp_path):
    from reviewer.attempt import prepare_attempt, mark_dispatching
    _, path = prepare_attempt(tmp_path,["o/r",1,"h","b","m"],"c","p",{},attempt_id="a1")
    mark_dispatching(path)
    assert run(monkeypatch, "--reconcile-semantic", "a1", "--json", "--state-root", str(tmp_path)) is None
    assert json.loads(capsys.readouterr().out)["status"] == "SEMANTIC_RECONCILED"


def test_publish_and_reconcile_flags(monkeypatch, capsys, tmp_path):
    receipt = tmp_path / "r.json"
    receipt.write_text(json.dumps({"review_identity": ["o/r", 1, "h", "b", "m"]}))
    monkeypatch.setattr(cli, "publish_review", lambda root, transport, value: Path(root) / "pub.json")
    assert run(monkeypatch, "--publish-receipt", str(receipt), "--json", "--state-root", str(tmp_path)) is None
    assert json.loads(capsys.readouterr().out)["status"] == "AUTOMATED_PRE_REVIEW_PUBLISHED"
    monkeypatch.setattr(cli, "reconcile_publication", lambda root, transport, aid: Path(root) / "done.json")
    assert run(monkeypatch, "--reconcile-publication", "a1", "--json", "--state-root", str(tmp_path)) is None
    assert json.loads(capsys.readouterr().out)["status"] == "PUBLICATION_RECONCILED"


def test_review_runs_current_preflight_profile(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(cli, "preflight_opencli", lambda *a: PreflightResult("READY", profile={"id": "p-current"}))
    seen = {}
    class T:
        def __init__(self, executable='opencli', profile=None): seen["profile"] = profile
    monkeypatch.setattr(cli, "OpenCLITransport", T)
    monkeypatch.setattr(cli, "review_ready", lambda *args, **kwargs: ({"transport_result": "REVIEW_COMPLETED"}, tmp_path / "r.json"))
    monkeypatch.setattr(cli, "GhCliTransport", lambda: object())
    assert run(monkeypatch, "--repo", "o/r", "--review-pr", "1", "--local-only", "--json", "--state-root", str(tmp_path)) is None
    assert seen["profile"] == "p-current"
