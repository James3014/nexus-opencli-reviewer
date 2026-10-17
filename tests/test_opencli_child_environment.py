import json
import os
import stat
import sys

from reviewer.opencli import OpenCLITransport

SENTINELS = {
    'GITHUB_TOKEN': 'ghs-sentinel',
    'GH_TOKEN': 'gh-sentinel',
    'github_token': 'lower-sentinel',
    'Token': 'mixed-sentinel',
    'OPENAI_API_KEY': 'sk-sentinel',
    'ANTHROPIC_API_KEY': 'ant-sentinel',
    'MY_SECRET': 'secret-sentinel',
    'DB_PASSWORD': 'pw-sentinel',
    'SERVICE_CREDENTIAL': 'cred-sentinel',
    'SOME_TOKEN': 'tok-sentinel',
    'PROVIDER_TOKEN': 'prov-sentinel',
    'OPENCLI_TOKEN': 'oc-tok-sentinel',
    'OPENCLI_API_KEY': 'oc-key-sentinel',
    'AWS_ACCESS_KEY_ID': 'aws-sentinel',
    'STRIPE_KEY': 'stripe-sentinel',
    'SSH_AUTH_SOCK': '/tmp/agent.sock',
    'AUTHORIZATION': 'Bearer x',
    'SESSION_COOKIE': 'cookie-sentinel',
    'GITLAB_PAT': 'pat-sentinel',
    'DATABASE_URL': 'postgres://u:p@h/db',
    'KUBECONFIG': '/tmp/kube',
    'GH_OPENCLI_HOST': 'x',
}
KEPT = {
    'HOME': '/home/kept', 'LANG': 'C.UTF-8', 'TMPDIR': '/tmp/kept',
    'OPENCLI_KEEP_ME': 'kept', 'AUTHOR_NAME': 'kept', 'PROVIDER_NAME': 'kept',
    'MONKEY_COUNT': '3',
}


def _recording_opencli(tmp_path):
    dump = tmp_path / 'environ-dump.json'
    script = tmp_path / 'bin' / 'opencli'
    script.parent.mkdir()
    script.write_text(
        f'#!{sys.executable}\n'
        'import json, os, sys\n'
        f'with open({str(dump)!r}, "a") as fh:\n'
        '    fh.write(json.dumps(dict(os.environ)) + "\\n")\n'
        'if len(sys.argv) < 3:\n'
        '    print("opencli 0.0-test")\n'
        'elif sys.argv[2] == "ask":\n'
        '    print(json.dumps([{"conversationId": "c1", "response": "snap"}]))\n'
        'elif sys.argv[2] == "detail" and "-f" in sys.argv and "--wait" in sys.argv:\n'
        '    row = {"Role": "Assistant", "Text": "ok", "Generating": False, "StableSeconds": 6}\n'
        '    print(json.dumps([row]))\n'
        'else:\n'
        '    print("[]")\n')
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script.parent, dump


def _prepare(tmp_path, monkeypatch):
    bin_dir, dump = _recording_opencli(tmp_path)
    monkeypatch.setenv('PATH', f'{bin_dir}{os.pathsep}{os.environ["PATH"]}')
    for name, value in {**SENTINELS, **KEPT}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv('OPENCLI_PROFILE', raising=False)
    return bin_dir, dump


def _assert_clean(dump, bin_dir, profile='lab', expected=1):
    dumps = [json.loads(line) for line in dump.read_text().splitlines()]
    assert len(dumps) >= expected
    for child_env in dumps:
        present = {name for name in SENTINELS if name in child_env}
        assert not present
        assert str(bin_dir) in child_env['PATH']
        for name, value in KEPT.items():
            assert child_env[name] == value
        if profile:
            assert child_env['OPENCLI_PROFILE'] == profile


def test_child_process_environment_excludes_credentials(tmp_path, monkeypatch):
    bin_dir, dump = _prepare(tmp_path, monkeypatch)

    result = OpenCLITransport(executable='opencli', process_timeout=20, profile='lab').invoke('hi')

    assert result.status == 'REVIEW_COMPLETED'
    _assert_clean(dump, bin_dir, expected=3)  # ask, detail and --version


def test_service_cli_opencli_children_use_filtered_environment(tmp_path, monkeypatch):
    from reviewer import service_cli
    bin_dir, dump = _prepare(tmp_path, monkeypatch)
    assert service_cli._opencli_json('opencli', 'lab', ['chatgpt', 'history']) == []
    assert service_cli._opencli_browser('opencli', 'lab', ['tabs']) == []
    _assert_clean(dump, bin_dir, expected=2)
    dump.unlink()
    assert service_cli._daemon_restart('opencli') is True  # takes no profile
    _assert_clean(dump, bin_dir, profile=None)


def test_preflight_child_uses_filtered_environment(tmp_path, monkeypatch):
    from reviewer.preflight import OpenCLIPreflight
    bin_dir, dump = _prepare(tmp_path, monkeypatch)
    _proc, raw, error = OpenCLIPreflight(executable='opencli')._run(['opencli', 'profile', 'list'])
    assert error is None and raw.strip() == '[]'
    _assert_clean(dump, bin_dir, profile=None)


def test_filter_unit_cases():
    from reviewer.opencli import child_environment
    for name in SENTINELS:
        os.environ[name] = 'x'
    try:
        env = child_environment('p')
    finally:
        for name in SENTINELS:
            os.environ.pop(name, None)
    assert not set(SENTINELS) & set(env)
    assert env['OPENCLI_PROFILE'] == 'p'
