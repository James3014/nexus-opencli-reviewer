import json
import os
import stat
import sys

from reviewer.opencli import OpenCLITransport

SENTINELS = {
    'GITHUB_TOKEN': 'ghs-sentinel',
    'GH_TOKEN': 'gh-sentinel',
    'OPENAI_API_KEY': 'sk-sentinel',
    'ANTHROPIC_API_KEY': 'ant-sentinel',
    'MY_SECRET': 'secret-sentinel',
    'DB_PASSWORD': 'pw-sentinel',
    'SERVICE_CREDENTIAL': 'cred-sentinel',
    'SOME_TOKEN': 'tok-sentinel',
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
        'else:\n'
        '    row = {"Role": "Assistant", "Text": "ok", "Generating": False, "StableSeconds": 6}\n'
        '    print(json.dumps([row]))\n')
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script.parent, dump


def test_child_process_environment_excludes_credentials(tmp_path, monkeypatch):
    bin_dir, dump = _recording_opencli(tmp_path)
    monkeypatch.setenv('PATH', f'{bin_dir}{os.pathsep}{os.environ["PATH"]}')
    for name, value in SENTINELS.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv('OPENCLI_KEEP_ME', 'kept')
    monkeypatch.delenv('OPENCLI_PROFILE', raising=False)

    result = OpenCLITransport(executable='opencli', process_timeout=20, profile='lab').invoke('hi')

    assert result.status == 'REVIEW_COMPLETED'
    dumps = [json.loads(line) for line in dump.read_text().splitlines()]
    assert len(dumps) >= 3  # ask, detail and --version all ran under the filtered environment
    for child_env in dumps:
        for name in SENTINELS:
            assert name not in child_env
        assert str(bin_dir) in child_env['PATH']
        assert child_env['OPENCLI_PROFILE'] == 'lab'
        assert child_env['OPENCLI_KEEP_ME'] == 'kept'
