import json
import pytest
from reviewer.opencli import OpenCLITransport, unwrap_opencli_json

ASK = [{'conversationId': 'c1', 'response': 'snap'}]
ROW = {'Index': 1, 'Role': 'Assistant', 'Text': 'final', 'Generating': False, 'StableSeconds': 6}
WRAP = lambda d: json.dumps({'ok': True, 'data': d})


def test_unwrap_accepts_bare_and_ok_envelope():
    assert unwrap_opencli_json(json.dumps(ASK)) == ASK
    assert unwrap_opencli_json(WRAP(ASK)) == ASK


@pytest.mark.parametrize('raw', [
    json.dumps({'ok': False, 'error': {'code': 'X'}}),
    json.dumps({'ok': True, 'data': {'a': 1}}),
    json.dumps({'ok': True, 'data': ASK, 'extra': 1}),
    json.dumps({'ok': 'true', 'data': ASK}),
    json.dumps({'data': ASK}),
])
def test_unwrap_other_shapes_not_list(raw):
    assert not isinstance(unwrap_opencli_json(raw), list)


@pytest.mark.parametrize('wrap', [lambda d: json.dumps(d), WRAP])
def test_invoke_success_both_shapes(monkeypatch, wrap):
    outs = iter([wrap(ASK), wrap([ROW])])
    monkeypatch.setattr(OpenCLITransport, '_run_process',
                        lambda self, a, e: (0, next(outs), '', False))
    monkeypatch.setattr(OpenCLITransport, 'version', lambda self: 'v')
    r = OpenCLITransport().invoke('p')
    assert r.status == 'REVIEW_COMPLETED' and r.raw == 'final'


def test_invoke_ok_false_fails_closed(monkeypatch):
    bad = json.dumps({'ok': False, 'error': {'code': 'E', 'message': 'm'}})
    monkeypatch.setattr(OpenCLITransport, '_run_process', lambda self, a, e: (0, bad, '', False))
    assert OpenCLITransport().invoke('p').status == 'OPENCLI_PROCESS_FAILURE'
    outs = iter([WRAP(ASK), bad])
    monkeypatch.setattr(OpenCLITransport, '_run_process', lambda self, a, e: (0, next(outs), '', False))
    assert OpenCLITransport().invoke('p').status == 'OPENCLI_STABLE_READ_FAILURE'


def test_nonzero_exit_envelope_only_from_success_shape(monkeypatch):
    monkeypatch.setattr(OpenCLITransport, '_run_process', lambda self, a, e: (3, WRAP(ASK), '', False))
    assert OpenCLITransport().invoke('p').envelope == ASK[0]
    bad = json.dumps({'ok': False, 'error': {'code': 'E'}})
    monkeypatch.setattr(OpenCLITransport, '_run_process', lambda self, a, e: (3, bad, '', False))
    assert OpenCLITransport().invoke('p').envelope is None
