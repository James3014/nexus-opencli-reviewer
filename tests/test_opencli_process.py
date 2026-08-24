import json, stat, textwrap
from reviewer.opencli import OpenCLITransport

SHIM = textwrap.dedent('''\
#!/usr/bin/env python3
import json, signal, subprocess, sys, time
command=sys.argv[2]
value=sys.argv[3]
if command=='ask':
    mode=value
    if mode in ('valid','ask-invalid-stable-valid','detail-malformed','detail-nonzero','detail-generating','detail-timeout'):
        response='not-json' if mode=='ask-invalid-stable-valid' else 'ask-snapshot'
        print(json.dumps([{'conversationId':'c-'+mode,'response':response}]), flush=True)
    elif mode=='malformed': print('not-json', flush=True)
    elif mode=='nonzero': print('failure', flush=True); sys.exit(3)
    elif mode=='nonzero-envelope': print(json.dumps([{'conversationId':'c-nonzero-envelope','response':'snapshot'}]), flush=True); sys.exit(3)
    elif mode=='partial': print('{"partial":', end='', flush=True); time.sleep(30)
    elif mode=='descendant': subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); time.sleep(30)
    elif mode=='setsid-descendant':
        subprocess.Popen([sys.executable,'-c','import os,time; os.setsid(); time.sleep(30)'])
        time.sleep(30)
    elif mode=='ignore-term': signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)
elif command=='detail':
    mode=value.removeprefix('c-')
    stable={'schema':'reviewer.semantic_response.v1','status':'PASS','summary':'ok','findings':[],'evidence_gaps':[]}
    row={'Index':1,'Role':'Assistant','Text':json.dumps(stable),'Generating':False,'StableSeconds':6}
    if mode in ('valid','ask-invalid-stable-valid'): print(json.dumps([row]), flush=True)
    elif mode=='detail-malformed': print('not-json', flush=True)
    elif mode=='detail-nonzero': print('failure', flush=True); sys.exit(4)
    elif mode=='detail-generating': row['Generating']=True; row['StableSeconds']=0; print(json.dumps([row]), flush=True)
    elif mode=='detail-timeout': time.sleep(30)
''')

def shim(tmp_path):
    p=tmp_path/'opencli-shim'; p.write_text(SHIM); p.chmod(p.stat().st_mode|stat.S_IXUSR); return str(p)

def call(path, mode, **kw):
    return OpenCLITransport(executable=path, process_timeout=kw.pop('process_timeout',5), terminate_grace=kw.pop('terminate_grace',.1), **kw).invoke(mode)

def test_real_process_valid_malformed_nonzero(tmp_path):
    p=shim(tmp_path)
    assert call(p,'valid').status=='REVIEW_COMPLETED'
    assert call(p,'ask-invalid-stable-valid').status=='REVIEW_COMPLETED'
    assert call(p,'malformed').status=='OPENCLI_PROCESS_FAILURE'
    assert call(p,'nonzero').status=='OPENCLI_PROCESS_FAILURE'
    r=call(p,'nonzero-envelope')
    assert r.status=='OPENCLI_PROCESS_FAILURE'
    assert r.envelope['conversationId']=='c-nonzero-envelope'


def test_stable_read_failures_do_not_fall_back_to_ask_snapshot(tmp_path):
    p=shim(tmp_path)
    for mode in ('detail-malformed','detail-nonzero','detail-generating'):
        r=call(p,mode)
        assert r.status=='OPENCLI_STABLE_READ_FAILURE'
        assert r.retry_safe is False
    r=call(p,'detail-timeout',process_timeout=.5,terminate_grace=.05)
    assert r.status=='OPENCLI_STABLE_READ_FAILURE'
    assert r.retry_safe is False

def test_real_process_timeout_partial_output(tmp_path):
    r=call(shim(tmp_path),'partial'); assert r.outcome_unknown and 'partial' in r.raw

def test_real_process_kills_ignored_term_and_descendant(tmp_path):
    p=shim(tmp_path)
    assert call(p,'ignore-term',process_timeout=.15,terminate_grace=.05).outcome_unknown
    assert call(p,'descendant',process_timeout=.15,terminate_grace=.05).outcome_unknown


def test_timeout_final_read_is_bounded_when_setsid_descendant_holds_pipes(tmp_path):
    """Regression (live 18-min daemon stall): after SIGTERM/SIGKILL a detached
    setsid descendant can still hold the stdout pipes; the final read must be
    bounded instead of blocking the service cycle."""
    import time as _time
    p=shim(tmp_path)
    started=_time.monotonic()
    r=call(p,'setsid-descendant',process_timeout=.15,terminate_grace=.05)
    elapsed=_time.monotonic()-started
    assert r.outcome_unknown
    assert elapsed < 10, f"transport blocked for {elapsed:.1f}s"
