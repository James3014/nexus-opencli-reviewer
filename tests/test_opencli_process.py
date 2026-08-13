import json, stat, textwrap
from reviewer.opencli import OpenCLITransport

SHIM = textwrap.dedent('''\
#!/usr/bin/env python3
import json, signal, subprocess, sys, time
mode=sys.argv[3]
if mode=='valid': print(json.dumps([{'response':'ok'}]), flush=True)
elif mode=='malformed': print('not-json', flush=True)
elif mode=='nonzero': print('failure', flush=True); sys.exit(3)
elif mode=='partial': print('{"partial":', end='', flush=True); time.sleep(30)
elif mode=='descendant': subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); time.sleep(30)
elif mode=='ignore-term': signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)
''')

def shim(tmp_path):
    p=tmp_path/'opencli-shim'; p.write_text(SHIM); p.chmod(p.stat().st_mode|stat.S_IXUSR); return str(p)

def call(path, mode, **kw):
    return OpenCLITransport(executable=path, process_timeout=kw.pop('process_timeout',5), terminate_grace=kw.pop('terminate_grace',.1), **kw).invoke(mode)

def test_real_process_valid_malformed_nonzero(tmp_path):
    p=shim(tmp_path)
    assert call(p,'valid').status=='REVIEW_COMPLETED'
    assert call(p,'malformed').status=='OPENCLI_PROCESS_FAILURE'
    assert call(p,'nonzero').status=='OPENCLI_PROCESS_FAILURE'

def test_real_process_timeout_partial_output(tmp_path):
    r=call(shim(tmp_path),'partial'); assert r.outcome_unknown and 'partial' in r.raw

def test_real_process_kills_ignored_term_and_descendant(tmp_path):
    p=shim(tmp_path)
    assert call(p,'ignore-term',process_timeout=.15,terminate_grace=.05).outcome_unknown
    assert call(p,'descendant',process_timeout=.15,terminate_grace=.05).outcome_unknown
