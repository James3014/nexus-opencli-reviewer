import json, stat, textwrap
from reviewer.preflight import preflight_opencli

SHIM=textwrap.dedent('''\
#!/usr/bin/env python3
import json,sys
mode=sys.argv[2] if sys.argv[1]=='profile' else sys.argv[3]
if mode=='list':
 print('Connected Browser Bridge profiles\\n\\n  a default — connected v1.0.22')
elif mode=='ambiguous': print('Connected Browser Bridge profiles\\n\\n  a — connected v1\\n  b — connected v1')
elif mode=='none': print('No Browser Bridge profiles connected.')
elif mode=='notlogged': print(json.dumps([{'Status':'Connected','Login':'No'}]))
elif mode=='challenge': print(json.dumps([{'Status':'challenge','Login':'Yes'}]))
elif mode=='quota': print(json.dumps([{'error':'rate_limit'}]))
else: print(json.dumps([{'Status':'Connected','Login':'Yes','Url':'https://chatgpt.com/'}]))
''')

def make(tmp_path, mode):
 p=tmp_path/'opencli'
 profile_mode = mode if mode in {'none', 'ambiguous'} else 'list'
 status_mode = 'ready' if mode == 'list' else mode
 p.write_text(SHIM.replace(
  "mode=sys.argv[2] if sys.argv[1]=='profile' else sys.argv[3]",
  f"mode='{profile_mode}' if sys.argv[1]=='profile' else '{status_mode}'",
 ))
 p.chmod(p.stat().st_mode|stat.S_IXUSR); return str(p)

def test_ready_and_profile_resolution(tmp_path):
 r=preflight_opencli(make(tmp_path,'list')); assert r.status=='READY' and r.profile['id']=='a'

def test_explicit_profile_failures(tmp_path):
 assert preflight_opencli(make(tmp_path,'none')).status=='BROWSER_BRIDGE_REQUIRED'
 assert preflight_opencli(make(tmp_path,'ambiguous')).status=='PROFILE_SELECTION_AMBIGUOUS'

def test_chatgpt_status_failures(tmp_path):
 assert preflight_opencli(make(tmp_path,'notlogged')).status=='CHATGPT_NOT_LOGGED_IN'
 assert preflight_opencli(make(tmp_path,'challenge')).status=='CHATGPT_CHALLENGE'
 assert preflight_opencli(make(tmp_path,'quota')).status=='CHATGPT_QUOTA_OR_RATE_LIMIT'

def test_missing_binary(tmp_path):
 assert preflight_opencli(str(tmp_path/'missing')).status=='OPENCLI_NOT_FOUND'
