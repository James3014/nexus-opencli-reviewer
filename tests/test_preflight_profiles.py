# Issue #113: a Browser Bridge profile counts as connected only when its status says so.
import stat
from reviewer.preflight import OpenCLIPreflight, preflight_opencli

HEAD = 'Connected Browser Bridge profiles\n\n'


def rows(*lines):
 return OpenCLIPreflight._profiles(HEAD + ''.join(f'  {x}\n' for x in lines))


def test_disconnected_and_not_connected_rows_are_dropped():
 assert rows('m5c6uje4 default — disconnected v1.0.24') == []
 assert rows('m5c6uje4 default — not connected v1.0.24') == []
 assert rows('m5c6uje4 — Disconnected v1.0.24', 'b — NOT CONNECTED v1') == []


def test_a_connected_row_still_parses():
 r = rows('m5c6uje4 default — connected v1.0.24')
 assert [(p['id'], p['connected'], p['default']) for p in r] == [('m5c6uje4', True, True)]
 r = rows('a — Connected v1', 'b — disconnected v1')
 assert [p['id'] for p in r] == ['a'] and r[0]['default'] is False


def test_profile_ids_that_contain_the_words_are_judged_by_status():
 assert [p['id'] for p in rows('disconnected1 — connected v1')] == ['disconnected1']
 assert rows('connected9 default — disconnected v1') == []


def test_only_disconnected_profiles_require_the_bridge(tmp_path):
 p = tmp_path / 'opencli'
 p.write_text(
  '#!/usr/bin/env python3\n'
  'import json,sys\n'
  "if sys.argv[1]=='profile': print('Connected Browser Bridge profiles\\n\\n  a default — disconnected v1')\n"
  "else: print(json.dumps([{'Status':'Connected','Login':'Yes','Url':'https://chatgpt.com/'}]))\n"
 )
 p.chmod(p.stat().st_mode | stat.S_IXUSR)
 assert preflight_opencli(str(p)).status == 'BROWSER_BRIDGE_REQUIRED'


def test_real_opencli_output_with_saved_disconnected_profiles():
 # opencli 1.8.8 prints saved, disconnected profiles in their own section after the connected ones.
 raw = (HEAD + '  abc work default — connected v1.0.24\n\n'
        'Disconnected saved profiles:\n'
        '  def home — not connected\n'
        '  ghi — default, not connected\n')
 assert [p['id'] for p in OpenCLIPreflight._profiles(raw)] == ['abc']
