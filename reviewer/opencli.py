from __future__ import annotations
import subprocess
import json
from datetime import datetime,timezone
class TransportResult:
    def __init__(self,status,raw='',version='',envelope=None,argv=None,outcome_unknown=False,retry_safe=False,started_at='',finished_at=''): self.status=status; self.raw=raw; self.version=version; self.envelope=envelope; self.argv=argv or []; self.outcome_unknown=outcome_unknown; self.retry_safe=retry_safe; self.started_at=started_at; self.finished_at=finished_at
class OpenCLITransport:
    def __init__(self, executable='opencli', timeout=120, process_timeout=None): self.executable=executable; self.timeout=timeout; self.process_timeout=process_timeout or timeout+60
    def invoke(self,prompt):
        now=lambda:datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z')
        started=now()
        args=[self.executable,'chatgpt','ask',prompt,'--new','--timeout',str(self.timeout),'--site-session','ephemeral','-f','json']
        try: p=subprocess.run(args,check=False,capture_output=True,text=True,timeout=self.process_timeout)
        except FileNotFoundError:return TransportResult('OPENCLI_NOT_FOUND',argv=args,started_at=started,finished_at=now())
        except subprocess.TimeoutExpired:return TransportResult('OPENCLI_OUTCOME_UNKNOWN','',argv=args,outcome_unknown=True,retry_safe=False,started_at=started,finished_at=now())
        if p.returncode: return TransportResult('OPENCLI_PROCESS_FAILURE',p.stdout or p.stderr,argv=args,started_at=started,finished_at=now())
        try:
            env=json.loads(p.stdout)
            if not isinstance(env,list) or len(env)!=1 or not isinstance(env[0],dict) or not isinstance(env[0].get('response'),str): raise ValueError
            env=env[0]
        except (ValueError,json.JSONDecodeError): return TransportResult('OPENCLI_PROCESS_FAILURE',p.stdout,argv=args,started_at=started,finished_at=now())
        return TransportResult('REVIEW_COMPLETED',env['response'],version=self.version(),envelope=env,argv=[self.executable,'chatgpt','ask','<prompt>','--new','--timeout',str(self.timeout),'--site-session','ephemeral','-f','json'],started_at=started,finished_at=now())
    def version(self):
        try:return subprocess.run([self.executable,'--version'],check=False,capture_output=True,text=True,timeout=10).stdout.strip()
        except Exception:return ''
