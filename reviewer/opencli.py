from __future__ import annotations
import subprocess
import json
class TransportResult:
    def __init__(self,status,raw='',version='',envelope=None,argv=None): self.status=status; self.raw=raw; self.version=version; self.envelope=envelope; self.argv=argv or []
class OpenCLITransport:
    def __init__(self, executable='opencli', timeout=120): self.executable=executable; self.timeout=timeout
    def invoke(self,prompt):
        args=[self.executable,'chatgpt','ask',prompt,'--new','--timeout',str(self.timeout),'--site-session','ephemeral','-f','json']
        try: p=subprocess.run(args,check=False,capture_output=True,text=True,timeout=self.timeout)
        except FileNotFoundError:return TransportResult('OPENCLI_NOT_FOUND',argv=args)
        except subprocess.TimeoutExpired:return TransportResult('OPENCLI_TIMEOUT',argv=args)
        if p.returncode: return TransportResult('OPENCLI_PROCESS_FAILURE',p.stdout or p.stderr,argv=args)
        try:
            env=json.loads(p.stdout)
            if not isinstance(env,list) or len(env)!=1 or not isinstance(env[0],dict) or not isinstance(env[0].get('response'),str): raise ValueError
            env=env[0]
        except (ValueError,json.JSONDecodeError): return TransportResult('OPENCLI_PROCESS_FAILURE',p.stdout,argv=args)
        return TransportResult('REVIEW_COMPLETED',env['response'],version=self.version(),envelope=env,argv=[self.executable,'chatgpt','ask','<prompt>','--new','--timeout',str(self.timeout),'--site-session','ephemeral','-f','json'])
    def version(self):
        try:return subprocess.run([self.executable,'--version'],check=False,capture_output=True,text=True,timeout=10).stdout.strip()
        except Exception:return ''
