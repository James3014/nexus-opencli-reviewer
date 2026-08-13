from __future__ import annotations
import subprocess
class TransportResult:
    def __init__(self,status,raw='',version=''): self.status=status; self.raw=raw; self.version=version
class OpenCLITransport:
    def __init__(self, executable='opencli', timeout=120): self.executable=executable; self.timeout=timeout
    def invoke(self,prompt):
        args=[self.executable,'chatgpt','ask',prompt,'--new','--timeout',str(self.timeout),'--site-session','ephemeral']
        try: p=subprocess.run(args,check=False,capture_output=True,text=True,timeout=self.timeout)
        except FileNotFoundError:return TransportResult('OPENCLI_NOT_FOUND')
        except subprocess.TimeoutExpired:return TransportResult('OPENCLI_TIMEOUT')
        if p.returncode: return TransportResult('OPENCLI_PROCESS_FAILURE',p.stdout or p.stderr)
        return TransportResult('REVIEW_COMPLETED',p.stdout)
