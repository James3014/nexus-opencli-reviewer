from __future__ import annotations
import json, re, subprocess
from datetime import datetime, timezone
from typing import Any, Protocol

REPO_RE=re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
class GitHubError(RuntimeError): pass
class GitHubTransport(Protocol):
    def get_ref(self, repo:str, branch:str)->dict[str,Any]: ...
    def list_open_prs(self, repo:str)->list[dict[str,Any]]: ...
    def list_files(self, repo:str, number:int)->list[dict[str,Any]]: ...
    def list_checks(self, repo:str, sha:str)->list[dict[str,Any]]: ...
    def get_patch(self, repo:str, number:int)->str: ...
    def get_pr(self, repo:str, number:int)->dict[str,Any]: ...

class GhCliTransport:
    def __init__(self, gh='gh'): self.gh=gh
    def _validate(self,repo):
        if not REPO_RE.fullmatch(repo): raise ValueError('repository must be owner/name')
    def _get(self, endpoint, **params):
        if params:
            sep='&' if '?' in endpoint else '?'
            endpoint += sep + '&'.join(f'{k}={v}' for k,v in params.items())
        args=[self.gh,'api',endpoint]
        try: p=subprocess.run(args,check=False,capture_output=True,text=True,timeout=30)
        except (OSError, subprocess.TimeoutExpired) as e: raise GitHubError(str(e)) from e
        if p.returncode: raise GitHubError(p.stderr.strip() or 'gh api failed')
        try:return json.loads(p.stdout)
        except json.JSONDecodeError as e:raise GitHubError('invalid GitHub JSON') from e
    def auth_preflight(self):
        p=subprocess.run([self.gh,'auth','status'],check=False,capture_output=True,text=True,timeout=30)
        if p.returncode: raise GitHubError('GitHub auth/read access unavailable')
    def get_ref(self,repo,branch):
        self._validate(repo); return self._get(f'repos/{repo}/git/ref/heads/{branch}')
    def _paginate(self, endpoint):
        out=[]
        for page in range(1,101):
            value=self._get(endpoint,per_page=100,page=page)
            if not isinstance(value,list): raise GitHubError('expected paginated list')
            out.extend(value)
            if len(value)<100: return out
        raise GitHubError('pagination exceeded safety bound')
    def list_open_prs(self,repo): self._validate(repo); return self._paginate(f'repos/{repo}/pulls?state=open')
    def list_files(self,repo,number): self._validate(repo); return self._paginate(f'repos/{repo}/pulls/{int(number)}/files')
    def list_checks(self,repo,sha):
        self._validate(repo); out=[]
        for page in range(1,101):
            value=self._get(f'repos/{repo}/commits/{sha}/check-runs',per_page=100,page=page)
            if not isinstance(value,dict) or not isinstance(value.get('check_runs'),list): raise GitHubError('expected check-runs page')
            rows=value['check_runs']; out.extend(rows)
            if len(rows)<100:return out
        raise GitHubError('check-runs pagination exceeded safety bound')
    def get_pr(self,repo,number): self._validate(repo); return self._get(f'repos/{repo}/pulls/{int(number)}')
    def get_patch(self,repo,number):
        self._validate(repo)
        args=[self.gh,'api',f'repos/{repo}/pulls/{int(number)}','-H','Accept: application/vnd.github.v3.patch']
        try:p=subprocess.run(args,check=False,capture_output=True,text=True,timeout=30)
        except (OSError,subprocess.TimeoutExpired) as e:raise GitHubError(str(e)) from e
        if p.returncode:raise GitHubError(p.stderr.strip() or 'patch acquisition failed')
        return p.stdout

def utc_now(): return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z')
