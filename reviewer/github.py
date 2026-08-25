from __future__ import annotations
import json, os, re, selectors, socket, subprocess, time
import urllib.error, urllib.request
from datetime import datetime, timezone
from typing import Any, Protocol

REPO_RE=re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
READ_TIMEOUTS=(30,15)
class GitHubError(RuntimeError): pass
class GitHubTransport(Protocol):
    def get_ref(self, repo:str, branch:str)->dict[str,Any]: ...
    def list_open_prs(self, repo:str)->list[dict[str,Any]]: ...
    def list_files(self, repo:str, number:int)->list[dict[str,Any]]: ...
    def list_checks(self, repo:str, sha:str)->list[dict[str,Any]]: ...
    def list_check_annotations(self, repo:str, check_run_id:int)->list[dict[str,Any]]: ...
    def get_workflow_run(self, repo:str, run_id:int)->dict[str,Any]: ...
    def list_workflow_runs_for_suite(self, repo:str, check_suite_id:int)->list[dict[str,Any]]: ...
    def list_workflow_artifacts(self, repo:str, run_id:int)->list[dict[str,Any]]: ...
    def list_workflow_jobs(self, repo:str, run_id:int)->list[dict[str,Any]]: ...
    def get_job_log(self, repo:str, job_id:int)->bytes: ...
    def get_artifact_archive(self, repo:str, artifact_id:int)->bytes: ...
    def get_patch(self, repo:str, number:int)->str: ...
    def get_pr(self, repo:str, number:int)->dict[str,Any]: ...
    def get_issue(self, repo:str, number:int)->dict[str,Any]: ...
    def get_file(self, repo:str, path:str, ref:str)->str: ...
    def create_comment(self, repo:str, pr_number:int, body:str)->dict[str,Any]: ...
    def list_comments(self, repo:str, pr_number:int)->list[dict[str,Any]]: ...

class GhCliTransport:
    def __init__(self, gh='gh'):
        self.gh=gh
        self._token=None
    def _validate(self,repo):
        if not REPO_RE.fullmatch(repo): raise ValueError('repository must be owner/name')
    def _env(self):
        if not self._token:
            return None
        env=os.environ.copy();env['GH_TOKEN']=self._token
        return env
    def _http_get(self,endpoint,*,accept='application/vnd.github+json'):
        self._validate_endpoint(endpoint)
        if not self._token:
            self.auth_preflight()
        request=urllib.request.Request(
            f'https://api.github.com/{endpoint}',
            headers={
                'Authorization': f'Bearer {self._token}',
                'Accept': accept,
                'X-GitHub-Api-Version': '2022-11-28',
                'User-Agent': 'nexus-opencli-reviewer',
            },
            method='GET',
        )
        last_error=None
        for index,timeout in enumerate(READ_TIMEOUTS):
            try:
                with urllib.request.urlopen(request,timeout=timeout) as response:
                    return response.read()
            except urllib.error.HTTPError as exc:
                try: detail=exc.read(8192).decode(errors='replace').strip()
                except Exception: detail=''
                raise GitHubError(detail or f'GitHub HTTP {exc.code}') from exc
            except (urllib.error.URLError,TimeoutError,socket.timeout,OSError) as exc:
                last_error=exc
                if index+1 < len(READ_TIMEOUTS):
                    time.sleep(.25)
                    continue
                raise GitHubError(str(exc)) from exc
        raise GitHubError(str(last_error) if last_error else 'GitHub read failed')
    def _get(self, endpoint, **params):
        if params:
            sep='&' if '?' in endpoint else '?'
            endpoint += sep + '&'.join(f'{k}={v}' for k,v in params.items())
        raw=self._http_get(endpoint)
        try:return json.loads(raw.decode())
        except (UnicodeDecodeError,json.JSONDecodeError) as e:raise GitHubError('invalid GitHub JSON') from e
    def auth_preflight(self):
        if self._token:
            return
        last_timeout=None
        for index,timeout in enumerate(READ_TIMEOUTS):
            try:
                p=subprocess.run([self.gh,'auth','token','--hostname','github.com'],check=False,
                                 capture_output=True,text=True,timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                last_timeout=exc
                if index+1 < len(READ_TIMEOUTS):
                    time.sleep(.25)
                    continue
                raise GitHubError(f'GitHub auth credential unavailable: {exc}') from exc
            except OSError as exc:
                raise GitHubError(f'GitHub auth credential unavailable: {exc}') from exc
            if p.returncode:
                raise GitHubError('GitHub auth credential unavailable')
            token=p.stdout.strip()
            if not token:
                raise GitHubError('GitHub auth credential unavailable')
            self._token=token
            return
        raise GitHubError(f'GitHub auth credential unavailable: {last_timeout}')
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
    def list_check_annotations(self, repo, check_run_id):
        self._validate(repo)
        return self._paginate(f'repos/{repo}/check-runs/{int(check_run_id)}/annotations')
    def get_workflow_run(self, repo, run_id):
        self._validate(repo)
        return self._get(f'repos/{repo}/actions/runs/{int(run_id)}')
    def list_workflow_runs_for_suite(self, repo, check_suite_id):
        self._validate(repo)
        out=[]
        for page in range(1,101):
            value=self._get(f'repos/{repo}/actions/runs',check_suite_id=int(check_suite_id),per_page=100,page=page)
            if not isinstance(value,dict) or not isinstance(value.get('workflow_runs'),list):
                raise GitHubError('expected workflow-runs page')
            rows=value['workflow_runs']; out.extend(rows)
            if len(rows)<100:return out
        raise GitHubError('workflow-runs pagination exceeded safety bound')
    def list_workflow_artifacts(self, repo, run_id):
        self._validate(repo); out=[]
        for page in range(1,101):
            value=self._get(f'repos/{repo}/actions/runs/{int(run_id)}/artifacts',per_page=100,page=page)
            if not isinstance(value,dict) or not isinstance(value.get('artifacts'),list):
                raise GitHubError('expected workflow-artifacts page')
            rows=value['artifacts']; out.extend(rows)
            if len(rows)<100:return out
        raise GitHubError('workflow-artifacts pagination exceeded safety bound')
    def list_workflow_jobs(self, repo, run_id):
        self._validate(repo)
        out=[]
        for page in range(1,101):
            value=self._get(f'repos/{repo}/actions/runs/{int(run_id)}/jobs',per_page=100,page=page)
            if not isinstance(value,dict) or not isinstance(value.get('jobs'),list):
                raise GitHubError('expected workflow-jobs page')
            rows=value['jobs']; out.extend(rows)
            if len(rows)<100:return out
        raise GitHubError('workflow-jobs pagination exceeded safety bound')
    def _get_bytes(self, endpoint, *, max_bytes=1024 * 1024):
        self._validate_endpoint(endpoint)
        if type(max_bytes) is not int or max_bytes <= 0:
            raise ValueError('invalid byte limit')
        process = None
        try:
            process = subprocess.Popen([self.gh, 'api', endpoint], stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, env=self._env())
            assert process.stdout is not None
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            output = bytearray()
            deadline = time.monotonic() + 30
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired([self.gh, 'api', endpoint], 30)
                events = selector.select(remaining)
                if not events:
                    raise subprocess.TimeoutExpired([self.gh, 'api', endpoint], 30)
                chunk = process.stdout.read1(min(65536, max_bytes + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > max_bytes:
                    raise GitHubError('response exceeds byte limit')
            returncode = process.wait(timeout=max(0.1, deadline - time.monotonic()))
            stderr = process.stderr.read(8192) if process.stderr is not None else b''
        except (OSError, subprocess.TimeoutExpired) as e:
            if process is not None:
                process.kill()
                process.wait()
            raise GitHubError(str(e)) from e
        except Exception:
            if process is not None:
                process.kill()
                process.wait()
            raise
        if returncode:
            raise GitHubError(stderr.decode(errors='replace').strip() or 'gh api failed')
        return bytes(output)
    def _validate_endpoint(self, endpoint):
        if not isinstance(endpoint,str) or endpoint.startswith(('/', 'http:', 'https:')):
            raise ValueError('invalid GitHub endpoint')
    def get_job_log(self, repo, job_id):
        self._validate(repo)
        return self._get_bytes(f'repos/{repo}/actions/jobs/{int(job_id)}/logs')
    def get_artifact_archive(self, repo, artifact_id):
        self._validate(repo)
        return self._get_bytes(f'repos/{repo}/actions/artifacts/{int(artifact_id)}/zip')
    def get_pr(self,repo,number): self._validate(repo); return self._get(f'repos/{repo}/pulls/{int(number)}')
    def create_comment(self, repo, pr_number, body):
        self._validate(repo)
        return self._post(f'repos/{repo}/issues/{int(pr_number)}/comments', {'body': body})
    def list_comments(self, repo, pr_number):
        self._validate(repo)
        return self._paginate(f'repos/{repo}/issues/{int(pr_number)}/comments')
    def get_issue(self,repo,number): self._validate(repo); return self._get(f'repos/{repo}/issues/{int(number)}')
    def get_file(self,repo,path,ref):
        self._validate(repo); value=self._get(f'repos/{repo}/contents/{path}',ref=ref)
        import base64
        try:return base64.b64decode(value['content']).decode()
        except Exception as e:raise GitHubError('task card acquisition failed') from e
    def get_patch(self,repo,number):
        self._validate(repo)
        try:
            return self._http_get(
                f'repos/{repo}/pulls/{int(number)}',
                accept='application/vnd.github.v3.patch',
            ).decode()
        except UnicodeDecodeError as exc:
            raise GitHubError('patch acquisition failed') from exc

    def _post(self, endpoint, payload):
        args=[self.gh,'api',endpoint,'--method','POST','--input','-']
        try:
            p=subprocess.run(args,input=json.dumps(payload),check=False,capture_output=True,text=True,
                             timeout=30,env=self._env())
        except (OSError, subprocess.TimeoutExpired) as e:
            raise GitHubError(str(e)) from e
        if p.returncode: raise GitHubError(p.stderr.strip() or 'gh api POST failed')
        try: return json.loads(p.stdout)
        except json.JSONDecodeError as e: raise GitHubError('invalid GitHub JSON') from e

def utc_now(): return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z')
