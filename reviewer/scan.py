from .github import GitHubError, utc_now
from .normalize import snapshot_from_github
from .classifier import classify
from .overlap import detect
from .queue import ReviewQueue
from pathlib import Path
import json, re
def persist(repo, main_sha, observed, items, queue, root='.reviewer-state'):
    safe=re.sub(r'[^A-Za-z0-9_.-]+','_',repo)
    d=Path(root)/safe; d.mkdir(parents=True,exist_ok=True)
    (d/'latest-scan.json').write_text(json.dumps({'repository':repo,'observed_at':observed,'current_main_sha':main_sha,'items':[x.to_dict() for x in items]},indent=2,sort_keys=True))
    queue.save(d/'queue-state.json')
    return d
def scan(repo,transport,authority_patterns=None,persist_state=False,state_root='.reviewer-state'):
    transport.auth_preflight() if hasattr(transport,'auth_preflight') else None
    ref=transport.get_ref(repo,'main'); main_sha=ref['object']['sha']; observed=utc_now(); out=[]
    for raw in transport.list_open_prs(repo):
        errors=[]
        try: files=transport.list_files(repo,raw['number'])
        except Exception as e: files=[]; errors.append(f'changed_files: {e}')
        try: checks=transport.list_checks(repo,raw.get('head',{}).get('sha',''))
        except Exception as e: checks=[]; errors.append(f'checks: {e}')
        p=snapshot_from_github(repo,raw,main_sha,files,checks,observed,errors)
        out.append(classify(p,authority_patterns) if authority_patterns else classify(p))
    detect(out); q=ReviewQueue();q.ingest(out)
    if persist_state:persist(repo,main_sha,observed,out,q,state_root)
    return main_sha,observed,out,q
