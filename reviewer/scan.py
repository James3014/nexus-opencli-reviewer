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
def review_ready(repo,transport,pr_number,patch_provider,budget=200000,state_root='.reviewer-state'):
    from .review_context import ReviewContext, envelope, ContextError
    from .opencli import OpenCLITransport
    from .receipt import make_receipt,persist_receipt,reusable_receipt
    from .semantic import parse_response,SemanticParseError
    main_sha,observed,items,q=scan(repo,transport)
    selected=next((x for x in items if x.snapshot.pr_number==pr_number),None)
    if selected is None or selected.disposition.value!='REVIEW_READY': raise ContextError('PR_NOT_REVIEW_READY')
    current=next((x for x in scan(repo,transport)[2] if x.snapshot.pr_number==pr_number),None)
    if not current or current.review_identity!=selected.review_identity: raise ContextError('REVIEW_CONTEXT_STALE')
    try: context=ReviewContext.build(current,patch_provider(pr_number),budget)
    except ContextError: raise
    old=reusable_receipt(state_root,context.review_identity)
    if old:return old
    prompt=envelope(context); cli=OpenCLITransport(); result=cli.invoke(prompt)
    parsed=None; parse_result='NOT_ATTEMPTED'
    if result.status=='REVIEW_COMPLETED':
        try: parsed=parse_response(result.raw);parse_result='PARSED'
        except SemanticParseError: parse_result='REVIEW_PARSE_FAILED'
    receipt=make_receipt(context,current,result,prompt,observed,parsed,parse_result); path=persist_receipt(state_root,receipt); return receipt,path
