from .github import GitHubError, utc_now
from .normalize import snapshot_from_github
from .classifier import classify
from .overlap import detect
from .queue import ReviewQueue
from pathlib import Path
import hashlib
import json, os, re, tempfile, time
from dataclasses import asdict

_TERMINAL_FAILURES={'failure','failed','error','cancelled','timed_out','action_required'}

def _collect_check_evidence(repo, check_rows, transport, pr_head_sha):
    """Enrich failed checks with immutable, read-only GitHub evidence."""
    enriched=[]; errors=[]
    for check in check_rows:
        row=dict(check)
        status=str(row.get('conclusion') or row.get('status') or row.get('state','unknown')).lower()
        if status not in _TERMINAL_FAILURES or row.get('expected_failure'):
            enriched.append(row); continue
        check_id=row.get('id') or row.get('check_run_id')
        run_id=row.get('run_id')
        if type(check_id) is not int or check_id<=0:
            errors.append('check annotations: check run identity unavailable')
        else:
            try:
                annotations=transport.list_check_annotations(repo,check_id)
                row['annotation_count']=len(annotations)
            except Exception as exc:
                errors.append(f'check annotations: {type(exc).__name__}: {exc}')
        if type(run_id) is not int or run_id<=0:
            errors.append('workflow run: run identity unavailable')
        else:
            try:
                run=transport.get_workflow_run(repo,run_id)
                run_head=run.get('head_sha')
                if run_head and run_head != pr_head_sha:
                    errors.append('workflow run: foreign head identity')
                row['workflow_name']=row.get('workflow_name') or run.get('name')
                row['head_sha']=row.get('head_sha') or run_head
                if not row.get('details_url'):
                    row['details_url']=run.get('html_url') or run.get('logs_url')
            except Exception as exc:
                errors.append(f'workflow run: {type(exc).__name__}: {exc}')
            try:
                artifacts=transport.list_workflow_artifacts(repo,run_id)
                identities=[str(x.get('id')) for x in artifacts if x.get('id') is not None]
                if identities:
                    row['artifact_identity']=row.get('artifact_identity') or '|'.join(sorted(identities))
                else:
                    errors.append('workflow artifacts: artifact identity unavailable')
            except Exception as exc:
                errors.append(f'workflow artifacts: {type(exc).__name__}: {exc}')
        enriched.append(row)
    return enriched, errors

def _ci_evidence_for(classification):
    from .receipt import build_ci_failure_evidence
    snapshot=classification.snapshot
    failed=[asdict(x) for x in snapshot.checks
            if x.status.lower() in _TERMINAL_FAILURES and not x.expected_failure]
    if not failed:
        return None
    selected=failed[0]
    return build_ci_failure_evidence(
        repository=snapshot.repository, pr_number=snapshot.pr_number,
        base_sha=snapshot.base_sha, head_sha=snapshot.head_sha,
        current_main_sha=snapshot.current_main_sha, checks=failed,
        collection_complete=snapshot.collection_complete,
        collection_errors=snapshot.collection_errors,
        expected_check_run_id=selected.get('check_run_id'),
        expected_run_id=selected.get('run_id'),
        expected_artifact_identity=(selected.get('artifact_identity') or selected.get('external_id')),
        canonical_disposition='NOT_AVAILABLE')

def _atomic_json(path, value):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    data=(json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
    fd,tmp=tempfile.mkstemp(prefix=f'.{path.name}.',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        try:os.unlink(tmp)
        except FileNotFoundError:pass
def persist(repo, main_sha, observed, items, queue, root='.reviewer-state'):
    safe=re.sub(r'[^A-Za-z0-9_.-]+','_',repo)
    d=Path(root)/safe; d.mkdir(parents=True,exist_ok=True)
    identities=[list(i) for i in sorted(queue._seen)]
    _atomic_json(d/'latest-scan.json',{'repository':repo,'observed_at':observed,'current_main_sha':main_sha,'items':[x.to_dict() for x in items],'queue_identities':identities})
    queue.save(d/'queue-state.json')
    return d
def scan(repo,transport,authority_patterns=None,persist_state=False,state_root='.reviewer-state'):
    transport.auth_preflight() if hasattr(transport,'auth_preflight') else None
    ref=transport.get_ref(repo,'main'); main_sha=ref['object']['sha']; observed=utc_now(); out=[]
    for raw in transport.list_open_prs(repo):
        errors=[]
        try: files=transport.list_files(repo,raw['number'])
        except Exception as e: files=[]; errors.append(f'changed_files: {e}')
        try:
            checks=transport.list_checks(repo,raw.get('head',{}).get('sha',''))
            checks, enrichment_errors=_collect_check_evidence(
                repo, checks, transport, raw.get('head',{}).get('sha',''))
            errors.extend(enrichment_errors)
        except Exception as e: checks=[]; errors.append(f'checks: {e}')
        p=snapshot_from_github(repo,raw,main_sha,files,checks,observed,errors)
        out.append(classify(p,authority_patterns) if authority_patterns else classify(p))
    detect(out); q=ReviewQueue();q.ingest(out)
    if persist_state:persist(repo,main_sha,observed,out,q,state_root)
    return main_sha,observed,out,q
def review_ready(repo,transport,pr_number,semantic_transport=None,patch_provider=None,budget=200000,state_root='.reviewer-state',dispatch_gate=None,resume_attempt=None,profile_resolver=None,allow_semantic_dispatch=True):
    from .review_context import ReviewContext, envelope, ContextError, SemanticReviewError
    from .receipt import make_receipt,persist_receipt,persist_failure,reusable_receipt
    from .semantic import parse_response,SemanticParseError
    from .attempt import (prepare_attempt, mark_dispatching, finish_attempt,
                          discover_for_identity, load_attempt, PREPARED, COMPLETED, FAILED, OUTCOME_UNKNOWN)
    main_sha,observed,items,q=scan(repo,transport)
    selected=next((x for x in items if x.snapshot.pr_number==pr_number),None)
    if selected is None or selected.disposition.value!='REVIEW_READY': raise ContextError('PR_NOT_REVIEW_READY')
    current=selected
    try:
        patch=patch_provider(pr_number) if patch_provider else transport.get_patch(repo,pr_number)
        extra={}
        if hasattr(transport,'get_issue'): extra['issues']=[transport.get_issue(repo,n) for n in current.snapshot.issue_numbers]
        if hasattr(transport,'get_file'):
            extra['task_cards']={path:transport.get_file(repo,path,current.snapshot.head_sha) for path in current.snapshot.changed_files if path.startswith('tasks/') and path.endswith('.md')}
        context=ReviewContext.build(current,patch,budget,extra)
    except ContextError: raise
    except Exception as e: raise ContextError('CONTEXT_INCOMPLETE') from e
    rebound=transport.get_pr(repo,pr_number) if hasattr(transport,'get_pr') else None
    main_rebound=transport.get_ref(repo,'main')['object']['sha'] if hasattr(transport,'get_ref') else current.snapshot.current_main_sha
    if rebound is not None:
        identity=(repo,pr_number,(rebound.get('head') or {}).get('sha',''),(rebound.get('base') or {}).get('sha',''),main_rebound)
        if identity!=context.review_identity: raise ContextError('REVIEW_CONTEXT_STALE')
    prompt=envelope(context)
    prompt_sha = hashlib.sha256(prompt.encode()).hexdigest()
    old=reusable_receipt(state_root,context.review_identity,
                         context_sha256=context.context_sha256,
                         prompt_sha256=prompt_sha)
    if old:return old
    if not allow_semantic_dispatch:
        raise ContextError('COMPLETED_IDENTITY_NOT_FOUND')
    if semantic_transport is None: raise ContextError('SEMANTIC_TRANSPORT_REQUIRED')
    # An unfinished attempt for this exact identity is ambiguous: never replay
    # an external semantic request until an operator reconciles it.
    # Any prior dispatch-bound attempt without a reusable exact-context receipt
    # is ambiguous or already consumed. Never send a second semantic call.
    prior=discover_for_identity(state_root, context.review_identity,
                                context_pack_sha256=context.context_sha256,
                                prompt_sha256=prompt_sha)
    attempt=None;attempt_path=None
    if resume_attempt:
        attempt,attempt_path=load_attempt(state_root,resume_attempt)
        if (attempt not in prior or attempt.get('state')!=PREPARED
                or attempt.get('retry_safe') is not True
                or attempt.get('dispatching_at') is not None):
            raise ContextError('ATTEMPT_NOT_SAFE_TO_RESUME')
        profile=attempt.get('browser_profile')
        if not profile: raise ContextError('ATTEMPT_PROFILE_MISSING')
        semantic_transport.profile=str(profile)
    elif prior:
        raise ContextError('RECONCILIATION_REQUIRED')
    elif profile_resolver is not None:
        semantic_transport.profile=str(profile_resolver())
    provenance = {
        'source': 'review_ready',
        'executable': getattr(semantic_transport, 'executable', 'unknown'),
        'version': (semantic_transport.version() if callable(getattr(semantic_transport, 'version', None)) else getattr(semantic_transport, 'version', '')),
    }
    if attempt is None:
        attempt, attempt_path = prepare_attempt(state_root, context.review_identity,
                                          context.context_sha256, prompt_sha,
                                          provenance,
                                          safe_argv=(semantic_transport.safe_argv() if hasattr(semantic_transport, 'safe_argv') else []),
                                          executable=provenance['executable'], version=provenance['version'],
                                          browser_profile=getattr(semantic_transport, 'profile', None),
                                          session_mode='ephemeral')
    if dispatch_gate:
        gate=Path(dispatch_gate);deadline=time.monotonic()+120
        while not gate.exists():
            if time.monotonic()>=deadline:
                raise ContextError(f'DISPATCH_GATE_TIMEOUT attempt={attempt_path}')
            time.sleep(.1)
    mark_dispatching(attempt_path)
    try:
        result=semantic_transport.invoke(prompt)
    except Exception as exc:
        finish_attempt(attempt_path, OUTCOME_UNKNOWN, result={'error': type(exc).__name__})
        raise
    parsed=None; parse_result='NOT_ATTEMPTED'
    if result.status=='REVIEW_COMPLETED':
        try: parsed=parse_response(result.raw);parse_result='PARSED'
        except SemanticParseError: parse_result='REVIEW_PARSE_FAILED'
    terminal = (COMPLETED if result.status == 'REVIEW_COMPLETED' and parse_result == 'PARSED'
                else (OUTCOME_UNKNOWN if getattr(result, 'outcome_unknown', False) or result.status == 'OPENCLI_OUTCOME_UNKNOWN' else FAILED))
    finish_attempt(attempt_path, terminal, result={'transport_result': result.status, 'parse_result': parse_result}, retry_safe=False)
    if parse_result == 'REVIEW_PARSE_FAILED':
        path=persist_failure(state_root,attempt['attempt_id'],{
            'review_identity':list(context.review_identity),'context_pack_sha256':context.context_sha256,
            'prompt_sha256':prompt_sha,'transport_result':result.status,'parse_result':parse_result,
            'raw_response_sha256':hashlib.sha256((result.raw or '').encode()).hexdigest() or None,
            'claim_ceiling':'PRE_REVIEW_ONLY','retry_safe':False})
        raise SemanticReviewError(f'REVIEW_PARSE_FAILED evidence={path}')
    if result.status != 'REVIEW_COMPLETED':
        path=persist_failure(state_root,attempt['attempt_id'],{
            'review_identity':list(context.review_identity),'context_pack_sha256':context.context_sha256,
            'prompt_sha256':prompt_sha,'transport_result':result.status,'parse_result':parse_result,
            'raw_response_sha256':hashlib.sha256((result.raw or '').encode()).hexdigest() if result.raw else None,
            'claim_ceiling':'PRE_REVIEW_ONLY','retry_safe':False})
        raise SemanticReviewError(f'{result.status} evidence={path}')
    receipt=make_receipt(context,current,result,prompt,observed,parsed,parse_result,
                         ci_failure_evidence=_ci_evidence_for(current))
    path=persist_receipt(state_root,receipt)
    return receipt,path
