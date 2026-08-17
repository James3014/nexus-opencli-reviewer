import re
from .github import utc_now
from .models import CheckObservation, PRSnapshot

def issue_numbers(body, title=''):
    strong=[]
    for pat in (r'\bissue[- ]#?(\d+)\b',r'\b(?:implements|closes|fixes|resolves)\s+(?:issue\s*)?#(\d+)\b'):
        strong += [int(x) for x in re.findall(pat,body or '',re.I)]
    title_hits=[int(x) for x in re.findall(r'\bissue[- ]#?(\d+)\b',title or '',re.I)]
    return tuple(dict.fromkeys(title_hits+strong))
def markers(body):
    text=body or ''; low=text.lower()
    dnm=bool(re.search(r'\bdo[- ]not[- ]merge\b',low))
    expected=bool(re.search(r'controlled negative test|expected result\s*:\s*exit\s*\d+',low))
    return dnm,expected
def snapshot_from_github(repo, raw, main_sha, files, checks, observed_at=None, errors=()):
    body=raw.get('body') or ''; dnm,expected=markers(body)
    head=raw.get('head') or {}; base=raw.get('base') or {}
    complete=not errors
    normalized_checks = [{'name': x.get('name', x.get('context', 'check')),
                          'status': x.get('conclusion') or x.get('state', 'unknown'),
                          'expected_failure': bool(x.get('expected_failure', False)),
                          'check_run_id': x.get('id'), 'run_id': x.get('run_id'),
                          'external_id': x.get('external_id'), 'details_url': x.get('details_url'),
                          'html_url': x.get('html_url'), 'node_id': x.get('node_id'),
                          'workflow_name': x.get('workflow_name'), 'head_sha': x.get('head_sha'),
                          'check_suite_id': x.get('check_suite_id'),
                          'started_at': x.get('started_at'), 'completed_at': x.get('completed_at'),
                          'artifact_identity': x.get('artifact_identity'),
                          'annotation_count': x.get('annotation_count'), 'app_slug': x.get('app_slug')}
                         for x in checks]
    return PRSnapshot.from_dict({'repository':repo,'pr_number':int(raw['number']),'title':raw.get('title',''),'state':raw.get('state','OPEN'),'draft':bool(raw.get('draft',False)),'mergeable':raw.get('mergeable'),'base_branch':base.get('ref','main'),'base_sha':base.get('sha',''),'head_branch':head.get('ref',''),'head_sha':head.get('sha',''),'changed_files':[x.get('filename','') for x in files],'issue_numbers':issue_numbers(body,raw.get('title','')),'labels':[x.get('name','') if isinstance(x,dict) else str(x) for x in raw.get('labels',[])],'body':body,'checks':normalized_checks,'observed_at':observed_at or utc_now(),'source_identity':f'github:{repo}:pr:{raw["number"]}@{head.get("sha","")}', 'expected_failure':expected,'do_not_merge':dnm,'collection_complete':complete,'collection_errors':list(errors),'created_at':raw.get('created_at',''),'updated_at':raw.get('updated_at','')},main_sha)
