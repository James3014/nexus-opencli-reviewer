import re
from .github import utc_now
from .models import CheckObservation, PRSnapshot

def issue_numbers(body):
    strong=[]
    for pat in (r'\bissue[- ]#?(\d+)\b',r'\b(?:implements|closes|fixes|resolves)\s+(?:issue\s*)?#(\d+)\b'):
        strong += [int(x) for x in re.findall(pat,body or '',re.I)]
    return tuple(dict.fromkeys(strong))
def markers(body):
    text=body or ''; low=text.lower()
    dnm=bool(re.search(r'\bdo[- ]not[- ]merge\b',low))
    expected=bool(re.search(r'controlled negative test|expected result\s*:\s*exit\s*\d+',low))
    return dnm,expected
def snapshot_from_github(repo, raw, main_sha, files, checks, observed_at=None, errors=()):
    body=raw.get('body') or ''; dnm,expected=markers(body)
    head=raw.get('head') or {}; base=raw.get('base') or {}
    complete=not errors
    return PRSnapshot.from_dict({'repository':repo,'pr_number':int(raw['number']),'title':raw.get('title',''),'state':raw.get('state','OPEN'),'draft':bool(raw.get('draft',False)),'mergeable':raw.get('mergeable'),'base_branch':base.get('ref','main'),'base_sha':base.get('sha',''),'head_branch':head.get('ref',''),'head_sha':head.get('sha',''),'changed_files':[x.get('filename','') for x in files],'issue_numbers':issue_numbers(body),'labels':[x.get('name','') if isinstance(x,dict) else str(x) for x in raw.get('labels',[])],'body':body,'checks':[{'name':x.get('name',x.get('context','check')),'status':x.get('conclusion') or x.get('state','unknown')} for x in checks],'observed_at':observed_at or utc_now(),'source_identity':f'github:{repo}:pr:{raw["number"]}@{head.get("sha","")}', 'expected_failure':expected,'do_not_merge':dnm,'collection_complete':complete,'collection_errors':list(errors),'created_at':raw.get('created_at',''),'updated_at':raw.get('updated_at','')},main_sha)
