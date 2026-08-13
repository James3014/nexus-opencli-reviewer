import argparse,json
from pathlib import Path
from .collector import load_fixture
from .classifier import classify
from .overlap import detect
from .github import GhCliTransport, GitHubError
from .scan import scan,review_ready
from .attempt import reconcile_unfinished, reconcile_attempt
from .opencli import OpenCLITransport
from .review_context import ContextError
from .status import inventory
from .preflight import preflight_opencli
from .publication import publish_review, reconcile_publication, PublicationError
def main():
    p=argparse.ArgumentParser();p.add_argument('--fixtures');p.add_argument('--main-sha');p.add_argument('--repo');p.add_argument('--review-pr',type=int);p.add_argument('--local-only',action='store_true');p.add_argument('--dispatch-gate');p.add_argument('--opencli',default='opencli');p.add_argument('--reconcile-attempt', action='store_true');p.add_argument('--reconcile-semantic',metavar='ATTEMPT_ID');p.add_argument('--reconcile-publication');p.add_argument('--publish-receipt');p.add_argument('--status', action='store_true');p.add_argument('--preflight', action='store_true');p.add_argument('--state-root', default='.reviewer-state');p.add_argument('--json',action='store_true');a=p.parse_args()
    try:
        if a.publish_receipt:
            receipt=json.loads(Path(a.publish_receipt).read_text())
            path=publish_review(a.state_root, GhCliTransport(), receipt)
            payload={'status':'AUTOMATED_PRE_REVIEW_PUBLISHED','claim_ceiling':'PRE_REVIEW_ONLY','path':str(path),'evidence_path':str(path)}
            print(json.dumps(payload,indent=2,sort_keys=True) if a.json else f"AUTOMATED_PRE_REVIEW_PUBLISHED claim=PRE_REVIEW_ONLY evidence={path}")
            return
        if a.reconcile_publication:
            path=reconcile_publication(a.state_root, GhCliTransport(), a.reconcile_publication)
            payload={'status':'PUBLICATION_RECONCILED','claim_ceiling':'PRE_REVIEW_ONLY','path':str(path),'evidence_path':str(path)}
            print(json.dumps(payload,indent=2,sort_keys=True) if a.json else f"RECONCILED {path}")
            return
        if a.status:
            payload=inventory(a.state_root)
            print(json.dumps(payload,indent=2,sort_keys=True) if a.json else f"STATUS root={a.state_root} invalid={len(payload['invalid_files'])}")
            return
        if a.preflight:
            result=preflight_opencli(a.opencli)
            payload={'status':result.status,'profile':result.profile,'profiles':result.profiles,'argv':result.argv,'evidence_path':a.state_root}
            print(json.dumps(payload,indent=2,sort_keys=True) if a.json else f"PREFLIGHT {result.status}")
            return 0 if result.status=='READY' else 2
        if a.reconcile_semantic:
            record = reconcile_attempt(a.state_root,a.reconcile_semantic)
            payload={'status':'SEMANTIC_RECONCILED','attempt_id':a.reconcile_semantic,'evidence_path':str(Path(a.state_root)/'reviews'/'attempts'/f'{a.reconcile_semantic}.json'),'attempt':record}
            print(json.dumps(payload,indent=2,sort_keys=True) if a.json else f"SEMANTIC_RECONCILED {a.reconcile_semantic}")
            return
        if a.reconcile_attempt:
            records = reconcile_unfinished(a.state_root)
            evidence = str(Path(a.state_root) / 'reviews' / 'attempts')
            payload = {'status':'RECONCILED','count':len(records),'evidence_path':evidence,'attempts':records}
            print(json.dumps(payload,indent=2,sort_keys=True) if a.json else f"RECONCILED {len(records)} evidence={evidence}")
            return
        if a.review_pr is not None and not a.repo: raise ValueError('--review-pr requires --repo')
        if a.review_pr is not None:
            ready=preflight_opencli(a.opencli)
            if ready.status!='READY': raise ContextError(ready.status)
            profile=(ready.profile or {}).get('id') or (ready.profile or {}).get('contextId') or (ready.profile or {}).get('name')
            if not profile: raise ContextError('PROFILE_SELECTION_AMBIGUOUS')
            gh=GhCliTransport()
            result=review_ready(a.repo,gh,a.review_pr,OpenCLITransport(executable=a.opencli,profile=str(profile)),state_root=a.state_root,dispatch_gate=a.dispatch_gate)
            payload=dict(result[0]); payload['evidence_path']=str(result[1])
            if not a.local_only and payload.get('parse_result')=='PARSED' and payload.get('semantic_result',{}).get('status') in {'PASS','FINDINGS'}:
                publication_path=publish_review(a.state_root,gh,payload)
                payload['status']='AUTOMATED_PRE_REVIEW_PUBLISHED';payload['claim_ceiling']='PRE_REVIEW_ONLY';payload['publication_evidence_path']=str(publication_path)
            print(json.dumps(payload,indent=2,sort_keys=True) if a.json else f'{payload.get("status","PRE_REVIEW")} claim=PRE_REVIEW_ONLY evidence={result[1]}')
            return
        if a.repo:
            main_sha,observed,xs,q=scan(a.repo,GhCliTransport(),persist_state=True,state_root=a.state_root)
        elif a.fixtures and a.main_sha:
            xs=[classify(x) for x in load_fixture(a.fixtures,a.main_sha)];detect(xs)
        else: raise ValueError('provide --repo or --fixtures with --main-sha')
    except (GitHubError,ValueError,ContextError,PublicationError,OSError,json.JSONDecodeError) as e:
        payload={'status':'ERROR','error':str(e),'evidence_path':str(__import__('pathlib').Path(a.state_root))}
        print(json.dumps(payload,indent=2,sort_keys=True) if a.json else f"ERROR {e} evidence={payload['evidence_path']}")
        return 2
    if a.json:print(json.dumps([x.to_dict() for x in xs],indent=2,sort_keys=True))
    else:
        print('PR    DISPOSITION       RISK   REASONS')
        for x in sorted(xs,key=lambda x:x.snapshot.pr_number):print(f'{x.snapshot.pr_number:<5} {x.disposition.value:<17} {x.risk:<6} {",".join(x.findings) or "-"}')
if __name__=='__main__': raise SystemExit(main() or 0)
