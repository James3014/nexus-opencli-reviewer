from __future__ import annotations
import hashlib,json
import os,tempfile
from datetime import datetime,timezone
from pathlib import Path
from .semantic import parse_response,SemanticParseError
def receipt_path(root, identity):
    key=hashlib.sha256(json.dumps(list(identity),separators=(',',':')).encode()).hexdigest(); p=Path(root)/'reviews'/f'{key}.json'; p.parent.mkdir(parents=True,exist_ok=True); return p
def make_receipt(context, classification, transport, prompt, observed_at, parsed=None, parse_result='NOT_ATTEMPTED'):
    raw=transport.raw or ''; now=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z'); version=getattr(transport,'version',''); version=version() if callable(version) else version; prompt_sha=hashlib.sha256(prompt.encode()).hexdigest(); raw_sha=hashlib.sha256(raw.encode()).hexdigest() if raw else None; receipt_id=hashlib.sha256(json.dumps({'identity':list(context.review_identity),'context':context.context_sha256,'prompt':prompt_sha,'raw':raw_sha},sort_keys=True,separators=(',',':')).encode()).hexdigest(); return {'schema':'reviewer.pre_review.v1','receipt_id':receipt_id,'repository':context.review_identity[0],'pr_number':context.review_identity[1],'base_sha':context.review_identity[3],'head_sha':context.review_identity[2],'current_main_sha':context.review_identity[4],'review_identity':list(context.review_identity),'source_observed_at':observed_at,'source_identity':classification.snapshot.source_identity,'deterministic_findings':classification.findings,'risk':classification.risk,'changed_files':list(classification.snapshot.changed_files),'context_pack_sha256':context.context_sha256,'prompt_sha256':prompt_sha,'opencli_executable':getattr(transport,'executable','fake'),'opencli_version':version,'browser_profile':getattr(transport,'profile',None),'session_mode':getattr(transport,'session_mode','ephemeral'),'safe_argv':getattr(transport,'argv',[]),'invocation_started_at':getattr(transport,'started_at',now) or now,'invocation_finished_at':getattr(transport,'finished_at',now) or now,'transport_result':transport.status,'outcome_unknown':getattr(transport,'outcome_unknown',False),'retry_safe':getattr(transport,'retry_safe',False),'raw_response_sha256':raw_sha,'parse_result':parse_result,'semantic_result':parsed,'claim_ceiling':'PRE_REVIEW_ONLY'}
def persist_receipt(root, receipt):
    p=receipt_path(root,tuple(receipt['review_identity']))
    data=(json.dumps(receipt,indent=2,sort_keys=True)+'\n').encode()
    fd,tmp=tempfile.mkstemp(prefix=f'.{p.name}.',dir=p.parent)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,p)
    finally:
        try: os.unlink(tmp)
        except FileNotFoundError: pass
    return p
def persist_failure(root, attempt_id, evidence):
    p=Path(root)/'reviews'/'failures'/f'{attempt_id}.json';p.parent.mkdir(parents=True,exist_ok=True)
    value={'schema':'reviewer.semantic_failure.v1','attempt_id':attempt_id,**evidence}
    data=(json.dumps(value,indent=2,sort_keys=True)+'\n').encode();fd,tmp=tempfile.mkstemp(prefix=f'.{p.name}.',dir=p.parent)
    try:
        with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(tmp,p)
    finally:
        try:os.unlink(tmp)
        except FileNotFoundError:pass
    return p
def reusable_receipt(root, identity, *, context_sha256=None, prompt_sha256=None):
    p=receipt_path(root,identity)
    if not p.exists(): return None
    try:
        value=json.loads(p.read_text())
        if (value.get('schema')=='reviewer.pre_review.v1'
            and value.get('review_identity') == list(identity)
            and value.get('transport_result')=='REVIEW_COMPLETED'
            and value.get('parse_result')=='PARSED'
            and value.get('claim_ceiling')=='PRE_REVIEW_ONLY'
            and value.get('outcome_unknown') is False
            and isinstance(value.get('semantic_result'),dict)
            and value['semantic_result'].get('schema')=='reviewer.semantic_response.v1'
            and value.get('context_pack_sha256')
            and value.get('prompt_sha256')
            and (context_sha256 is None or value.get('context_pack_sha256') == context_sha256)
            and (prompt_sha256 is None or value.get('prompt_sha256') == prompt_sha256)
        ): return value,p
    except (OSError,ValueError): pass
    return None
