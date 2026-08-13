from __future__ import annotations
import hashlib,json
from pathlib import Path
from .semantic import parse_response,SemanticParseError
def receipt_path(root, identity):
    key=hashlib.sha256(json.dumps(list(identity),separators=(',',':')).encode()).hexdigest(); p=Path(root)/'reviews'/f'{key}.json'; p.parent.mkdir(parents=True,exist_ok=True); return p
def make_receipt(context, classification, transport, prompt, observed_at, parsed=None, parse_result='NOT_ATTEMPTED'):
    raw=transport.raw or ''; return {'schema':'reviewer.pre_review.v1','repository':context.review_identity[0],'pr_number':context.review_identity[1],'base_sha':context.review_identity[3],'head_sha':context.review_identity[2],'current_main_sha':context.review_identity[4],'review_identity':list(context.review_identity),'source_observed_at':observed_at,'source_identity':classification.snapshot.source_identity,'deterministic_findings':classification.findings,'risk':classification.risk,'changed_files':list(classification.snapshot.changed_files),'context_pack_sha256':context.context_sha256,'prompt_sha256':hashlib.sha256(prompt.encode()).hexdigest(),'opencli_executable':getattr(transport,'executable','fake'),'transport_result':transport.status,'raw_response_sha256':hashlib.sha256(raw.encode()).hexdigest() if raw else None,'parse_result':parse_result,'semantic_result':parsed,'claim_ceiling':'PRE_REVIEW_ONLY'}
def persist_receipt(root, receipt):
    p=receipt_path(root,tuple(receipt['review_identity'])); p.write_text(json.dumps(receipt,indent=2,sort_keys=True)); return p
def reusable_receipt(root, identity):
    p=receipt_path(root,identity)
    if not p.exists(): return None
    try:
        value=json.loads(p.read_text())
        if value.get('schema')=='reviewer.pre_review.v1' and value.get('transport_result')=='REVIEW_COMPLETED' and value.get('parse_result')=='PARSED': return value,p
    except (OSError,ValueError): pass
    return None
