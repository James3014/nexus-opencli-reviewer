from __future__ import annotations
import json
MAX_TEXT=10_000; MAX_ITEMS=50
class SemanticParseError(ValueError): pass
def parse_response(text):
    try: value=json.loads(text)
    except Exception as e: raise SemanticParseError('REVIEW_PARSE_FAILED') from e
    if not isinstance(value,dict) or set(value)-{'schema','status','summary','findings','evidence_gaps'}: raise SemanticParseError('REVIEW_PARSE_FAILED')
    if value.get('schema')!='reviewer.semantic_response.v1' or value.get('status') not in {'PASS','FINDINGS','BLOCKED'}: raise SemanticParseError('REVIEW_PARSE_FAILED')
    if not isinstance(value.get('summary'),str) or len(value['summary'])>MAX_TEXT or not isinstance(value.get('findings'),list) or not isinstance(value.get('evidence_gaps'),list): raise SemanticParseError('REVIEW_PARSE_FAILED')
    if len(value['findings'])>MAX_ITEMS or len(value['evidence_gaps'])>MAX_ITEMS: raise SemanticParseError('REVIEW_PARSE_FAILED')
    allowed={'severity','category','path','evidence','reason','recommended_action'}
    for f in value['findings']:
        if not isinstance(f,dict) or set(f)-allowed or f.get('severity') not in {'CRITICAL','HIGH','MEDIUM','LOW'} or not isinstance(f.get('path'),(str,type(None))): raise SemanticParseError('REVIEW_PARSE_FAILED')
        if any(not isinstance(f.get(k),str) or len(f[k])>MAX_TEXT for k in ('category','evidence','reason','recommended_action')): raise SemanticParseError('REVIEW_PARSE_FAILED')
    if any(not isinstance(x,str) or len(x)>MAX_TEXT for x in value['evidence_gaps']): raise SemanticParseError('REVIEW_PARSE_FAILED')
    return value
