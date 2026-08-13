from __future__ import annotations
import json
MAX_TEXT=10_000; MAX_ITEMS=50
TOP_LEVEL_KEYS={'schema','status','summary','findings','evidence_gaps'}
FINDING_KEYS={'severity','category','path','evidence','reason','recommended_action'}
STATUSES={'PASS','FINDINGS','BLOCKED'}
SEVERITIES={'CRITICAL','HIGH','MEDIUM','LOW'}
class SemanticParseError(ValueError): pass

def response_contract():
    """The single machine-readable contract shared by prompt and parser."""
    return {
        'type':'object','additionalProperties':False,
        'required':sorted(TOP_LEVEL_KEYS),
        'properties':{
            'schema':{'const':'reviewer.semantic_response.v1'},
            'status':{'enum':sorted(STATUSES)},
            'summary':{'type':'string','maxLength':MAX_TEXT},
            'findings':{'type':'array','maxItems':MAX_ITEMS,'items':{
                'type':'object','additionalProperties':False,
                'required':sorted(FINDING_KEYS),
                'properties':{
                    'severity':{'enum':sorted(SEVERITIES)},
                    'category':{'type':'string','maxLength':MAX_TEXT},
                    'path':{'type':['string','null']},
                    'evidence':{'type':'string','maxLength':MAX_TEXT},
                    'reason':{'type':'string','maxLength':MAX_TEXT},
                    'recommended_action':{'type':'string','maxLength':MAX_TEXT},
                }}},
            'evidence_gaps':{'type':'array','maxItems':MAX_ITEMS,
                             'items':{'type':'string','maxLength':MAX_TEXT}},
        },
    }

def parse_response(text):
    try: value=json.loads(text)
    except Exception as e: raise SemanticParseError('REVIEW_PARSE_FAILED') from e
    if not isinstance(value,dict) or set(value)!=TOP_LEVEL_KEYS: raise SemanticParseError('REVIEW_PARSE_FAILED')
    if value.get('schema')!='reviewer.semantic_response.v1' or value.get('status') not in STATUSES: raise SemanticParseError('REVIEW_PARSE_FAILED')
    if not isinstance(value.get('summary'),str) or len(value['summary'])>MAX_TEXT or not isinstance(value.get('findings'),list) or not isinstance(value.get('evidence_gaps'),list): raise SemanticParseError('REVIEW_PARSE_FAILED')
    if len(value['findings'])>MAX_ITEMS or len(value['evidence_gaps'])>MAX_ITEMS: raise SemanticParseError('REVIEW_PARSE_FAILED')
    for f in value['findings']:
        if not isinstance(f,dict) or set(f)!=FINDING_KEYS or f.get('severity') not in SEVERITIES or not isinstance(f.get('path'),(str,type(None))): raise SemanticParseError('REVIEW_PARSE_FAILED')
        if any(not isinstance(f.get(k),str) or len(f[k])>MAX_TEXT for k in ('category','evidence','reason','recommended_action')): raise SemanticParseError('REVIEW_PARSE_FAILED')
    if any(not isinstance(x,str) or len(x)>MAX_TEXT for x in value['evidence_gaps']): raise SemanticParseError('REVIEW_PARSE_FAILED')
    return value
