from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import re

class Disposition(str, Enum):
    REVIEW_READY='REVIEW_READY'; WAIT_REBIND='WAIT_REBIND'; NEEDS_ATTENTION='NEEDS_ATTENTION'; EVIDENCE_ONLY='EVIDENCE_ONLY'; STALE='STALE'; EXCLUDED='EXCLUDED'
@dataclass(frozen=True)
class CheckObservation:
    name:str; status:str; expected_failure:bool=False
@dataclass(frozen=True)
class PRSnapshot:
    repository:str; pr_number:int; title:str; state:str; draft:bool; mergeable:bool|None; base_branch:str; base_sha:str; head_branch:str; head_sha:str; current_main_sha:str; changed_files:tuple[str,...]=(); issue_numbers:tuple[int,...]=(); labels:tuple[str,...]=(); body:str=''; checks:tuple[CheckObservation,...]=(); observed_at:str=''; source_identity:str='fixture'; declared_base_sha:str|None=None; declared_head_sha:str|None=None; declared_main_sha:str|None=None; expected_failure:bool=False; do_not_merge:bool=False
    @classmethod
    def from_dict(cls,d:dict[str,Any],main:str):
        body=d.get('body','') or ''
        def declared(key):
            if d.get('declared_'+key) is not None:return d['declared_'+key]
            m=re.search(rf'exact\s+{key}\s*[:=]\s*([A-Za-z0-9_-]+)',body,re.I)
            return m.group(1) if m else None
        return cls(d['repository'],int(d['pr_number']),d.get('title',''),d.get('state','OPEN'),bool(d.get('draft',False)),d.get('mergeable'),d.get('base_branch','main'),d['base_sha'],d.get('head_branch',''),d['head_sha'],main,tuple(d.get('changed_files',[])),tuple(d.get('issue_numbers',[])),tuple(d.get('labels',[])),body,tuple(CheckObservation(**x) for x in d.get('checks',[])),d.get('observed_at',''),d.get('source_identity','fixture'),declared('base'),declared('head'),declared('main'),bool(d.get('expected_failure',False)),bool(d.get('do_not_merge',False)))
@dataclass
class Classification:
    snapshot:PRSnapshot; findings:list[str]=field(default_factory=list); reasons:list[str]=field(default_factory=list); disposition:Disposition=Disposition.REVIEW_READY; risk:str='MED'; overlaps:dict[int,list[str]]=field(default_factory=dict)
    @property
    def review_identity(self):
        s=self.snapshot; return (s.repository,s.pr_number,s.head_sha,s.base_sha,s.current_main_sha)
    def to_dict(self): return {'pr_number':self.snapshot.pr_number,'disposition':self.disposition.value,'findings':self.findings,'reasons':self.reasons,'risk':self.risk,'overlaps':self.overlaps,'review_identity':list(self.review_identity)}
