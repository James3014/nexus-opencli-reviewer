from reviewer.github import GhCliTransport
from reviewer.normalize import issue_numbers,markers,snapshot_from_github
from reviewer.classifier import classify
from reviewer.models import Disposition
from reviewer.scan import scan

class Fake:
    def __init__(self,fail=False):self.fail=fail
    def auth_preflight(self):
        if self.fail: raise RuntimeError('auth failed')
    def get_ref(self,r,b):return {'object':{'sha':'m'}}
    def list_open_prs(self,r):return [{'number':1,'title':'x','state':'open','draft':False,'mergeable':True,'base':{'ref':'main','sha':'m'},'head':{'ref':'f','sha':'h'},'body':'Exact head: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`','labels':[]}]
    def list_files(self,r,n):return [{'filename':'a.py'}]
    def list_checks(self,r,s):return []

def test_pagination_and_repo_validation(monkeypatch):
    t=GhCliTransport(); calls=[]
    monkeypatch.setattr(t,'_get',lambda e,**p: calls.append((e,p)) or ([{'filename':'a'}]*100 if p['page']==1 else [{'filename':'b'}]))
    assert len(t.list_files('o/r',1))==101 and len(calls)==2
    try:t.list_files('bad;rm -rf /',1);assert False
    except ValueError:pass

def test_normalization_and_issue_controls():
    body='Implements Issue #116. Excluded #191 and #143. controlled negative test Expected result: exit 2. DO NOT MERGE'
    assert issue_numbers(body)==(116,) and markers(body)==(True,True)
    p=snapshot_from_github('o/r',{'number':1,'base':{'sha':'m'},'head':{'sha':'h'},'body':'Exact head: `old`'},'m',[{'filename':'x'}],[])
    assert p.head_sha=='h' and p.declared_head_sha is None

def test_scan_incomplete_is_not_review_ready():
    class Incomplete(Fake):
        def list_files(self,r,n):raise RuntimeError('timeout')
    _,_,xs,q=scan('o/r',Incomplete());assert 'COLLECTION_INCOMPLETE' in xs[0].findings and not q.semantic_review()

def test_scan_auth_failure_is_not_empty_success():
    try:scan('o/r',Fake(True));assert False
    except RuntimeError:pass
