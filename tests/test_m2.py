from reviewer.github import GhCliTransport
from reviewer.normalize import issue_numbers,markers,snapshot_from_github
from reviewer.classifier import classify
from reviewer.models import Disposition
from reviewer.scan import scan
from reviewer.github import GitHubError

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

def test_check_run_pagination_and_failure_closed(monkeypatch):
    t=GhCliTransport(); calls=[]
    def page(endpoint,**p):
        calls.append(p['page']); n=100 if p['page']==1 else 5
        return {'check_runs':[{'name':str(i),'conclusion':'success'} for i in range(n)]}
    monkeypatch.setattr(t,'_get',page); assert len(t.list_checks('o/r','h'))==105 and calls==[1,2]
    monkeypatch.setattr(t,'_get',lambda e,**p: (_ for _ in ()).throw(GitHubError('page failed')) if p['page']==2 else {'check_runs':[{}]*100})
    try:t.list_checks('o/r','h');assert False
    except GitHubError:pass

def test_title_issue_and_same_issue_chain():
    from reviewer.normalize import issue_numbers
    from reviewer.overlap import detect
    a=snapshot_from_github('o/r',{'number':1,'title':'feat(issue-163): x','base':{'sha':'m'},'head':{'sha':'h'},'body':''},'m',[],[])
    b=snapshot_from_github('o/r',{'number':2,'title':'other','base':{'sha':'m'},'head':{'sha':'h2'},'body':'Issue #163'},'m',[],[])
    from reviewer.classifier import classify
    xs=[classify(a),classify(b)];detect(xs);assert a.issue_numbers==(163,) and b.issue_numbers==(163,) and all('SAME_ISSUE_CHAIN' in x.findings for x in xs)
    assert issue_numbers('#191 and #143 excluded')==()

def test_live_state_persisted_and_context_changes(tmp_path):
    first=Fake(); _,_,xs,q=scan('o/r',first,persist_state=True,state_root=tmp_path)
    state=tmp_path/'o_r'; data=__import__('json').loads((state/'latest-scan.json').read_text()); assert data['current_main_sha']=='m' and data['items'][0]['head_sha']=='h'
    class Changed(Fake):
        def get_ref(self,r,b):return {'object':{'sha':'m2'}}
        def list_open_prs(self,r):
            x=super().list_open_prs(r)[0];x['head']['sha']='h2';return [x]
    scan('o/r',Changed(),persist_state=True,state_root=tmp_path); data2=__import__('json').loads((state/'latest-scan.json').read_text()); assert data2['current_main_sha']=='m2' and data2['items'][0]['review_identity'][-1]=='m2'
    assert 'token' not in (state/'latest-scan.json').read_text().lower()
