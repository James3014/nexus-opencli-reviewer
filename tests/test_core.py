import json
from pathlib import Path
from reviewer.collector import load_fixture
from reviewer.classifier import classify
from reviewer.overlap import detect
from reviewer.models import Disposition, PRSnapshot
from reviewer.queue import ReviewQueue

def test_fixture_behaviors():
    xs=[classify(x) for x in load_fixture('tests/fixtures/prs.json','main-2')]; detect(xs); by={x.snapshot.pr_number:x for x in xs}
    assert by[1].disposition==Disposition.WAIT_REBIND
    assert 'STALE_BASE' in by[2].findings and by[2].disposition==Disposition.STALE
    assert 'PATH_OVERLAP' in by[1].findings
    assert 'AUTHORITY_OVERLAP' in by[4].findings
    assert 'SAME_ISSUE_CHAIN' in by[3].findings
    assert by[6].disposition==Disposition.EXCLUDED
    assert by[7].disposition==Disposition.EXCLUDED
    assert by[8].disposition==Disposition.EVIDENCE_ONLY
    assert 'STALE_EVIDENCE' in by[9].findings
    assert 'STALE_LONG_LIVED' in by[10].findings

def test_semantic_queue_boundaries_and_authority():
    current=classify(PRSnapshot.from_dict({'repository':'r','pr_number':1,'base_sha':'m','head_sha':'h'},'m'))
    authority=classify(PRSnapshot.from_dict({'repository':'r','pr_number':2,'base_sha':'m','head_sha':'h2','changed_files':['custom/policy.yml']},'m'), authority_patterns=('custom/',))
    dnm=classify(PRSnapshot.from_dict({'repository':'r','pr_number':3,'base_sha':'m','head_sha':'h3','do_not_merge':True},'m'))
    draft=classify(PRSnapshot.from_dict({'repository':'r','pr_number':4,'base_sha':'m','head_sha':'h4','draft':True},'m'))
    held=classify(PRSnapshot.from_dict({'repository':'r','pr_number':5,'base_sha':'old','head_sha':'h5'},'m'))
    q=ReviewQueue();q.ingest([current,authority,dnm,draft,held])
    assert current.disposition==Disposition.REVIEW_READY
    assert authority.disposition==Disposition.REVIEW_READY and authority.risk=='HIGH' and 'AUTHORITY_OVERLAP' in authority.findings
    assert {x.snapshot.pr_number for x in q.semantic_review()}=={1,2}
    assert dnm not in q.semantic_review() and draft not in q.semantic_review() and held not in q.semantic_review()

def test_overlap_paths_and_state_persistence(tmp_path):
    a=classify(PRSnapshot.from_dict({'repository':'r','pr_number':1,'base_sha':'m','head_sha':'h','changed_files':['a.py','shared.py']},'m'))
    b=classify(PRSnapshot.from_dict({'repository':'r','pr_number':2,'base_sha':'m','head_sha':'h2','changed_files':['shared.py']},'m'))
    detect([a,b]);assert a.overlaps=={2:['shared.py']}
    q=ReviewQueue();q.ingest([a]);p=tmp_path/'state.json';q.save(p);loaded=ReviewQueue.load(p);loaded.ingest([a,b]);assert len(loaded.items)==1
    changed=classify(PRSnapshot.from_dict({'repository':'r','pr_number':1,'base_sha':'m','head_sha':'h3'},'m'));loaded.ingest([changed]);assert len(loaded.items)==2

def test_lineage_and_declared_evidence():
    p=PRSnapshot.from_dict({'repository':'r','pr_number':1,'base_sha':'physical-base','head_sha':'physical-head','body':'Exact head: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','observed_at':'now','source_identity':'fixture:x'},'main')
    assert p.observed_at=='now' and p.source_identity=='fixture:x'
    assert classify(p).snapshot.head_sha=='physical-head' and 'STALE_EVIDENCE' in classify(p).findings

def test_identity_changes_with_head_and_context():
    a=PRSnapshot.from_dict({'repository':'r','pr_number':1,'base_sha':'b','head_sha':'h'},'m1')
    b=PRSnapshot.from_dict({'repository':'r','pr_number':1,'base_sha':'b','head_sha':'h2'},'m1')
    c=PRSnapshot.from_dict({'repository':'r','pr_number':1,'base_sha':'b','head_sha':'h'},'m2')
    assert classify(a).review_identity!=classify(b).review_identity
    assert classify(a).review_identity!=classify(c).review_identity

def test_queue_dedupes_exact_identity_only():
    a=classify(PRSnapshot.from_dict({'repository':'r','pr_number':1,'base_sha':'b','head_sha':'h'},'m'))
    b=classify(PRSnapshot.from_dict({'repository':'r','pr_number':1,'base_sha':'b','head_sha':'h2'},'m'))
    q=ReviewQueue();q.ingest([a,a,b]);assert len(q.items)==2

def test_expected_and_unexpected_failures_are_distinct():
    expected=classify(PRSnapshot.from_dict({'repository':'r','pr_number':1,'base_sha':'m','head_sha':'h','expected_failure':True,'checks':[{'name':'x','status':'failure','expected_failure':True}]},'m'))
    unexpected=classify(PRSnapshot.from_dict({'repository':'r','pr_number':2,'base_sha':'m','head_sha':'h2','checks':[{'name':'x','status':'failure'}]},'m'))
    assert 'EXPECTED_FAILURE' in expected.findings and 'UNEXPECTED_FAILURE' not in expected.findings
    assert 'UNEXPECTED_FAILURE' in unexpected.findings and 'EXPECTED_FAILURE' not in unexpected.findings
