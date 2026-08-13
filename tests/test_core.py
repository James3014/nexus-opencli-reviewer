import json
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
