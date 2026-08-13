from .models import *
DEFAULT_AUTHORITY_PATTERNS=('AGENTS.md','docs/agents/','docs/governance/','policy/')
def classify(pr,authority_patterns=DEFAULT_AUTHORITY_PATTERNS):
    c=Classification(pr)
    def add(f,r=None): c.findings.append(f); c.reasons.append(r or f)
    if pr.base_sha!=pr.current_main_sha:add('STALE_BASE')
    if (pr.declared_base_sha and pr.declared_base_sha!=pr.base_sha) or (pr.declared_head_sha and pr.declared_head_sha!=pr.head_sha) or (pr.declared_main_sha and pr.declared_main_sha!=pr.current_main_sha):add('STALE_EVIDENCE')
    if pr.draft:add('DRAFT')
    if pr.mergeable is False:add('NON_MERGEABLE')
    if pr.do_not_merge or any(x.lower() in ('do-not-merge','do not merge') for x in pr.labels) or 'do not merge' in pr.body.lower():add('DO_NOT_MERGE')
    if pr.expected_failure or any(x.expected_failure for x in pr.checks):add('EXPECTED_FAILURE')
    if any(x.status.lower() in ('failure','failed','red') and not x.expected_failure for x in pr.checks):add('UNEXPECTED_FAILURE')
    if any(any(f==p or (p.endswith('/') and f.startswith(p)) for p in authority_patterns) for f in pr.changed_files):add('AUTHORITY_OVERLAP');c.risk='HIGH'
    if any(x.lower() in ('long-lived','stale-long-lived') for x in pr.labels):add('STALE_LONG_LIVED')
    blockers={'STALE_BASE','STALE_EVIDENCE','DRAFT','NON_MERGEABLE','DO_NOT_MERGE','STALE_LONG_LIVED'}
    if not (set(c.findings)&blockers):c.disposition=Disposition.REVIEW_READY
    elif 'DO_NOT_MERGE' in c.findings:c.disposition=Disposition.EVIDENCE_ONLY
    elif 'DRAFT' in c.findings or 'NON_MERGEABLE' in c.findings:c.disposition=Disposition.EXCLUDED
    elif 'STALE_LONG_LIVED' in c.findings or 'STALE_BASE' in c.findings or 'STALE_EVIDENCE' in c.findings:c.disposition=Disposition.STALE
    else:c.disposition=Disposition.NEEDS_ATTENTION
    return c
