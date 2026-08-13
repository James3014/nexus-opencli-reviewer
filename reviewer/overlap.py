from .models import Disposition
def detect(items):
    for i,a in enumerate(items):
        for b in items[i+1:]:
            paths=sorted(set(a.snapshot.changed_files)&set(b.snapshot.changed_files))
            if paths:
                a.overlaps[b.snapshot.pr_number]=paths;b.overlaps[a.snapshot.pr_number]=paths
                for c,o in ((a,b),(b,a)):
                    if 'PATH_OVERLAP' not in c.findings:c.findings.append('PATH_OVERLAP');c.reasons.append(f'overlaps PR {o.snapshot.pr_number}')
                    if c.disposition==Disposition.REVIEW_READY:c.disposition=Disposition.WAIT_REBIND
    issues={}
    for c in items:
        for n in c.snapshot.issue_numbers:issues.setdefault(n,[]).append(c)
    for cs in issues.values():
        if len(cs)>1:
            for c in cs:
                c.findings.append('SAME_ISSUE_CHAIN');c.reasons.append('multiple active PRs share an Issue')
                if c.disposition==Disposition.REVIEW_READY:c.disposition=Disposition.WAIT_REBIND
