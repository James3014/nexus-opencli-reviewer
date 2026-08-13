import argparse,json
from .collector import load_fixture
from .classifier import classify
from .overlap import detect
from .github import GhCliTransport, GitHubError
from .scan import scan
def main():
    p=argparse.ArgumentParser();p.add_argument('--fixtures');p.add_argument('--main-sha');p.add_argument('--repo');p.add_argument('--json',action='store_true');a=p.parse_args()
    try:
        if a.repo:
            main_sha,observed,xs,q=scan(a.repo,GhCliTransport(),persist_state=True)
        elif a.fixtures and a.main_sha:
            xs=[classify(x) for x in load_fixture(a.fixtures,a.main_sha)];detect(xs)
        else:p.error('provide --repo or --fixtures with --main-sha')
    except (GitHubError,ValueError) as e:p.error(str(e))
    if a.json:print(json.dumps([x.to_dict() for x in xs],indent=2,sort_keys=True))
    else:
        print('PR    DISPOSITION       RISK   REASONS')
        for x in sorted(xs,key=lambda x:x.snapshot.pr_number):print(f'{x.snapshot.pr_number:<5} {x.disposition.value:<17} {x.risk:<6} {",".join(x.findings) or "-"}')
if __name__=='__main__':main()
