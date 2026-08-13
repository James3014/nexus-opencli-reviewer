import argparse,json
from .collector import load_fixture
from .classifier import classify
from .overlap import detect
def main():
    p=argparse.ArgumentParser();p.add_argument('--fixtures',required=True);p.add_argument('--main-sha',required=True);p.add_argument('--json',action='store_true');a=p.parse_args();xs=[classify(x) for x in load_fixture(a.fixtures,a.main_sha)];detect(xs)
    if a.json:print(json.dumps([x.to_dict() for x in xs],indent=2,sort_keys=True))
    else:
        print('PR    DISPOSITION       RISK   REASONS')
        for x in sorted(xs,key=lambda x:x.snapshot.pr_number):print(f'{x.snapshot.pr_number:<5} {x.disposition.value:<17} {x.risk:<6} {",".join(x.findings) or "-"}')
if __name__=='__main__':main()
