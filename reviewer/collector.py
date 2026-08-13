import json
from .models import PRSnapshot
def load_fixture(path,main):
    with open(path) as f:
        return [PRSnapshot.from_dict(x,main) for x in json.load(f)['prs']]
