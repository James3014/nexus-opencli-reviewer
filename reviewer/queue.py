from .models import Disposition
import json,os,tempfile
from pathlib import Path
class ReviewQueue:
    def __init__(self):self.items=[];self._seen=set()
    def ingest(self,items):
        for x in items:
            if x.review_identity not in self._seen:self._seen.add(x.review_identity);self.items.append(x)
    def semantic_review(self):return [x for x in self.items if x.disposition==Disposition.REVIEW_READY]
    def save(self,path):
        path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
        data=(json.dumps([list(i) for i in sorted(self._seen)],indent=2)+'\n').encode()
        fd,tmp=tempfile.mkstemp(prefix=f'.{path.name}.',dir=path.parent)
        try:
            with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
            os.replace(tmp,path)
        finally:
            try:os.unlink(tmp)
            except FileNotFoundError:pass
    @classmethod
    def load(cls,path):
        q=cls(); q._seen={tuple(i) for i in json.loads(Path(path).read_text())}; return q
