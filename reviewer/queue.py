from .models import Disposition
class ReviewQueue:
    def __init__(self):self.items=[];self._seen=set()
    def ingest(self,items):
        for x in items:
            if x.review_identity not in self._seen:self._seen.add(x.review_identity);self.items.append(x)
    def semantic_review(self):return [x for x in self.items if x.disposition==Disposition.REVIEW_READY]
