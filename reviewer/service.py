"""Small, side-effect-aware coordinator for repeated review workflows.

The coordinator owns ordering and replay safety; all I/O is supplied by the
caller.  In particular, an uncertain publication is reconciled before a new
POST/publish is ever attempted.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping


@dataclass(frozen=True)
class WorkflowResult:
    outcome: str
    identity: tuple[Any, ...]
    semantic_called: bool = False
    publication_called: bool = False
    reconciliation_called: bool = False
    detail: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "identity": list(self.identity),
            "semantic_called": self.semantic_called,
            "publication_called": self.publication_called,
            "reconciliation_called": self.reconciliation_called,
            "detail": dict(self.detail),
        }


class ReviewWorkflowService:
    """Coordinate scan -> semantic review -> publication with fail-closed replay."""

    def __init__(
        self,
        *,
        scan: Callable[[tuple[Any, ...]], Mapping[str, Any] | None],
        review: Callable[[tuple[Any, ...]], Mapping[str, Any]],
        publish: Callable[[tuple[Any, ...], Mapping[str, Any]], Mapping[str, Any] | bool],
        reconcile: Callable[[tuple[Any, ...]], Mapping[str, Any] | None],
    ) -> None:
        self.scan = scan
        self.review = review
        self.publish = publish
        self.reconcile = reconcile

    @staticmethod
    def _state(value: Any, default: str = "NONE") -> str:
        if isinstance(value, str):
            return value.upper()
        return default

    @staticmethod
    def _ok(value: Any) -> bool:
        return value is True or (isinstance(value, Mapping) and value.get("status", "").upper() in {"OK", "PUBLISHED", "COMPLETE", "RESOLVED"})

    def run(self, identity: tuple[Any, ...] | list[Any]) -> WorkflowResult:
        ident = tuple(identity)
        record = self.scan(ident) or {}
        semantic = self._state(record.get("semantic"), "NONE")
        publication = self._state(record.get("publication"), "NONE")

        if semantic in {"UNRESOLVED", "UNKNOWN", "PENDING"}:
            rec = self.reconcile(ident) or {}
            rec_semantic = self._state(rec.get("semantic"), semantic)
            if rec_semantic in {"UNRESOLVED", "UNKNOWN", "PENDING"}:
                return WorkflowResult("RECONCILIATION_REQUIRED", ident, reconciliation_called=True)
            semantic = rec_semantic
            publication = self._state(rec.get("publication"), publication)

        if semantic == "COMPLETE" and publication == "COMPLETE":
            return WorkflowResult("ALREADY_COMPLETE", ident)
        if semantic in {"UNRESOLVED", "UNKNOWN", "PENDING"}:
            return WorkflowResult("SEMANTIC_UNRESOLVED", ident)

        semantic_called = False
        review_record: Mapping[str, Any] = record
        if semantic in {"NONE", "NEW"}:
            review_record = self.review(ident) or {}
            semantic_called = True
            semantic = self._state(review_record.get("semantic"), "UNRESOLVED")
            if semantic in {"UNRESOLVED", "UNKNOWN", "PENDING"}:
                return WorkflowResult("SEMANTIC_UNRESOLVED", ident, semantic_called=True)

        publication = self._state(review_record.get("publication"), publication)
        if publication == "COMPLETE":
            return WorkflowResult("ALREADY_COMPLETE", ident, semantic_called=semantic_called)

        # Any pre-existing uncertain publication must be reconciled first.
        reconciliation_called = False
        if publication in {"UNRESOLVED", "UNKNOWN", "PENDING"}:
            reconciled = self.reconcile(ident) or {}
            reconciliation_called = True
            if self._state(reconciled.get("publication"), publication) != "COMPLETE":
                return WorkflowResult("PUBLICATION_UNRESOLVED", ident, semantic_called=semantic_called, reconciliation_called=True)
            return WorkflowResult("PUBLICATION_RECONCILED", ident, semantic_called=semantic_called, reconciliation_called=True)

        published = self.publish(ident, review_record)
        if self._ok(published):
            return WorkflowResult("PUBLISHED", ident, semantic_called=semantic_called, publication_called=True)
        return WorkflowResult("PUBLICATION_UNRESOLVED", ident, semantic_called=semantic_called, publication_called=True, detail={"publish": published})


Service = ReviewWorkflowService
