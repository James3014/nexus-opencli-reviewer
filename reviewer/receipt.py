from __future__ import annotations
import hashlib,json
import os,tempfile
from datetime import datetime,timezone
from pathlib import Path
from .semantic import parse_response,SemanticParseError


def _valid_check_shape(check):
    if not isinstance(check, dict):
        return False
    allowed_keys = {"name", "status", "expected_failure", "check_run_id", "run_id",
                    "external_id", "artifact_identity", "details_url", "html_url",
                    "node_id", "workflow_name", "head_sha", "check_suite_id",
                    "started_at", "completed_at", "annotation_count", "app_slug"}
    if set(check) - allowed_keys:
        return False
    if not isinstance(check.get("name"), str) or not isinstance(check.get("status"), str):
        return False
    if type(check.get("expected_failure", False)) is not bool:
        return False
    if type(check.get("check_run_id")) is not int or check["check_run_id"] <= 0:
        return False
    if type(check.get("run_id")) is not int or check["run_id"] <= 0:
        return False
    if not isinstance(check.get("head_sha"), str) or not check.get("head_sha"):
        return False
    external = check.get("external_id")
    artifact = check.get("artifact_identity")
    if (external is not None and (type(external) is not str or not external)
            or (artifact is not None and (type(artifact) is not str or not artifact))
            or (external is None and artifact is None)
            or (external is not None and artifact is not None and external != artifact)):
        return False
    exact = {
        "details_url": str, "html_url": str, "node_id": str,
        "workflow_name": str, "started_at": str, "completed_at": str,
        "app_slug": str,
    }
    for key, expected in exact.items():
        if key in check and check[key] is not None and type(check[key]) is not expected:
            return False
    if "check_suite_id" in check and check["check_suite_id"] is not None and (type(check["check_suite_id"]) is not int or check["check_suite_id"] <= 0):
        return False
    if "annotation_count" in check and check["annotation_count"] is not None:
        if type(check["annotation_count"]) is not int or check["annotation_count"] < 0:
            return False
    return True


def _valid_review_identity(identity):
    return (isinstance(identity, list) and len(identity) == 5
            and type(identity[0]) is str and bool(identity[0])
            and type(identity[1]) is int and identity[1] > 0
            and all(type(value) is str and bool(value) for value in identity[2:]))


def build_ci_failure_evidence(*, repository, pr_number, base_sha, head_sha,
                              current_main_sha, checks, collection_complete=True,
                              collection_errors=(), expected_run_id=None,
                              expected_artifact_identity=None,
                              expected_check_run_id=None,
                              canonical_disposition=None):
    """Build a deterministic, advisory CI trigger capsule.

    This is evidence normalization, not a second classifier: only the
    existing exact-base check path is considered and every identity-bearing
    field is retained.  Missing or mismatched evidence is explicitly UNKNOWN.
    """
    identity = [repository, pr_number, head_sha, base_sha, current_main_sha]
    normalized = []
    gaps = list(collection_errors)
    if (type(repository) is not str or not repository or type(pr_number) is not int or pr_number <= 0
            or any(type(value) is not str or not value for value in (head_sha, base_sha, current_main_sha))):
        gaps.append("review identity domain invalid")
    dispositions = {"NEW_REGRESSION", "EXACT_BASELINE_DEBT", "CI_BOOTSTRAP_DEFECT",
                    "IMPACT_UNKNOWN", "NOT_AVAILABLE"}
    if canonical_disposition not in dispositions:
        gaps.append("canonical disposition unavailable")
        canonical_disposition = "IMPACT_UNKNOWN"
    if type(expected_check_run_id) is not int or expected_check_run_id <= 0:
        gaps.append("check run identity unavailable")
    if type(expected_run_id) is not int or expected_run_id <= 0:
        gaps.append("run identity unavailable")
    if type(expected_artifact_identity) is not str or not expected_artifact_identity:
        gaps.append("artifact identity unavailable")
    if not checks:
        gaps.append("check evidence unavailable")
    for check in checks or ():
        if not _valid_check_shape(check):
            gaps.append("check identity type or shape invalid")
            continue
        item = {key: check.get(key) for key in (
            "name", "status", "check_run_id", "run_id", "external_id",
            "details_url", "html_url", "node_id", "workflow_name", "head_sha",
            "check_suite_id", "started_at", "completed_at", "artifact_identity",
            "annotation_count", "app_slug",
        ) if check.get(key) is not None}
        item["expected_failure"] = check.get("expected_failure", False)
        normalized.append(item)
        if item.get("head_sha") != head_sha:
            gaps.append("foreign check head identity")
        if item.get("expected_failure"):
            gaps.append("expected failure is not a trigger")
        if item.get("status") not in {"failure", "failed", "error", "cancelled", "timed_out", "action_required"}:
            gaps.append("terminal failure unavailable")
        if item.get("check_run_id") != expected_check_run_id:
            gaps.append("foreign check identity")
        if item.get("run_id") != expected_run_id:
            gaps.append("foreign check run identity")
        if (item.get("external_id") != expected_artifact_identity
                and item.get("artifact_identity") != expected_artifact_identity):
            gaps.append("foreign check artifact identity")
    normalized.sort(key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    if not collection_complete:
        state = "UNKNOWN"
    elif gaps:
        state = "UNKNOWN"
    elif canonical_disposition in {"NEW_REGRESSION", "CI_BOOTSTRAP_DEFECT"}:
        state = "TRIGGERED"
    elif canonical_disposition == "EXACT_BASELINE_DEBT":
        state = "CLEAR"
    else:
        state = "UNKNOWN"
    capsule = {
        "schema": "reviewer.ci_failure_evidence.v1",
        "review_identity": identity,
        "state": state,
        "trigger": "NEXUS_EXACT_BASE" if state == "TRIGGERED" else None,
        "canonical_disposition": canonical_disposition,
        "expected_check_run_id": expected_check_run_id,
        "expected_run_id": expected_run_id,
        "expected_artifact_identity": expected_artifact_identity,
        "checks": normalized,
        "evidence_gaps": sorted(set(str(gap) for gap in gaps)),
        "claim_ceiling": "CI_EVIDENCE_ONLY",
    }
    fingerprint_payload = {
        "review_identity": identity,
        "check_identity": [item.get("check_run_id") for item in normalized],
        "run_identity": [item.get("run_id") for item in normalized],
        "artifact_identity": [item.get("external_id") or item.get("artifact_identity") for item in normalized],
        "canonical_disposition": canonical_disposition,
    }
    capsule["failure_fingerprint"] = hashlib.sha256(
        json.dumps(fingerprint_payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    canonical = json.dumps(capsule, sort_keys=True, separators=(",", ":"))
    capsule["content_sha256"] = hashlib.sha256(canonical.encode()).hexdigest()
    return capsule


def make_ci_failure_evidence(**kwargs):
    return build_ci_failure_evidence(**kwargs)


def ci_failure_evidence_manifest(evidence):
    """Return a stable manifest projection for a validated evidence capsule."""
    if not isinstance(evidence, dict) or evidence.get("schema") != "reviewer.ci_failure_evidence.v1":
        raise ValueError("CI_FAILURE_EVIDENCE_REQUIRED")
    supplied = evidence.get("content_sha256")
    unsigned = {key: value for key, value in evidence.items() if key != "content_sha256"}
    actual = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if not supplied or supplied != actual:
        raise ValueError("CI_FAILURE_EVIDENCE_HASH_MISMATCH")
    if evidence.get("claim_ceiling") != "CI_EVIDENCE_ONLY":
        raise ValueError("CI_FAILURE_EVIDENCE_CLAIM_CEILING_INVALID")
    expected_keys = {"schema", "review_identity", "state", "trigger", "canonical_disposition",
                     "expected_check_run_id", "expected_run_id", "expected_artifact_identity",
                     "checks", "evidence_gaps", "claim_ceiling", "failure_fingerprint", "content_sha256"}
    if set(evidence) != expected_keys:
        raise ValueError("CI_FAILURE_EVIDENCE_SCHEMA_FIELDS_INVALID")
    identity = evidence.get("review_identity")
    if not _valid_review_identity(identity):
        raise ValueError("CI_FAILURE_EVIDENCE_IDENTITY_MISSING")
    expected_check = evidence.get("expected_check_run_id")
    expected_run = evidence.get("expected_run_id")
    expected_artifact = evidence.get("expected_artifact_identity")
    if (type(expected_check) is not int or expected_check <= 0
            or type(expected_run) is not int or expected_run <= 0
            or type(expected_artifact) is not str or not expected_artifact):
        raise ValueError("CI_FAILURE_EVIDENCE_IDENTITY_MISSING")
    checks = evidence.get("checks")
    if not isinstance(checks, list) or not checks or any(not isinstance(check, dict) for check in checks):
        raise ValueError("CI_FAILURE_EVIDENCE_IDENTITY_MISSING")
    for check in checks:
        if not _valid_check_shape(check):
            raise ValueError("CI_FAILURE_EVIDENCE_CHECK_SHAPE_INVALID")
        if (check.get("head_sha") != identity[2]
                or check.get("check_run_id") != expected_check
                or check.get("run_id") != expected_run
                or (check.get("external_id") != expected_artifact
                    and check.get("artifact_identity") != expected_artifact)):
            raise ValueError("CI_FAILURE_EVIDENCE_IDENTITY_MISMATCH")
    allowed = {"NEW_REGRESSION", "EXACT_BASELINE_DEBT", "CI_BOOTSTRAP_DEFECT",
               "IMPACT_UNKNOWN", "NOT_AVAILABLE"}
    disposition = evidence.get("canonical_disposition")
    if disposition not in allowed:
        raise ValueError("CI_FAILURE_EVIDENCE_DISPOSITION_UNKNOWN")
    gaps = evidence.get("evidence_gaps")
    if not isinstance(gaps, list) or any(not isinstance(gap, str) for gap in gaps):
        raise ValueError("CI_FAILURE_EVIDENCE_GAPS_INVALID")
    state = evidence.get("state")
    if state not in {"TRIGGERED", "CLEAR", "UNKNOWN"}:
        raise ValueError("CI_FAILURE_EVIDENCE_STATE_INVALID")
    if state == "TRIGGERED" and (gaps or disposition not in {"NEW_REGRESSION", "CI_BOOTSTRAP_DEFECT"}):
        raise ValueError("CI_FAILURE_EVIDENCE_STATE_INCOHERENT")
    if state == "CLEAR" and disposition != "EXACT_BASELINE_DEBT":
        raise ValueError("CI_FAILURE_EVIDENCE_STATE_INCOHERENT")
    if state == "UNKNOWN" and not gaps:
        raise ValueError("CI_FAILURE_EVIDENCE_GAP_REQUIRED")
    if state == "TRIGGERED" and any(check.get("expected_failure") or check.get("status") not in {
            "failure", "failed", "error", "cancelled", "timed_out", "action_required"} for check in checks):
        raise ValueError("CI_FAILURE_EVIDENCE_TERMINAL_FAILURE_INVALID")
    canonical_checks = sorted(checks, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    if checks != canonical_checks or len({json.dumps(item, sort_keys=True, separators=(",", ":")) for item in checks}) != len(checks):
        raise ValueError("CI_FAILURE_EVIDENCE_CHECK_ORDER_INVALID")
    fp_payload = {
        "review_identity": identity,
        "check_identity": [check.get("check_run_id") for check in checks],
        "run_identity": [check.get("run_id") for check in checks],
        "artifact_identity": [check.get("external_id") or check.get("artifact_identity") for check in checks],
        "canonical_disposition": disposition,
    }
    expected_fingerprint = hashlib.sha256(
        json.dumps(fp_payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if evidence.get("failure_fingerprint") != expected_fingerprint:
        raise ValueError("CI_FAILURE_EVIDENCE_FINGERPRINT_MISMATCH")
    expected_trigger = "NEXUS_EXACT_BASE" if state == "TRIGGERED" else None
    if evidence.get("trigger") != expected_trigger:
        raise ValueError("CI_FAILURE_EVIDENCE_TRIGGER_MISMATCH")
    if evidence.get("canonical_disposition") not in {
        "NEW_REGRESSION", "EXACT_BASELINE_DEBT", "CI_BOOTSTRAP_DEFECT",
        "IMPACT_UNKNOWN", "NOT_AVAILABLE",
    }:
        raise ValueError("CI_FAILURE_EVIDENCE_DISPOSITION_UNKNOWN")
    return {"schema": evidence["schema"], "content_sha256": evidence.get("content_sha256"),
            "review_identity": list(evidence.get("review_identity", [])),
            "state": evidence.get("state"), "claim_ceiling": evidence.get("claim_ceiling")}
def receipt_path(root, identity):
    key=hashlib.sha256(json.dumps(list(identity),separators=(',',':')).encode()).hexdigest(); p=Path(root)/'reviews'/f'{key}.json'; p.parent.mkdir(parents=True,exist_ok=True); return p
def make_receipt(context, classification, transport, prompt, observed_at, parsed=None, parse_result='NOT_ATTEMPTED', ci_failure_evidence=None):
    if ci_failure_evidence is not None:
        ci_failure_evidence_manifest(ci_failure_evidence)
        if ci_failure_evidence.get("review_identity") != list(context.review_identity):
            raise ValueError("CI_FAILURE_EVIDENCE_REVIEW_IDENTITY_MISMATCH")
    raw=transport.raw or ''; now=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z'); version=getattr(transport,'version',''); version=version() if callable(version) else version; prompt_sha=hashlib.sha256(prompt.encode()).hexdigest(); raw_sha=hashlib.sha256(raw.encode()).hexdigest() if raw else None; receipt_id=hashlib.sha256(json.dumps({'identity':list(context.review_identity),'context':context.context_sha256,'prompt':prompt_sha,'raw':raw_sha},sort_keys=True,separators=(',',':')).encode()).hexdigest(); return {'schema':'reviewer.pre_review.v1','receipt_id':receipt_id,'repository':context.review_identity[0],'pr_number':context.review_identity[1],'base_sha':context.review_identity[3],'head_sha':context.review_identity[2],'current_main_sha':context.review_identity[4],'review_identity':list(context.review_identity),'source_observed_at':observed_at,'source_identity':classification.snapshot.source_identity,'deterministic_findings':classification.findings,'risk':classification.risk,'changed_files':list(classification.snapshot.changed_files),'context_pack_sha256':context.context_sha256,'prompt_sha256':prompt_sha,'opencli_executable':getattr(transport,'executable','fake'),'opencli_version':version,'browser_profile':getattr(transport,'profile',None),'session_mode':getattr(transport,'session_mode','ephemeral'),'safe_argv':getattr(transport,'argv',[]),'invocation_started_at':getattr(transport,'started_at',now) or now,'invocation_finished_at':getattr(transport,'finished_at',now) or now,'transport_result':transport.status,'outcome_unknown':getattr(transport,'outcome_unknown',False),'retry_safe':getattr(transport,'retry_safe',False),'raw_response_sha256':raw_sha,'parse_result':parse_result,'semantic_result':parsed,'ci_failure_evidence':ci_failure_evidence,'claim_ceiling':'PRE_REVIEW_ONLY'}
def persist_receipt(root, receipt):
    p=receipt_path(root,tuple(receipt['review_identity']))
    data=(json.dumps(receipt,indent=2,sort_keys=True)+'\n').encode()
    fd,tmp=tempfile.mkstemp(prefix=f'.{p.name}.',dir=p.parent)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,p)
    finally:
        try: os.unlink(tmp)
        except FileNotFoundError: pass
    return p
def persist_failure(root, attempt_id, evidence):
    p=Path(root)/'reviews'/'failures'/f'{attempt_id}.json';p.parent.mkdir(parents=True,exist_ok=True)
    value={'schema':'reviewer.semantic_failure.v1','attempt_id':attempt_id,**evidence}
    data=(json.dumps(value,indent=2,sort_keys=True)+'\n').encode();fd,tmp=tempfile.mkstemp(prefix=f'.{p.name}.',dir=p.parent)
    try:
        with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(tmp,p)
    finally:
        try:os.unlink(tmp)
        except FileNotFoundError:pass
    return p
def reusable_receipt(root, identity, *, context_sha256=None, prompt_sha256=None):
    p=receipt_path(root,identity)
    if not p.exists(): return None
    try:
        value=json.loads(p.read_text())
        ci = value.get('ci_failure_evidence')
        if ci is not None:
            ci_failure_evidence_manifest(ci)
            if ci.get('review_identity') != list(identity):
                return None
        if (value.get('schema')=='reviewer.pre_review.v1'
            and value.get('review_identity') == list(identity)
            and value.get('transport_result')=='REVIEW_COMPLETED'
            and value.get('parse_result')=='PARSED'
            and value.get('claim_ceiling')=='PRE_REVIEW_ONLY'
            and value.get('outcome_unknown') is False
            and isinstance(value.get('semantic_result'),dict)
            and value['semantic_result'].get('schema')=='reviewer.semantic_response.v1'
            and value.get('context_pack_sha256')
            and value.get('prompt_sha256')
            and (context_sha256 is None or value.get('context_pack_sha256') == context_sha256)
            and (prompt_sha256 is None or value.get('prompt_sha256') == prompt_sha256)
        ): return value,p
    except (OSError,ValueError): pass
    return None
