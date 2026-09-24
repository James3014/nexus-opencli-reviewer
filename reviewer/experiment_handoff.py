"""Canonical experiment-integrity handoff artifact for decision-model research.

Issue #40: emit a machine-readable artifact that binds calibration / held-out
integrity, policy freeze order, sealed digests, terminal results (including
negative/stop/defer), failure taxonomy, model-call usage, quality-gated cost,
training prohibition, and the private/public artifact boundary.

The reviewer remains the experiment producer; Nexus Learning
(``nexus.learning_experiment_integrity.v1``,
``nexus.learning_quality_qualified_economics.v1``, data-purpose admission)
remains the canonical owner of generic experiment/effectiveness semantics.
This module therefore does not import Nexus Learning and owns no route,
verifier, Candidate-acceptance, merge, release, or production authority.

Schema compatibility is intentional: the ``nexus_projection`` block carries the
nexus schema identifiers and value vocabulary so a Nexus Learning consumer can
deterministically translate or validate the artifact, while this module's own
verifier recomputes every derived hash and derived disposition from the
embedded neutral inputs and fails closed on tampering.
"""
from __future__ import annotations

import hashlib
import json
from math import isfinite
from typing import Any, Mapping

HANDOFF_SCHEMA = "reviewer.experiment_evidence_handoff.v1"
HANDOFF_CLAIM_CEILING = "REVIEWER_EXPERIMENT_EVIDENCE_HANDOFF_VERIFIED"

NEXUS_INTEGRITY_SCHEMA = "nexus.learning_experiment_integrity.v1"
NEXUS_ECONOMICS_SCHEMA = "nexus.learning_quality_qualified_economics.v1"
NEXUS_EPISODE_SCHEMA = "nexus.learning_episode.v1"
NEXUS_EVIDENCE_ORIGIN_SCHEMA = "nexus.learning_evidence_origin_provenance.v1"
LIVE_PROVIDER_CLAIM_CEILING = "REVIEWER_LIVE_PROVIDER_PROVENANCE_GATE_VERIFIED"

SIMULATION_ONLY = "SIMULATION_ONLY"
MOCK_TRANSPORT = "MOCK_TRANSPORT"
LOCAL_FAKE_PROVIDER = "LOCAL_FAKE_PROVIDER"
PHYSICAL_LOCAL_MODEL = "PHYSICAL_LOCAL_MODEL"
REMOTE_PROVIDER_OBSERVED = "REMOTE_PROVIDER_OBSERVED"
UNKNOWN_ORIGIN = "UNKNOWN"
_EVIDENCE_ORIGINS = frozenset(
    {SIMULATION_ONLY, MOCK_TRANSPORT, LOCAL_FAKE_PROVIDER, PHYSICAL_LOCAL_MODEL,
     REMOTE_PROVIDER_OBSERVED, UNKNOWN_ORIGIN}
)

EFFECT_NOT_STARTED = "NOT_STARTED"
EFFECT_SUCCEEDED = "SUCCEEDED"
EFFECT_FAILED = "FAILED"
EFFECT_OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
_EFFECT_OUTCOMES = frozenset(
    {EFFECT_NOT_STARTED, EFFECT_SUCCEEDED, EFFECT_FAILED, EFFECT_OUTCOME_UNKNOWN}
)
_PUBLIC_SAFE_RECEIPT_FIELDS = frozenset(
    {
        "receipt_id", "effect_identity", "operation_id", "transport_class",
        "external_effect_started", "outcome", "observed_provider", "observed_model",
        "observed_revision", "source_receipt_ref", "source_receipt_sha256",
    }
)

INDEPENDENCE_UNIT_ROW = "row_identity"
INDEPENDENCE_UNIT_BASE = "base_identity"
_INDEPENDENCE_UNITS = frozenset({INDEPENDENCE_UNIT_ROW, INDEPENDENCE_UNIT_BASE})

CALIBRATED = "CALIBRATED"
INSUFFICIENT_CALIBRATION = "INSUFFICIENT_CALIBRATION"
EXPLORATORY_UNCALIBRATED = "EXPLORATORY_UNCALIBRATED"
FROZEN_REJECT_ALL = "FROZEN_REJECT_ALL"
_CALIBRATION_STATUSES = frozenset(
    {CALIBRATED, INSUFFICIENT_CALIBRATION, EXPLORATORY_UNCALIBRATED, FROZEN_REJECT_ALL}
)

TERMINAL_PASS = "PASS"
TERMINAL_STOP = "STOP"
TERMINAL_DEFER = "DEFER"
TERMINAL_NEGATIVE = "NEGATIVE"
_TERMINAL_OUTCOMES = frozenset({TERMINAL_PASS, TERMINAL_STOP, TERMINAL_DEFER, TERMINAL_NEGATIVE})
_NEGATIVE_TERMINAL_OUTCOMES = frozenset({TERMINAL_STOP, TERMINAL_DEFER, TERMINAL_NEGATIVE})

DATA_PURPOSE_TRAINING_CANDIDATE = "TRAINING_CANDIDATE"
DATA_PURPOSE_EVALUATION_ONLY = "EVALUATION_ONLY"
DATA_PURPOSE_LEARNING_POLICY_EVIDENCE = "LEARNING_POLICY_EVIDENCE"
_FORBIDDEN_DATA_PURPOSES = frozenset(
    {DATA_PURPOSE_EVALUATION_ONLY, DATA_PURPOSE_LEARNING_POLICY_EVIDENCE}
)
TRAINING_ADMISSION_FORBIDDEN = "TRAINING_FORBIDDEN"
TRAINING_ADMISSION_QUALITY_GATED = "QUALITY_GATED"

QUALITY_QUALIFIED = "QUALITY_QUALIFIED"
QUALITY_FLOOR_FAILED = "QUALITY_FLOOR_FAILED"
INSUFFICIENT_COST_EVIDENCE = "INSUFFICIENT_COST_EVIDENCE"
COST_COMPARABLE = "COST_COMPARABLE"
NO_INCREMENTAL_VALUE = "NO_INCREMENTAL_VALUE"
QUALITY_SUPERIOR = "QUALITY_SUPERIOR"
_QUALITY_GATE_RESULTS = frozenset(
    {
        QUALITY_QUALIFIED,
        QUALITY_FLOOR_FAILED,
        INSUFFICIENT_COST_EVIDENCE,
        COST_COMPARABLE,
        NO_INCREMENTAL_VALUE,
        QUALITY_SUPERIOR,
    }
)
_ECONOMICS_ELIGIBLE_GATE_RESULTS = frozenset(
    {QUALITY_QUALIFIED, COST_COMPARABLE, QUALITY_SUPERIOR}
)

_STABLE_OPTIONAL_COST = (
    "latency_ms_p50",
    "latency_ms_p95",
    "token_usage",
    "monetary_cost_usd",
    "wall_time_seconds",
)


def _hash(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _optional_text(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"HANDOFF_EVIDENCE_ORIGIN_{field.upper()}_INVALID")
    return value.strip()


def _origin_identity(*, provider: str | None, model: str | None, revision: str | None = None) -> dict[str, str | None]:
    return {
        "provider": _optional_text(provider, "identity_provider"),
        "model": _optional_text(model, "identity_model"),
        "revision": _optional_text(revision, "identity_revision"),
    }


def _sha256_ref(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(char in "0123456789abcdef" for char in value[7:])
    )


def build_evidence_origin_compat(
    *,
    origin_class: str,
    requested_provider: str | None = None,
    requested_model: str | None = None,
    configured_provider: str | None = None,
    configured_model: str | None = None,
    observed_provider: str | None = None,
    observed_model: str | None = None,
    observed_revision: str | None = None,
    external_effect_started: bool = False,
    effect_outcome: str = EFFECT_NOT_STARTED,
    effect_identity: str | None = None,
    operation_id: str | None = None,
    observation_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Project reviewer evidence into the exact Nexus Learning #27 vocabulary.

    This compatibility builder is producer-side only.  Canonical semantics remain
    owned by Nexus Learning and are checked by the cross-repository compatibility
    verifier.  Receipt payloads are intentionally restricted to public-safe fields.
    """
    receipt = None
    if observation_receipt is not None:
        if not isinstance(observation_receipt, Mapping):
            raise ValueError("HANDOFF_EVIDENCE_ORIGIN_RECEIPT_INVALID")
        payload = dict(observation_receipt)
        if set(payload) - _PUBLIC_SAFE_RECEIPT_FIELDS:
            raise ValueError("HANDOFF_EVIDENCE_ORIGIN_PRIVATE_RECEIPT_FIELD_FORBIDDEN")
        receipt = {"payload": payload, "payload_hash": _hash(payload)}
    unsigned = {
        "schema": NEXUS_EVIDENCE_ORIGIN_SCHEMA,
        "origin_class": str(origin_class).strip().upper(),
        "requested_identity": _origin_identity(provider=requested_provider, model=requested_model),
        "configured_identity": _origin_identity(provider=configured_provider, model=configured_model),
        "observed_identity": _origin_identity(
            provider=observed_provider, model=observed_model, revision=observed_revision
        ),
        "external_effect": {
            "started": external_effect_started,
            "outcome": str(effect_outcome).strip().upper(),
            "effect_identity": _optional_text(effect_identity, "effect_identity"),
            "operation_id": _optional_text(operation_id, "operation_id"),
        },
        "observation_receipt": receipt,
        "claim_ceiling": (
            "evidence-origin provenance only; external receipt authenticity and "
            "provider/model success claims require the owning producer gate"
        ),
    }
    value = {**unsigned, "binding_hash": _hash(unsigned)}
    verify_evidence_origin_compat(value)
    return value


def _verify_origin_identity(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"provider", "model", "revision"}:
        raise ValueError(f"HANDOFF_EVIDENCE_ORIGIN_{field.upper()}_IDENTITY_INVALID")
    return {
        key: _optional_text(value.get(key), f"{field}_{key}")
        for key in ("provider", "model", "revision")
    }


def verify_evidence_origin_compat(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("HANDOFF_EVIDENCE_ORIGIN_NOT_A_MAPPING")
    if value.get("schema") != NEXUS_EVIDENCE_ORIGIN_SCHEMA:
        raise ValueError("HANDOFF_EVIDENCE_ORIGIN_SCHEMA_INVALID")
    origin = str(value.get("origin_class") or "").upper()
    if origin not in _EVIDENCE_ORIGINS:
        raise ValueError("HANDOFF_EVIDENCE_ORIGIN_CLASS_INVALID")
    _verify_origin_identity(value.get("requested_identity"), "requested")
    _verify_origin_identity(value.get("configured_identity"), "configured")
    observed = _verify_origin_identity(value.get("observed_identity"), "observed")

    effect = value.get("external_effect")
    if not isinstance(effect, Mapping) or set(effect) != {"started", "outcome", "effect_identity", "operation_id"}:
        raise ValueError("HANDOFF_EVIDENCE_ORIGIN_EFFECT_INVALID")
    if not isinstance(effect.get("started"), bool):
        raise ValueError("HANDOFF_EVIDENCE_ORIGIN_EFFECT_STARTED_INVALID")
    outcome = str(effect.get("outcome") or "").upper()
    if outcome not in _EFFECT_OUTCOMES:
        raise ValueError("HANDOFF_EVIDENCE_ORIGIN_EFFECT_OUTCOME_INVALID")
    effect_identity = _optional_text(effect.get("effect_identity"), "effect_identity")
    operation_id = _optional_text(effect.get("operation_id"), "operation_id")

    receipt_wrapper = value.get("observation_receipt")
    receipt_payload = None
    if receipt_wrapper is not None:
        if not isinstance(receipt_wrapper, Mapping) or set(receipt_wrapper) != {"payload", "payload_hash"}:
            raise ValueError("HANDOFF_EVIDENCE_ORIGIN_RECEIPT_INVALID")
        payload = receipt_wrapper.get("payload")
        if not isinstance(payload, Mapping):
            raise ValueError("HANDOFF_EVIDENCE_ORIGIN_RECEIPT_INVALID")
        if set(payload) - _PUBLIC_SAFE_RECEIPT_FIELDS:
            raise ValueError("HANDOFF_EVIDENCE_ORIGIN_PRIVATE_RECEIPT_FIELD_FORBIDDEN")
        if receipt_wrapper.get("payload_hash") != _hash(dict(payload)):
            raise ValueError("HANDOFF_EVIDENCE_ORIGIN_RECEIPT_HASH_MISMATCH")
        receipt_payload = payload

    unsigned = dict(value)
    binding_hash = unsigned.pop("binding_hash", None)
    if binding_hash != _hash(unsigned):
        raise ValueError("HANDOFF_EVIDENCE_ORIGIN_BINDING_HASH_MISMATCH")
    if value.get("claim_ceiling") != (
        "evidence-origin provenance only; external receipt authenticity and "
        "provider/model success claims require the owning producer gate"
    ):
        raise ValueError("HANDOFF_EVIDENCE_ORIGIN_CLAIM_CEILING_INVALID")

    if origin in {SIMULATION_ONLY, MOCK_TRANSPORT, LOCAL_FAKE_PROVIDER}:
        if effect.get("started") is not False:
            raise ValueError("HANDOFF_EVIDENCE_ORIGIN_NONPHYSICAL_EFFECT_FORBIDDEN")
        return {"origin_class": origin, "live_provider_observed": False}
    if origin == UNKNOWN_ORIGIN:
        return {"origin_class": origin, "live_provider_observed": False}

    if effect.get("started") is not True or not effect_identity or not operation_id:
        raise ValueError("HANDOFF_EVIDENCE_ORIGIN_PHYSICAL_EFFECT_IDENTITY_MISSING")
    if receipt_payload is None:
        raise ValueError("HANDOFF_EVIDENCE_ORIGIN_PHYSICAL_RECEIPT_MISSING")
    if receipt_payload.get("effect_identity") != effect_identity or receipt_payload.get("operation_id") != operation_id:
        raise ValueError("HANDOFF_EVIDENCE_ORIGIN_RECEIPT_EFFECT_IDENTITY_MISMATCH")
    if receipt_payload.get("external_effect_started") is not True:
        raise ValueError("HANDOFF_EVIDENCE_ORIGIN_RECEIPT_EFFECT_NOT_STARTED")
    if str(receipt_payload.get("outcome") or "").upper() != outcome:
        raise ValueError("HANDOFF_EVIDENCE_ORIGIN_RECEIPT_OUTCOME_MISMATCH")
    if not _optional_text(receipt_payload.get("source_receipt_ref"), "source_receipt_ref"):
        raise ValueError("HANDOFF_EVIDENCE_ORIGIN_SOURCE_RECEIPT_REF_MISSING")
    if not _sha256_ref(receipt_payload.get("source_receipt_sha256")):
        raise ValueError("HANDOFF_EVIDENCE_ORIGIN_SOURCE_RECEIPT_HASH_INVALID")

    transport_class = str(receipt_payload.get("transport_class") or "").upper()
    if origin == PHYSICAL_LOCAL_MODEL:
        if transport_class != "LOCAL_MODEL" or not observed["model"]:
            raise ValueError("HANDOFF_EVIDENCE_ORIGIN_LOCAL_IDENTITY_INVALID")
        if receipt_payload.get("observed_model") != observed["model"]:
            raise ValueError("HANDOFF_EVIDENCE_ORIGIN_RECEIPT_MODEL_MISMATCH")
        return {"origin_class": origin, "live_provider_observed": False}

    if transport_class != "REMOTE_PROVIDER":
        raise ValueError("HANDOFF_EVIDENCE_ORIGIN_REMOTE_TRANSPORT_MISMATCH")
    if not observed["provider"] or not observed["model"]:
        raise ValueError("HANDOFF_EVIDENCE_ORIGIN_REMOTE_OBSERVED_IDENTITY_MISSING")
    if receipt_payload.get("observed_provider") != observed["provider"]:
        raise ValueError("HANDOFF_EVIDENCE_ORIGIN_RECEIPT_PROVIDER_MISMATCH")
    if receipt_payload.get("observed_model") != observed["model"]:
        raise ValueError("HANDOFF_EVIDENCE_ORIGIN_RECEIPT_MODEL_MISMATCH")
    if receipt_payload.get("observed_revision") != observed["revision"]:
        raise ValueError("HANDOFF_EVIDENCE_ORIGIN_RECEIPT_REVISION_MISMATCH")
    return {
        "origin_class": origin,
        "live_provider_observed": outcome == EFFECT_SUCCEEDED,
    }


def require_live_provider_observation(value: Any) -> dict[str, Any]:
    evidence = value.get("evidence_origin") if isinstance(value, Mapping) and value.get("schema") == HANDOFF_SCHEMA else value
    result = verify_evidence_origin_compat(evidence)
    if result["origin_class"] != REMOTE_PROVIDER_OBSERVED:
        raise ValueError("HANDOFF_LIVE_PROVIDER_REMOTE_OBSERVATION_REQUIRED")
    if not result["live_provider_observed"]:
        raise ValueError("HANDOFF_LIVE_PROVIDER_SUCCESSFUL_OUTCOME_REQUIRED")
    return dict(evidence)


def _member_identity(member: Mapping[str, Any], independence_unit: str) -> str:
    if independence_unit == INDEPENDENCE_UNIT_BASE:
        base = str(member.get("base_identity") or "").strip()
        if not base:
            raise ValueError("HANDOFF_MEMBER_MISSING_BASE_IDENTITY")
        return base
    identity = str(member.get("identity") or "").strip()
    if not identity:
        raise ValueError("HANDOFF_MEMBER_MISSING_IDENTITY")
    return identity


def _canonical_members(
    members: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
    independence_unit: str,
) -> tuple[dict[str, Any], ...]:
    if not isinstance(members, (list, tuple)):
        raise ValueError("HANDOFF_POPULATION_MUST_BE_SEQUENCE")
    canonical: list[dict[str, Any]] = []
    for member in members:
        if not isinstance(member, Mapping):
            raise ValueError("HANDOFF_POPULATION_MEMBER_INVALID")
        item = dict(member)
        _member_identity(item, independence_unit)
        _hash(item)
        canonical.append(item)
    if not canonical:
        raise ValueError("HANDOFF_EMPTY_POPULATION")
    return tuple(
        sorted(
            canonical,
            key=lambda item: (_member_identity(item, independence_unit), _hash(item)),
        )
    )


def _population_identities(
    members: tuple[dict[str, Any], ...], independence_unit: str
) -> tuple[str, ...]:
    identities = tuple(sorted({_member_identity(item, independence_unit) for item in members}))
    if not identities:
        raise ValueError("HANDOFF_EMPTY_POPULATION")
    return identities


def _population_binding(
    members: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
    independence_unit: str,
) -> dict[str, Any]:
    canonical = _canonical_members(members, independence_unit)
    identities = _population_identities(canonical, independence_unit)
    return {
        "population_hash": _hash({"identities": identities, "unit": independence_unit}),
        "members_hash": _hash({"unit": independence_unit, "members": canonical}),
        "member_identities": list(identities),
        "member_count": len(identities),
        "members": [dict(item) for item in canonical],
    }


def _overlap(
    calibration: tuple[str, ...], heldout: tuple[str, ...]
) -> tuple[list[str], bool]:
    shared = sorted(set(calibration) & set(heldout))
    if shared:
        return shared, True
    return [], False


def _freeze_proof(
    *,
    freeze_generation: int,
    heldout_evaluation_start_generation: int,
    calibration_status: str,
) -> dict[str, Any]:
    if (
        isinstance(freeze_generation, bool)
        or not isinstance(freeze_generation, int)
        or isinstance(heldout_evaluation_start_generation, bool)
        or not isinstance(heldout_evaluation_start_generation, int)
    ):
        raise ValueError("HANDOFF_GENERATION_MUST_BE_INTEGER")
    if freeze_generation < 0 or heldout_evaluation_start_generation < 0:
        raise ValueError("HANDOFF_GENERATION_NEGATIVE_FORBIDDEN")
    if not freeze_generation < heldout_evaluation_start_generation:
        raise ValueError(
            "HANDOFF_POLICY_FROZEN_AFTER_EVALUATION_START "
            f"({freeze_generation} !< {heldout_evaluation_start_generation})"
        )
    return {
        "policy_frozen_before_heldout_evaluation": True,
        "freeze_generation": int(freeze_generation),
        "heldout_evaluation_start_generation": int(heldout_evaluation_start_generation),
        "calibration_status": calibration_status,
    }


def _frozen_policy_payload(
    *, policy: Mapping[str, Any], policy_derivation_ref: str, freeze_generation: int
) -> dict[str, Any]:
    return {
        "policy": dict(policy),
        "policy_derivation_ref": str(policy_derivation_ref).strip(),
        "freeze_generation": int(freeze_generation),
    }


def _training_admission(data_purpose: Any) -> str:
    """Resolve a data purpose to a training admission (schema-compatible).

    Mirrors Nexus Learning ``resolve_training_admission`` vocabulary so the
    handoff is deterministically translatable.  Unknown purposes fail closed
    instead of silently downgrading into trainable data.
    """
    purpose = str(data_purpose or DATA_PURPOSE_TRAINING_CANDIDATE).strip()
    if purpose in _FORBIDDEN_DATA_PURPOSES:
        return TRAINING_ADMISSION_FORBIDDEN
    if purpose == DATA_PURPOSE_TRAINING_CANDIDATE:
        return TRAINING_ADMISSION_QUALITY_GATED
    raise ValueError(f"HANDOFF_UNKNOWN_DATA_PURPOSE:{purpose}")


def _missingness_spec(missingness: Any) -> tuple[str, ...]:
    if missingness is None:
        return ()
    if isinstance(missingness, (list, tuple)):
        output = tuple(
            sorted({str(item).strip() for item in missingness if str(item).strip()})
        )
        return output
    raise ValueError("HANDOFF_MISSINGNESS_MUST_BE_SEQUENCE")


def _usage_field(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"HANDOFF_{name}_INVALID")
    return value


NEXUS_TRANSLATOR_VERSION = "reviewer-to-nexus-learning-v1"


def _quality_floor(value: Any) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not isfinite(value)
        or not 0 <= value <= 1
    ):
        raise ValueError("HANDOFF_REQUIRED_QUALITY_FLOOR_INVALID")
    return float(value)


def _workflow_section(raw: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise ValueError("HANDOFF_WORKFLOW_SECTION_INVALID")
    identity_fields = ("workflow_identity", "workflow_revision", "task_fingerprint")
    identity = {}
    for field in identity_fields:
        value = str(raw.get(field) or "").strip()
        if not value:
            raise ValueError(f"HANDOFF_{field.upper()}_MISSING")
        identity[field] = value
    counts = {}
    for field in (
        "attempt_count",
        "qualified_success_count",
        "semantic_failure_count",
        "provider_failure_count",
        "false_allow_count",
        "human_intervention_count",
    ):
        counts[field] = _usage_field(raw.get(field), field.upper())
    if counts["qualified_success_count"] > counts["attempt_count"]:
        raise ValueError("HANDOFF_QUALIFIED_SUCCESS_EXCEEDS_ATTEMPTS")
    if any(
        counts[field] > counts["attempt_count"]
        for field in ("semantic_failure_count", "provider_failure_count")
    ):
        raise ValueError("HANDOFF_WORKFLOW_FAILURE_COUNT_EXCEEDS_ATTEMPTS")
    ineligibility = _missingness_spec(raw.get("ineligibility_reasons"))
    return {**identity, **counts, "ineligibility_reasons": list(ineligibility)}


def project_nexus_experiment_integrity_input(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Project neutral handoff evidence into canonical Nexus Learning builder input."""
    experiment = payload.get("experiment") or {}
    populations = payload.get("populations") or {}
    policy = payload.get("policy_freeze") or {}
    frozen = policy.get("frozen_policy") or {}
    order = policy.get("freeze_order_proof") or {}
    terminal = payload.get("terminal") or {}
    return {
        "experiment_id": str(experiment.get("experiment_id") or "").strip(),
        "calibration_members": list((populations.get("calibration") or {}).get("members") or []),
        "heldout_members": list((populations.get("heldout") or {}).get("members") or []),
        "independence_unit": populations.get("independence_unit"),
        "policy_derivation_ref": str(policy.get("policy_derivation_ref") or "").strip(),
        "frozen_policy": dict(frozen.get("policy") or {}),
        "freeze_generation": frozen.get("freeze_generation"),
        "heldout_evaluation_start_generation": order.get(
            "heldout_evaluation_start_generation"
        ),
        "calibration_status": policy.get("calibration_status"),
        "terminal_outcome": terminal.get("outcome"),
        "insufficient_calibration_reasons": list(
            policy.get("insufficient_calibration_reasons") or []
        ),
        "reject_all_policy": (
            dict(policy.get("reject_all_policy"))
            if isinstance(policy.get("reject_all_policy"), Mapping)
            else None
        ),
        "negative_terminal": terminal.get("outcome") == TERMINAL_NEGATIVE,
        "evidence_origin": dict(payload.get("evidence_origin") or {}),
    }


def project_nexus_quality_workflow_row(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Project neutral handoff evidence into a canonical QualityWorkflowRow input."""
    workflow = _workflow_section(payload.get("workflow") or {})
    usage = payload.get("usage") or {}
    quality = payload.get("quality_gate") or {}
    cost = payload.get("cost") or {}
    return {
        "workflow_identity": workflow["workflow_identity"],
        "workflow_revision": workflow["workflow_revision"],
        "task_fingerprint": workflow["task_fingerprint"],
        "attempt_count": workflow["attempt_count"],
        "qualified_success_count": workflow["qualified_success_count"],
        "critical_failure_count": quality.get("critical_failure_count"),
        "semantic_failure_count": workflow["semantic_failure_count"],
        "provider_failure_count": workflow["provider_failure_count"],
        "false_allow_count": workflow["false_allow_count"],
        "model_invocation_count": usage.get("model_invocation_count"),
        "provider_invocation_count": usage.get("provider_invocation_count"),
        "fallback_count": usage.get("fallback_count"),
        "token_usage": cost.get("token_usage"),
        "wall_time_seconds": cost.get("wall_time_seconds"),
        "monetary_cost_usd": cost.get("monetary_cost_usd"),
        "human_intervention_count": workflow["human_intervention_count"],
        "missingness_reasons": list(cost.get("missingness") or []),
        "ineligibility_reasons": list(workflow["ineligibility_reasons"]),
    }


def build_experiment_handoff(
    *,
    experiment_id: str,
    experiment_version: str,
    providers: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
    calibration_members: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
    heldout_members: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
    independence_unit: str,
    policy_derivation_ref: str,
    frozen_policy: Mapping[str, Any],
    freeze_generation: int,
    heldout_evaluation_start_generation: int,
    calibration_status: str,
    workflow_identity: str,
    workflow_revision: str,
    task_fingerprint: str,
    attempt_count: int,
    qualified_success_count: int,
    semantic_failure_count: int,
    provider_failure_count: int,
    false_allow_count: int,
    human_intervention_count: int,
    required_quality_floor: float,
    workflow_ineligibility_reasons: list[str] | tuple[str, ...] = (),
    insufficient_calibration_reasons: list[str] | tuple[str, ...] = (),
    reject_all_policy: Mapping[str, Any] | None = None,
    sealed_input_digest: str = "",
    sealed_truth_digest: str = "",
    terminal_outcome: str = TERMINAL_PASS,
    failure_taxonomy: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...] = (),
    model_invocation_count: int = 0,
    provider_invocation_count: int = 0,
    fallback_count: int = 0,
    required_quality_floor_passed: bool = False,
    critical_failure_count: int = 0,
    critical_failure_ceiling: int = 0,
    quality_gate_result: str = INSUFFICIENT_COST_EVIDENCE,
    economics_compared: bool = False,
    cost_telemetry_complete: bool = False,
    missingness: list[str] | tuple[str, ...] = (),
    latency_ms_p50: float | int | None = None,
    latency_ms_p95: float | int | None = None,
    token_usage: int | None = None,
    monetary_cost_usd: float | int | None = None,
    wall_time_seconds: float | int | None = None,
    data_purpose: str = DATA_PURPOSE_TRAINING_CANDIDATE,
    provider_private_required: bool = True,
    public_safe: bool = True,
    evidence_origin: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a canonical, hash-bound experiment-integrity handoff artifact."""
    if independence_unit not in _INDEPENDENCE_UNITS:
        raise ValueError("HANDOFF_INDEPENDENCE_UNIT_INVALID")
    if calibration_status not in _CALIBRATION_STATUSES:
        raise ValueError("HANDOFF_CALIBRATION_STATUS_INVALID")
    outcome = str(terminal_outcome).upper()
    if outcome not in _TERMINAL_OUTCOMES:
        raise ValueError("HANDOFF_TERMINAL_OUTCOME_INVALID")
    if len(str(experiment_id).strip()) == 0:
        raise ValueError("HANDOFF_EXPERIMENT_ID_MISSING")
    if not isinstance(providers, (list, tuple)) or not providers:
        raise ValueError("HANDOFF_PROVIDERS_REQUIRED")
    for provider in providers:
        if not isinstance(provider, Mapping):
            raise ValueError("HANDOFF_PROVIDER_INVALID")
        if any(
            not isinstance(str(provider.get(field) or "").strip(), str)
            or not str(provider.get(field) or "").strip()
            for field in ("provider", "model", "model_revision")
        ):
            raise ValueError("HANDOFF_PROVIDER_IDENTITY_INCOMPLETE")

    model_inv = _usage_field(model_invocation_count, "MODEL_INVOCATION_COUNT")
    provider_inv = _usage_field(provider_invocation_count, "PROVIDER_INVOCATION_COUNT")
    fallbacks = _usage_field(fallback_count, "FALLBACK_COUNT")
    critical_failures = _usage_field(critical_failure_count, "CRITICAL_FAILURE_COUNT")
    ceiling = _usage_field(critical_failure_ceiling, "CRITICAL_FAILURE_CEILING")
    floor = _quality_floor(required_quality_floor)
    workflow = _workflow_section(
        {
            "workflow_identity": workflow_identity,
            "workflow_revision": workflow_revision,
            "task_fingerprint": task_fingerprint,
            "attempt_count": attempt_count,
            "qualified_success_count": qualified_success_count,
            "semantic_failure_count": semantic_failure_count,
            "provider_failure_count": provider_failure_count,
            "false_allow_count": false_allow_count,
            "human_intervention_count": human_intervention_count,
            "ineligibility_reasons": workflow_ineligibility_reasons,
        }
    )
    if critical_failures > workflow["attempt_count"]:
        raise ValueError("HANDOFF_CRITICAL_FAILURE_COUNT_EXCEEDS_ATTEMPTS")

    if quality_gate_result not in _QUALITY_GATE_RESULTS:
        raise ValueError("HANDOFF_QUALITY_GATE_RESULT_INVALID")
    if not isinstance(required_quality_floor_passed, bool):
        raise ValueError("HANDOFF_QUALITY_FLOOR_REQUIRES_BOOL")
    observed_floor_passed = (
        workflow["attempt_count"] > 0
        and workflow["qualified_success_count"] / workflow["attempt_count"] >= floor
    )
    if required_quality_floor_passed != observed_floor_passed:
        raise ValueError("HANDOFF_QUALITY_FLOOR_FLAG_MISMATCH")
    if not isinstance(economics_compared, bool):
        raise ValueError("HANDOFF_ECONOMICS_COMPARED_REQUIRES_BOOL")

    calibration = _population_binding(calibration_members, independence_unit)
    heldout = _population_binding(heldout_members, independence_unit)
    cal_ids = tuple(calibration["member_identities"])
    heldout_ids = tuple(heldout["member_identities"])
    shared, has_overlap = _overlap(cal_ids, heldout_ids)
    if has_overlap:
        raise ValueError(
            f"HANDOFF_POPULATION_OVERLAP:{independence_unit}:{','.join(shared[:5])}"
        )
    overlap_proof = {
        "basis": "semantic_" + independence_unit,
        "overlap": False,
        "shared_identities": [],
    }

    policy_payload = _frozen_policy_payload(
        policy=frozen_policy,
        policy_derivation_ref=policy_derivation_ref,
        freeze_generation=freeze_generation,
    )
    policy_hash = _hash(policy_payload)

    order_proof = _freeze_proof(
        freeze_generation=freeze_generation,
        heldout_evaluation_start_generation=heldout_evaluation_start_generation,
        calibration_status=calibration_status,
    )

    reasons = _missingness_spec(insufficient_calibration_reasons)
    if calibration_status == CALIBRATED and reasons:
        raise ValueError("HANDOFF_CALIBRATED_WITH_INSUFFICIENT_REASONS")
    if calibration_status in {INSUFFICIENT_CALIBRATION, EXPLORATORY_UNCALIBRATED} and not reasons:
        raise ValueError("HANDOFF_UNCALIBRATED_WITHOUT_REASONS")
    if calibration_status == FROZEN_REJECT_ALL and reject_all_policy is None:
        raise ValueError("HANDOFF_REJECT_ALL_POLICY_REQUIRED")
    if reject_all_policy is not None:
        if calibration_status != FROZEN_REJECT_ALL:
            raise ValueError("HANDOFF_REJECT_ALL_STATUS_MISMATCH")
        if (
            not isinstance(reject_all_policy, Mapping)
            or not reject_all_policy.get("target_policy_delta")
        ):
            raise ValueError("HANDOFF_REJECT_ALL_POLICY_INVALID")
        if reject_all_policy.get("model_success_claim") is not False:
            raise ValueError("HANDOFF_REJECT_ALL_CLAIMS_MODEL_SUCCESS")

    terminal_negative = outcome in _NEGATIVE_TERMINAL_OUTCOMES
    if outcome == TERMINAL_PASS and calibration_status != CALIBRATED:
        raise ValueError("HANDOFF_PASS_WITHOUT_PREFROZEN_CALIBRATION")

    taxonomy = tuple(
        sorted(
            (
                {
                    "kind": str(item.get("kind") or "").strip(),
                    "count": _usage_field(item.get("count"), "TAXONOMY_COUNT"),
                    "description": str(item.get("description") or "").strip(),
                }
                for item in failure_taxonomy or ()
                if isinstance(item, Mapping)
            ),
            key=lambda item: item["kind"],
        )
    )
    if any(not item["kind"] for item in taxonomy):
        raise ValueError("HANDOFF_TAXONOMY_KIND_MISSING")

    missing = _missingness_spec(missingness)
    cost: dict[str, Any] = {
        "latency_ms_p50": latency_ms_p50,
        "latency_ms_p95": latency_ms_p95,
        "token_usage": token_usage,
        "monetary_cost_usd": monetary_cost_usd,
        "wall_time_seconds": wall_time_seconds,
    }
    for name in _STABLE_OPTIONAL_COST:
        value = cost[name]
        if value is None:
            if name not in missing:
                raise ValueError(f"HANDOFF_COST_MISSING_REASON_REQUIRED:{name}")
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"HANDOFF_COST_{name.upper()}_INVALID")
        if value < 0:
            raise ValueError(f"HANDOFF_COST_{name.upper()}_NEGATIVE_FORBIDDEN")
        if name == "token_usage" and not isinstance(value, int):
            raise ValueError("HANDOFF_COST_TOKEN_USAGE_MUST_BE_INTEGER")
    numeric_present = [name for name in _STABLE_OPTIONAL_COST if cost[name] is not None]
    if cost_telemetry_complete and any(cost[name] is None for name in _STABLE_OPTIONAL_COST):
        raise ValueError("HANDOFF_COST_TELEMETRY_INCOMPLETE_WHILE_COMPLETE")
    if cost_telemetry_complete and missing:
        raise ValueError("HANDOFF_COST_TELEMETRY_COMPLETE_WITH_MISSINGNESS")
    if not cost_telemetry_complete and numeric_present:
        raise ValueError("HANDOFF_COST_TELEMETRY_INCOMPLETE_WITH_VALUES")

    quality_eligible = quality_gate_result in _ECONOMICS_ELIGIBLE_GATE_RESULTS
    if economics_compared and not (quality_eligible and required_quality_floor_passed):
        raise ValueError("HANDOFF_ECONOMICS_COMPARED_BEFORE_QUALITY")
    if critical_failures > ceiling and quality_gate_result in _ECONOMICS_ELIGIBLE_GATE_RESULTS:
        raise ValueError("HANDOFF_CRITICAL_FAILURES_ABOVE_CEILING")

    training_admission = _training_admission(data_purpose)
    providers_normalized = tuple(
        dict(
            (
                ("provider", str(provider.get("provider") or "").strip()),
                ("model", str(provider.get("model") or "").strip()),
                ("model_revision", str(provider.get("model_revision") or "").strip()),
                ("adapter_version", str(provider.get("adapter_version") or "").strip()),
                ("transport", str(provider.get("transport") or "").strip()),
            )
        )
        for provider in providers
    )

    if evidence_origin is None:
        configured = providers_normalized[0] if len(providers_normalized) == 1 else {}
        evidence_origin_value = build_evidence_origin_compat(
            origin_class=UNKNOWN_ORIGIN,
            configured_provider=configured.get("provider"),
            configured_model=configured.get("model"),
        )
    else:
        evidence_origin_value = dict(evidence_origin)
        verify_evidence_origin_compat(evidence_origin_value)
    live_provider_verified = verify_evidence_origin_compat(evidence_origin_value)[
        "live_provider_observed"
    ]

    terminal = {
        "outcome": outcome,
        "negative_terminal": terminal_negative,
        "failure_taxonomy": list(taxonomy),
    }

    handoff = {
        "schema": HANDOFF_SCHEMA,
        "experiment": {
            "experiment_id": str(experiment_id).strip(),
            "experiment_version": str(experiment_version).strip(),
        },
        "providers": list(providers_normalized),
        "populations": {
            "independence_unit": independence_unit,
            "calibration": calibration,
            "heldout": heldout,
            "overlap_proof": overlap_proof,
        },
        "policy_freeze": {
            "policy_derivation_ref": str(policy_derivation_ref).strip(),
            "frozen_policy": {
                "policy": dict(frozen_policy),
                "policy_hash": policy_hash,
                "freeze_generation": int(freeze_generation),
                "policy_derivation_ref": str(policy_derivation_ref).strip(),
            },
            "freeze_order_proof": order_proof,
            "calibration_status": calibration_status,
            "insufficient_calibration_reasons": list(reasons),
            "reject_all_policy": dict(reject_all_policy) if reject_all_policy is not None else None,
        },
        "sealed": {
            "input_digest": str(sealed_input_digest).strip(),
            "truth_digest": str(sealed_truth_digest).strip(),
        },
        "terminal": terminal,
        "workflow": workflow,
        "usage": {
            "model_invocation_count": model_inv,
            "provider_invocation_count": provider_inv,
            "fallback_count": fallbacks,
        },
        "quality_gate": {
            "required_quality_floor": floor,
            "required_quality_floor_passed": required_quality_floor_passed,
            "critical_failure_count": critical_failures,
            "critical_failure_ceiling": ceiling,
            "quality_gate_result": quality_gate_result,
            "economics_compared": economics_compared,
        },
        "cost": {
            "cost_telemetry_complete": cost_telemetry_complete,
            "missingness": list(missing),
            "latency_ms_p50": latency_ms_p50,
            "latency_ms_p95": latency_ms_p95,
            "token_usage": token_usage,
            "monetary_cost_usd": monetary_cost_usd,
            "wall_time_seconds": wall_time_seconds,
        },
        "training": {
            "data_purpose": str(data_purpose).strip(),
            "training_admission": training_admission,
            "training_forbidden": training_admission == TRAINING_ADMISSION_FORBIDDEN,
        },
        "boundary": {
            "provider_private_required": provider_private_required,
            "public_safe": public_safe,
        },
        "evidence_origin": evidence_origin_value,
        "live_provider_claim": {
            "verified": live_provider_verified,
            "claim_ceiling": LIVE_PROVIDER_CLAIM_CEILING,
        },
        "nexus_projection": {
            "experiment_integrity_schema": NEXUS_INTEGRITY_SCHEMA,
            "economics_schema": NEXUS_ECONOMICS_SCHEMA,
            "episode_schema": NEXUS_EPISODE_SCHEMA,
            "translator_version": NEXUS_TRANSLATOR_VERSION,
            "deterministically_translatable": True,
            "negative_terminal_preserved": terminal_negative,
        },
        "claim_ceiling": HANDOFF_CLAIM_CEILING,
    }
    handoff["nexus_projection"]["experiment_integrity_input"] = (
        project_nexus_experiment_integrity_input(handoff)
    )
    handoff["nexus_projection"]["quality_workflow_input"] = (
        project_nexus_quality_workflow_row(handoff)
    )
    verify_experiment_handoff(handoff)
    return handoff


def _normalize_provider(provider: Any) -> dict[str, str]:
    if not isinstance(provider, Mapping):
        raise ValueError("HANDOFF_PROVIDER_INVALID")
    return {
        "provider": str(provider.get("provider") or "").strip(),
        "model": str(provider.get("model") or "").strip(),
        "model_revision": str(provider.get("model_revision") or "").strip(),
        "adapter_version": str(provider.get("adapter_version") or "").strip(),
        "transport": str(provider.get("transport") or "").strip(),
    }


def _revalidate_calibration_status(payload: Mapping[str, Any]) -> None:
    calibrated = payload.get("calibration_status")
    reasons = _missingness_spec(payload.get("insufficient_calibration_reasons"))
    if calibrated not in _CALIBRATION_STATUSES:
        raise ValueError("HANDOFF_CALIBRATION_STATUS_INVALID")
    if calibrated == CALIBRATED and reasons:
        raise ValueError("HANDOFF_CALIBRATED_WITH_INSUFFICIENT_REASONS")
    if calibrated in {INSUFFICIENT_CALIBRATION, EXPLORATORY_UNCALIBRATED} and not reasons:
        raise ValueError("HANDOFF_UNCALIBRATED_WITHOUT_REASONS")
    reject_all = payload.get("reject_all_policy")
    if calibrated == FROZEN_REJECT_ALL and reject_all is None:
        raise ValueError("HANDOFF_REJECT_ALL_POLICY_REQUIRED")
    if reject_all is not None:
        if calibrated != FROZEN_REJECT_ALL:
            raise ValueError("HANDOFF_REJECT_ALL_STATUS_MISMATCH")
        if not isinstance(reject_all, Mapping) or not reject_all.get("target_policy_delta"):
            raise ValueError("HANDOFF_REJECT_ALL_POLICY_INVALID")
        if reject_all.get("model_success_claim") is not False:
            raise ValueError("HANDOFF_REJECT_ALL_CLAIMS_MODEL_SUCCESS")
    if payload.get("reject_all_policy") is not None:
        if calibrated != FROZEN_REJECT_ALL:
            raise ValueError("HANDOFF_REJECT_ALL_STATUS_MISMATCH")


def verify_experiment_handoff(payload: Any) -> dict[str, Any]:
    """Fail-closed semantic verifier for a handoff artifact.

    Recomputes population binding, overlap, policy hash, freeze order,
    terminal disposition, training admission, and derived completeness from the
    embedded neutral inputs; rejects tampering rather than only a byte-hash
    mismatch.  Returns a stable manifest projection.
    """
    if not isinstance(payload, Mapping):
        raise ValueError("HANDOFF_NOT_A_MAPPING")
    if payload.get("schema") != HANDOFF_SCHEMA:
        raise ValueError("HANDOFF_SCHEMA_INVALID")
    if payload.get("claim_ceiling") != HANDOFF_CLAIM_CEILING:
        raise ValueError("HANDOFF_CLAIM_CEILING_INVALID")
    if not str(payload.get("experiment", {}).get("experiment_id") or "").strip():
        raise ValueError("HANDOFF_EXPERIMENT_ID_MISSING")

    experiment = payload.get("experiment") or {}
    if not isinstance(experiment, Mapping) or not str(experiment.get("experiment_version") or "").strip():
        raise ValueError("HANDOFF_EXPERIMENT_VERSION_MISSING")

    providers = payload.get("providers")
    if not isinstance(providers, (list, tuple)) or not providers:
        raise ValueError("HANDOFF_PROVIDERS_REQUIRED")
    for provider in providers:
        normalized = _normalize_provider(provider)
        if any(not value for value in (
            normalized["provider"], normalized["model"], normalized["model_revision"]
        )):
            raise ValueError("HANDOFF_PROVIDER_IDENTITY_INCOMPLETE")

    populations = payload.get("populations") or {}
    independence_unit = populations.get("independence_unit")
    if independence_unit not in _INDEPENDENCE_UNITS:
        raise ValueError("HANDOFF_INDEPENDENCE_UNIT_INVALID")

    calibration = populations.get("calibration") or {}
    heldout = populations.get("heldout") or {}
    cal_ids = tuple(str(item) for item in calibration.get("member_identities", []) or [])
    heldout_ids = tuple(str(item) for item in heldout.get("member_identities", []) or [])
    if not cal_ids or not heldout_ids:
        raise ValueError("HANDOFF_EMPTY_POPULATION")

    expected_cal_hash = _hash({"identities": cal_ids, "unit": independence_unit})
    expected_heldout_hash = _hash({"identities": heldout_ids, "unit": independence_unit})
    recomputed_cal = _population_binding(calibration.get("members", []) or [], independence_unit)
    recomputed_heldout = _population_binding(heldout.get("members", []) or [], independence_unit)
    if calibration.get("population_hash") != expected_cal_hash:
        raise ValueError("HANDOFF_CALIBRATION_POPULATION_HASH_MISMATCH")
    if heldout.get("population_hash") != expected_heldout_hash:
        raise ValueError("HANDOFF_HELDOUT_POPULATION_HASH_MISMATCH")
    if calibration.get("members_hash") != recomputed_cal["members_hash"]:
        raise ValueError("HANDOFF_CALIBRATION_MEMBERS_HASH_MISMATCH")
    if heldout.get("members_hash") != recomputed_heldout["members_hash"]:
        raise ValueError("HANDOFF_HELDOUT_MEMBERS_HASH_MISMATCH")
    if list(calibration.get("member_identities", []) or []) != recomputed_cal["member_identities"]:
        raise ValueError("HANDOFF_CALIBRATION_IDENTITY_MISMATCH")
    if list(heldout.get("member_identities", []) or []) != recomputed_heldout["member_identities"]:
        raise ValueError("HANDOFF_HELDOUT_IDENTITY_MISMATCH")
    if calibration.get("member_count") != recomputed_cal["member_count"]:
        raise ValueError("HANDOFF_CALIBRATION_MEMBER_COUNT_MISMATCH")
    if heldout.get("member_count") != recomputed_heldout["member_count"]:
        raise ValueError("HANDOFF_HELDOUT_MEMBER_COUNT_MISMATCH")

    shared, has_overlap = _overlap(cal_ids, heldout_ids)
    if has_overlap:
        raise ValueError(f"HANDOFF_POPULATION_OVERLAP:{','.join(shared[:5])}")
    overlap_proof = populations.get("overlap_proof") or {}
    if (
        overlap_proof.get("basis") != "semantic_" + independence_unit
        or overlap_proof.get("overlap") is not False
        or overlap_proof.get("shared_identities")
    ):
        raise ValueError("HANDOFF_OVERLAP_PROOF_TAMPERED")

    freeze = payload.get("policy_freeze") or {}
    calibration_status = freeze.get("calibration_status")
    _revalidate_calibration_status(freeze)
    raw_freeze_generation = freeze.get("freeze_generation")
    if isinstance(raw_freeze_generation, bool) or not isinstance(raw_freeze_generation, int):
        raw_freeze_generation = (freeze.get("frozen_policy") or {}).get("freeze_generation")
    if isinstance(raw_freeze_generation, bool) or not isinstance(raw_freeze_generation, int):
        raw_freeze_generation = (freeze.get("freeze_order_proof") or {}).get("freeze_generation")
    if not isinstance(raw_freeze_generation, int):
        raise ValueError("HANDOFF_FREEZE_GENERATION_INVALID")

    frozen = freeze.get("frozen_policy") or {}
    if not isinstance(frozen, Mapping) or "policy" not in frozen:
        raise ValueError("HANDOFF_FROZEN_POLICY_MISSING")
    policy_payload = _frozen_policy_payload(
        policy=frozen.get("policy") or {},
        policy_derivation_ref=frozen.get("policy_derivation_ref") or "",
        freeze_generation=raw_freeze_generation,
    )
    expected_policy_hash = _hash(policy_payload)
    if frozen.get("policy_hash") != expected_policy_hash:
        raise ValueError("HANDOFF_POLICY_HASH_MISMATCH")
    derivation_ref = str(freeze.get("policy_derivation_ref") or "").strip()
    if not derivation_ref:
        raise ValueError("HANDOFF_POLICY_DERIVATION_REF_MISSING")
    if derivation_ref != str(frozen.get("policy_derivation_ref") or "").strip():
        raise ValueError("HANDOFF_POLICY_DERIVATION_REF_MISMATCH")

    order_proof = freeze.get("freeze_order_proof") or {}
    derived_eval_start = order_proof.get("heldout_evaluation_start_generation")
    if isinstance(derived_eval_start, bool) or not isinstance(derived_eval_start, int):
        derived_eval_start = -1
    if not isinstance(raw_freeze_generation, int) or raw_freeze_generation < 0 or derived_eval_start < 0:
        raise ValueError("HANDOFF_FREEZE_ORDER_INCOMPLETE")
    if not raw_freeze_generation < derived_eval_start:
        raise ValueError("HANDOFF_POLICY_FROZEN_AFTER_EVALUATION_START")
    if order_proof.get("policy_frozen_before_heldout_evaluation") is not True:
        raise ValueError("HANDOFF_FREEZE_ORDER_PROOF_TAMPERED")
    if order_proof.get("calibration_status") != calibration_status:
        raise ValueError("HANDOFF_FREEZE_ORDER_CALIBRATION_STATUS_MISMATCH")
    if order_proof.get("freeze_generation") != raw_freeze_generation:
        raise ValueError("HANDOFF_FREEZE_ORDER_GENERATION_MISMATCH")

    terminal = payload.get("terminal") or {}
    outcome = str(terminal.get("outcome") or "").upper()
    if outcome not in _TERMINAL_OUTCOMES:
        raise ValueError("HANDOFF_TERMINAL_OUTCOME_INVALID")
    expected_negative = outcome in _NEGATIVE_TERMINAL_OUTCOMES
    if not isinstance(terminal.get("negative_terminal"), bool) or terminal.get(
        "negative_terminal"
    ) != expected_negative:
        raise ValueError("HANDOFF_TERMINAL_NEGATIVE_FLAG_MISMATCH")
    if outcome == TERMINAL_PASS and calibration_status != CALIBRATED:
        raise ValueError("HANDOFF_PASS_WITHOUT_PREFROZEN_CALIBRATION")

    taxonomy = terminal.get("failure_taxonomy") or []
    if not isinstance(taxonomy, (list, tuple)):
        raise ValueError("HANDOFF_TAXONOMY_INVALID")
    kinds = [str(item.get("kind") or "") for item in taxonomy]
    if any(not kind for kind in kinds):
        raise ValueError("HANDOFF_TAXONOMY_KIND_MISSING")
    if len(set(kinds)) != len(kinds):
        raise ValueError("HANDOFF_TAXONOMY_DUPLICATE_KIND")

    usage = payload.get("usage") or {}
    if any(
        isinstance(usage.get(name), bool)
        or not isinstance(usage.get(name), int)
        or usage.get(name) < 0
        for name in ("model_invocation_count", "provider_invocation_count", "fallback_count")
    ):
        raise ValueError("HANDOFF_USAGE_COUNT_INVALID")

    workflow = _workflow_section(payload.get("workflow") or {})
    quality = payload.get("quality_gate") or {}
    floor = _quality_floor(quality.get("required_quality_floor"))
    if quality.get("critical_failure_count") > workflow["attempt_count"]:
        raise ValueError("HANDOFF_CRITICAL_FAILURE_COUNT_EXCEEDS_ATTEMPTS")
    observed_floor_passed = (
        workflow["attempt_count"] > 0
        and workflow["qualified_success_count"] / workflow["attempt_count"] >= floor
    )
    if quality.get("required_quality_floor_passed") != observed_floor_passed:
        raise ValueError("HANDOFF_QUALITY_FLOOR_FLAG_MISMATCH")
    gate_result = quality.get("quality_gate_result")
    if gate_result not in _QUALITY_GATE_RESULTS:
        raise ValueError("HANDOFF_QUALITY_GATE_RESULT_INVALID")
    if not isinstance(quality.get("required_quality_floor_passed"), bool):
        raise ValueError("HANDOFF_QUALITY_FLOOR_REQUIRES_BOOL")
    if any(
        isinstance(quality.get(name), bool)
        or not isinstance(quality.get(name), int)
        or quality.get(name) < 0
        for name in ("critical_failure_count", "critical_failure_ceiling")
    ):
        raise ValueError("HANDOFF_CRITICAL_FAILURE_COUNT_INVALID")
    if not isinstance(quality.get("economics_compared"), bool):
        raise ValueError("HANDOFF_ECONOMICS_COMPARED_REQUIRES_BOOL")

    cost = payload.get("cost") or {}
    if not isinstance(cost, Mapping):
        raise ValueError("HANDOFF_COST_SECTION_INVALID")
    missing = _missingness_spec(cost.get("missingness"))
    numeric_present: list[str] = []
    for name in _STABLE_OPTIONAL_COST:
        value = cost.get(name)
        if value is None:
            if name not in missing:
                raise ValueError(f"HANDOFF_COST_MISSING_REASON_REQUIRED:{name}")
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            raise ValueError(f"HANDOFF_COST_{name.upper()}_INVALID")
        if name == "token_usage" and not isinstance(value, int):
            raise ValueError("HANDOFF_COST_TOKEN_USAGE_MUST_BE_INTEGER")
        numeric_present.append(name)
    if not isinstance(cost.get("cost_telemetry_complete"), bool):
        raise ValueError("HANDOFF_COST_TELEMETRY_FLAG_INVALID")
    if cost.get("cost_telemetry_complete") and missing:
        raise ValueError("HANDOFF_COST_TELEMETRY_COMPLETE_WITH_MISSINGNESS")
    if cost.get("cost_telemetry_complete") and any(cost[name] is None for name in _STABLE_OPTIONAL_COST):
        raise ValueError("HANDOFF_COST_TELEMETRY_INCOMPLETE_WHILE_COMPLETE")
    if not cost.get("cost_telemetry_complete") and numeric_present:
        raise ValueError("HANDOFF_COST_TELEMETRY_INCOMPLETE_WITH_VALUES")

    if cost.get("cost_telemetry_complete"):
        gate_eligible = gate_result in _ECONOMICS_ELIGIBLE_GATE_RESULTS
        if not quality.get("economics_compared"):
            raise ValueError("HANDOFF_ECONOMICS_GATE_REQUIRED_BEFORE_COMPARISON")
        if not quality.get("required_quality_floor_passed"):
            raise ValueError("HANDOFF_QUALITY_FLOOR_FAILED_BEFORE_COMPARISON")
        if not gate_eligible:
            raise ValueError("HANDOFF_QUALITY_GATE_FAILED_BEFORE_COMPARISON")

    training = payload.get("training") or {}
    admission = _training_admission(training.get("data_purpose"))
    if training.get("training_admission") != admission:
        raise ValueError("HANDOFF_TRAINING_ADMISSION_MISMATCH")
    if training.get("training_forbidden") != (admission == TRAINING_ADMISSION_FORBIDDEN):
        raise ValueError("HANDOFF_TRAINING_FORBIDDEN_FLAG_MISMATCH")

    evidence_origin = payload.get("evidence_origin")
    origin_result = verify_evidence_origin_compat(evidence_origin)
    live_claim = payload.get("live_provider_claim") or {}
    if live_claim.get("claim_ceiling") != LIVE_PROVIDER_CLAIM_CEILING:
        raise ValueError("HANDOFF_LIVE_PROVIDER_CLAIM_CEILING_INVALID")
    if live_claim.get("verified") is not origin_result["live_provider_observed"]:
        raise ValueError("HANDOFF_LIVE_PROVIDER_CLAIM_MISMATCH")

    projection = payload.get("nexus_projection") or {}
    if projection.get("experiment_integrity_schema") != NEXUS_INTEGRITY_SCHEMA:
        raise ValueError("HANDOFF_NEXUS_INTEGRITY_SCHEMA_INVALID")
    if projection.get("economics_schema") != NEXUS_ECONOMICS_SCHEMA:
        raise ValueError("HANDOFF_NEXUS_ECONOMICS_SCHEMA_INVALID")
    if projection.get("translator_version") != NEXUS_TRANSLATOR_VERSION:
        raise ValueError("HANDOFF_NEXUS_TRANSLATOR_VERSION_INVALID")
    if projection.get("deterministically_translatable") is not True:
        raise ValueError("HANDOFF_NEXUS_TRANSLATION_FLAG_INVALID")
    if projection.get("negative_terminal_preserved") != expected_negative:
        raise ValueError("HANDOFF_NEXUS_NEGATIVE_TERMINAL_MISMATCH")
    if projection.get("experiment_integrity_input") != project_nexus_experiment_integrity_input(payload):
        raise ValueError("HANDOFF_NEXUS_INTEGRITY_PROJECTION_MISMATCH")
    if projection.get("quality_workflow_input") != project_nexus_quality_workflow_row(payload):
        raise ValueError("HANDOFF_NEXUS_ECONOMICS_PROJECTION_MISMATCH")

    boundary = payload.get("boundary") or {}
    if not isinstance(boundary.get("provider_private_required"), bool):
        raise ValueError("HANDOFF_BOUNDARY_PRIVATE_FLAG_INVALID")
    if not isinstance(boundary.get("public_safe"), bool):
        raise ValueError("HANDOFF_BOUNDARY_PUBLIC_SAFE_FLAG_INVALID")

    return {
        "schema": HANDOFF_SCHEMA,
        "schema_verified": HANDOFF_SCHEMA,
        "claim_ceiling": HANDOFF_CLAIM_CEILING,
        "handoff_id": _hash(
            {
                "experiment_id": experiment.get("experiment_id"),
                "experiment_version": experiment.get("experiment_version"),
                "population_hashes": [
                    calibration.get("population_hash"),
                    heldout.get("population_hash"),
                ],
                "policy_hash": frozen.get("policy_hash"),
                "terminal_outcome": outcome,
            }
        ),
        "content_sha256": _hash(payload),
    }