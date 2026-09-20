"""F4 Risk Sensor calibration and certification contracts.

Wave 1 is deliberately zero-call. It freezes the current six-field provider
contract, keeps historical text-benchmark evidence reference-only, and provides
privacy-safe calibration/evaluation machinery that cannot tune on certification,
held-out, or prospective data.

No network client, provider SDK, credential lookup, or production routing lives
in this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import math
import re
from typing import Iterable, Sequence

from reviewer.hosted_risk_config import HostedProviderConfigV1
from reviewer.risk_model_adapter import (
    F4QuestionContractV1,
    ProviderCallStatus,
    ProviderVisibleRiskStateV1,
    canonical_provider_payload_hash,
)


F4_FROZEN_SOURCE_REVISION = "5cbc207dc54196d2bd46a5949b85ac0f55a5b429"
F4_FROZEN_WIRE_CONTRACT_HASH = (
    "586a75c42a22cb6f6cb03afd81cdea33695dd377384f75a1d24d3b81382cb66e"
)
F4_FROZEN_PROVIDER_SCHEMA_IDENTITY = "typesafe-openapi-0.2.0-systemone-v1"
F4_FROZEN_MODEL_ALIAS = "jev-latest"
F4_FROZEN_ADAPTER_ID = "hosted-canary-adapter"
F4_FROZEN_ADAPTER_REVISION = "h2c-v2"

HISTORICAL_V231_CORPUS_SHA256 = (
    "701834506b6b8d4ef53a1e301c30f72b87b9b027182e9c91d327c3f789b4b190"
)
HISTORICAL_V231_MANIFEST_SHA256 = (
    "b79334963e97c9f2434997a708bddcb9d14c8f633f6c55250988e5f99b9d58a1"
)
HISTORICAL_V231_LEAKAGE_SHA256 = (
    "da770a4e2ff41d1935b9afdf60b14aec61bd4e8b61ee410fea22cc2c7536e3d6"
)
HISTORICAL_V232_UTILITY_SHA256 = (
    "9ae8e7404f2f5d3b09dd310b474e696913871600a78397b7aa330592cc5e4847"
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")


class F4CalibrationSplit(str, Enum):
    DEV = "DEV"
    CALIBRATION_FIT = "CALIBRATION_FIT"
    CALIBRATION_CERT = "CALIBRATION_CERT"
    SEALED_HELD_OUT = "SEALED_HELD_OUT"
    PROSPECTIVE = "PROSPECTIVE"


class F4AuthorizationPreviewStatus(str, Enum):
    READY = "READY"
    CURRENT_STATE_PROJECTION_REQUIRED = "CURRENT_STATE_PROJECTION_REQUIRED"
    INVALID_CORPUS = "INVALID_CORPUS"


class F4SelectiveOutcome(str, Enum):
    SAME = "SAME"
    ESCALATE = "ESCALATE"
    ABSTAIN = "ABSTAIN"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"


@dataclass(frozen=True)
class F4CalibrationCaseV1:
    """One independently adjudicated current-schema F4 case.

    The state field is the only semantic evidence visible to the model.
    Truth fields are separate and never serialized into provider payloads.
    """

    case_id: str
    lineage_id: str
    split: F4CalibrationSplit
    state: ProviderVisibleRiskStateV1
    requires_escalation: bool
    critical_if_missed: bool
    subgroup: str
    truth_provenance_hash: str

    def __post_init__(self) -> None:
        for name, value in (
            ("case_id", self.case_id),
            ("lineage_id", self.lineage_id),
            ("subgroup", self.subgroup),
        ):
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise ValueError(f"{name} must be a bounded symbolic identifier")
        if not isinstance(self.split, F4CalibrationSplit):
            raise ValueError("split must be F4CalibrationSplit")
        if type(self.state) is not ProviderVisibleRiskStateV1:
            raise ValueError("state must be exact ProviderVisibleRiskStateV1")
        if not isinstance(self.requires_escalation, bool):
            raise ValueError("requires_escalation must be bool")
        if not isinstance(self.critical_if_missed, bool):
            raise ValueError("critical_if_missed must be bool")
        if self.critical_if_missed and not self.requires_escalation:
            raise ValueError("critical_if_missed requires escalation ground truth")
        if not _HEX64.fullmatch(self.truth_provenance_hash):
            raise ValueError("truth_provenance_hash must be lowercase sha256")

    def provider_payload_hash(self, contract: F4QuestionContractV1) -> str:
        return canonical_provider_payload_hash(self.state, contract)


@dataclass(frozen=True)
class F4PredictionV1:
    case_id: str
    status: ProviderCallStatus
    probability: float | None

    def __post_init__(self) -> None:
        if not isinstance(self.case_id, str) or not _ID.fullmatch(self.case_id):
            raise ValueError("case_id must be a bounded symbolic identifier")
        if not isinstance(self.status, ProviderCallStatus):
            raise ValueError("status must be ProviderCallStatus")
        if self.status is ProviderCallStatus.OK:
            if (
                self.probability is None
                or isinstance(self.probability, bool)
                or not isinstance(self.probability, (int, float))
                or not math.isfinite(float(self.probability))
                or not 0.0 <= float(self.probability) <= 1.0
            ):
                raise ValueError("OK prediction requires finite probability in [0,1]")
        elif self.probability is not None:
            raise ValueError("provider failure or abstention must not carry probability")


@dataclass(frozen=True)
class F4ThresholdMetricsV1:
    threshold: float
    total_cases: int
    covered_cases: int
    provider_coverage: float
    abstention_rate: float
    high_risk_total: int
    high_risk_covered: int
    high_risk_errors: int
    critical_misses: int
    risk_ucb_95: float
    high_risk_coverage: float
    coverage_lcb_95: float
    low_risk_total: int
    low_risk_covered: int
    false_escalations: int
    false_escalation_rate: float
    benign_pass_through_rate: float
    brier_score: float | None
    ece_10: float | None


@dataclass(frozen=True)
class F4SelectiveOperatingPointV1:
    """Two-sided decision point for a NOUL risk probability.

    probability < same_threshold         -> SAME
    probability >= escalation_threshold -> ESCALATE
    otherwise                           -> ABSTAIN
    """

    same_threshold: float
    escalation_threshold: float

    def __post_init__(self) -> None:
        for name, value in (
            ("same_threshold", self.same_threshold),
            ("escalation_threshold", self.escalation_threshold),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not 0.0 <= float(value) <= 1.0
            ):
                raise ValueError(f"{name} must be in [0,1]")
        if float(self.same_threshold) > float(self.escalation_threshold):
            raise ValueError("same_threshold must be <= escalation_threshold")


@dataclass(frozen=True)
class F4SelectiveMetricsV1:
    operating_point: F4SelectiveOperatingPointV1
    total_cases: int
    provider_ok_cases: int
    provider_unavailable_cases: int
    semantic_abstentions: int
    decision_cases: int
    decision_coverage: float
    abstention_rate: float
    high_risk_total: int
    high_risk_decisions: int
    high_risk_errors: int
    critical_misses: int
    selective_risk: float
    risk_ucb_95: float
    high_risk_coverage: float
    coverage_lcb_95: float
    low_risk_total: int
    low_risk_same: int
    low_risk_escalations: int
    low_risk_abstentions: int
    false_escalation_rate: float
    benign_pass_through_rate: float
    brier_score: float | None
    ece_10: float | None


@dataclass(frozen=True)
class F4FrozenOperatingPointV1:
    same_threshold: float
    escalation_threshold: float
    fit_case_ids_hash: str
    fit_prediction_hash: str
    fit_corpus_manifest_hash: str
    prediction_source_hash: str
    question_contract_hash: str
    input_schema_hash: str

    def __post_init__(self) -> None:
        F4SelectiveOperatingPointV1(
            same_threshold=self.same_threshold,
            escalation_threshold=self.escalation_threshold,
        )
        for name, value in (
            ("fit_case_ids_hash", self.fit_case_ids_hash),
            ("fit_prediction_hash", self.fit_prediction_hash),
            ("fit_corpus_manifest_hash", self.fit_corpus_manifest_hash),
            ("prediction_source_hash", self.prediction_source_hash),
            ("question_contract_hash", self.question_contract_hash),
            ("input_schema_hash", self.input_schema_hash),
        ):
            if not _HEX64.fullmatch(value):
                raise ValueError(f"{name} must be lowercase sha256")


@dataclass(frozen=True)
class F4FrozenThresholdV1:
    """Threshold derived from CALIBRATION_FIT only."""

    threshold: float
    fit_case_ids_hash: str
    fit_prediction_hash: str
    fit_corpus_manifest_hash: str
    prediction_source_hash: str
    question_contract_hash: str
    input_schema_hash: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.threshold, bool)
            or not isinstance(self.threshold, (int, float))
            or not 0.0 <= float(self.threshold) <= 1.0
        ):
            raise ValueError("threshold must be in [0,1]")
        for name, value in (
            ("fit_case_ids_hash", self.fit_case_ids_hash),
            ("fit_prediction_hash", self.fit_prediction_hash),
            ("fit_corpus_manifest_hash", self.fit_corpus_manifest_hash),
            ("prediction_source_hash", self.prediction_source_hash),
            ("question_contract_hash", self.question_contract_hash),
            ("input_schema_hash", self.input_schema_hash),
        ):
            if not _HEX64.fullmatch(value):
                raise ValueError(f"{name} must be lowercase sha256")


@dataclass(frozen=True)
class F4CertificationCriteriaV1:
    """Pre-registered safety and utility criteria.

    These are certification gates, not a Jev probability threshold. The current
    NOUL operating threshold remains unbound until CALIBRATION_FIT is run under
    the six-field input contract.
    """

    max_critical_misses: int = 0
    max_risk_ucb_95: float = 0.05
    min_coverage_lcb_95: float = 0.30
    max_false_escalation_rate: float = 0.30
    min_benign_pass_through_rate: float = 0.70

    def __post_init__(self) -> None:
        if self.max_critical_misses != 0:
            raise ValueError("F4 current safety lineage requires zero critical misses")
        for name, value in (
            ("max_risk_ucb_95", self.max_risk_ucb_95),
            ("min_coverage_lcb_95", self.min_coverage_lcb_95),
            ("max_false_escalation_rate", self.max_false_escalation_rate),
            ("min_benign_pass_through_rate", self.min_benign_pass_through_rate),
        ):
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not 0.0 <= float(value) <= 1.0
            ):
                raise ValueError(f"{name} must be in [0,1]")


@dataclass(frozen=True)
class F4CalibrationBatchPreviewV1:
    partition: F4CalibrationSplit
    batch_index: int
    case_ids: tuple[str, ...]
    provider_payload_hashes: tuple[str, ...]
    corpus_manifest_hash: str
    authorization_hash: str


@dataclass(frozen=True)
class F4AuthorizationPreviewV1:
    status: F4AuthorizationPreviewStatus
    source_revision: str
    config_hash: str
    wire_contract_hash: str
    question_contract_hash: str
    input_schema_hash: str
    max_calls_per_batch: int
    calibration_fit_count: int
    calibration_cert_count: int
    missing_fit_count: int
    missing_cert_count: int
    corpus_manifest_hash: str
    batches: tuple[F4CalibrationBatchPreviewV1, ...]
    plan_hash: str
    reason: str | None
    network_attempts: int = 0
    api_key_reads: int = 0


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def canonical_corpus_manifest_hash(
    cases: Sequence[F4CalibrationCaseV1],
    contract: F4QuestionContractV1,
) -> str:
    """Commit exact case identity, truth, provenance, split, and model-visible payload.

    The hash binds labels without placing labels in the provider payload.
    """
    payload = [
        {
            "case_id": case.case_id,
            "lineage_id": case.lineage_id,
            "split": case.split.value,
            "provider_payload_hash": case.provider_payload_hash(contract),
            "requires_escalation": case.requires_escalation,
            "critical_if_missed": case.critical_if_missed,
            "subgroup": case.subgroup,
            "truth_provenance_hash": case.truth_provenance_hash,
        }
        for case in sorted(cases, key=lambda c: c.case_id)
    ]
    return _canonical_hash(payload)


def _binomial_cdf(k: int, n: int, p: float) -> float:
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    return sum(
        math.comb(n, i) * (p**i) * ((1.0 - p) ** (n - i))
        for i in range(k + 1)
    )


def clopper_pearson_upper(errors: int, n: int, alpha: float = 0.05) -> float:
    """Exact one-sided binomial upper confidence bound by CDF inversion."""
    if n <= 0:
        return 1.0
    if not 0 <= errors <= n:
        raise ValueError("errors must be in [0,n]")
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be in (0,1)")
    if errors == n:
        return 1.0
    lo, hi = 0.0, 1.0
    for _ in range(90):
        mid = (lo + hi) / 2.0
        if _binomial_cdf(errors, n, mid) > alpha:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


def clopper_pearson_lower(successes: int, n: int, alpha: float = 0.05) -> float:
    """Exact one-sided binomial lower confidence bound by tail inversion."""
    if n <= 0:
        return 0.0
    if not 0 <= successes <= n:
        raise ValueError("successes must be in [0,n]")
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be in (0,1)")
    if successes == 0:
        return 0.0
    lo, hi = 0.0, 1.0
    for _ in range(90):
        mid = (lo + hi) / 2.0
        tail = 1.0 - _binomial_cdf(successes - 1, n, mid)
        if tail < alpha:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


def brier_score(probabilities: Sequence[float], labels: Sequence[bool]) -> float:
    if len(probabilities) != len(labels) or not probabilities:
        raise ValueError("probabilities and labels must be same non-zero length")
    return sum(
        (float(p) - (1.0 if y else 0.0)) ** 2
        for p, y in zip(probabilities, labels)
    ) / len(labels)


def expected_calibration_error(
    probabilities: Sequence[float],
    labels: Sequence[bool],
    *,
    bins: int = 10,
) -> float:
    if len(probabilities) != len(labels) or not probabilities:
        raise ValueError("probabilities and labels must be same non-zero length")
    if not isinstance(bins, int) or isinstance(bins, bool) or bins <= 0:
        raise ValueError("bins must be positive integer")
    total = len(labels)
    error = 0.0
    for b in range(bins):
        low = b / bins
        high = (b + 1) / bins
        idx = [
            i
            for i, p in enumerate(probabilities)
            if (low <= float(p) < high)
            or (b == bins - 1 and float(p) == 1.0)
        ]
        if not idx:
            continue
        confidence = sum(float(probabilities[i]) for i in idx) / len(idx)
        accuracy = sum(1.0 if labels[i] else 0.0 for i in idx) / len(idx)
        error += (len(idx) / total) * abs(accuracy - confidence)
    return error


def _prediction_map(
    predictions: Sequence[F4PredictionV1],
) -> dict[str, F4PredictionV1]:
    mapped: dict[str, F4PredictionV1] = {}
    for prediction in predictions:
        if prediction.case_id in mapped:
            raise ValueError(f"duplicate prediction for {prediction.case_id}")
        mapped[prediction.case_id] = prediction
    return mapped


def evaluate_threshold(
    cases: Sequence[F4CalibrationCaseV1],
    predictions: Sequence[F4PredictionV1],
    threshold: float,
) -> F4ThresholdMetricsV1:
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not 0.0 <= float(threshold) <= 1.0
    ):
        raise ValueError("threshold must be in [0,1]")
    if not cases:
        raise ValueError("cases must be non-empty")

    pmap = _prediction_map(predictions)
    case_ids = {case.case_id for case in cases}
    if set(pmap) != case_ids:
        raise ValueError("predictions must match exact case ID set")

    covered: list[tuple[F4CalibrationCaseV1, float]] = []
    for case in cases:
        prediction = pmap[case.case_id]
        if prediction.status is ProviderCallStatus.OK:
            assert prediction.probability is not None
            covered.append((case, float(prediction.probability)))

    high = [case for case in cases if case.requires_escalation]
    low = [case for case in cases if not case.requires_escalation]
    high_cov = [(case, p) for case, p in covered if case.requires_escalation]
    low_cov = [(case, p) for case, p in covered if not case.requires_escalation]

    high_errors = sum(1 for _case, p in high_cov if p < float(threshold))
    critical_misses = sum(
        1
        for case, p in high_cov
        if case.critical_if_missed and p < float(threshold)
    )
    false_escalations = sum(
        1 for _case, p in low_cov if p >= float(threshold)
    )

    risk_ucb = (
        clopper_pearson_upper(high_errors, len(high_cov))
        if high_cov
        else 1.0
    )
    coverage = len(high_cov) / len(high) if high else 0.0
    coverage_lcb = (
        clopper_pearson_lower(len(high_cov), len(high))
        if high
        else 0.0
    )
    false_rate = false_escalations / len(low_cov) if low_cov else 1.0
    benign_rate = (
        (len(low_cov) - false_escalations) / len(low_cov)
        if low_cov
        else 0.0
    )

    probs = [p for _case, p in covered]
    labels = [case.requires_escalation for case, _p in covered]
    brier = brier_score(probs, labels) if probs else None
    ece = expected_calibration_error(probs, labels) if probs else None

    return F4ThresholdMetricsV1(
        threshold=float(threshold),
        total_cases=len(cases),
        covered_cases=len(covered),
        provider_coverage=len(covered) / len(cases),
        abstention_rate=1.0 - (len(covered) / len(cases)),
        high_risk_total=len(high),
        high_risk_covered=len(high_cov),
        high_risk_errors=high_errors,
        critical_misses=critical_misses,
        risk_ucb_95=risk_ucb,
        high_risk_coverage=coverage,
        coverage_lcb_95=coverage_lcb,
        low_risk_total=len(low),
        low_risk_covered=len(low_cov),
        false_escalations=false_escalations,
        false_escalation_rate=false_rate,
        benign_pass_through_rate=benign_rate,
        brier_score=brier,
        ece_10=ece,
    )



def classify_selective_probability(
    probability: float,
    operating_point: F4SelectiveOperatingPointV1,
) -> F4SelectiveOutcome:
    if (
        isinstance(probability, bool)
        or not isinstance(probability, (int, float))
        or not math.isfinite(float(probability))
        or not 0.0 <= float(probability) <= 1.0
    ):
        raise ValueError("probability must be finite and in [0,1]")
    p = float(probability)
    if p < float(operating_point.same_threshold):
        return F4SelectiveOutcome.SAME
    if p >= float(operating_point.escalation_threshold):
        return F4SelectiveOutcome.ESCALATE
    return F4SelectiveOutcome.ABSTAIN


def evaluate_selective_operating_point(
    cases: Sequence[F4CalibrationCaseV1],
    predictions: Sequence[F4PredictionV1],
    operating_point: F4SelectiveOperatingPointV1,
) -> F4SelectiveMetricsV1:
    """Evaluate selective F4 risk behavior.

    Provider failure and the probability middle band are abstentions, not safe
    predictions.  Risk/coverage use only non-abstained high-risk decisions,
    preserving the earlier F4 selective-risk interpretation.
    """
    if not cases:
        raise ValueError("cases must be non-empty")
    pmap = _prediction_map(predictions)
    if set(pmap) != {case.case_id for case in cases}:
        raise ValueError("predictions must match exact case ID set")

    outcomes: list[tuple[F4CalibrationCaseV1, F4SelectiveOutcome, float | None]] = []
    for case in cases:
        prediction = pmap[case.case_id]
        if prediction.status is not ProviderCallStatus.OK:
            outcomes.append((case, F4SelectiveOutcome.PROVIDER_UNAVAILABLE, None))
            continue
        assert prediction.probability is not None
        p = float(prediction.probability)
        outcomes.append(
            (case, classify_selective_probability(p, operating_point), p)
        )

    provider_ok = sum(
        outcome is not F4SelectiveOutcome.PROVIDER_UNAVAILABLE
        for _case, outcome, _p in outcomes
    )
    provider_unavailable = len(cases) - provider_ok
    semantic_abstentions = sum(
        outcome is F4SelectiveOutcome.ABSTAIN
        for _case, outcome, _p in outcomes
    )
    decisions = [
        (case, outcome, p)
        for case, outcome, p in outcomes
        if outcome in (F4SelectiveOutcome.SAME, F4SelectiveOutcome.ESCALATE)
    ]

    high = [case for case in cases if case.requires_escalation]
    low = [case for case in cases if not case.requires_escalation]
    high_decisions = [
        (case, outcome, p)
        for case, outcome, p in decisions
        if case.requires_escalation
    ]
    high_errors = sum(
        outcome is F4SelectiveOutcome.SAME
        for _case, outcome, _p in high_decisions
    )
    critical_misses = sum(
        case.critical_if_missed and outcome is F4SelectiveOutcome.SAME
        for case, outcome, _p in high_decisions
    )
    risk = high_errors / len(high_decisions) if high_decisions else 1.0
    risk_ucb = (
        clopper_pearson_upper(high_errors, len(high_decisions))
        if high_decisions
        else 1.0
    )
    high_coverage = len(high_decisions) / len(high) if high else 0.0
    coverage_lcb = (
        clopper_pearson_lower(len(high_decisions), len(high))
        if high
        else 0.0
    )

    low_same = sum(
        case.requires_escalation is False and outcome is F4SelectiveOutcome.SAME
        for case, outcome, _p in outcomes
    )
    low_escalations = sum(
        case.requires_escalation is False
        and outcome is F4SelectiveOutcome.ESCALATE
        for case, outcome, _p in outcomes
    )
    low_abstentions = len(low) - low_same - low_escalations
    false_rate = low_escalations / len(low) if low else 1.0
    benign_rate = low_same / len(low) if low else 0.0

    ok_probs = [
        float(p)
        for _case, outcome, p in outcomes
        if outcome is not F4SelectiveOutcome.PROVIDER_UNAVAILABLE and p is not None
    ]
    ok_labels = [
        case.requires_escalation
        for case, outcome, p in outcomes
        if outcome is not F4SelectiveOutcome.PROVIDER_UNAVAILABLE and p is not None
    ]
    brier = brier_score(ok_probs, ok_labels) if ok_probs else None
    ece = expected_calibration_error(ok_probs, ok_labels) if ok_probs else None

    nondecisions = len(cases) - len(decisions)
    return F4SelectiveMetricsV1(
        operating_point=operating_point,
        total_cases=len(cases),
        provider_ok_cases=provider_ok,
        provider_unavailable_cases=provider_unavailable,
        semantic_abstentions=semantic_abstentions,
        decision_cases=len(decisions),
        decision_coverage=len(decisions) / len(cases),
        abstention_rate=nondecisions / len(cases),
        high_risk_total=len(high),
        high_risk_decisions=len(high_decisions),
        high_risk_errors=high_errors,
        critical_misses=critical_misses,
        selective_risk=risk,
        risk_ucb_95=risk_ucb,
        high_risk_coverage=high_coverage,
        coverage_lcb_95=coverage_lcb,
        low_risk_total=len(low),
        low_risk_same=low_same,
        low_risk_escalations=low_escalations,
        low_risk_abstentions=low_abstentions,
        false_escalation_rate=false_rate,
        benign_pass_through_rate=benign_rate,
        brier_score=brier,
        ece_10=ece,
    )


def _ids_hash(values: Iterable[str]) -> str:
    return _canonical_hash(sorted(values))


def _prediction_hash(predictions: Sequence[F4PredictionV1]) -> str:
    payload = [
        {
            "case_id": p.case_id,
            "status": p.status.value,
            "probability": p.probability,
        }
        for p in sorted(predictions, key=lambda p: p.case_id)
    ]
    return _canonical_hash(payload)



def fit_selective_operating_point(
    cases: Sequence[F4CalibrationCaseV1],
    predictions: Sequence[F4PredictionV1],
    contract: F4QuestionContractV1,
    *,
    prediction_source_hash: str,
) -> F4FrozenOperatingPointV1:
    """Fit SAME/ESCALATE/ABSTAIN boundaries on CALIBRATION_FIT only.

    Selection is deterministic:
    1. zero high-risk SAME decisions / critical misses;
    2. maximize benign pass-through over all controls;
    3. maximize high-risk selective coverage;
    4. maximize total decision coverage;
    5. minimize false escalation;
    6. deterministic threshold tie-break.
    """
    if not _HEX64.fullmatch(prediction_source_hash):
        raise ValueError("prediction_source_hash must be lowercase sha256")
    if not cases or any(
        case.split is not F4CalibrationSplit.CALIBRATION_FIT
        for case in cases
    ):
        raise ValueError("operating-point fitting is restricted to CALIBRATION_FIT")
    pmap = _prediction_map(predictions)
    if set(pmap) != {case.case_id for case in cases}:
        raise ValueError("predictions must match exact CALIBRATION_FIT case IDs")
    if any(p.status is not ProviderCallStatus.OK for p in predictions):
        raise ValueError("operating-point fitting requires complete provider coverage")

    probabilities = sorted(
        {
            0.0,
            1.0,
            *(float(p.probability) for p in predictions if p.probability is not None),
        }
    )
    best: tuple[tuple[float, ...], F4SelectiveOperatingPointV1] | None = None
    for same_threshold in probabilities:
        for escalation_threshold in probabilities:
            if same_threshold > escalation_threshold:
                continue
            point = F4SelectiveOperatingPointV1(
                same_threshold=same_threshold,
                escalation_threshold=escalation_threshold,
            )
            metrics = evaluate_selective_operating_point(
                cases,
                predictions,
                point,
            )
            if metrics.high_risk_errors != 0 or metrics.critical_misses != 0:
                continue
            score = (
                metrics.benign_pass_through_rate,
                metrics.high_risk_coverage,
                metrics.decision_coverage,
                -metrics.false_escalation_rate,
                -metrics.abstention_rate,
                same_threshold,
                -escalation_threshold,
            )
            if best is None or score > best[0]:
                best = (score, point)

    if best is None:
        raise ValueError(
            "no selective operating point satisfies zero-miss calibration-fit invariant"
        )
    chosen = best[1]
    return F4FrozenOperatingPointV1(
        same_threshold=chosen.same_threshold,
        escalation_threshold=chosen.escalation_threshold,
        fit_case_ids_hash=_ids_hash(case.case_id for case in cases),
        fit_prediction_hash=_prediction_hash(predictions),
        fit_corpus_manifest_hash=canonical_corpus_manifest_hash(cases, contract),
        prediction_source_hash=prediction_source_hash,
        question_contract_hash=contract.contract_hash,
        input_schema_hash=contract.input_schema_hash,
    )


def fit_operating_threshold(
    cases: Sequence[F4CalibrationCaseV1],
    predictions: Sequence[F4PredictionV1],
    contract: F4QuestionContractV1,
    *,
    prediction_source_hash: str,
) -> F4FrozenThresholdV1:
    """Fit only on CALIBRATION_FIT.

    Select the highest threshold producing zero high-risk and critical misses on
    covered fit cases. This maximizes benign pass-through without peeking at
    certification, held-out, or prospective partitions.
    """
    if not _HEX64.fullmatch(prediction_source_hash):
        raise ValueError("prediction_source_hash must be lowercase sha256")
    if not cases or any(
        case.split is not F4CalibrationSplit.CALIBRATION_FIT
        for case in cases
    ):
        raise ValueError("threshold fitting is restricted to CALIBRATION_FIT")
    pmap = _prediction_map(predictions)
    if set(pmap) != {case.case_id for case in cases}:
        raise ValueError("predictions must match exact CALIBRATION_FIT case IDs")
    if any(p.status is not ProviderCallStatus.OK for p in predictions):
        raise ValueError("threshold fitting requires complete provider coverage")

    candidates = sorted(
        {
            0.0,
            1.0,
            *(
                float(p.probability)
                for p in predictions
                if p.probability is not None
            ),
        },
        reverse=True,
    )
    chosen: float | None = None
    for threshold in candidates:
        metrics = evaluate_threshold(cases, predictions, threshold)
        if metrics.high_risk_errors == 0 and metrics.critical_misses == 0:
            chosen = threshold
            break
    if chosen is None:
        raise ValueError("no threshold satisfies zero-miss calibration-fit invariant")

    return F4FrozenThresholdV1(
        threshold=chosen,
        fit_case_ids_hash=_ids_hash(case.case_id for case in cases),
        fit_prediction_hash=_prediction_hash(predictions),
        fit_corpus_manifest_hash=canonical_corpus_manifest_hash(cases, contract),
        prediction_source_hash=prediction_source_hash,
        question_contract_hash=contract.contract_hash,
        input_schema_hash=contract.input_schema_hash,
    )


def certify_metrics(
    metrics: F4SelectiveMetricsV1,
    criteria: F4CertificationCriteriaV1,
) -> tuple[bool, tuple[str, ...]]:
    failures: list[str] = []
    if metrics.critical_misses > criteria.max_critical_misses:
        failures.append("CRITICAL_MISS")
    if metrics.risk_ucb_95 > criteria.max_risk_ucb_95:
        failures.append("RISK_UCB")
    if metrics.coverage_lcb_95 < criteria.min_coverage_lcb_95:
        failures.append("COVERAGE_LCB")
    if metrics.false_escalation_rate > criteria.max_false_escalation_rate:
        failures.append("FALSE_ESCALATION")
    if metrics.benign_pass_through_rate < criteria.min_benign_pass_through_rate:
        failures.append("BENIGN_PASS_THROUGH")
    return not failures, tuple(failures)


def validate_corpus(
    cases: Sequence[F4CalibrationCaseV1],
) -> dict[F4CalibrationSplit, int]:
    case_ids: set[str] = set()
    lineage_ids: set[str] = set()
    counts = {split: 0 for split in F4CalibrationSplit}
    for case in cases:
        if case.case_id in case_ids:
            raise ValueError(f"duplicate case_id across partitions: {case.case_id}")
        if case.lineage_id in lineage_ids:
            raise ValueError(
                f"duplicate lineage_id across partitions: {case.lineage_id}"
            )
        case_ids.add(case.case_id)
        lineage_ids.add(case.lineage_id)
        counts[case.split] += 1
    return counts


def _authorization_batch_hash(
    *,
    source_revision: str,
    config_hash: str,
    wire_contract_hash: str,
    contract: F4QuestionContractV1,
    partition: F4CalibrationSplit,
    batch_index: int,
    case_ids: Sequence[str],
    payload_hashes: Sequence[str],
    corpus_manifest_hash: str,
) -> str:
    return _canonical_hash(
        {
            "schema": "f4-calibration-batch-authorization-preview.v1",
            "source_revision": source_revision,
            "config_hash": config_hash,
            "wire_contract_hash": wire_contract_hash,
            "question_contract_hash": contract.contract_hash,
            "input_schema_hash": contract.input_schema_hash,
            "partition": partition.value,
            "batch_index": batch_index,
            "case_ids": list(case_ids),
            "provider_payload_hashes": list(payload_hashes),
            "corpus_manifest_hash": corpus_manifest_hash,
            "max_calls": len(case_ids),
            "retry": "NONE",
        }
    )


def build_zero_call_authorization_preview(
    cases: Sequence[F4CalibrationCaseV1],
    config: HostedProviderConfigV1,
    contract: F4QuestionContractV1 | None = None,
    *,
    source_revision: str = F4_FROZEN_SOURCE_REVISION,
    wire_contract_hash: str = F4_FROZEN_WIRE_CONTRACT_HASH,
    required_fit_count: int = 50,
    required_cert_count: int = 50,
) -> F4AuthorizationPreviewV1:
    """Build an effect-free calibration authorization preview.

    Only CALIBRATION_FIT and CALIBRATION_CERT are eligible for Wave 2 calls.
    The function performs no credential lookup and imports no network client.
    """
    contract = contract or F4QuestionContractV1()
    counts = validate_corpus(cases)
    fit = sorted(
        (
            c
            for c in cases
            if c.split is F4CalibrationSplit.CALIBRATION_FIT
        ),
        key=lambda c: c.case_id,
    )
    cert = sorted(
        (
            c
            for c in cases
            if c.split is F4CalibrationSplit.CALIBRATION_CERT
        ),
        key=lambda c: c.case_id,
    )
    missing_fit = max(0, required_fit_count - len(fit))
    missing_cert = max(0, required_cert_count - len(cert))
    corpus_manifest_hash = canonical_corpus_manifest_hash(cases, contract)

    plan_payload = {
        "schema": "f4-calibration-zero-call-plan.v1",
        "source_revision": source_revision,
        "config_hash": config.canonical_config_hash(),
        "wire_contract_hash": wire_contract_hash,
        "question_contract_hash": contract.contract_hash,
        "input_schema_hash": contract.input_schema_hash,
        "required_fit_count": required_fit_count,
        "required_cert_count": required_cert_count,
        "observed_counts": {k.value: v for k, v in counts.items()},
        "max_calls_per_batch": config.max_canary_quota,
        "corpus_manifest_hash": corpus_manifest_hash,
        "historical_text_corpus_sha256": HISTORICAL_V231_CORPUS_SHA256,
        "historical_reference_only": True,
        "retry": "NONE",
    }
    plan_hash = _canonical_hash(plan_payload)

    if missing_fit or missing_cert:
        return F4AuthorizationPreviewV1(
            status=(
                F4AuthorizationPreviewStatus.CURRENT_STATE_PROJECTION_REQUIRED
            ),
            source_revision=source_revision,
            config_hash=config.canonical_config_hash(),
            wire_contract_hash=wire_contract_hash,
            question_contract_hash=contract.contract_hash,
            input_schema_hash=contract.input_schema_hash,
            max_calls_per_batch=config.max_canary_quota,
            calibration_fit_count=len(fit),
            calibration_cert_count=len(cert),
            missing_fit_count=missing_fit,
            missing_cert_count=missing_cert,
            corpus_manifest_hash=corpus_manifest_hash,
            batches=(),
            plan_hash=plan_hash,
            reason=(
                "Current six-field ProviderVisibleRiskStateV1 projections are "
                "required; historical v2.3.1 text-prompt cases are reference-only."
            ),
        )

    if len(fit) != required_fit_count or len(cert) != required_cert_count:
        return F4AuthorizationPreviewV1(
            status=F4AuthorizationPreviewStatus.INVALID_CORPUS,
            source_revision=source_revision,
            config_hash=config.canonical_config_hash(),
            wire_contract_hash=wire_contract_hash,
            question_contract_hash=contract.contract_hash,
            input_schema_hash=contract.input_schema_hash,
            max_calls_per_batch=config.max_canary_quota,
            calibration_fit_count=len(fit),
            calibration_cert_count=len(cert),
            missing_fit_count=0,
            missing_cert_count=0,
            corpus_manifest_hash=corpus_manifest_hash,
            batches=(),
            plan_hash=plan_hash,
            reason="Calibration partitions must match frozen exact target counts.",
        )

    if config.max_canary_quota <= 0:
        raise ValueError("max_canary_quota must be positive")

    batches: list[F4CalibrationBatchPreviewV1] = []
    batch_index = 0
    for partition, partition_cases in (
        (F4CalibrationSplit.CALIBRATION_FIT, fit),
        (F4CalibrationSplit.CALIBRATION_CERT, cert),
    ):
        for start in range(
            0,
            len(partition_cases),
            config.max_canary_quota,
        ):
            selected = partition_cases[
                start : start + config.max_canary_quota
            ]
            case_ids = tuple(c.case_id for c in selected)
            payload_hashes = tuple(
                c.provider_payload_hash(contract)
                for c in selected
            )
            batches.append(
                F4CalibrationBatchPreviewV1(
                    partition=partition,
                    batch_index=batch_index,
                    case_ids=case_ids,
                    provider_payload_hashes=payload_hashes,
                    corpus_manifest_hash=corpus_manifest_hash,
                    authorization_hash=_authorization_batch_hash(
                        source_revision=source_revision,
                        config_hash=config.canonical_config_hash(),
                        wire_contract_hash=wire_contract_hash,
                        contract=contract,
                        partition=partition,
                        batch_index=batch_index,
                        case_ids=case_ids,
                        payload_hashes=payload_hashes,
                        corpus_manifest_hash=corpus_manifest_hash,
                    ),
                )
            )
            batch_index += 1

    return F4AuthorizationPreviewV1(
        status=F4AuthorizationPreviewStatus.READY,
        source_revision=source_revision,
        config_hash=config.canonical_config_hash(),
        wire_contract_hash=wire_contract_hash,
        question_contract_hash=contract.contract_hash,
        input_schema_hash=contract.input_schema_hash,
        max_calls_per_batch=config.max_canary_quota,
        calibration_fit_count=len(fit),
        calibration_cert_count=len(cert),
        missing_fit_count=0,
        missing_cert_count=0,
        corpus_manifest_hash=corpus_manifest_hash,
        batches=tuple(batches),
        plan_hash=plan_hash,
        reason=None,
    )
