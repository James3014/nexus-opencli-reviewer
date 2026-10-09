"""Family-specific operating policy over raw risk-model results.

This is deliberately a separate consumer layer. It contains no provider calls and
ships no default calibration. A caller must supply an explicit family calibration
identity and operating point before a probability can become an operating outcome.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from reviewer.risk_model_adapter import ProviderCallStatus, RiskModelResult


class FamilyPolicyOutcome(str, Enum):
    SAME = "SAME"
    ESCALATE = "ESCALATE"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"


@dataclass(frozen=True)
class FamilyCalibrationPolicy:
    """One explicit family operating point bound to calibration evidence."""

    family_id: str
    calibration_id: str
    escalation_threshold: float

    def __post_init__(self) -> None:
        if not isinstance(self.family_id, str) or not self.family_id.strip():
            raise ValueError("family_id must be non-empty")
        if not isinstance(self.calibration_id, str) or not self.calibration_id.strip():
            raise ValueError("calibration_id must be non-empty")
        if (
            isinstance(self.escalation_threshold, bool)
            or not isinstance(self.escalation_threshold, (int, float))
            or not 0.0 <= float(self.escalation_threshold) <= 1.0
        ):
            raise ValueError("escalation_threshold must be in [0.0, 1.0]")


@dataclass(frozen=True)
class FamilyPolicyResult:
    family_id: str
    calibration_id: str
    provider_status: ProviderCallStatus
    probability: float | None
    escalation_threshold: float
    outcome: FamilyPolicyOutcome


def apply_family_policy(
    result: RiskModelResult,
    policy: FamilyCalibrationPolicy,
) -> FamilyPolicyResult:
    """Apply an explicitly supplied family policy to a raw provider result."""

    if result.status is not ProviderCallStatus.OK:
        return FamilyPolicyResult(
            family_id=policy.family_id,
            calibration_id=policy.calibration_id,
            provider_status=result.status,
            probability=None,
            escalation_threshold=float(policy.escalation_threshold),
            outcome=FamilyPolicyOutcome.PROVIDER_UNAVAILABLE,
        )

    if result.probability is None:
        raise ValueError("OK provider result is missing probability")

    outcome = (
        FamilyPolicyOutcome.ESCALATE
        if float(result.probability) >= float(policy.escalation_threshold)
        else FamilyPolicyOutcome.SAME
    )
    return FamilyPolicyResult(
        family_id=policy.family_id,
        calibration_id=policy.calibration_id,
        provider_status=result.status,
        probability=float(result.probability),
        escalation_threshold=float(policy.escalation_threshold),
        outcome=outcome,
    )
