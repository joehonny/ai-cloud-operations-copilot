"""Provider-independent domain models for cloud operations analysis."""

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

NonBlankText = Annotated[
    str,
    StringConstraints(strict=True, strip_whitespace=True, min_length=1),
]
Confidence = Annotated[float, Field(strict=True, ge=0.0, le=1.0)]


class IncidentSeverity(StrEnum):
    """Supported operational incident severities."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RiskLevel(StrEnum):
    """Risk level attached to a proposed remediation."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DomainModel(BaseModel):
    """Strict, immutable base contract for all domain data."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_default=True,
    )


class IncidentInput(DomainModel):
    """Validated incident evidence supplied to an analysis provider."""

    source: NonBlankText
    severity: IncidentSeverity
    summary: NonBlankText
    evidence: tuple[NonBlankText, ...] = Field(min_length=1)
    runbook_ids: tuple[NonBlankText, ...] = ()


class Runbook(DomainModel):
    """An immutable operational runbook retrieved for an incident."""

    runbook_id: NonBlankText
    title: NonBlankText
    content: NonBlankText


class RemediationRecommendation(DomainModel):
    """Advisory remediation output that always requires human approval."""

    assessment: NonBlankText
    risk: RiskLevel
    evidence: tuple[NonBlankText, ...] = Field(min_length=1)
    steps: tuple[NonBlankText, ...] = Field(min_length=1)
    requires_human_approval: Literal[True] = True
    confidence: Confidence

    @field_validator("requires_human_approval", mode="before")
    @classmethod
    def require_boolean_true(cls, value: object) -> object:
        """Reject values Pydantic could otherwise coerce to boolean true."""
        if value is not True:
            raise ValueError("requires_human_approval must be the boolean true")
        return value


class SafetyFinding(DomainModel):
    """Non-sensitive metadata describing a safety control finding."""

    category: NonBlankText
    source: NonBlankText
    count: Annotated[int, Field(strict=True, ge=1)] = 1
    severity: NonBlankText | None = None


class SafetyReport(DomainModel):
    """Safe control evidence emitted with every recommendation."""

    redaction_findings: tuple[SafetyFinding, ...] = ()
    injection_findings: tuple[SafetyFinding, ...] = ()
    provider_input_redacted: Literal[True] = True
    human_approval_required: Literal[True] = True


class AnalysisEnvelope(DomainModel):
    """Validated recommendation plus non-sensitive safety metadata."""

    recommendation: RemediationRecommendation
    safety: SafetyReport
