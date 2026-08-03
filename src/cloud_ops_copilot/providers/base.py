"""Provider interface for incident analysis implementations."""

from typing import Protocol, runtime_checkable

from cloud_ops_copilot.models import IncidentInput, RemediationRecommendation, Runbook


@runtime_checkable
class AnalysisProvider(Protocol):
    """A provider that returns advisory remediation recommendations."""

    def analyze(
        self,
        incident: IncidentInput,
        runbooks: list[Runbook],
    ) -> RemediationRecommendation:
        """Analyze an incident without executing any remediation."""
        ...
