"""Safe provider-independent orchestration for incident analysis."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from pydantic import ValidationError

from cloud_ops_copilot.models import (
    AnalysisEnvelope,
    IncidentInput,
    RemediationRecommendation,
    Runbook,
    SafetyFinding,
    SafetyReport,
)
from cloud_ops_copilot.providers.base import AnalysisProvider
from cloud_ops_copilot.retrieval.runbooks import retrieve_runbooks
from cloud_ops_copilot.safety.injection import detect_untrusted_instruction
from cloud_ops_copilot.safety.redaction import Finding, redact


class ServiceError(RuntimeError):
    """A sanitized analysis failure safe for a caller to display."""


class Retriever(Protocol):
    """Narrow deterministic retrieval dependency."""

    def __call__(self, query: str, limit: int) -> list[Runbook]: ...


Observer = Callable[[str], None]


def _safe_findings(
    findings: list[Finding] | tuple[Finding, ...], source: str
) -> list[SafetyFinding]:
    return [
        SafetyFinding(
            category=finding.category,
            source=source,
            count=finding.count,
            severity=finding.severity,
        )
        for finding in findings
    ]


def _check_text(text: str, source: str) -> list[SafetyFinding]:
    return _safe_findings(detect_untrusted_instruction(text), source)


def _redact_text(text: str, source: str) -> tuple[str, list[SafetyFinding]]:
    result = redact(text)
    return result.text, _safe_findings(result.findings, source)


class AnalysisService:
    """Validate, sanitize, retrieve, analyze, and revalidate without executing actions."""

    def __init__(
        self,
        *,
        provider: AnalysisProvider,
        retriever: Retriever = retrieve_runbooks,
        observer: Observer | None = None,
        retrieval_limit: int = 3,
    ) -> None:
        self._provider = provider
        self._retriever = retriever
        self._observer = observer or (lambda _event: None)
        self._retrieval_limit = retrieval_limit

    def analyze(self, incident_data: IncidentInput | object) -> AnalysisEnvelope:
        """Return only advisory output and safety metadata."""
        incident = IncidentInput.model_validate(incident_data)
        self._observer("parsed")

        redaction_findings: list[SafetyFinding] = []

        def clean(value: str, source: str) -> str:
            text, findings = _redact_text(value, source)
            redaction_findings.extend(findings)
            return text

        safe_incident = IncidentInput(
            source=clean(incident.source, "incident.source"),
            severity=clean(incident.severity.value, "incident.severity"),
            summary=clean(incident.summary, "incident.summary"),
            evidence=tuple(
                clean(value, f"incident.evidence[{index}]")
                for index, value in enumerate(incident.evidence)
            ),
            runbook_ids=tuple(
                clean(value, f"incident.runbook_ids[{index}]")
                for index, value in enumerate(incident.runbook_ids)
            ),
        )
        self._observer("incident_redacted")

        injection_findings: list[SafetyFinding] = []
        for field_name, value in (
            ("incident.source", incident.source),
            ("incident.severity", incident.severity.value),
            ("incident.summary", incident.summary),
            *(
                (f"incident.evidence[{index}]", value)
                for index, value in enumerate(incident.evidence)
            ),
            *(
                (f"incident.runbook_ids[{index}]", value)
                for index, value in enumerate(incident.runbook_ids)
            ),
        ):
            injection_findings.extend(_check_text(value, field_name))
        self._observer("incident_checked")
        query = " ".join((safe_incident.summary, *safe_incident.runbook_ids))
        try:
            runbooks = self._retriever(query, self._retrieval_limit)
        except Exception:
            raise ServiceError("Runbook retrieval failed") from None
        self._observer("retrieved")

        safe_runbooks: list[Runbook] = []
        for index, runbook_data in enumerate(runbooks):
            runbook = Runbook.model_validate(runbook_data)
            prefix = f"runbooks[{index}]"
            safe_runbooks.append(
                Runbook(
                    runbook_id=clean(runbook.runbook_id, f"{prefix}.runbook_id"),
                    title=clean(runbook.title, f"{prefix}.title"),
                    content=clean(runbook.content, f"{prefix}.content"),
                )
            )
            self._observer("runbook_redacted")
            for field_name, value in (
                (f"{prefix}.runbook_id", runbook.runbook_id),
                (f"{prefix}.title", runbook.title),
                (f"{prefix}.content", runbook.content),
            ):
                injection_findings.extend(_check_text(value, field_name))
        self._observer("runbooks_checked")

        try:
            proposed = self._provider.analyze(safe_incident, safe_runbooks)
        except Exception:
            raise ServiceError("Analysis provider failed") from None
        self._observer("provider_called")
        try:
            if isinstance(proposed, RemediationRecommendation):
                payload = proposed.model_dump(mode="python")
            else:
                payload = proposed
            recommendation = RemediationRecommendation.model_validate(payload)
        except (ValidationError, TypeError, ValueError):
            raise ServiceError("Provider returned an invalid recommendation") from None
        if recommendation.requires_human_approval is not True:
            raise ServiceError("Provider returned an invalid recommendation")
        self._observer("validated")
        envelope = AnalysisEnvelope(
            recommendation=recommendation,
            safety=SafetyReport(
                redaction_findings=tuple(redaction_findings),
                injection_findings=tuple(injection_findings),
            ),
        )
        self._observer("emitted")
        return envelope


__all__ = ["AnalysisService", "ServiceError"]
