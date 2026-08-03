"""Deterministic offline provider for tests, demos, and evaluations."""

from __future__ import annotations

import hashlib
import json

from cloud_ops_copilot.models import IncidentInput, RemediationRecommendation, RiskLevel, Runbook


class MockAnalysisProvider:
    """Produce recommendations without network access or action execution."""

    def __init__(self, seed: int = 0) -> None:
        self._seed = seed

    def analyze(
        self,
        incident: IncidentInput,
        runbooks: list[Runbook],
    ) -> RemediationRecommendation:
        """Return a stable fixture response or a stable generic recommendation."""
        if incident.source == "fixture:incident-dns-001" and self._seed == 17:
            return RemediationRecommendation(
                assessment="DNS resolution failed for the private endpoint.",
                risk=RiskLevel.HIGH,
                evidence=("Lookup returned NXDOMAIN.",),
                steps=(
                    "Verify the private DNS zone link.",
                    "Confirm the private endpoint record exists and is correct.",
                ),
                requires_human_approval=True,
                confidence=0.92,
            )

        material = json.dumps(
            {
                "seed": self._seed,
                "incident": incident.model_dump(mode="json"),
                "runbook_ids": [runbook.runbook_id for runbook in runbooks],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest = hashlib.sha256(material).digest()
        confidence = round(0.70 + (int.from_bytes(digest[:2], "big") % 21) / 100, 2)
        evidence = incident.evidence[:2]
        return RemediationRecommendation(
            assessment="The supplied evidence requires operator review.",
            risk=RiskLevel(incident.severity.value),
            evidence=evidence,
            steps=(
                "Review the incident evidence and relevant runbooks.",
                "Have an authorized operator validate any proposed change before implementation.",
            ),
            requires_human_approval=True,
            confidence=confidence,
        )
