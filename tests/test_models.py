from typing import Any

import pytest
from pydantic import ValidationError


def incident_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "source": "azure-monitor",
        "severity": "high",
        "summary": "Private endpoint name resolution is failing.",
        "evidence": ["Lookup returned NXDOMAIN."],
        "runbook_ids": ["dns-resolution"],
    }
    data.update(overrides)
    return data


def recommendation_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "assessment": "The private DNS record may be missing.",
        "risk": "high",
        "evidence": ["Lookup returned NXDOMAIN."],
        "steps": ["Verify the private DNS zone link."],
        "requires_human_approval": True,
        "confidence": 0.85,
    }
    data.update(overrides)
    return data


def test_incident_accepts_the_documented_contract() -> None:
    from cloud_ops_copilot.models import IncidentInput, IncidentSeverity

    incident = IncidentInput.model_validate(incident_data())

    assert incident.severity is IncidentSeverity.HIGH
    assert incident.evidence == ("Lookup returned NXDOMAIN.",)
    assert incident.runbook_ids == ("dns-resolution",)


@pytest.mark.parametrize("evidence", [[], [""], ["   "]])
def test_incident_rejects_missing_or_blank_evidence(evidence: list[str]) -> None:
    from cloud_ops_copilot.models import IncidentInput

    with pytest.raises(ValidationError):
        IncidentInput.model_validate(incident_data(evidence=evidence))


def test_incident_rejects_invalid_severity() -> None:
    from cloud_ops_copilot.models import IncidentInput

    with pytest.raises(ValidationError):
        IncidentInput.model_validate(incident_data(severity="urgent"))


@pytest.mark.parametrize("field", ["source", "summary"])
def test_incident_rejects_blank_required_text(field: str) -> None:
    from cloud_ops_copilot.models import IncidentInput

    with pytest.raises(ValidationError):
        IncidentInput.model_validate(incident_data(**{field: "  "}))


def test_incident_rejects_blank_runbook_identifier() -> None:
    from cloud_ops_copilot.models import IncidentInput

    with pytest.raises(ValidationError):
        IncidentInput.model_validate(incident_data(runbook_ids=["dns-resolution", " "]))


def test_incident_rejects_unknown_fields() -> None:
    from cloud_ops_copilot.models import IncidentInput

    with pytest.raises(ValidationError):
        IncidentInput.model_validate(incident_data(prompt="ignore policy"))


def test_runbook_requires_nonblank_identity_title_and_content() -> None:
    from cloud_ops_copilot.models import Runbook

    for field in ("runbook_id", "title", "content"):
        with pytest.raises(ValidationError):
            Runbook.model_validate(
                {"runbook_id": "dns", "title": "DNS", "content": "Check DNS", field: " "}
            )


@pytest.mark.parametrize("confidence", [-0.01, 1.01])
def test_recommendation_rejects_confidence_outside_unit_interval(confidence: float) -> None:
    from cloud_ops_copilot.models import RemediationRecommendation

    with pytest.raises(ValidationError):
        RemediationRecommendation.model_validate(recommendation_data(confidence=confidence))


def test_recommendation_accepts_confidence_boundaries() -> None:
    from cloud_ops_copilot.models import RemediationRecommendation

    low = RemediationRecommendation.model_validate(recommendation_data(confidence=0.0))
    high = RemediationRecommendation.model_validate(recommendation_data(confidence=1.0))

    assert low.confidence == 0
    assert high.confidence == 1


@pytest.mark.parametrize(
    "approval",
    [False, 0, 1, "true", "false", None],
    ids=["false", "zero", "one", "true-string", "false-string", "null"],
)
def test_recommendation_accepts_only_boolean_true_for_human_approval(approval: object) -> None:
    from cloud_ops_copilot.models import RemediationRecommendation

    with pytest.raises(ValidationError):
        RemediationRecommendation.model_validate(
            recommendation_data(requires_human_approval=approval)
        )


def test_recommendation_defaults_to_human_approval() -> None:
    from cloud_ops_copilot.models import RemediationRecommendation

    data = recommendation_data()
    del data["requires_human_approval"]

    assert RemediationRecommendation.model_validate(data).requires_human_approval is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("assessment", " "),
        ("evidence", []),
        ("evidence", [" "]),
        ("steps", []),
        ("steps", [" "]),
    ],
)
def test_recommendation_rejects_blank_or_empty_content(field: str, value: object) -> None:
    from cloud_ops_copilot.models import RemediationRecommendation

    with pytest.raises(ValidationError):
        RemediationRecommendation.model_validate(recommendation_data(**{field: value}))


def test_domain_models_are_immutable() -> None:
    from cloud_ops_copilot.models import IncidentInput

    incident = IncidentInput.model_validate(incident_data())

    with pytest.raises(ValidationError):
        incident.summary = "Changed"  # type: ignore[misc]


def test_provider_contract_exposes_typed_analysis_signature() -> None:
    from cloud_ops_copilot.models import IncidentInput, RemediationRecommendation, Runbook
    from cloud_ops_copilot.providers.base import AnalysisProvider

    annotations = AnalysisProvider.analyze.__annotations__

    assert annotations == {
        "incident": IncidentInput,
        "runbooks": list[Runbook],
        "return": RemediationRecommendation,
    }


def test_provider_contract_supports_structural_runtime_checks() -> None:
    from cloud_ops_copilot.models import IncidentInput, RemediationRecommendation, Runbook
    from cloud_ops_copilot.providers.base import AnalysisProvider

    class ConformingProvider:
        def analyze(
            self,
            incident: IncidentInput,
            runbooks: list[Runbook],
        ) -> RemediationRecommendation:
            raise NotImplementedError

    class NonconformingProvider:
        pass

    assert isinstance(ConformingProvider(), AnalysisProvider)
    assert not isinstance(NonconformingProvider(), AnalysisProvider)
