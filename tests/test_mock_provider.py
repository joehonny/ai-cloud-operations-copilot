def test_mock_provider_is_deterministic_for_the_same_fixture_and_seed() -> None:
    from cloud_ops_copilot.models import IncidentInput, RemediationRecommendation, Runbook
    from cloud_ops_copilot.providers.mock import MockAnalysisProvider

    incident = IncidentInput.model_validate(
        {
            "source": "fixture:incident-dns-001",
            "severity": "high",
            "summary": "Private endpoint name resolution is failing.",
            "evidence": ["Lookup returned NXDOMAIN."],
            "runbook_ids": ["dns-resolution"],
        }
    )
    runbooks = [
        Runbook(
            runbook_id="dns-resolution",
            title="DNS resolution",
            content="Verify the private DNS zone link and record.",
        )
    ]
    expected = RemediationRecommendation.model_validate(
        {
            "assessment": "DNS resolution failed for the private endpoint.",
            "risk": "high",
            "evidence": ["Lookup returned NXDOMAIN."],
            "steps": [
                "Verify the private DNS zone link.",
                "Confirm the private endpoint record exists and is correct.",
            ],
            "requires_human_approval": True,
            "confidence": 0.92,
        }
    )

    first = MockAnalysisProvider(seed=17).analyze(incident, runbooks)
    second = MockAnalysisProvider(seed=17).analyze(incident, runbooks)

    assert first == second == expected
