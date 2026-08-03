"""Optional OpenAI Responses API provider."""

from __future__ import annotations

import os
from collections.abc import Mapping

from cloud_ops_copilot.models import IncidentInput, RemediationRecommendation, Runbook
from cloud_ops_copilot.providers._responses import (
    ClientFactory,
    ProviderError,
    build_analysis_input,
    build_analysis_instructions,
    create_client,
    parse_recommendation_response,
    require_configuration,
)


class OpenAIResponsesProvider:
    """Request structured advisory output from OpenAI without enabling tools."""

    def __init__(
        self,
        *,
        environ: Mapping[str, str] | None = None,
        client_factory: ClientFactory | None = None,
    ) -> None:
        configuration = os.environ if environ is None else environ
        api_key, model = require_configuration(configuration, ("OPENAI_API_KEY", "OPENAI_MODEL"))
        self._model = model
        self._client = create_client(client_factory, api_key=api_key)

    def analyze(
        self,
        incident: IncidentInput,
        runbooks: list[Runbook],
    ) -> RemediationRecommendation:
        """Return a validated recommendation and never execute remediation."""
        try:
            response = self._client.responses.parse(
                model=self._model,
                instructions=build_analysis_instructions(),
                input=build_analysis_input(incident, runbooks),
                text_format=RemediationRecommendation,
                store=False,
            )
        except ProviderError:
            raise
        except Exception:
            raise ProviderError("Provider request failed") from None
        return parse_recommendation_response(response)


__all__ = ["OpenAIResponsesProvider", "ProviderError"]
