"""Optional Azure OpenAI adapter using the OpenAI Responses API client."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from urllib.parse import urlsplit

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


def normalize_azure_endpoint(endpoint: str) -> str:
    """Validate an Azure OpenAI resource endpoint and form its v1 base URL."""
    try:
        parsed = urlsplit(endpoint)
    except ValueError:
        raise ProviderError("Azure OpenAI endpoint is invalid") from None
    hostname = parsed.hostname
    if hostname is None:
        raise ProviderError("Azure OpenAI endpoint is invalid")
    path = parsed.path.rstrip("/")
    try:
        port = parsed.port
    except ValueError:
        raise ProviderError("Azure OpenAI endpoint is invalid") from None
    hostname_match = re.fullmatch(
        r"(?P<resource>[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
        r"(?:\.openai\.azure\.com|\.services\.ai\.azure\.com)",
        hostname.lower(),
    )
    valid_hostname = bool(hostname_match and hostname_match.group("resource") != "privatelink")
    if (
        parsed.scheme.lower() != "https"
        or not valid_hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.query
        or parsed.fragment
        or path not in ("", "/openai/v1")
    ):
        raise ProviderError("Azure OpenAI endpoint is invalid")
    return f"https://{hostname.lower()}/openai/v1/"


class AzureOpenAIProvider:
    """Request structured advice through an Azure OpenAI v1 endpoint."""

    def __init__(
        self,
        *,
        environ: Mapping[str, str] | None = None,
        client_factory: ClientFactory | None = None,
    ) -> None:
        configuration = os.environ if environ is None else environ
        api_key, endpoint, deployment = require_configuration(
            configuration,
            (
                "AZURE_OPENAI_API_KEY",
                "AZURE_OPENAI_ENDPOINT",
                "AZURE_OPENAI_DEPLOYMENT",
            ),
        )
        self._deployment = deployment
        self._client = create_client(
            client_factory,
            api_key=api_key,
            base_url=normalize_azure_endpoint(endpoint),
        )

    def analyze(
        self,
        incident: IncidentInput,
        runbooks: list[Runbook],
    ) -> RemediationRecommendation:
        """Return a validated recommendation and never execute remediation."""
        try:
            response = self._client.responses.parse(
                model=self._deployment,
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


__all__ = ["AzureOpenAIProvider", "normalize_azure_endpoint"]
