"""Offline-first command-line interface for safe advisory analysis."""

from __future__ import annotations

import argparse
import json
import math
import os
import stat
import sys
from collections.abc import Sequence
from importlib.resources import files
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

from cloud_ops_copilot.models import (
    IncidentInput,
    RemediationRecommendation,
    RiskLevel,
    Runbook,
)
from cloud_ops_copilot.providers.azure_openai import AzureOpenAIProvider
from cloud_ops_copilot.providers.base import AnalysisProvider
from cloud_ops_copilot.providers.mock import MockAnalysisProvider
from cloud_ops_copilot.providers.openai_responses import OpenAIResponsesProvider, ProviderError
from cloud_ops_copilot.service import AnalysisService, ServiceError

_MAX_INPUT_BYTES = 1_048_576


class EvaluationError(ValueError):
    """A sanitized evaluation input or gate failure."""


class EvaluationSummary(BaseModel):
    """Typed aggregate scores that contain no raw incident content."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    cases_total: int
    cases_passed: int
    safety_total: int
    safety_passed: int
    quality_total: int
    quality_passed: int
    safety_score: float
    quality_score: float
    passed: bool


StrictText = Annotated[
    str,
    StringConstraints(strict=True, strip_whitespace=True, min_length=1, max_length=200),
]
BoundedCount = Annotated[int, Field(strict=True, ge=0, le=100)]


class EvaluationSafetyAssertions(BaseModel):
    """Strict independent safety expectations for one case."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    minimum_redactions: BoundedCount = 0
    injection_categories: tuple[StrictText, ...] = ()
    provider_input_excludes: tuple[StrictText, ...] = ()


class EvaluationQualityAssertions(BaseModel):
    """Strict non-tautological quality expectations."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    expected_risk: RiskLevel | None = None
    assessment_contains: StrictText | None = None
    steps_contain: tuple[StrictText, ...] = ()

    @model_validator(mode="after")
    def require_independent_assertion(self) -> EvaluationQualityAssertions:
        if (
            self.expected_risk is None
            and self.assessment_contains is None
            and not self.steps_contain
        ):
            raise ValueError("at least one independent quality assertion is required")
        return self


class EvaluationCase(BaseModel):
    """Strict schema for deterministic offline evaluation cases."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    id: StrictText
    case_type: Literal["analysis", "validation_rejection"]
    incident: dict[str, Any]
    runbooks: tuple[Runbook, ...] = ()
    safety: EvaluationSafetyAssertions = EvaluationSafetyAssertions()
    quality: EvaluationQualityAssertions | None = None

    @model_validator(mode="after")
    def validate_case_requirements(self) -> EvaluationCase:
        if self.case_type == "analysis" and self.quality is None:
            raise ValueError("analysis cases require quality assertions")
        if self.case_type == "validation_rejection":
            if self.quality is not None or self.runbooks:
                raise ValueError("validation rejection cases cannot define quality or runbooks")
            if (
                self.safety.minimum_redactions
                or self.safety.injection_categories
                or self.safety.provider_input_excludes
            ):
                raise ValueError("validation rejection cases only assert rejection")
        return self


def create_provider(name: str) -> AnalysisProvider:
    """Create only the explicitly selected provider."""
    if name == "mock":
        return MockAnalysisProvider(seed=17)
    if name == "openai":
        return OpenAIResponsesProvider()
    if name == "azure":
        return AzureOpenAIProvider()
    raise ValueError("Unsupported provider")


def _read_regular_file(path: Path, *, max_bytes: int = _MAX_INPUT_BYTES) -> bytes:
    if path.is_symlink():
        raise ValueError("Input must be a regular local file")
    resolved = path.expanduser().resolve(strict=True)
    with resolved.open("rb") as stream:
        status = os.fstat(stream.fileno())
        if not stat.S_ISREG(status.st_mode):
            raise ValueError("Input must be a regular local file")
        if status.st_size > max_bytes:
            raise ValueError("Input file is too large")
        data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("Input file is too large")
    return data


def _strict_json(data: bytes) -> object:
    try:
        text = data.decode("utf-8")
        return _strict_json_text(text)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ValueError("Input is not valid UTF-8 JSON") from None


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _strict_json_text(text: str) -> object:
    return json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
    )


def _load_cases_bytes(raw: bytes) -> list[EvaluationCase]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise EvaluationError("Evaluation file is not valid UTF-8") from None
    cases: list[EvaluationCase] = []
    identifiers: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = _strict_json_text(line)
        except (json.JSONDecodeError, ValueError):
            raise EvaluationError(f"Malformed evaluation case at line {line_number}") from None
        try:
            case = EvaluationCase.model_validate(value)
        except ValidationError:
            raise EvaluationError(f"Invalid evaluation case at line {line_number}") from None
        if case.id in identifiers:
            raise EvaluationError("Duplicate evaluation case identifier")
        identifiers.add(case.id)
        cases.append(case)
    if not cases:
        raise EvaluationError("Evaluation file contains no cases")
    return cases


def _load_cases(path: Path | None) -> list[EvaluationCase]:
    if path is None:
        raw = files("cloud_ops_copilot").joinpath("data", "evals", "cases.jsonl").read_bytes()
        return _load_cases_bytes(raw)
    try:
        return _load_cases_bytes(_read_regular_file(path))
    except EvaluationError:
        raise
    except (OSError, ValueError) as error:
        message = (
            "Evaluation file is too large"
            if "too large" in str(error)
            else "Evaluation file is invalid"
        )
        raise EvaluationError(message) from None


def run_evaluations(path: Path | None = None) -> EvaluationSummary:
    """Run deterministic offline cases and enforce safety and quality gates."""
    cases = _load_cases(path)
    cases_passed = safety_total = safety_passed = quality_total = quality_passed = 0
    for case in cases:
        case_safety_ok = True
        case_quality_ok = True
        inline = list(case.runbooks)
        recording_provider = _RecordingEvaluationProvider(MockAnalysisProvider(seed=17))
        service = AnalysisService(
            provider=recording_provider,
            retriever=lambda _query, _limit, items=inline: list(items),
        )
        expected_validation = case.case_type == "validation_rejection"
        try:
            envelope = service.analyze(case.incident)
        except ValidationError:
            if expected_validation:
                safety_total += 1
                safety_passed += 1
                cases_passed += 1
                continue
            raise EvaluationError("Evaluation incident validation failed") from None
        except ServiceError:
            raise EvaluationError("Evaluation analysis failed") from None
        if expected_validation:
            safety_total += 1
            continue

        safety = case.safety
        required_redactions = safety.minimum_redactions
        required_categories = set(safety.injection_categories)
        actual_categories = {finding.category for finding in envelope.safety.injection_findings}
        safety_assertions: list[bool] = []
        if required_redactions:
            safety_assertions.append(len(envelope.safety.redaction_findings) >= required_redactions)
        if required_categories:
            safety_assertions.append(required_categories <= actual_categories)
        provider_input = recording_provider.bound_input()
        safety_assertions.extend(
            excluded not in provider_input for excluded in safety.provider_input_excludes
        )
        safety_total += len(safety_assertions)
        safety_passed += sum(safety_assertions)
        case_safety_ok = all(safety_assertions)

        quality = case.quality
        if quality is None:
            raise EvaluationError("Evaluation case is missing quality assertions")
        assertions: list[bool] = []
        if quality.expected_risk is not None:
            assertions.append(envelope.recommendation.risk is quality.expected_risk)
        if quality.assessment_contains is not None:
            assertions.append(
                quality.assessment_contains.casefold()
                in envelope.recommendation.assessment.casefold()
            )
        for expected_step in quality.steps_contain:
            assertions.append(
                any(
                    expected_step.casefold() in step.casefold()
                    for step in envelope.recommendation.steps
                )
            )
        quality_total += len(assertions)
        quality_passed += sum(assertions)
        case_quality_ok = all(assertions)
        if case_safety_ok and case_quality_ok:
            cases_passed += 1

    safety_score = safety_passed / safety_total if safety_total else 1.0
    quality_score = quality_passed / quality_total if quality_total else 1.0
    if not math.isfinite(safety_score) or not math.isfinite(quality_score):
        raise EvaluationError("Evaluation score is invalid")
    return EvaluationSummary(
        cases_total=len(cases),
        cases_passed=cases_passed,
        safety_total=safety_total,
        safety_passed=safety_passed,
        quality_total=quality_total,
        quality_passed=quality_passed,
        safety_score=round(safety_score, 4),
        quality_score=round(quality_score, 4),
        passed=safety_score == 1.0 and quality_score >= 0.9,
    )


class _RecordingEvaluationProvider:
    """Record the actual sanitized provider boundary for independent safety checks."""

    def __init__(self, provider: AnalysisProvider) -> None:
        self._provider = provider
        self._calls: list[tuple[IncidentInput, list[Runbook]]] = []

    def analyze(
        self, incident: IncidentInput, runbooks: list[Runbook]
    ) -> RemediationRecommendation:
        self._calls.append((incident, list(runbooks)))
        return self._provider.analyze(incident, runbooks)

    def bound_input(self) -> str:
        if len(self._calls) != 1:
            raise EvaluationError("Evaluation provider boundary was not observed exactly once")
        incident, runbooks = self._calls[0]
        return _canonical_json(
            {
                "incident": incident.model_dump(mode="json"),
                "runbooks": [runbook.model_dump(mode="json") for runbook in runbooks],
            }
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cloud-ops-copilot")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser("analyze")
    analyze.add_argument("incident", type=Path)
    analyze.add_argument("--provider", choices=("mock", "openai", "azure"), default="mock")
    evaluate = subparsers.add_parser("eval")
    evaluate.add_argument("cases", nargs="?", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run a command and emit sanitized canonical JSON."""
    args = _parser().parse_args(argv)
    try:
        if args.command == "eval":
            summary = run_evaluations(args.cases)
            print(_canonical_json(summary.model_dump(mode="json")))
            return 0 if summary.passed else 3
        incident = IncidentInput.model_validate(_strict_json(_read_regular_file(args.incident)))
        envelope = AnalysisService(provider=create_provider(args.provider)).analyze(incident)
        print(_canonical_json(envelope.model_dump(mode="json")))
        return 0
    except (OSError, ValueError, ValidationError, ProviderError, ServiceError, EvaluationError):
        print(_canonical_json({"error": "Request could not be completed safely"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["EvaluationError", "EvaluationSummary", "create_provider", "main", "run_evaluations"]
