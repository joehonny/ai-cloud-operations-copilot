from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from cloud_ops_copilot.cli import EvaluationError, main, run_evaluations
from cloud_ops_copilot.providers.mock import MockAnalysisProvider


def write_cases(path: Path, rows: Sequence[object]) -> None:
    path.write_text(
        "".join(json.dumps(row, allow_nan=True) + "\n" for row in rows), encoding="utf-8"
    )


def test_bundled_evaluations_are_deterministic_and_pass_gates() -> None:
    first = run_evaluations()
    second = run_evaluations()
    assert first == second
    assert first.safety_passed == first.safety_total
    assert first.quality_score >= 0.9
    assert first.passed is True
    assert first.quality_total == 5
    # Validation rejection (1), secret finding count (1), two provider-bound
    # secret exclusions (2), and injection categories (1). Literal model defaults
    # are deliberately excluded because they are not independent assertions.
    assert first.safety_total == 5


@pytest.mark.parametrize(
    "content",
    [
        "not-json\n",
        '{"id":"same"}\n{"id":"same"}\n',
        '{"id":"nan","incident":{"source":"x","severity":"low","summary":"x","evidence":[NaN],"runbook_ids":[]}}\n',
    ],
)
def test_eval_rejects_malformed_duplicate_and_nonfinite_jsonl(tmp_path: Path, content: str) -> None:
    path = tmp_path / "cases.jsonl"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(EvaluationError):
        run_evaluations(path)


def test_eval_rejects_oversize_file(tmp_path: Path) -> None:
    path = tmp_path / "cases.jsonl"
    path.write_bytes(b" " * 1_048_577)
    with pytest.raises(EvaluationError, match="too large"):
        run_evaluations(path)


@pytest.mark.parametrize(
    "content",
    [
        '{"id":"one","id":"two"}\n',
        '{"id":"one","incident":{"source":"a","source":"b"}}\n',
    ],
)
def test_eval_rejects_duplicate_json_keys_at_any_depth(tmp_path: Path, content: str) -> None:
    path = tmp_path / "cases.jsonl"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(EvaluationError, match="Malformed evaluation case"):
        run_evaluations(path)


@pytest.mark.parametrize(
    "change",
    [
        {"unknown": "field"},
        {"case_type": True},
        {"safety": {"minimum_redactions": True}},
        {"safety": {"minimum_redactions": -1}},
        {"safety": {"minimum_redactions": 101}},
        {"quality": {"expected_risk": "high", "unknown": 1}},
    ],
)
def test_eval_schema_rejects_unknown_coerced_or_unbounded_values(
    tmp_path: Path, change: dict[str, object]
) -> None:
    case: dict[str, object] = {
        "id": "strict",
        "case_type": "analysis",
        "incident": {
            "source": "fixture:strict",
            "severity": "high",
            "summary": "DNS failure",
            "evidence": ["NXDOMAIN"],
            "runbook_ids": [],
        },
        "safety": {},
        "quality": {"expected_risk": "high"},
    }
    case.update(change)
    path = tmp_path / "cases.jsonl"
    write_cases(path, [case])
    with pytest.raises(EvaluationError, match="Invalid evaluation case"):
        run_evaluations(path)


def test_eval_requires_independent_quality_assertion_for_analysis(tmp_path: Path) -> None:
    path = tmp_path / "cases.jsonl"
    write_cases(
        path,
        [
            {
                "id": "no-quality",
                "case_type": "analysis",
                "incident": {
                    "source": "fixture:no-quality",
                    "severity": "low",
                    "summary": "DNS failure",
                    "evidence": ["NXDOMAIN"],
                    "runbook_ids": [],
                },
                "safety": {},
                "quality": {},
            }
        ],
    )
    with pytest.raises(EvaluationError, match="Invalid evaluation case"):
        run_evaluations(path)


@pytest.mark.parametrize(("mismatches", "expected"), [(1, True), (2, False)])
def test_quality_gate_is_inclusive_at_ninety_percent(
    tmp_path: Path, mismatches: int, expected: bool
) -> None:
    cases: list[dict[str, object]] = []
    for index in range(10):
        cases.append(
            {
                "id": f"quality-{index}",
                "case_type": "analysis",
                "incident": {
                    "source": f"fixture:quality-{index}",
                    "severity": "low",
                    "summary": "DNS failure",
                    "evidence": ["NXDOMAIN"],
                    "runbook_ids": [],
                },
                "safety": {},
                "quality": {"expected_risk": "high" if index < mismatches else "low"},
            }
        )
    path = tmp_path / "cases.jsonl"
    write_cases(path, cases)
    summary = run_evaluations(path)
    assert summary.quality_score == (10 - mismatches) / 10
    assert summary.passed is expected


def test_eval_checks_exclusions_against_actual_provider_bound_input(tmp_path: Path) -> None:
    path = tmp_path / "cases.jsonl"
    write_cases(
        path,
        [
            {
                "id": "provider-bound-exclusion",
                "case_type": "analysis",
                "incident": {
                    "source": "fixture:provider-bound",
                    "severity": "low",
                    "summary": "DNS failure",
                    "evidence": ["NXDOMAIN"],
                    "runbook_ids": [],
                },
                "safety": {"provider_input_excludes": ["DNS failure"]},
                "quality": {"expected_risk": "low"},
            }
        ],
    )

    summary = run_evaluations(path)

    assert summary.safety_total == 1
    assert summary.safety_passed == 0
    assert summary.passed is False


def test_incident_json_rejects_duplicate_keys_without_echoing_values(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "incident.json"
    path.write_text(
        '{"source":"fixture:a","source":"SENSITIVE-DUPLICATE",'
        '"severity":"low","summary":"DNS","evidence":["NXDOMAIN"],'
        '"runbook_ids":[]}',
        encoding="utf-8",
    )
    assert main(["analyze", str(path)]) == 2
    captured = capsys.readouterr()
    assert "SENSITIVE-DUPLICATE" not in captured.out + captured.err


def test_nested_incident_json_rejects_duplicate_keys(tmp_path: Path) -> None:
    path = tmp_path / "incident.json"
    path.write_text(
        '{"source":"fixture:a","severity":"low","summary":"DNS",'
        '"evidence":["NXDOMAIN"],"runbook_ids":[],"metadata":{"x":1,"x":2}}',
        encoding="utf-8",
    )
    assert main(["analyze", str(path)]) == 2


def test_cli_analyze_defaults_offline_and_never_prints_secret(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "TOP-SECRET-PASSWORD"
    path = tmp_path / "incident.json"
    path.write_text(
        json.dumps(
            {
                "source": "fixture:cli",
                "severity": "high",
                "summary": f"password={secret}",
                "evidence": ["DNS failed"],
                "runbook_ids": ["dns-resolution"],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("socket.create_connection", lambda *_a, **_k: pytest.fail("network used"))
    code = main(["analyze", str(path)])
    captured = capsys.readouterr()
    assert code == 0
    assert secret not in captured.out + captured.err
    assert json.loads(captured.out)["recommendation"]["requires_human_approval"] is True


def test_cli_live_provider_is_explicit_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "incident.json"
    path.write_text(
        json.dumps(
            {
                "source": "fixture:cli",
                "severity": "low",
                "summary": "DNS failed",
                "evidence": ["NXDOMAIN"],
                "runbook_ids": [],
            }
        ),
        encoding="utf-8",
    )
    calls: list[str] = []

    def fake_create_provider(name: str) -> MockAnalysisProvider:
        calls.append(name)
        return MockAnalysisProvider()

    monkeypatch.setattr("cloud_ops_copilot.cli.create_provider", fake_create_provider)
    assert main(["analyze", str(path)]) == 0
    assert calls == ["mock"]
    calls.clear()
    assert main(["analyze", str(path), "--provider", "openai"]) == 0
    assert calls == ["openai"]


def test_cli_eval_is_offline_even_if_live_provider_option_is_attempted(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit):
        main(["eval", "--provider", "openai"])
    assert "OPENAI_API_KEY" not in capsys.readouterr().err
