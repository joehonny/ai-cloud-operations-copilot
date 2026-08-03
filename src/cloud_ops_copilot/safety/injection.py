"""Conservative detection of instructions embedded in untrusted evidence.

Detection only emits metadata. It never interprets, executes, or follows input text.
Regex heuristics have false positives and false negatives, so findings require review.
"""

import re
from dataclasses import dataclass
from typing import Final

from cloud_ops_copilot.safety.redaction import Finding


@dataclass(frozen=True, slots=True)
class _InstructionPattern:
    category: str
    severity: str
    expression: re.Pattern[str]


_PATTERNS: Final[tuple[_InstructionPattern, ...]] = (
    _InstructionPattern(
        "instruction_override",
        "critical",
        re.compile(
            r"\b(?:ignore|disregard|override|forget|replace)\b.{0,40}"
            r"\b(?:previous|prior|system|developer)\b.{0,20}\binstructions?\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    _InstructionPattern(
        "role_reassignment",
        "critical",
        re.compile(
            r"\b(?:you\s+are\s+now|act\s+as)\s+(?:the\s+)?"
            r"(?:system|developer|administrator|root)\b",
            re.IGNORECASE,
        ),
    ),
    _InstructionPattern(
        "sensitive_instruction_request",
        "high",
        re.compile(
            r"\b(?:reveal|show|print|expose)\b.{0,30}\b(?:system|developer)\s+(?:prompt|instructions?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    _InstructionPattern(
        "secret_exfiltration",
        "critical",
        re.compile(
            r"\b(?:reveal|show|print|send|export|extract)\b.{0,50}"
            r"\b(?:api\s*keys?|credentials?|passwords?|tokens?|private\s+keys?|secrets?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    _InstructionPattern(
        "encoded_payload",
        "high",
        re.compile(
            r"(?:\bdecode\b.{0,30}\b(?:base64|hex|encoded)\b.{0,40}"
            r"\b(?:execute|run|command|payload)\b|"
            r"\bencode\b.{0,30}\b(?:credentials?|secrets?|tokens?)\b.{0,30}"
            r"\b(?:base64|hex)\b)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    _InstructionPattern(
        "execution_attempt",
        "critical",
        re.compile(
            r"(?:\b(?:execute|run|launch|invoke)\b.{0,45}\b(?:shell|command|powershell|bash|cmd|terraform|kubectl|az|aws)\b|"
            r"\b(?:terraform\s+apply|kubectl\s+(?:delete|apply)|az\s+\w+\s+(?:delete|create|update)|aws\s+\w+\s+(?:delete|create|update))\b)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    _InstructionPattern(
        "destructive_execution",
        "critical",
        re.compile(
            r"(?:\brm\s+-rf\b|\bRemove-Item\b.{0,30}\b-Recurse\b|"
            r"\bterraform\s+destroy\b|\bdelete\s+all\b.{0,25}\b(?:resources?|data|accounts?)\b)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
)


def _location(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    return line, offset - text.rfind("\n", 0, offset)


def detect_untrusted_instruction(text: str) -> list[Finding]:
    """Return safe metadata for suspicious untrusted instruction patterns."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    findings: list[Finding] = []
    for pattern in _PATTERNS:
        match = pattern.expression.search(text)
        if match is not None:
            line, column = _location(text, match.start())
            findings.append(
                Finding(
                    category=pattern.category,
                    count=1,
                    line=line,
                    column=column,
                    span_start=match.start(),
                    span_end=match.end(),
                    severity=pattern.severity,
                )
            )
    return findings
