"""Best-effort redaction for recognizable secret formats.

Regex redaction cannot identify every secret and can redact secret-shaped test data.
Callers must still avoid collecting unnecessary sensitive data and must never treat a
clean result as proof that text contains no secrets.
"""

import re
from dataclasses import dataclass
from typing import Final

_MAX_TEXT_CHARS: Final = 1_048_576
_MAX_PRIVATE_KEY_BLOCK_CHARS: Final = 131_072


@dataclass(frozen=True, slots=True)
class Finding:
    """Safe metadata about a finding, never the matched source text."""

    category: str
    count: int
    line: int
    column: int
    span_start: int
    span_end: int
    severity: str | None = None


@dataclass(frozen=True, slots=True)
class RedactionResult:
    """Redacted text plus metadata that cannot reconstruct matched secrets."""

    text: str
    findings: tuple[Finding, ...]


@dataclass(frozen=True, slots=True)
class _SecretPattern:
    category: str
    expression: re.Pattern[str]


@dataclass(frozen=True, slots=True)
class _Candidate:
    category: str
    priority: int
    start: int
    end: int


_QUOTED_OR_TOKEN_12 = r'(?P<value>"[^"\r\n]{12,}"|\'[^\'\r\n]{12,}\'|[^\s;\'\"]{12,})'
_QUOTED_OR_TOKEN_4 = r'(?P<value>"[^"\r\n]{4,}"|\'[^\'\r\n]{4,}\'|[^\s;\'\"]{4,})'
_PRIVATE_KEY_BEGIN: Final = re.compile(
    r"^-----BEGIN (?P<label>(?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY)-----"
    r"[ \t]*\r?\n",
    re.MULTILINE,
)
_PATTERNS: Final[tuple[_SecretPattern, ...]] = (
    _SecretPattern(
        "api_key",
        re.compile(
            rf"(?P<prefix>\b(?:OPENAI_API_KEY|AZURE_OPENAI_API_KEY|API_KEY)\s*=\s*)"
            rf"{_QUOTED_OR_TOKEN_12}",
            re.IGNORECASE,
        ),
    ),
    _SecretPattern(
        "api_key",
        re.compile(r"(?P<value>\bsk-(?:proj-)?[A-Za-z0-9_-]{20,})"),
    ),
    _SecretPattern(
        "azure_storage_key",
        re.compile(
            r"(?P<prefix>\bAccountKey\s*=\s*)"
            r"(?P<value>\"[A-Za-z0-9+/]{40,}={0,2}\"|'[A-Za-z0-9+/]{40,}={0,2}'|"
            r"[A-Za-z0-9+/]{40,}={0,2})",
            re.IGNORECASE,
        ),
    ),
    _SecretPattern(
        "bearer_token",
        re.compile(
            r"(?P<prefix>\bBearer\s+)(?P<value>[A-Za-z0-9._~+/=-]{8,})",
            re.IGNORECASE,
        ),
    ),
    _SecretPattern(
        "password",
        re.compile(
            rf"(?P<prefix>\b(?:password|passwd)\s*[:=]\s*){_QUOTED_OR_TOKEN_4}",
            re.IGNORECASE,
        ),
    ),
    _SecretPattern(
        "connection_string_secret",
        re.compile(
            rf"(?P<prefix>\b(?:Pwd|SharedAccessSignature)\s*=\s*){_QUOTED_OR_TOKEN_4}",
            re.IGNORECASE,
        ),
    ),
)


def _location(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    previous_newline = text.rfind("\n", 0, offset)
    return line, offset - previous_newline


def _secret_span(match: re.Match[str]) -> tuple[int, int]:
    start, end = match.span("value")
    value = match.group("value")
    if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
        return start + 1, end - 1
    return start, end


def _overlaps(candidate: _Candidate, accepted: list[_Candidate]) -> bool:
    return any(candidate.start < item.end and item.start < candidate.end for item in accepted)


def _private_key_candidates(text: str) -> list[_Candidate]:
    """Find complete, bounded private-key blocks with matching delimiter labels."""
    candidates: list[_Candidate] = []
    for match in _PRIVATE_KEY_BEGIN.finditer(text):
        footer = f"-----END {match.group('label')}-----"
        search_end = min(len(text), match.end() + _MAX_PRIVATE_KEY_BLOCK_CHARS)
        footer_start = text.find(footer, match.end(), search_end)
        if footer_start < 0 or (footer_start > 0 and text[footer_start - 1] != "\n"):
            continue
        if not text[match.end() : footer_start].strip():
            continue
        footer_end = footer_start + len(footer)
        line_end = text.find("\n", footer_end)
        if line_end < 0:
            line_end = len(text)
        trailing = text[footer_end:line_end].removesuffix("\r")
        if trailing.strip(" \t"):
            continue
        candidates.append(_Candidate("private_key", -1, match.start(), footer_end))
    return candidates


def redact(text: str) -> RedactionResult:
    """Replace recognizable secrets with deterministic category markers.

    The original matched value is neither returned nor stored in finding metadata.
    Already-redacted markers are ignored, making repeated redaction idempotent.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if len(text) > _MAX_TEXT_CHARS:
        raise ValueError("text is too large to redact safely")

    candidates = _private_key_candidates(text)
    for priority, pattern in enumerate(_PATTERNS):
        for match in pattern.expression.finditer(text):
            start, end = _secret_span(match)
            if text[start:end].startswith("[REDACTED:"):
                continue
            candidates.append(_Candidate(pattern.category, priority, start, end))

    # Lower pattern index has higher priority. This makes named assignments win over
    # bare key shapes, storage AccountKey win over generic connection-string shapes,
    # and resolves every overlap before any source offsets can change.
    accepted: list[_Candidate] = []
    for candidate in sorted(candidates, key=lambda item: (item.priority, item.start, item.end)):
        if not _overlaps(candidate, accepted):
            accepted.append(candidate)

    findings: list[Finding] = []
    for candidate in sorted(accepted, key=lambda item: (item.start, item.priority)):
        line, column = _location(text, candidate.start)
        findings.append(
            Finding(
                category=candidate.category,
                count=1,
                line=line,
                column=column,
                span_start=candidate.start,
                span_end=candidate.end,
            )
        )

    redacted = text
    for candidate in sorted(accepted, key=lambda item: item.start, reverse=True):
        marker = f"[REDACTED:{candidate.category.upper()}]"
        redacted = f"{redacted[: candidate.start]}{marker}{redacted[candidate.end :]}"
    return RedactionResult(text=redacted, findings=tuple(findings))
