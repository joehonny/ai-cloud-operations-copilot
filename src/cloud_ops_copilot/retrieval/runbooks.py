"""Deterministic retrieval of local runbooks as untrusted evidence.

This module only reads Markdown. It never evaluates code blocks or executes content.
The optional directory is an explicit dependency-injection seam for local tests and
callers that designate another local directory as trusted.
"""

import os
import re
import stat
from dataclasses import dataclass
from importlib.resources import as_file, files
from pathlib import Path
from typing import Final

from cloud_ops_copilot.models import Runbook

_TOKEN_PATTERN: Final = re.compile(r"[^\W_]+", re.UNICODE)
_MAX_RUNBOOK_BYTES: Final = 1_048_576


def _tokens(text: str) -> set[str]:
    return set(_TOKEN_PATTERN.findall(text.casefold()))


@dataclass(frozen=True, slots=True)
class _LoadedRunbook:
    path_key: str
    runbook: Runbook


def _markdown_title(content: str, filename: str) -> str:
    fence_character: str | None = None
    fence_length = 0
    for line in content.splitlines():
        fence = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        if fence is not None:
            marker = fence.group(1)
            if fence_character is None:
                fence_character = marker[0]
                fence_length = len(marker)
            elif marker[0] == fence_character and len(marker) >= fence_length:
                fence_character = None
                fence_length = 0
            continue
        if fence_character is None:
            title = re.match(r"^#\s+(.+?)\s*$", line)
            if title is not None:
                return title.group(1)
    raise ValueError(f"runbook must contain a level-one title: {filename}")


def _load_runbooks(root: Path) -> list[_LoadedRunbook]:
    trusted_root = root.resolve(strict=True)
    if not trusted_root.is_dir():
        raise ValueError("runbook_dir must be a directory")

    candidates = sorted(
        trusted_root.glob("*.md"),
        key=lambda path: (path.stem.casefold(), path.name.casefold(), path.name),
    )
    seen_ids: set[str] = set()
    runbooks: list[_LoadedRunbook] = []
    for candidate in candidates:
        if candidate.is_symlink():
            raise ValueError("runbook path resolves outside the trusted runbook directory")
        logical_id = candidate.stem.casefold()
        if logical_id in seen_ids:
            raise ValueError(f"duplicate runbook identifier: {candidate.stem}")
        seen_ids.add(logical_id)

        with candidate.open("rb") as stream:
            resolved = candidate.resolve(strict=True)
            try:
                resolved.relative_to(trusted_root)
            except ValueError as error:
                message = "runbook path resolves outside the trusted runbook directory"
                raise ValueError(message) from error
            file_status = os.fstat(stream.fileno())
            if not stat.S_ISREG(file_status.st_mode):
                raise ValueError(f"runbook must be a regular file: {candidate.name}")
            if file_status.st_size > _MAX_RUNBOOK_BYTES:
                raise ValueError(f"runbook exceeds {_MAX_RUNBOOK_BYTES} bytes: {candidate.name}")
            raw_content = stream.read(_MAX_RUNBOOK_BYTES + 1)
        if len(raw_content) > _MAX_RUNBOOK_BYTES:
            raise ValueError(f"runbook exceeds {_MAX_RUNBOOK_BYTES} bytes: {candidate.name}")
        content = raw_content.decode("utf-8")
        title = _markdown_title(content, candidate.name)
        path_key = candidate.relative_to(trusted_root).as_posix()
        runbooks.append(
            _LoadedRunbook(
                path_key=path_key,
                runbook=Runbook(runbook_id=candidate.stem, title=title, content=content),
            )
        )
    return runbooks


def retrieve_runbooks(
    query: str,
    limit: int = 3,
    *,
    runbook_dir: Path | None = None,
) -> list[Runbook]:
    """Rank local Markdown runbooks by distinct query-token overlap.

    Content is returned as evidence only. Consumers must run safety checks and must
    never treat retrieved prose or code blocks as instructions to execute.
    """
    if not isinstance(query, str):
        raise TypeError("query must be a string")
    query_tokens = _tokens(query)
    if not query.strip() or not query_tokens:
        raise ValueError("query must contain searchable text")
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise TypeError("limit must be an integer")
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if runbook_dir is not None and not isinstance(runbook_dir, Path):
        raise TypeError("runbook_dir must be a pathlib.Path")

    if runbook_dir is None:
        resource = files("cloud_ops_copilot").joinpath("data", "runbooks")
        with as_file(resource) as packaged_root:
            return retrieve_runbooks(query, limit, runbook_dir=packaged_root)
    root = runbook_dir
    ranked: list[tuple[int, str, str, str, Runbook]] = []
    for loaded in _load_runbooks(root):
        runbook = loaded.runbook
        searchable = _tokens(f"{runbook.runbook_id} {runbook.title} {runbook.content}")
        score = len(query_tokens & searchable)
        if score:
            ranked.append(
                (
                    -score,
                    runbook.runbook_id.casefold(),
                    loaded.path_key.casefold(),
                    loaded.path_key,
                    runbook,
                )
            )

    ranked.sort(key=lambda item: item[:4])
    return [item[4] for item in ranked[:limit]]
