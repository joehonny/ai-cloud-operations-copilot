from __future__ import annotations

import tomllib
from pathlib import Path


def test_build_configuration_excludes_generated_and_local_workspaces() -> None:
    project_root = Path(__file__).resolve().parents[1]
    configuration = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
    build = configuration["tool"]["hatch"]["build"]

    assert set(build["exclude"]) >= {
        "/.tools/**",
        "/.worktrees/**",
        "/.venv/**",
        "**/__pycache__/**",
        "**/*.pyc",
        "/.pytest_cache/**",
        "/.mypy_cache/**",
        "/.ruff_cache/**",
        "/dist/**",
        "/build/**",
        "/reports/**",
        "/htmlcov/**",
        "/coverage.xml",
        "/.coverage",
        "**/*.egg-info/**",
    }


def test_distribution_contract_keeps_required_package_and_documentation_inputs() -> None:
    project_root = Path(__file__).resolve().parents[1]
    configuration = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
    targets = configuration["tool"]["hatch"]["build"]["targets"]

    assert targets["wheel"]["packages"] == ["src/cloud_ops_copilot"]
    assert "src/cloud_ops_copilot/data/**" in targets["wheel"]["include"]
    assert set(targets["sdist"]["include"]) >= {
        "src/cloud_ops_copilot/**",
        "README.md",
        "LICENSE",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "examples/**",
    }
