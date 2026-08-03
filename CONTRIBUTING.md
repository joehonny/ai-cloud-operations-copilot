# Contributing

Contributions that improve the offline safety controls, deterministic evaluations, provider
boundaries, tests, or documentation are welcome.

## Development workflow

1. Use Python 3.12 or newer in an isolated environment.
2. Install development dependencies with `python -m pip install -e ".[dev]"`.
3. Create a focused branch and add a failing test before changing behavior.
4. Run the checks below before opening a pull request.

```text
python -m ruff format --check src tests
python -m ruff check src tests
python -m mypy src tests
python -m pytest --disable-socket
python -m cloud_ops_copilot.cli eval
python -m build
```

## Safety requirements

- Do not commit secrets, `.env` files, credentials, tokens, private endpoints, customer data, or
  provider response payloads.
- Do not add tests that call live APIs, cloud resources, or public network services.
- Do not add command execution, infrastructure deployment, autonomous remediation, or tool-use
  features.
- Preserve mandatory human approval and the `store=False` live-provider request setting.
- Keep incident and runbook content untrusted. Test injection detection and redaction separately.
- Use synthetic fixtures and sanitized error messages.

Pull requests should explain the risk addressed, the test evidence, any skipped live validation,
and whether documentation or evaluation expectations changed.
