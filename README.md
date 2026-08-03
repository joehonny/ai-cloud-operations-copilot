# AI Cloud Operations Copilot

An offline-first reference application that turns synthetic cloud incident evidence into a
structured, advisory remediation recommendation. It demonstrates practical AI engineering for
cloud operations teams and provides a reviewable starting point for consulting engagements in
safe incident-assistance workflows.

The application does not execute commands, call cloud control planes, or remediate infrastructure.
Every recommendation requires approval from an authorized human operator.

## What it demonstrates

- Provider-independent Pydantic contracts for incidents, runbooks, and recommendations
- Deterministic offline analysis for development, demonstrations, tests, and evaluations
- Optional OpenAI Responses API and Azure OpenAI-compatible provider adapters
- Redaction before the provider boundary and separate prompt-injection detection
- Local runbook retrieval that treats all retrieved content as untrusted evidence
- Structured output validation before a recommendation is emitted
- Reproducible safety and quality gates with network sockets blocked in CI

## Intended users

Cloud and platform engineers can use the project to examine a safe advisory workflow. Security and
governance reviewers can inspect its trust boundaries and deterministic tests. Consultants can use
it as a reference architecture when scoping a controlled proof of concept, not as a production
incident-response system.

## Architecture and data flow

```text
Incident JSON
    |
    v
Strict schema validation
    |
    v
Field-level redaction ----> non-sensitive finding counts
    |
    +----> injection detection on original incident text
    |
    v
Local runbook retrieval
    |
    +----> runbook redaction and injection detection
    |
    v
Explicit provider: mock | OpenAI | Azure OpenAI-compatible
    |
    v
Strict recommendation validation
    |
    v
Advisory JSON with mandatory human approval
```

### Trust boundaries

Incident fields and retrieved runbooks are untrusted. The service validates their shape, redacts
recognized secret patterns, and flags recognized instruction-like content before calling a
provider. Trusted provider instructions state that evidence must not be followed as instructions.
The provider receives no tools and the application exposes no execution interface.

Provider output is also untrusted. It must validate against `RemediationRecommendation`, including
an exact boolean `requires_human_approval=true`, before the CLI emits it. Regex redaction and
injection heuristics are imperfect, so operators must still review all input and output.

## Offline quick start

Prerequisites: Python 3.12 or newer. The live provider extra is not required for the default path.

```text
python -m venv .venv
python -m pip install -e ".[dev]"
cloud-ops-copilot analyze examples/incident.example.json
cloud-ops-copilot eval
```

`analyze` defaults to the deterministic mock provider. `eval` always uses the mock provider and
does not accept a live-provider option.

## Provider configuration

Live calls are opt-in. Install the optional SDK with `python -m pip install -e ".[live]"`, copy
`.env.example` to a file excluded from version control, and set the required variables in a secure
environment. This project does not load `.env` files automatically.

For OpenAI, set `OPENAI_API_KEY` and `OPENAI_MODEL`, then select `--provider openai`. For Azure,
set `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`, and `AZURE_OPENAI_DEPLOYMENT`, then select
`--provider azure`. There is no hardcoded model or deployment default.

The OpenAI adapter uses the Responses API structured-output parser with `store=False`. See the
[OpenAI Structured Outputs guide](https://platform.openai.com/docs/guides/structured-outputs) and
[OpenAI data controls](https://platform.openai.com/docs/models/default-usage-policies-by-endpoint).
The Azure adapter accepts supported Azure OpenAI or Foundry resource endpoints and forms the v1
base URL described in the [Microsoft Responses API guidance](https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/responses)
and [Microsoft REST reference](https://learn.microsoft.com/en-us/rest/api/microsoft-foundry/azureopenai/responses).

### Retention and privacy

The application has no database, response cache, or application logging path, and each live request
sets `store=False`. That setting does not make a universal zero-retention promise. Provider abuse
monitoring, service processing, account policy, regional configuration, and other provider terms
can still apply. Review the current provider documentation and organizational data controls before
sending sensitive operational data. Do not send credentials, regulated data, or client information
without an approved data-handling design.

## Models and safety controls

- `IncidentInput` requires a source, severity, summary, at least one evidence item, and optional
  runbook identifiers.
- `RemediationRecommendation` requires an assessment, risk, evidence, steps, confidence from 0 to
  1, and mandatory human approval.
- Redaction recognizes selected API key, password, bearer token, shared-access-signature,
  connection-string, and complete PEM/OpenSSH private-key block patterns. Private-key delimiters
  must use the same supported label, the block must close within 128 KiB, and each redaction input
  is limited to 1 MiB. The heuristics can miss truncated or novel formats and can redact benign
  secret-shaped text.
- Injection detection flags selected instruction override and execution-attempt phrases. It is a
  heuristic signal, not a semantic security boundary.
- Retrieval is deterministic token matching over packaged local Markdown runbooks. Retrieved text
  is reference material only and is never executable.

## Evaluations

The bundled JSONL suite covers DNS failure, network timeout, validation rejection for missing
evidence, secret redaction at the actual provider boundary, and malicious runbook text. The gate
requires 100 percent of explicit safety assertions and at least 90 percent of deterministic quality
assertions.

The source verification on 2026-08-03 produced 5 of 5 passing cases, 5 of 5 independent safety
assertions, and 5 of 5 quality assertions. These are synthetic offline results, not evidence of
production model accuracy. Reproduce them with:

```text
python -m cloud_ops_copilot.cli eval
```

## Development and verification

```text
python -m ruff format --check src tests
python -m ruff check src tests
python -m mypy src tests
python -m pytest --disable-socket
python -m cloud_ops_copilot.cli eval
python -m build
```

CI runs these offline checks on Python 3.12, 3.13, and 3.14, then installs the built wheel outside
the checkout and reruns the packaged evaluation. GitHub Actions are pinned to full commit SHAs and
receive read-only repository contents permission. Dependabot checks Python and action dependencies
monthly.

## Limitations and maintenance status

- No live OpenAI or Azure request was made during repository verification.
- No hosted deployment, cloud authentication flow, latency, cost, rate limit, or model quality claim
  has been validated.
- Endpoint validation intentionally supports Azure OpenAI resource hosts and Foundry resource hosts,
  not every possible Microsoft project endpoint or identity pattern.
- API-key authentication is the only implemented Azure authentication method.
- There is no conversational state, durable storage, observability backend, user interface, command
  execution, tool calling, or autonomous remediation.
- Deterministic fixtures are narrow and do not establish recall, precision, safety, or usefulness on
  real incident distributions.

The project is an actively maintained portfolio reference. Issues and pull requests should preserve
the offline default, strict schemas, no-execution boundary, and mandatory human approval.

## License

MIT. See [LICENSE](LICENSE).
