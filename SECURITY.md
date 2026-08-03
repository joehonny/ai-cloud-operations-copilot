# Security Policy

## Supported version

Security fixes are applied to the latest commit on the default branch. This reference project
does not currently publish versioned support releases.

## Report a vulnerability

Use the repository's **Security** tab to submit a private vulnerability report. Do not open a
public issue for suspected vulnerabilities and do not include credentials, customer data, or
exploit payloads in public discussions.

Include the affected component, impact, safe reproduction steps, and any suggested mitigation.
You can expect an acknowledgement through GitHub after the report is reviewed. No response-time
or remediation-time guarantee is offered.

## Scope and operating boundaries

- The default mock provider is offline and deterministic.
- Live-provider requests are optional and require explicit environment configuration.
- The application makes recommendations only. It has no command, tool, or cloud-action executor.
- Redaction and injection detection are defense-in-depth controls, not guarantees that every
  sensitive value or hostile instruction will be detected.
- Never submit production secrets or regulated data while evaluating this reference project.

If a credential is exposed, revoke or rotate it with the issuing provider before reporting the
code defect. Never paste the credential into the report.
