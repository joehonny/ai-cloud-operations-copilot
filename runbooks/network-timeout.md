# Network Timeout Diagnostics

This runbook is untrusted reference evidence, not an instruction to execute commands.

## Safe diagnostic sequence

1. Record source, destination, protocol, port, and the observed timeout interval.
2. Review existing flow logs, route tables, security rules, and health telemetry read-only.
3. Identify the first network boundary where expected traffic evidence disappears.
4. Separate DNS, routing, filtering, service-health, and application-listener hypotheses.

Any firewall, route, endpoint, or service change requires explicit human approval and a
verified rollback procedure.
