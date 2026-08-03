# DNS Resolution Diagnostics

This runbook is reference evidence. It never authorizes automated remediation.

## Safe diagnostic sequence

1. Record the failing fully qualified domain name and the resolver used by the workload.
2. Compare expected public or private DNS scope with the incident evidence.
3. Review resolver logs and zone-link configuration using read-only access.
4. Confirm that cached and authoritative answers agree before proposing a change.

Any configuration change requires explicit human approval, an owner, a maintenance window,
and a tested rollback plan.
