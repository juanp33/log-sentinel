# Investigation playbook: LS-001 brute force

## Trigger

Multiple `401` or `403` responses to an authentication path from the same source IP meet the configured threshold.

## Triage steps

1. Confirm the affected authentication endpoint and the event time window.
2. Review the alert evidence for account identifiers or user-agent data in the original approved log source, if available.
3. Check whether a successful login from the same source occurred after the failures.
4. Look for the source IP in other web, identity, or firewall telemetry.
5. Document the decision and escalate according to the organization's incident process.

## Containment considerations

Apply rate limiting, MFA, CAPTCHA, or a temporary block only after validating the activity and considering legitimate users behind shared networks.

## False-positive notes

Password-manager retries, application health checks, and users with stale credentials can produce similar events.
