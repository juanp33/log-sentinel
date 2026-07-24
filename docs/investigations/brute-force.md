# Investigation playbook: LS-001 brute force

## Trigger

Multiple `401` or `403` responses to an authentication path from the same source IP meet the configured threshold.

## Triage steps

1. Check the login endpoint and the time of the requests.
2. If the original log has them, review the username and user-agent.
3. Check if the same IP logged in successfully after the failed attempts.
4. Search the IP in firewall or application logs.
5. Save the result and escalate it if necessary.

## Containment considerations

After confirming the activity, consider rate limiting, MFA, CAPTCHA, or a temporary block. Keep in mind that an IP can belong to a shared network.

## False-positive notes

Password-manager retries, health checks, and old passwords can look like failed login attempts.
