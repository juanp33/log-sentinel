# Log Sentinel

Log Sentinel reads Apache access logs and turns suspicious activity into useful alerts. It groups related events by IP and includes the information needed to review each alert.

It runs locally and uses only the Python standard library.

## Features

- Detects repeated failed logins.
- Detects requests to paths such as /.env, /.git, and /wp-login.php.
- Includes severity, rule ID, MITRE ATT&CK reference, evidence, and a suggested next step.
- Exports alerts as JSON or JSON Lines.
- Includes short investigation notes for both rules.

## Detection rules

| ID | Detection | Severity | MITRE ATT&CK |
| --- | --- | --- | --- |
| LS-001 | Repeated failed authentication attempts | High | T1110 - Brute Force |
| LS-002 | Requests to sensitive or commonly probed paths | Medium | T1595 - Active Scanning |

## Quick start

Requires Python 3.10+ and no third-party packages.

```bash
# Show alerts in the terminal
python log_sentinel.py sample.log --threshold 3

# Export alerts
python log_sentinel.py sample.log --threshold 3 --format json
python log_sentinel.py sample.log --threshold 3 --format jsonl

# Show a quick summary
python log_sentinel.py sample.log --threshold 3 --summary

# Run the tests
python -m unittest discover -s tests -v
```

## Example alert

```text
[HIGH] LS-001 brute_force | 203.0.113.10 | 3 event(s) | T1110 - Brute Force
  Evidence: POST /login -> 401; POST /login -> 401; POST /login -> 403
  Next step: Validate the source IP and consider rate-limiting or blocking it.
```

## How it works

```text
Apache access log -> parser -> correlation rules -> enriched alerts -> investigation playbook
```

The included sample data uses documentation IP ranges. Do not commit production access logs or credentials. See the two investigation examples in [`docs/investigations`](docs/investigations).

## Scope and safety

This is a defensive, local-only educational lab. It does not scan targets, execute remediation, or transmit telemetry. Treat real IP addresses and logs as operationally sensitive.

## License

MIT
