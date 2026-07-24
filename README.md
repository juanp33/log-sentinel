# Log Sentinel

Log Sentinel is a **local, SIEM-style detection engineering lab** for Apache access logs. It ingests a log file, correlates events into alerts, maps detections to MITRE ATT&CK, and emits analyst-ready evidence and next steps.

It is intentionally small and dependency-free: the purpose is to show the detection lifecycle clearly, not to replace a production SIEM.

## What it demonstrates

- Local log ingestion with no network transmission.
- Rule-based correlation by source IP.
- Alert enrichment: severity, rule ID, MITRE technique, evidence, time range, and remediation advice.
- SIEM-friendly JSON and JSON Lines output.
- A dashboard-ready summary and documented investigation playbooks.

## Detection rules

| ID | Detection | Severity | MITRE ATT&CK |
| --- | --- | --- | --- |
| LS-001 | Repeated failed authentication attempts | High | T1110 – Brute Force |
| LS-002 | Requests to sensitive or commonly probed paths | Medium | T1595 – Active Scanning |

## Quick start

Requires Python 3.10+ and no third-party packages.

```bash
# Analyst-oriented alert output
python log_sentinel.py sample.log --threshold 3

# Alerts ready for a dashboard or another local tool
python log_sentinel.py sample.log --threshold 3 --format json
python log_sentinel.py sample.log --threshold 3 --format jsonl

# Compact dashboard-style view
python log_sentinel.py sample.log --threshold 3 --summary

# Verify the detection rules
python -m unittest discover -s tests -v
```

## Example alert

```text
[HIGH] LS-001 brute_force | 203.0.113.10 | 3 event(s) | T1110 - Brute Force
  Evidence: POST /login -> 401; POST /login -> 401; POST /login -> 403
  Next step: Validate the source IP and consider rate-limiting or blocking it.
```

## Lab workflow

```text
Apache access log -> parser -> correlation rules -> enriched alerts -> investigation playbook
```

The included sample data uses documentation IP ranges. Do not commit production access logs or credentials. See the two investigation examples in [`docs/investigations`](docs/investigations).

## Scope and safety

This is a defensive, local-only educational lab. It does not scan targets, execute remediation, or transmit telemetry. Treat real IP addresses and logs as operationally sensitive.

## License

MIT
