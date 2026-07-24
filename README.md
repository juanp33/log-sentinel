# Log Sentinel

`log-sentinel` is a compact detection-engineering project that parses Apache-style access logs and flags two useful security signals:

- Repeated failed authentication attempts from the same IP address.
- Requests to paths commonly probed by opportunistic scanners.

It is deliberately transparent: detections are rules in plain Python and results can be exported as JSON for a SIEM or dashboard prototype.

## Quick start

Requires Python 3.10+ and no third-party dependencies.

```bash
python log_sentinel.py sample.log --threshold 3
python log_sentinel.py sample.log --format json > alerts.json
python -m unittest discover -s tests -v
```

## Example alert

```text
[HIGH] brute_force 203.0.113.10: 3 failed authentication requests in the log window
[MEDIUM] suspicious_probe 198.51.100.7: Requested sensitive/probed path: /.env
```

## Notes

The parser supports the Apache Combined Log Format. Treat IP addresses and logs as sensitive operational data; this tool processes files locally and never sends them anywhere.

## License

MIT
