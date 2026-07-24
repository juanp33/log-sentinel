# Detection architecture

Log Sentinel processes a log file in five steps:

1. **Ingest:** read an Apache Combined Log Format file locally.
2. **Normalize:** extract source IP, timestamp, method, path, and response status.
3. **Correlate:** group failed sign-ins and sensitive-path probes by source IP.
4. **Create alert:** add the rule ID, severity, MITRE ATT&CK reference, evidence, and a suggested action.
5. **Review:** use the related note in docs/investigations to check the alert.

JSONL can be useful if the output needs to be read by another tool later. The project does not need credentials, cloud services, or a running SIEM.
