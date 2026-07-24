# Detection architecture

Log Sentinel models a small but realistic detection pipeline:

1. **Ingest:** read an Apache Combined Log Format file locally.
2. **Normalize:** extract source IP, timestamp, method, path, and response status.
3. **Correlate:** group failed sign-ins and sensitive-path probes by source IP.
4. **Enrich:** attach a rule identifier, severity, MITRE ATT&CK reference, evidence, and recommended analyst action.
5. **Investigate:** use the matching playbook in `docs/investigations` before taking defensive action.

The JSONL output represents the integration boundary for a dashboard, a message queue, or a larger SIEM. The project deliberately keeps that boundary local and does not include credentials, cloud services, or live scanning.
