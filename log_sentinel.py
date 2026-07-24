#!/usr/bin/env python3
"""A local, transparent SIEM-style lab for Apache access logs."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+)(?: \S+)?" (?P<status>\d{3})'
)
AUTH_PATHS = ("/login", "/signin", "/admin/login")
PROBE_PATHS = ("/.env", "/.git", "/wp-login.php", "/phpmyadmin", "/cgi-bin/")
RULES = {
    "LS-001": {
        "name": "brute_force",
        "severity": "HIGH",
        "mitre": "T1110 - Brute Force",
        "action": "Validate the source IP and consider rate-limiting or blocking it.",
    },
    "LS-002": {
        "name": "suspicious_probe",
        "severity": "MEDIUM",
        "mitre": "T1595 - Active Scanning",
        "action": "Review the request path, related activity, and web-server exposure.",
    },
}


@dataclass(frozen=True)
class Event:
    source_ip: str
    timestamp: str
    method: str
    path: str
    status: int


@dataclass(frozen=True)
class Alert:
    alert_id: str
    severity: str
    rule_id: str
    rule: str
    mitre_technique: str
    source_ip: str
    first_seen: str
    last_seen: str
    event_count: int
    evidence: list[str]
    recommended_action: str


def parse_log(line: str) -> Event | None:
    """Parse one Apache Combined Log Format line, returning None when invalid."""
    match = LOG_PATTERN.match(line)
    if not match:
        return None
    fields = match.groupdict()
    return Event(
        source_ip=fields["ip"],
        timestamp=fields["timestamp"],
        method=fields["method"],
        path=fields["path"],
        status=int(fields["status"]),
    )


def _alert(rule_id: str, source_ip: str, events: list[Event], evidence: list[str]) -> Alert:
    rule = RULES[rule_id]
    return Alert(
        alert_id=f"{rule_id}:{source_ip}:{events[0].timestamp}",
        severity=rule["severity"],
        rule_id=rule_id,
        rule=rule["name"],
        mitre_technique=rule["mitre"],
        source_ip=source_ip,
        first_seen=events[0].timestamp,
        last_seen=events[-1].timestamp,
        event_count=len(events),
        evidence=evidence,
        recommended_action=rule["action"],
    )


def detect(lines: list[str], threshold: int = 5) -> list[Alert]:
    """Correlate local web events into explainable, SIEM-style alerts."""
    failed_auth: dict[str, list[Event]] = defaultdict(list)
    probes: dict[str, list[Event]] = defaultdict(list)

    for line in lines:
        event = parse_log(line)
        if event is None:
            continue
        if event.path.startswith(AUTH_PATHS) and event.status in (401, 403):
            failed_auth[event.source_ip].append(event)
        if event.path.startswith(PROBE_PATHS):
            probes[event.source_ip].append(event)

    alerts: list[Alert] = []
    for ip, events in failed_auth.items():
        if len(events) >= threshold:
            evidence = [f"{event.method} {event.path} -> {event.status}" for event in events]
            alerts.append(_alert("LS-001", ip, events, evidence))
    for ip, events in probes.items():
        evidence = sorted({f"{event.method} {event.path} -> {event.status}" for event in events})
        alerts.append(_alert("LS-002", ip, events, evidence))
    return sorted(alerts, key=lambda alert: (alert.first_seen, alert.rule_id, alert.source_ip))


def summarize(alerts: list[Alert]) -> dict[str, object]:
    """Produce a dashboard-friendly alert summary without exposing raw logs."""
    by_severity = Counter(alert.severity for alert in alerts)
    by_rule = Counter(alert.rule for alert in alerts)
    sources = sorted({alert.source_ip for alert in alerts})
    return {
        "alerts_total": len(alerts),
        "alerts_by_severity": dict(sorted(by_severity.items())),
        "alerts_by_rule": dict(sorted(by_rule.items())),
        "unique_source_ips": len(sources),
        "source_ips": sources,
    }


def _print_text(alerts: list[Alert]) -> None:
    for alert in alerts:
        print(
            f"[{alert.severity}] {alert.rule_id} {alert.rule} | {alert.source_ip} | "
            f"{alert.event_count} event(s) | {alert.mitre_technique}"
        )
        print(f"  Evidence: {'; '.join(alert.evidence)}")
        print(f"  Next step: {alert.recommended_action}")
    print(f"\n{len(alerts)} alert(s) generated.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logfile", type=Path, help="Apache access-log file to analyze")
    parser.add_argument("--threshold", type=int, default=5, help="Failed logins required for LS-001")
    parser.add_argument("--format", choices=("text", "json", "jsonl"), default="text")
    parser.add_argument("--summary", action="store_true", help="Print only the SIEM dashboard summary")
    args = parser.parse_args()
    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    try:
        lines = args.logfile.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as error:
        parser.error(str(error))

    alerts = detect(lines, args.threshold)
    if args.summary:
        print(json.dumps(summarize(alerts), indent=2))
    elif args.format == "json":
        print(json.dumps([asdict(alert) for alert in alerts], indent=2))
    elif args.format == "jsonl":
        for alert in alerts:
            print(json.dumps(asdict(alert)))
    else:
        _print_text(alerts)


if __name__ == "__main__":
    main()
