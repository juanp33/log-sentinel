#!/usr/bin/env python3
"""Detect simple defensive security signals in Apache-style access logs."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+)(?: \S+)?" (?P<status>\d{3})'
)
AUTH_PATHS = ("/login", "/signin", "/admin/login")
PROBE_PATHS = ("/.env", "/wp-login.php", "/phpmyadmin", "/.git", "/cgi-bin/")


@dataclass(frozen=True)
class Alert:
    severity: str
    rule: str
    source_ip: str
    message: str


def parse_log(line: str) -> dict[str, str] | None:
    """Return the fields needed for detection, or None for an unparseable line."""
    match = LOG_PATTERN.match(line)
    return match.groupdict() if match else None


def detect(lines: list[str], threshold: int = 5) -> list[Alert]:
    """Apply transparent rules to a collection of log lines."""
    failed_auth: Counter[str] = Counter()
    alerts: list[Alert] = []

    for line in lines:
        event = parse_log(line)
        if not event:
            continue
        path, status, ip = event["path"], int(event["status"]), event["ip"]
        if path.startswith(AUTH_PATHS) and status in (401, 403):
            failed_auth[ip] += 1
        if path.startswith(PROBE_PATHS):
            alerts.append(Alert(
                "MEDIUM", "suspicious_probe", ip,
                f"Requested sensitive/probed path: {path}",
            ))

    for ip, count in failed_auth.items():
        if count >= threshold:
            alerts.append(Alert(
                "HIGH", "brute_force", ip,
                f"{count} failed authentication requests in the log window",
            ))
    return alerts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logfile", type=Path, help="Apache access-log file to analyze")
    parser.add_argument("--threshold", type=int, default=5, help="Failed logins required for an alert")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args()
    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    try:
        lines = args.logfile.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as error:
        parser.error(str(error))
    alerts = detect(lines, args.threshold)
    if args.format == "json":
        print(json.dumps([asdict(alert) for alert in alerts], indent=2))
    else:
        for alert in alerts:
            print(f"[{alert.severity}] {alert.rule} {alert.source_ip}: {alert.message}")
        print(f"\n{len(alerts)} alert(s) generated.")


if __name__ == "__main__":
    main()
