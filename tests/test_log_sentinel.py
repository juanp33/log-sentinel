import unittest

from log_sentinel import detect, parse_log, summarize


class LogSentinelTests(unittest.TestCase):
    def test_parse_valid_log_entry(self):
        event = parse_log('192.0.2.1 - - [12/Jul/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1')
        self.assertEqual(event.source_ip, "192.0.2.1")
        self.assertEqual(event.status, 200)

    def test_ignores_invalid_entry(self):
        self.assertIsNone(parse_log("not an Apache access log"))

    def test_correlates_brute_force_with_evidence(self):
        lines = [
            '203.0.113.1 - - [x] "POST /login HTTP/1.1" 401 1',
            '203.0.113.1 - - [x] "POST /login HTTP/1.1" 403 1',
        ]
        alert = detect(lines, threshold=2)[0]
        self.assertEqual(alert.rule_id, "LS-001")
        self.assertEqual(alert.event_count, 2)
        self.assertIn("T1110", alert.mitre_technique)

    def test_groups_multiple_probes_from_one_source(self):
        lines = [
            '198.51.100.1 - - [x] "GET /.env HTTP/1.1" 404 1',
            '198.51.100.1 - - [y] "GET /.git/config HTTP/1.1" 404 1',
        ]
        alert = detect(lines)[0]
        self.assertEqual(alert.rule_id, "LS-002")
        self.assertEqual(alert.event_count, 2)
        self.assertEqual(len(alert.evidence), 2)

    def test_returns_alerts_in_stable_time_order(self):
        lines = [
            '198.51.100.1 - - [a] "GET /.env HTTP/1.1" 404 1',
            '203.0.113.1 - - [b] "POST /login HTTP/1.1" 401 1',
        ]
        self.assertEqual([alert.rule_id for alert in detect(lines, threshold=1)], ["LS-002", "LS-001"])

    def test_builds_dashboard_summary(self):
        lines = [
            '203.0.113.1 - - [x] "POST /login HTTP/1.1" 401 1',
            '198.51.100.1 - - [y] "GET /.env HTTP/1.1" 404 1',
        ]
        summary = summarize(detect(lines, threshold=1))
        self.assertEqual(summary["alerts_total"], 2)
        self.assertEqual(summary["alerts_by_severity"], {"HIGH": 1, "MEDIUM": 1})


if __name__ == "__main__":
    unittest.main()
