import unittest

from log_sentinel import detect, parse_log


class LogSentinelTests(unittest.TestCase):
    def test_parse_valid_log_entry(self):
        event = parse_log('192.0.2.1 - - [12/Jul/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1')
        self.assertEqual(event["ip"], "192.0.2.1")
        self.assertEqual(event["status"], "200")

    def test_detects_brute_force_and_probe(self):
        lines = [
            '203.0.113.1 - - [x] "POST /login HTTP/1.1" 401 1',
            '203.0.113.1 - - [x] "POST /login HTTP/1.1" 403 1',
            '198.51.100.1 - - [x] "GET /.env HTTP/1.1" 404 1',
        ]
        rules = {alert.rule for alert in detect(lines, threshold=2)}
        self.assertEqual(rules, {"brute_force", "suspicious_probe"})


if __name__ == "__main__":
    unittest.main()
