#!/usr/bin/env python3
"""
Unit Tests for PEER'S SQL Injection Log Detection Engine
Sqrock IT Solutions - Cybersecurity Internship Phase 2 (Day 18)
"""

import os
import sys
import unittest
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from sqli_detector import SQLiLogDetector


class TestSQLiDetector(unittest.TestCase):
    """Test suite for web access log parsing, SQLi signature matching, and triage export."""

    def setUp(self):
        self.detector = SQLiLogDetector()

    def test_log_ingestion_and_parsing(self):
        """Test parsing of Common/Combined Log Format entries into structured objects."""
        mock = [
            '192.168.1.45 - - [17/Nov/2026:08:14:02 +0000] "GET /profile?id=5 HTTP/1.1" 200 4120 "https://sqrock.local" "Mozilla/5.0"'
        ]
        count = self.detector.load_and_parse_logs(mock_logs=mock)
        self.assertEqual(count, 1)
        entry = self.detector.parsed_entries[0]
        self.assertEqual(entry["ip"], "192.168.1.45")
        self.assertEqual(entry["method"], "GET")
        self.assertEqual(entry["status_code"], 200)

    def test_boolean_based_sqli_detection(self):
        """Test detection of classic boolean tautology injections (' OR '1'='1)."""
        mock = [
            '10.0.4.12 - - [17/Nov/2026:08:15:30 +0000] "POST /auth/login?user=admin\'%20OR%20\'1\'=\'1 HTTP/1.1" 401 512 "-" "curl/7.88"'
        ]
        self.detector.load_and_parse_logs(mock_logs=mock)
        alerts = self.detector.scan_for_sqli()
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["primary_attack_type"], "BOOLEAN_BASED")
        self.assertEqual(alerts[0]["source_ip"], "10.0.4.12")

    def test_union_select_sqli_detection(self):
        """Test detection of in-band UNION SELECT data harvesting attempts."""
        mock = [
            '172.16.5.9 - - [17/Nov/2026:08:18:22 +0000] "GET /search?q=UNION%20SELECT%20null,password%20FROM%20users-- HTTP/1.1" 500 1204 "-" "sqlmap"'
        ]
        self.detector.load_and_parse_logs(mock_logs=mock)
        alerts = self.detector.scan_for_sqli()
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["primary_attack_type"], "UNION_BASED")
        self.assertEqual(alerts[0]["severity"], "CRITICAL")

    def test_time_based_blind_detection(self):
        """Test detection of time-based blind injection probes (pg_sleep, WAITFOR DELAY)."""
        mock = [
            '198.51.100.88 - - [17/Nov/2026:08:23:12 +0000] "GET /catalog?cat=1%20AND%20pg_sleep(5)-- HTTP/1.1" 200 15200 "-" "Mozilla/5.0"'
        ]
        self.detector.load_and_parse_logs(mock_logs=mock)
        alerts = self.detector.scan_for_sqli()
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["primary_attack_type"], "TIME_BASED_BLIND")
        self.assertEqual(alerts[0]["severity"], "CRITICAL")

    def test_stacked_query_detection(self):
        """Test detection of destructive stacked SQL queries (; DROP TABLE)."""
        mock = [
            '203.0.113.72 - - [17/Nov/2026:08:40:15 +0000] "GET /api/v1/orders?order_id=1092\';%20DROP%20TABLE%20audit_logs;-- HTTP/1.1" 403 240 "-" "Python"'
        ]
        self.detector.load_and_parse_logs(mock_logs=mock)
        alerts = self.detector.scan_for_sqli()
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["primary_attack_type"], "STACKED_QUERIES")
        self.assertEqual(alerts[0]["severity"], "CRITICAL")

    def test_report_export_and_prepared_statements(self):
        """Test export of structured JSON/TXT dossiers and Prepared Statement comparison."""
        self.detector.load_and_parse_logs()
        self.detector.scan_for_sqli()
        dossier = self.detector.export_reports()

        self.assertGreaterEqual(dossier["metadata"]["total_attacks_detected"], 5)
        self.assertIn("CRITICAL", dossier["severity_breakdown"])

        comp = self.detector.get_prepared_statement_comparison()
        self.assertIn("secure_pattern", comp)
        self.assertIn("vulnerable_pattern", comp)

        json_path = os.path.join(BASE_DIR, "alerts", "sqli_alerts.json")
        txt_path = os.path.join(BASE_DIR, "alerts", "sqli_triage_summary.txt")
        self.assertTrue(os.path.exists(json_path))
        self.assertTrue(os.path.exists(txt_path))


if __name__ == "__main__":
    unittest.main()
