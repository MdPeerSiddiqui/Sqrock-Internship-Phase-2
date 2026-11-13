#!/usr/bin/env python3
"""
Unit Tests for PEER'S HTTP Security Header Analyzer
Sqrock IT Solutions - Cybersecurity Internship Phase 2 (Day 16)
"""

import os
import sys
import unittest
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from header_analyzer import HTTPSecurityHeaderAnalyzer


class TestHTTPSecurityHeaderAnalyzer(unittest.TestCase):
    """Test suite for HTTP security header evaluation, CSP parsing, and reporting."""

    def setUp(self):
        self.analyzer = HTTPSecurityHeaderAnalyzer()

    def test_hardened_headers_grade_a(self):
        """Test that a fully hardened production header configuration achieves Grade A+."""
        hardened = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none';",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }
        self.analyzer.fetch_headers(mock_headers=hardened)
        res = self.analyzer.analyze_headers()
        self.assertEqual(res["grade"], "A+")
        self.assertGreaterEqual(res["posture_score"], 95)
        self.assertEqual(res["configured_count"], 6)
        self.assertEqual(res["missing_count"], 0)

    def test_vulnerable_empty_headers_grade_f(self):
        """Test that a legacy server with zero security headers receives Grade F."""
        vuln = {
            "Server": "Apache/2.4.41 (Ubuntu)",
            "Content-Type": "text/html; charset=UTF-8",
            "X-Powered-By": "PHP/7.4.3"
        }
        self.analyzer.fetch_headers(mock_headers=vuln)
        res = self.analyzer.analyze_headers()
        self.assertEqual(res["grade"], "F")
        self.assertEqual(res["posture_score"], 0)
        self.assertEqual(res["configured_count"], 0)
        self.assertEqual(res["missing_count"], 6)

    def test_csp_unsafe_inline_warning(self):
        """Test that Content-Security-Policy with unsafe-inline triggers warnings and point deductions."""
        headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline';",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff"
        }
        self.analyzer.fetch_headers(mock_headers=headers)
        res = self.analyzer.analyze_headers()
        csp_finding = next(f for f in res["findings"] if f["header"] == "Content-Security-Policy")
        self.assertTrue(any("unsafe-inline" in w for w in csp_finding["warnings"]))
        self.assertLess(csp_finding["weight_awarded"], csp_finding["max_weight"])

    def test_hsts_subdomain_and_maxage_checks(self):
        """Test detection of sub-optimal HSTS max-age and missing includeSubDomains flag."""
        headers = {
            "Strict-Transport-Security": "max-age=86400"  # Only 1 day, no subdomains
        }
        self.analyzer.fetch_headers(mock_headers=headers)
        res = self.analyzer.analyze_headers()
        hsts_finding = next(f for f in res["findings"] if f["header"] == "Strict-Transport-Security")
        self.assertTrue(any("includeSubDomains" in w for w in hsts_finding["warnings"]))
        self.assertTrue(any("below recommended" in w for w in hsts_finding["warnings"]))

    def test_information_disclosure_detection(self):
        """Test identification of information leaking headers like Server and X-Powered-By."""
        headers = {
            "Server": "nginx/1.24.0",
            "X-Powered-By": "Express",
            "X-Runtime": "0.0421"
        }
        self.analyzer.fetch_headers(mock_headers=headers)
        res = self.analyzer.analyze_headers()
        leaks = res["information_disclosure_headers"]
        self.assertIn("Server", leaks)
        self.assertIn("X-Powered-By", leaks)
        self.assertEqual(leaks["Server"], "nginx/1.24.0")

    def test_report_export(self):
        """Test export of structured JSON and text audit dossiers to disk."""
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff"
        }
        self.analyzer.fetch_headers(mock_headers=headers)
        self.analyzer.analyze_headers()
        self.analyzer.export_reports()

        json_path = os.path.join(BASE_DIR, "audit_results", "header_audit_report.json")
        txt_path = os.path.join(BASE_DIR, "audit_results", "header_audit_summary.txt")
        self.assertTrue(os.path.exists(json_path))
        self.assertTrue(os.path.exists(txt_path))

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertIn("posture_score", data)
            self.assertIn("findings", data)


if __name__ == "__main__":
    unittest.main()
