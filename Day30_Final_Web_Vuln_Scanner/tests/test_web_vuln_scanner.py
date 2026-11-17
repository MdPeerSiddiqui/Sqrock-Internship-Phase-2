#!/usr/bin/env python3
"""
Unit Test Suite for PEER'S Capstone Automated Web Vulnerability Scanner (Day 30)
Sqrock IT Solutions Cybersecurity Internship Phase 2: Web App Security
"""

import unittest
import os
import sys
import json

# Ensure parent directory is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web_vuln_scanner import WebVulnerabilityScanner


class TestWebVulnerabilityScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = WebVulnerabilityScanner()
        self.vuln_target = self.scanner.targets[0]
        self.hardened_target = self.scanner.targets[1]

    def test_recon_banner_disclosure(self):
        """Test 1: Recon module flags server technology and version disclosure banners."""
        res = self.scanner.audit_target(self.vuln_target)
        recon_vuln = next((f for f in res["findings"] if f["id"] == "VULN-RECON-01"), None)
        self.assertIsNotNone(recon_vuln)
        self.assertEqual(recon_vuln["severity"], "LOW")
        self.assertIn("Apache", recon_vuln["target"])

    def test_security_header_auditing(self):
        """Test 2: Security header module flags missing critical headers (CSP, HSTS, X-Frame-Options)."""
        res = self.scanner.audit_target(self.vuln_target)
        hdr_vuln = next((f for f in res["findings"] if f["id"] == "VULN-HDR-02"), None)
        self.assertIsNotNone(hdr_vuln)
        self.assertEqual(hdr_vuln["severity"], "MEDIUM")
        self.assertGreaterEqual(hdr_vuln["cvss_score"], 5.0)

    def test_port_exposure_auditing(self):
        """Test 3: Port exposure module flags exposed non-standard ports (e.g. 8080)."""
        res = self.scanner.audit_target(self.vuln_target)
        net_vuln = next((f for f in res["findings"] if f["id"] == "VULN-NET-03"), None)
        self.assertIsNotNone(net_vuln)
        self.assertIn("8080", net_vuln["target"])

    def test_sensitive_directory_fuzzing(self):
        """Test 4: Directory fuzzer flags critical exposure of .env and backup.sql dumps."""
        res = self.scanner.audit_target(self.vuln_target)
        dir_vuln = next((f for f in res["findings"] if f["id"] == "VULN-DIR-04"), None)
        self.assertIsNotNone(dir_vuln)
        self.assertEqual(dir_vuln["severity"], "CRITICAL")
        self.assertGreaterEqual(dir_vuln["cvss_score"], 9.0)

    def test_application_injection_detection(self):
        """Test 5: Injection module flags both SQLi and XSS vulnerabilities on vulnerable targets."""
        res = self.scanner.audit_target(self.vuln_target)
        sqli_vuln = next((f for f in res["findings"] if f["id"] == "VULN-INJ-05"), None)
        xss_vuln = next((f for f in res["findings"] if f["id"] == "VULN-XSS-06"), None)
        self.assertIsNotNone(sqli_vuln)
        self.assertIsNotNone(xss_vuln)
        self.assertEqual(sqli_vuln["severity"], "CRITICAL")
        self.assertEqual(xss_vuln["severity"], "HIGH")

    def test_composite_security_scoring_and_report_export(self):
        """Test 6: Scoring engine calculates differentiated security scores and exports JSON telemetry."""
        vuln_res = self.scanner.audit_target(self.vuln_target)
        hardened_res = self.scanner.audit_target(self.hardened_target)

        # Vulnerable target should suffer heavy deductions (score < 50)
        self.assertLess(vuln_res["security_score"], 50)
        self.assertEqual(vuln_res["security_posture"], "CRITICAL EXPOSURE")

        # Hardened target should have 100 score and 0 findings
        self.assertEqual(hardened_res["security_score"], 100)
        self.assertEqual(hardened_res["security_posture"], "SECURE / HARDENED")
        self.assertEqual(hardened_res["total_findings"], 0)

        # Export test
        j_path, t_path = self.scanner.save_reports()
        self.assertTrue(os.path.exists(j_path))
        self.assertTrue(os.path.exists(t_path))

        with open(j_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["metadata"]["candidate"], "Mohammed Peer Siddiqui")
        self.assertGreaterEqual(data["targets_scanned"], 2)


if __name__ == "__main__":
    unittest.main()
