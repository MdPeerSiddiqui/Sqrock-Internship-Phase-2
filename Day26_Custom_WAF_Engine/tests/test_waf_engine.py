#!/usr/bin/env python3
"""
Unit Test Suite for PEER'S Web Application Firewall (WAF) Engine (Day 26)
Sqrock IT Solutions Cybersecurity Internship Phase 2: Web App Security
"""

import unittest
import os
import sys

# Ensure parent directory is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from waf_engine import WAFEngine


class TestWAFEngine(unittest.TestCase):
    def setUp(self):
        self.waf = WAFEngine()

    def test_clean_request_allowed(self):
        """Test 1: Legitimate HTTP request passes through with 200 OK and ALLOW action."""
        req = {
            "id": "TEST-CLEAN-01",
            "method": "GET",
            "path": "/api/v1/catalog/items",
            "query": "category=electronics&page=2&limit=50",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            "body": "",
            "client_ip": "10.0.0.15"
        }
        res = self.waf.inspect_request(req)
        self.assertEqual(res["status_code"], 200)
        self.assertEqual(res["action"], "ALLOW")
        self.assertEqual(res["risk_score"], 0.0)
        self.assertEqual(len(res["violations"]), 0)

    def test_sqli_union_select_blocked(self):
        """Test 2: SQL Injection UNION SELECT attack in query parameter is intercepted with 403."""
        req = {
            "id": "TEST-SQLI-01",
            "method": "GET",
            "path": "/products",
            "query": "id=1' UNION SELECT user, password FROM credentials--",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
            "client_ip": "198.51.100.22"
        }
        res = self.waf.inspect_request(req)
        self.assertEqual(res["status_code"], 403)
        self.assertEqual(res["action"], "BLOCK")
        self.assertEqual(res["primary_category"], "SQL Injection (SQLi)")
        self.assertGreaterEqual(res["risk_score"], 9.0)

    def test_xss_script_tag_blocked(self):
        """Test 3: Stored/Reflected XSS script payload in request body is dropped with 403."""
        req = {
            "id": "TEST-XSS-01",
            "method": "POST",
            "path": "/comments/post",
            "query": "",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": "text=<script>alert(document.cookie)</script>",
            "client_ip": "203.0.113.50"
        }
        res = self.waf.inspect_request(req)
        self.assertEqual(res["status_code"], 403)
        self.assertEqual(res["action"], "BLOCK")
        self.assertEqual(res["primary_category"], "Cross-Site Scripting (XSS)")

    def test_path_traversal_blocked(self):
        """Test 4: Directory traversal attempt to access /etc/passwd is blocked."""
        req = {
            "id": "TEST-TRAV-01",
            "method": "GET",
            "path": "/files/download",
            "query": "filename=../../../../etc/passwd",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
            "client_ip": "185.220.101.9"
        }
        res = self.waf.inspect_request(req)
        self.assertEqual(res["status_code"], 403)
        self.assertEqual(res["action"], "BLOCK")
        self.assertEqual(res["primary_category"], "Path Traversal / LFI")

    def test_os_command_injection_blocked(self):
        """Test 5: OS command injection via shell metacharacters is blocked."""
        req = {
            "id": "TEST-CMDI-01",
            "method": "POST",
            "path": "/api/diagnostics/ping",
            "query": "",
            "headers": {"Content-Type": "application/json"},
            "body": "{\"ip\": \"127.0.0.1; whoami\"}",
            "client_ip": "45.154.255.88"
        }
        res = self.waf.inspect_request(req)
        self.assertEqual(res["status_code"], 403)
        self.assertEqual(res["action"], "BLOCK")
        self.assertEqual(res["primary_category"], "OS Command Injection")
        self.assertGreaterEqual(res["risk_score"], 9.5)

    def test_malicious_scanner_user_agent_blocked(self):
        """Test 6: Automated vulnerability scanner user agent (sqlmap) is identified and blocked."""
        req = {
            "id": "TEST-SCAN-01",
            "method": "GET",
            "path": "/",
            "query": "",
            "headers": {"User-Agent": "sqlmap/1.6.12#stable"},
            "body": "",
            "client_ip": "91.240.118.4"
        }
        res = self.waf.inspect_request(req)
        self.assertEqual(res["status_code"], 403)
        self.assertEqual(res["action"], "BLOCK")
        self.assertEqual(res["primary_category"], "Malicious Scanner / Tool")


if __name__ == "__main__":
    unittest.main()
