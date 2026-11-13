#!/usr/bin/env python3
"""
Unit Tests for PEER'S Network Port & Service Scanner
Sqrock IT Solutions - Cybersecurity Internship Phase 2 (Day 17)
"""

import os
import sys
import unittest
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from port_scanner import LocalPortScanner, DEFAULT_PORTS_TO_AUDIT, KNOWN_SERVICES


class TestLocalPortScanner(unittest.TestCase):
    """Test suite for port sweeping, service taxonomy, topology mapping, and exposure audits."""

    def setUp(self):
        self.scanner = LocalPortScanner()

    def test_default_ports_configuration(self):
        """Test that default ports include critical syllabus targets (22, 80, 443, 5432, 8080)."""
        for p in [22, 80, 443, 5432, 8080]:
            self.assertIn(p, DEFAULT_PORTS_TO_AUDIT)
            self.assertIn(p, KNOWN_SERVICES)

    def test_simulated_scan_detection(self):
        """Test that simulated open ports are accurately parsed and states recorded."""
        mock = {80: "nginx", 443: "nginx"}
        res = self.scanner.scan_ports(mock_open=mock)
        self.assertEqual(res["open_port_count"], 2)
        self.assertIn(80, res["open_ports"])
        self.assertIn(443, res["open_ports"])
        self.assertEqual(len(res["closed_ports"]), len(DEFAULT_PORTS_TO_AUDIT) - 2)

    def test_database_critical_exposure_rating(self):
        """Test that exposed database sockets (PostgreSQL 5432) trigger CRITICAL exposure ratings."""
        mock = {22: "OpenSSH", 5432: "PostgreSQL 15.3"}
        res = self.scanner.scan_ports(mock_open=mock)
        self.assertIn("CRITICAL", res["exposure_rating"])

    def test_hardened_host_rating(self):
        """Test that a strictly hardened host exposing only HTTPS (443) receives a LOW exposure rating."""
        mock = {443: "nginx/1.24.0"}
        res = self.scanner.scan_ports(mock_open=mock)
        self.assertEqual(res["exposure_rating"], "LOW")

    def test_network_topology_tier_mapping(self):
        """Test that services are correctly segregated into 4 enterprise architecture tiers."""
        mock = {
            22: "OpenSSH",
            80: "Apache",
            5432: "PostgreSQL",
            8080: "Express"
        }
        res = self.scanner.scan_ports(mock_open=mock)
        top = res["topology_mapping"]
        self.assertTrue(any("22" in s for s in top["Management Tier (Administrative Access)"]))
        self.assertTrue(any("80" in s for s in top["Presentation Tier (Web Frontend)"]))
        self.assertTrue(any("5432" in s for s in top["Data Persistence Tier (Databases & Caches)"]))
        self.assertTrue(any("8080" in s for s in top["Application Tier (Microservices / APIs)"]))

    def test_report_export_json_txt(self):
        """Test export of structured JSON and text network topology dossiers."""
        mock = {22: "OpenSSH", 80: "HTTP"}
        self.scanner.scan_ports(mock_open=mock)
        self.scanner.export_reports()

        json_path = os.path.join(BASE_DIR, "scan_results", "port_scan_report.json")
        txt_path = os.path.join(BASE_DIR, "scan_results", "port_scan_summary.txt")
        self.assertTrue(os.path.exists(json_path))
        self.assertTrue(os.path.exists(txt_path))

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertEqual(data["open_port_count"], 2)
            self.assertIn("topology_mapping", data)


if __name__ == "__main__":
    unittest.main()
