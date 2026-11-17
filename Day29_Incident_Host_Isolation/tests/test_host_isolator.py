#!/usr/bin/env python3
"""
Unit Test Suite for PEER'S Incident Containment & Host Isolator (Day 29)
Sqrock IT Solutions Cybersecurity Internship Phase 2: Web App Security
"""

import unittest
import os
import sys
import json

# Ensure parent directory is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from host_isolator import HostIsolator


class TestHostIsolator(unittest.TestCase):
    def setUp(self):
        self.isolator = HostIsolator()

    def test_context_ingestion(self):
        """Test 1: Verifies host metadata and incident context load correctly from JSON."""
        host = self.isolator.host_data.get("host_metadata", {})
        incident = self.isolator.host_data.get("incident_context", {})
        self.assertEqual(host.get("hostname"), "srv-prod-db01.sqrock.internal")
        self.assertEqual(host.get("primary_ip"), "10.0.4.15")
        self.assertEqual(incident.get("incident_id"), "INC-2026-9042")

    def test_firewall_rule_generation(self):
        """Test 2: Verifies emergency iptables script contains default DROP policies and loopback rule."""
        ipt_path, _ = self.isolator.generate_firewall_rules()
        self.assertTrue(os.path.exists(ipt_path))
        with open(ipt_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("iptables -P INPUT DROP", content)
        self.assertIn("iptables -P OUTPUT DROP", content)
        self.assertIn("iptables -A INPUT -i lo -j ACCEPT", content)

    def test_bastion_tunnel_pinholing(self):
        """Test 3: Verifies SOC bastion jumpbox (10.0.100.50) is specifically whitelisted on ports 22 and 443."""
        ipt_path, _ = self.isolator.generate_firewall_rules()
        with open(ipt_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("10.0.100.50", content)
        self.assertIn("--dport 22", content)
        self.assertIn("--dport 443", content)

    def test_rogue_session_termination(self):
        """Test 4: Verifies unauthorized sessions and processes are targeted for termination while bastion is protected."""
        terminated = self.isolator.terminate_unauthorized_sessions()
        self.assertEqual(len(terminated), 3)  # 1 rogue session + 2 rogue processes
        pids = [t["pid"] for t in terminated]
        self.assertIn(9411, pids)
        self.assertIn(9412, pids)
        self.assertIn(9415, pids)
        # Bastion session (PID 4812) must NOT be terminated
        self.assertNotIn(4812, pids)

    def test_forensic_evidence_preservation(self):
        """Test 5: Verifies evidence bundle generation and 64-char SHA-256 cryptographic hash."""
        terminated = self.isolator.terminate_unauthorized_sessions()
        ev_path, ev_hash = self.isolator.preserve_forensic_evidence(terminated)
        self.assertTrue(os.path.exists(ev_path))
        self.assertEqual(len(ev_hash), 64)

        with open(ev_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        self.assertEqual(bundle["evidence_integrity_sha256"], ev_hash)
        self.assertEqual(bundle["metadata"]["candidate"], "Mohammed Peer Siddiqui")

    def test_containment_rollback_generation(self):
        """Test 6: Verifies rollback script is generated with default ACCEPT policies."""
        _, roll_path = self.isolator.generate_firewall_rules()
        self.assertTrue(os.path.exists(roll_path))
        with open(roll_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("iptables -P INPUT ACCEPT", content)
        self.assertIn("iptables -P OUTPUT ACCEPT", content)


if __name__ == "__main__":
    unittest.main()
