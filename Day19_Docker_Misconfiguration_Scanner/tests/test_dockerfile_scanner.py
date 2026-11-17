"""
Unit Tests for PEER'S Docker Container Misconfiguration Scanner v2.0
Validates CIS Docker Benchmark & NIST SP 800-190 static analysis rules.
"""

import os
import sys
import json
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from dockerfile_scanner import DockerSecurityScanner

class TestDockerfileScanner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        cls.vulnerable_dockerfile = os.path.join(cls.base_dir, 'samples', 'Dockerfile.vulnerable')
        cls.hardened_dockerfile = os.path.join(cls.base_dir, 'samples', 'Dockerfile.hardened')
        cls.test_output_json = os.path.join(cls.base_dir, 'audits', 'test_audit_report.json')
        cls.test_output_txt = os.path.join(cls.base_dir, 'audits', 'test_audit_summary.txt')

    def test_root_user_detection(self):
        """Test CIS 4.1: Flagging execution as root user."""
        scanner = DockerSecurityScanner(self.vulnerable_dockerfile)
        findings = scanner.audit()
        root_findings = [f for f in findings if f["rule_id"] == "DOCKER_USER_ROOT"]
        self.assertGreaterEqual(len(root_findings), 1)
        self.assertEqual(root_findings[0]["severity"], "CRITICAL")
        self.assertEqual(root_findings[0]["cis_id"], "CIS 4.1")

    def test_unpinned_base_image_detection(self):
        """Test CIS 4.2: Flagging :latest or untagged base image."""
        scanner = DockerSecurityScanner(self.vulnerable_dockerfile)
        findings = scanner.audit()
        tag_findings = [f for f in findings if f["rule_id"] == "DOCKER_TAG_LATEST"]
        self.assertGreaterEqual(len(tag_findings), 1)
        self.assertEqual(tag_findings[0]["severity"], "HIGH")
        self.assertIn("ubuntu:latest", tag_findings[0]["context"]["detected_image"])

    def test_dangerous_ssh_port_exposure(self):
        """Test CIS 4.3: Flagging dangerous SSH port 22 exposure."""
        scanner = DockerSecurityScanner(self.vulnerable_dockerfile)
        findings = scanner.audit()
        ssh_findings = [f for f in findings if f["rule_id"] == "DOCKER_EXPOSE_SSH"]
        self.assertGreaterEqual(len(ssh_findings), 1)
        self.assertEqual(ssh_findings[0]["severity"], "CRITICAL")
        self.assertIn("22", ssh_findings[0]["context"]["exposed_ports"])

    def test_hardcoded_secret_detection(self):
        """Test CIS 4.4: Flagging hardcoded secrets in ENV/ARG instructions."""
        scanner = DockerSecurityScanner(self.vulnerable_dockerfile)
        findings = scanner.audit()
        secret_findings = [f for f in findings if f["rule_id"] == "DOCKER_HARDCODED_SECRET"]
        self.assertGreaterEqual(len(secret_findings), 2)
        secret_texts = [f["raw_instruction"] for f in secret_findings]
        self.assertTrue(any("DB_PASSWORD" in t for t in secret_texts))
        self.assertTrue(any("AWS_SECRET_ACCESS_KEY" in t for t in secret_texts))

    def test_hardened_dockerfile_compliance(self):
        """Test CIS compliance: Hardened multi-stage Dockerfile produces 0 critical/high misconfigurations."""
        scanner = DockerSecurityScanner(self.hardened_dockerfile)
        findings = scanner.audit()
        critical_or_high = [f for f in findings if f["severity"] in ["CRITICAL", "HIGH"]]
        self.assertEqual(len(critical_or_high), 0)
        self.assertEqual(scanner.summary_stats["CRITICAL"], 0)
        self.assertEqual(scanner.summary_stats["HIGH"], 0)

    def test_json_and_txt_report_export(self):
        """Test structured JSON and formatted text export generation."""
        scanner = DockerSecurityScanner(self.vulnerable_dockerfile)
        scanner.audit()
        json_path = scanner.save_json(self.test_output_json)
        txt_path = scanner.save_summary_text(self.test_output_txt)

        self.assertTrue(os.path.exists(json_path))
        self.assertTrue(os.path.exists(txt_path))

        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.assertIn("metadata", data)
        self.assertIn("findings", data)
        self.assertIn("summary_stats", data)
        self.assertEqual(data["findings_count"], len(scanner.findings))

        # Cleanup test files
        if os.path.exists(self.test_output_json):
            os.remove(self.test_output_json)
        if os.path.exists(self.test_output_txt):
            os.remove(self.test_output_txt)

if __name__ == '__main__':
    unittest.main()
