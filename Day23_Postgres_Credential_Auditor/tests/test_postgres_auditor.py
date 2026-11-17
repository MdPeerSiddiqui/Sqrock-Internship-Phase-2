"""
Unit Tests for PEER'S PostgreSQL Database Credential & Configuration Auditor v2.0
Validates pg_hba.conf authentication analysis, default credentials, entropy calculations, and report generation.
"""

import os
import sys
import json
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from postgres_auditor import PostgresSecurityAuditor

class TestPostgresAuditor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        cls.insecure_hba = os.path.join(cls.base_dir, 'samples', 'pg_hba.conf.insecure')
        cls.hardened_hba = os.path.join(cls.base_dir, 'samples', 'pg_hba.conf.hardened')
        cls.dict_file = os.path.join(cls.base_dir, 'samples', 'credentials_dictionary.txt')
        cls.test_json = os.path.join(cls.base_dir, 'audit_results', 'test_audit_report.json')
        cls.test_txt = os.path.join(cls.base_dir, 'audit_results', 'test_audit_summary.txt')

    def test_insecure_trust_method_detection(self):
        """Test detection of insecure 'trust' authentication method (CRITICAL)."""
        auditor = PostgresSecurityAuditor(pghba_path=self.insecure_hba)
        findings = auditor.audit_pghba()
        trust_findings = [f for f in findings if f["method"] == "trust"]
        self.assertGreaterEqual(len(trust_findings), 2)
        for f in trust_findings:
            self.assertEqual(f["severity"], "CRITICAL")

    def test_insecure_global_cidr_detection(self):
        """Test detection of 0.0.0.0/0 or ::/0 global network exposure."""
        auditor = PostgresSecurityAuditor(pghba_path=self.insecure_hba)
        findings = auditor.audit_pghba()
        global_rules = [f for f in findings if f["address"] in ["0.0.0.0/0", "::/0"]]
        self.assertGreaterEqual(len(global_rules), 2)
        for r in global_rules:
            self.assertIn("global IP address space", r["description"])

    def test_hardened_pghba_compliance(self):
        """Test that hardened pg_hba.conf produces zero CRITICAL or HIGH violations."""
        auditor = PostgresSecurityAuditor(pghba_path=self.hardened_hba)
        findings = auditor.audit_pghba()
        violations = [f for f in findings if f["severity"] in ["CRITICAL", "HIGH"]]
        self.assertEqual(len(violations), 0)
        self.assertEqual(auditor.metrics["critical_hba_violations"], 0)

    def test_default_credential_detection(self):
        """Test detection of known default and trivial database credentials."""
        auditor = PostgresSecurityAuditor(dict_path=self.dict_file)
        findings = auditor.audit_credentials()
        default_pairs = [f for f in findings if f["is_default"]]
        self.assertGreaterEqual(len(default_pairs), 4)
        for p in default_pairs:
            self.assertEqual(p["severity"], "CRITICAL")

    def test_entropy_calculation_accuracy(self):
        """Test password Shannon entropy calculation for weak vs complex strings."""
        auditor = PostgresSecurityAuditor()
        weak_entropy = auditor.calculate_entropy("password")
        strong_entropy = auditor.calculate_entropy("Str0ng!P@ssw0rd#2026_Enterprise")
        self.assertLess(weak_entropy, 40.0)
        self.assertGreater(strong_entropy, 100.0)

    def test_json_and_txt_reporting(self):
        """Test serialization and generation of structured JSON and TXT reports."""
        auditor = PostgresSecurityAuditor(pghba_path=self.insecure_hba, dict_path=self.dict_file)
        auditor.audit_pghba()
        auditor.audit_credentials()
        j_path = auditor.save_json(self.test_json)
        t_path = auditor.save_summary_text(self.test_txt)

        self.assertTrue(os.path.exists(j_path))
        self.assertTrue(os.path.exists(t_path))

        with open(j_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.assertIn("metadata", data)
        self.assertIn("metrics", data)
        self.assertIn("hba_findings", data)

        # Cleanup test files
        if os.path.exists(self.test_json): os.remove(self.test_json)
        if os.path.exists(self.test_txt): os.remove(self.test_txt)

if __name__ == '__main__':
    unittest.main()
