"""
Unit Tests for PEER'S Web Directory Brute-Force & Content Discovery Engine v2.0
Validates differential HTTP status code analysis, wordlist parsing, and report output.
"""

import os
import sys
import json
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from dir_fuzzer import WebDirectoryFuzzer

class TestDirectoryFuzzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        cls.wordlist_file = os.path.join(cls.base_dir, 'wordlists', 'common_dirs.txt')
        cls.test_json = os.path.join(cls.base_dir, 'fuzz_results', 'test_fuzz_report.json')
        cls.test_txt = os.path.join(cls.base_dir, 'fuzz_results', 'test_fuzz_summary.txt')

    def test_wordlist_loading(self):
        """Test wordlist loading and sanitization of leading slashes."""
        fuzzer = WebDirectoryFuzzer(wordlist_path=self.wordlist_file, use_mock=True)
        wordlist = fuzzer.load_wordlist()
        self.assertGreaterEqual(len(wordlist), 10)
        self.assertFalse(any(item.startswith('/') for item in wordlist))
        self.assertIn("admin", wordlist)
        self.assertIn(".env", wordlist)

    def test_critical_asset_identification(self):
        """Test detection and risk severity assignment for .env and backup.sql (CRITICAL)."""
        fuzzer = WebDirectoryFuzzer(wordlist_path=self.wordlist_file, use_mock=True)
        findings = fuzzer.run_scan()
        critical_paths = [f["path"] for f in findings if f["severity"] == "CRITICAL"]
        self.assertIn("/.env", critical_paths)
        self.assertIn("/backup.sql", critical_paths)
        self.assertEqual(fuzzer.metrics["critical_exposures"], 2)

    def test_status_403_differentiation(self):
        """Test that 403 Forbidden responses are retained and flagged as HIGH priority assets."""
        fuzzer = WebDirectoryFuzzer(wordlist_path=self.wordlist_file, use_mock=True)
        findings = fuzzer.run_scan()
        forbidden = [f for f in findings if f["status_code"] == 403]
        self.assertGreaterEqual(len(forbidden), 4)
        for f in forbidden:
            self.assertEqual(f["severity"], "HIGH")
        paths_403 = [f["path"] for f in forbidden]
        self.assertIn("/admin", paths_403)
        self.assertIn("/.git", paths_403)

    def test_status_401_authentication_handling(self):
        """Test that 401 Unauthorized responses are recognized as protected endpoints (MEDIUM)."""
        fuzzer = WebDirectoryFuzzer(wordlist_path=self.wordlist_file, use_mock=True)
        findings = fuzzer.run_scan()
        unauthorized = [f for f in findings if f["status_code"] == 401]
        self.assertGreaterEqual(len(unauthorized), 1)
        for f in unauthorized:
            self.assertEqual(f["severity"], "MEDIUM")
        paths_401 = [f["path"] for f in unauthorized]
        self.assertIn("/dashboard", paths_401)

    def test_status_404_discarding(self):
        """Test that 404 Not Found endpoints are discarded from findings and tracked in metrics."""
        fuzzer = WebDirectoryFuzzer(wordlist_path=self.wordlist_file, use_mock=True)
        findings = fuzzer.run_scan()
        not_found_in_findings = [f for f in findings if f["status_code"] == 404]
        self.assertEqual(len(not_found_in_findings), 0)
        self.assertGreaterEqual(fuzzer.metrics["status_404"], 2)

    def test_json_and_txt_reporting(self):
        """Test that JSON and TXT discovery reports are correctly serialized to disk."""
        fuzzer = WebDirectoryFuzzer(wordlist_path=self.wordlist_file, use_mock=True)
        fuzzer.run_scan()
        j_path = fuzzer.save_json(self.test_json)
        t_path = fuzzer.save_summary_text(self.test_txt)

        self.assertTrue(os.path.exists(j_path))
        self.assertTrue(os.path.exists(t_path))

        with open(j_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.assertIn("metadata", data)
        self.assertIn("metrics", data)
        self.assertIn("findings", data)
        self.assertEqual(len(data["findings"]), len(fuzzer.findings))

        # Cleanup test files
        if os.path.exists(self.test_json):
            os.remove(self.test_json)
        if os.path.exists(self.test_txt):
            os.remove(self.test_txt)

if __name__ == '__main__':
    unittest.main()
