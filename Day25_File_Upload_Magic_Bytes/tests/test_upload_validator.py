"""
Unit Tests for PEER'S File Upload Vulnerability & Magic Bytes Security Validator v2.0
Validates magic byte signatures, extension spoofing, polyglot malware detection, and telemetry.
"""

import os
import sys
import json
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from upload_validator import FileUploadValidator

class TestFileUploadValidator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        cls.samples_dir = os.path.join(cls.base_dir, 'samples')
        cls.test_json = os.path.join(cls.base_dir, 'validation_results', 'test_upload_report.json')
        cls.test_txt = os.path.join(cls.base_dir, 'validation_results', 'test_upload_summary.txt')
        cls.validator = FileUploadValidator(cls.samples_dir)

    def test_legit_image_png_validation(self):
        """Test that legitimate PNG with authentic magic bytes is approved."""
        path = os.path.join(self.samples_dir, 'legit_image.png')
        res = self.validator.validate_file(path)
        self.assertEqual(res["verdict"], "ALLOWED")
        self.assertEqual(res["severity"], "SAFE")
        self.assertEqual(res["detected_mime"], "image/png")
        self.assertEqual(len(res["violations"]), 0)

    def test_legit_document_pdf_validation(self):
        """Test that legitimate PDF document with %PDF header is approved."""
        path = os.path.join(self.samples_dir, 'legit_document.pdf')
        res = self.validator.validate_file(path)
        self.assertEqual(res["verdict"], "ALLOWED")
        self.assertEqual(res["detected_mime"], "application/pdf")

    def test_double_extension_spoofing_detection(self):
        """Test detection and blocking of double-extension spoofing (e.g. .php.png)."""
        path = os.path.join(self.samples_dir, 'spoofed_webshell.php.png')
        res = self.validator.validate_file(path)
        self.assertEqual(res["verdict"], "REJECTED")
        self.assertEqual(res["severity"], "CRITICAL")
        self.assertTrue(any("Double-extension" in v for v in res["violations"]))
        self.assertTrue(any("Magic bytes" in v for v in res["violations"]))

    def test_polyglot_malware_detection(self):
        """Test detection of embedded PHP code within valid JPEG container."""
        path = os.path.join(self.samples_dir, 'polyglot_malware.jpg')
        res = self.validator.validate_file(path)
        self.assertEqual(res["verdict"], "REJECTED")
        self.assertEqual(res["severity"], "CRITICAL")
        self.assertTrue(any("Polyglot attack" in v for v in res["violations"]))

    def test_direct_executable_extension_blocking(self):
        """Test that direct executable shell script (.sh) is blocked."""
        path = os.path.join(self.samples_dir, 'malicious_script.sh')
        res = self.validator.validate_file(path)
        self.assertEqual(res["verdict"], "REJECTED")
        self.assertTrue(any("Direct executable" in v for v in res["violations"]))

    def test_json_and_txt_reporting(self):
        """Test serialization of validation report JSON and summary text."""
        self.validator.validate_directory()
        j_path = self.validator.save_json(self.test_json)
        t_path = self.validator.save_summary_text(self.test_txt)

        self.assertTrue(os.path.exists(j_path))
        self.assertTrue(os.path.exists(t_path))

        with open(j_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.assertIn("metadata", data)
        self.assertIn("metrics", data)
        self.assertIn("findings", data)

        # Cleanup test files
        if os.path.exists(self.test_json): os.remove(self.test_json)
        if os.path.exists(self.test_txt): os.remove(self.test_txt)

if __name__ == '__main__':
    unittest.main()
