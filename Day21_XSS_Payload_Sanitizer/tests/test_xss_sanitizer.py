"""
Unit Tests for PEER'S Cross-Site Scripting (XSS) Payload Sanitizer v2.0
Validates HTML entity encoding, tag stripping, event handler neutralization, and CSP policy generation.
"""

import os
import sys
import json
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from xss_sanitizer import XSSSanitizer

class TestXSSSanitizer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        cls.sample_payloads = os.path.join(cls.base_dir, 'samples', 'test_payloads.json')
        cls.test_json = os.path.join(cls.base_dir, 'sanitizer_results', 'test_xss_report.json')
        cls.test_txt = os.path.join(cls.base_dir, 'sanitizer_results', 'test_xss_summary.txt')
        cls.sanitizer = XSSSanitizer(cls.sample_payloads)

    def test_script_tag_stripping(self):
        """Test complete neutralization and stripping of <script> execution tags."""
        payload = "<script>alert('XSS')</script>"
        sanitized = self.sanitizer.sanitize_context_aware(payload, context="html_body")
        self.assertNotIn("<script>", sanitized.lower())
        self.assertNotIn("alert", sanitized)

    def test_html_entity_encoding(self):
        """Test encoding of dangerous special characters into immutable HTML entities."""
        raw = """<div class="test" data-val='quote' / & >"""
        encoded = self.sanitizer.html_entity_encode(raw)
        self.assertNotIn("<", encoded)
        self.assertNotIn(">", encoded)
        self.assertIn("&lt;", encoded)
        self.assertIn("&gt;", encoded)
        self.assertIn("&quot;", encoded)
        self.assertIn("&#x27;", encoded)
        self.assertIn("&amp;", encoded)

    def test_event_handler_neutralization(self):
        """Test neutralization of inline DOM event handlers (onerror, onload)."""
        payload = """<img src="x" onerror="alert(1)" onload="fetch('/')">"""
        neutralized = self.sanitizer.neutralize_event_handlers(payload)
        self.assertNotIn(" onerror=", neutralized)
        self.assertNotIn(" onload=", neutralized)
        self.assertIn("data-disabled-onerror=", neutralized)
        self.assertIn("data-disabled-onload=", neutralized)

    def test_javascript_pseudo_protocol(self):
        """Test blocking of javascript: URI attribute schemes."""
        uri_payload = "javascript:alert(document.cookie)"
        sanitized = self.sanitizer.sanitize_context_aware(uri_payload, context="uri_attribute")
        self.assertEqual(sanitized, "#blocked-insecure-uri")

    def test_benign_text_preservation(self):
        """Test that benign alphanumeric text is preserved without corruption."""
        benign = "Sqrock IT Solutions Cybersecurity Internship 2026 - Defensive Automation"
        sanitized = self.sanitizer.sanitize_context_aware(benign, context="html_body")
        self.assertEqual(sanitized, benign)

    def test_csp_header_generation(self):
        """Test CSP Level 3 policy header generation compliance."""
        csp = self.sanitizer.generate_csp_header(nonce="test_nonce_123")
        self.assertIn("default-src 'self'", csp)
        self.assertIn("script-src 'self' 'nonce-test_nonce_123'", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)

if __name__ == '__main__':
    unittest.main()
