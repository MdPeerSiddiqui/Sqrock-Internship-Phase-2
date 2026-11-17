#!/usr/bin/env python3
"""
Unit Test Suite for PEER'S SIEM Webhook Dispatcher (Day 28)
Sqrock IT Solutions Cybersecurity Internship Phase 2: Web App Security
"""

import unittest
import os
import sys
import json

# Ensure parent directory is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from webhook_dispatcher import WebhookDispatcher, load_alerts


class TestWebhookDispatcher(unittest.TestCase):
    def setUp(self):
        self.disp = WebhookDispatcher()
        self.alerts = load_alerts()
        self.sample_alert = self.alerts[0] if self.alerts else {
            "id": "SEC-ALERT-TEST",
            "timestamp": "2026-11-17T11:00:00Z",
            "source_system": "Test-WAF",
            "rule_id": "WAF-001",
            "severity": "CRITICAL",
            "threat_category": "SQL Injection",
            "actor_ip": "1.2.3.4",
            "target_asset": "example.com",
            "payload_snippet": "' OR 1=1--",
            "action_taken": "BLOCKED",
            "mitre_technique": "T1190"
        }

    def test_slack_block_kit_formatting(self):
        """Test 1: Slack payload follows Block Kit schema with header, fields, and red attachment for CRITICAL."""
        payload = self.disp.format_slack_payload(self.sample_alert)
        self.assertIn("attachments", payload)
        self.assertEqual(payload["attachments"][0]["color"], "#A8201A")
        blocks = payload["attachments"][0]["blocks"]
        self.assertEqual(blocks[0]["type"], "header")
        self.assertIn("CRITICAL", blocks[0]["text"]["text"])

    def test_teams_message_card_formatting(self):
        """Test 2: MS Teams payload creates valid MessageCard structure with themeColor and facts."""
        payload = self.disp.format_teams_payload(self.sample_alert)
        self.assertEqual(payload["@type"], "MessageCard")
        self.assertEqual(payload["themeColor"], "A8201A")
        self.assertIn("sections", payload)
        facts = payload["sections"][0]["facts"]
        self.assertTrue(any(f["name"] == "Alert ID" for f in facts))

    def test_discord_embed_formatting(self):
        """Test 3: Discord payload generates rich embed with decimal color and footer attribution."""
        payload = self.disp.format_discord_payload(self.sample_alert)
        self.assertIn("embeds", payload)
        embed = payload["embeds"][0]
        self.assertIn("title", embed)
        self.assertEqual(embed["color"], 11018266)
        self.assertIn("Mohammed Peer Siddiqui", embed["footer"]["text"])

    def test_hmac_sha256_generation_and_verification(self):
        """Test 4: HMAC-SHA256 signature is deterministic and fails verification if payload is altered."""
        test_payload = json.dumps({"incident": "ransomware_detected", "severity": "CRITICAL"})
        sig = self.disp.generate_hmac_signature(test_payload)
        self.assertTrue(sig.startswith("sha256="))
        # Positive verification
        self.assertTrue(self.disp.verify_hmac_signature(test_payload, sig))
        # Tampered payload fails verification
        tampered_payload = json.dumps({"incident": "ransomware_detected", "severity": "LOW"})
        self.assertFalse(self.disp.verify_hmac_signature(tampered_payload, sig))

    def test_token_bucket_rate_throttling(self):
        """Test 5: Rapid bursts beyond token capacity trigger THROTTLED_429 status."""
        throttled_disp = WebhookDispatcher(burst_limit=3, rate_limit_per_min=5)
        # Consume the 3 initial burst tokens
        r1 = throttled_disp.dispatch_alert(self.sample_alert)
        r2 = throttled_disp.dispatch_alert(self.sample_alert)
        r3 = throttled_disp.dispatch_alert(self.sample_alert)
        self.assertIn("200", r1["status"])
        self.assertIn("200", r2["status"])
        self.assertIn("200", r3["status"])
        # Fourth rapid attempt without refill should be throttled
        r4 = throttled_disp.dispatch_alert(self.sample_alert)
        self.assertEqual(r4["status"], "THROTTLED_429")

    def test_dispatch_audit_telemetry_export(self):
        """Test 6: Dispatch telemetry writes valid JSON with metrics and records."""
        self.disp.dispatch_alert(self.sample_alert, channel="slack")
        self.disp.dispatch_alert(self.sample_alert, channel="teams")
        json_path = self.disp.save_telemetry_report()
        self.assertTrue(os.path.exists(json_path))

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("metadata", data)
        self.assertIn("summary", data)
        self.assertGreaterEqual(data["summary"]["total_dispatched"], 2)
        self.assertEqual(data["metadata"]["candidate"], "Mohammed Peer Siddiqui")


if __name__ == "__main__":
    unittest.main()
