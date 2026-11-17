"""
Unit Tests for PEER'S Threat Intelligence IP Blocking Pipeline v2.0
Validates feed ingestion, IP address parsing, confidence scoring, firewall rule compilation, and telemetry.
"""

import os
import sys
import json
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from threat_blocker import ThreatIntelPipeline

class TestThreatBlocker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        cls.feed_file = os.path.join(cls.base_dir, 'feeds', 'threat_intel_feed.json')
        cls.test_json = os.path.join(cls.base_dir, 'firewall_rules', 'test_threat_report.json')
        cls.test_txt = os.path.join(cls.base_dir, 'firewall_rules', 'test_threat_summary.txt')

    def test_feed_ingestion(self):
        """Test structured threat feed ingestion and metric recording."""
        pipeline = ThreatIntelPipeline(feed_path=self.feed_file, threshold=75)
        blocked = pipeline.load_feed()
        self.assertGreaterEqual(pipeline.metrics["total_iocs_ingested"], 6)
        self.assertGreaterEqual(len(blocked), 4)

    def test_ip_address_validation(self):
        """Test IPv4 format verification and rejection of malformed addresses."""
        pipeline = ThreatIntelPipeline()
        self.assertTrue(pipeline.validate_ip("192.168.1.1"))
        self.assertTrue(pipeline.validate_ip("185.220.101.5"))
        self.assertFalse(pipeline.validate_ip("999.999.999.999"))
        self.assertFalse(pipeline.validate_ip("not-an-ip-address"))

    def test_confidence_threshold_filtering(self):
        """Test filtering: IPs with score >= 75 are blocked, while lower scores are whitelisted."""
        pipeline = ThreatIntelPipeline(feed_path=self.feed_file, threshold=75)
        blocked = pipeline.load_feed()
        for b in blocked:
            self.assertGreaterEqual(b["confidence_score"], 75)
        for a in pipeline.allowed_iocs:
            self.assertLess(a["confidence_score"], 75)

    def test_iptables_rule_generation(self):
        """Test POSIX iptables drop script synthesis."""
        pipeline = ThreatIntelPipeline(feed_path=self.feed_file, threshold=75)
        pipeline.load_feed()
        rules = pipeline.generate_iptables_rules()
        self.assertIn("#!/bin/bash", rules)
        self.assertIn("iptables -N THREAT_INTEL_BLOCK", rules)
        self.assertIn("-j DROP", rules)
        self.assertIn("45.154.255.89", rules)  # Cobalt Strike IP

    def test_nftables_syntax_generation(self):
        """Test modern declarative Linux nftables ruleset synthesis."""
        pipeline = ThreatIntelPipeline(feed_path=self.feed_file, threshold=75)
        pipeline.load_feed()
        nft_rules = pipeline.generate_nftables_rules()
        self.assertIn("table inet filter", nft_rules)
        self.assertIn("set threat_intel_blocklist", nft_rules)
        self.assertIn("counter drop", nft_rules)
        self.assertIn("185.220.101.5", nft_rules)

    def test_json_and_txt_reporting(self):
        """Test telemetry JSON and executive summary reporting."""
        pipeline = ThreatIntelPipeline(feed_path=self.feed_file, threshold=75)
        pipeline.load_feed()
        j_path = pipeline.save_json(self.test_json)
        t_path = pipeline.save_summary_text(self.test_txt)

        self.assertTrue(os.path.exists(j_path))
        self.assertTrue(os.path.exists(t_path))

        with open(j_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.assertIn("metadata", data)
        self.assertIn("metrics", data)
        self.assertIn("blocked_iocs", data)

        # Cleanup test files
        if os.path.exists(self.test_json): os.remove(self.test_json)
        if os.path.exists(self.test_txt): os.remove(self.test_txt)

if __name__ == '__main__':
    unittest.main()
