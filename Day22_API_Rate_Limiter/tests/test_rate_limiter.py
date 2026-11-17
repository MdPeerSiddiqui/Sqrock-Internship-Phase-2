"""
Unit Tests for PEER'S API Rate Limiting & Token Bucket Defense Suite v2.0
Validates token consumption, burst limits, refill rates, HTTP 429 generation, and client isolation.
"""

import os
import sys
import time
import json
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from rate_limiter import TokenBucket, APIRateLimiter

class TestRateLimiter(unittest.TestCase):
    def test_token_bucket_initial_capacity(self):
        """Test that a new token bucket initializes with full configured capacity."""
        bucket = TokenBucket(capacity=10.0, refill_rate=2.0)
        self.assertEqual(bucket.capacity, 10.0)
        self.assertEqual(bucket.tokens, 10.0)

    def test_token_consumption_allowed(self):
        """Test that single requests decrement tokens and are allowed."""
        bucket = TokenBucket(capacity=5.0, refill_rate=1.0)
        allowed, remaining, retry_after = bucket.consume(1.0)
        self.assertTrue(allowed)
        self.assertEqual(remaining, 4)
        self.assertEqual(retry_after, 0.0)

    def test_token_exhaustion_throttled(self):
        """Test that consuming beyond capacity results in denial and retry-after calculation."""
        bucket = TokenBucket(capacity=2.0, refill_rate=1.0)
        bucket.consume(1.0)
        bucket.consume(1.0)
        allowed, remaining, retry_after = bucket.consume(1.0)
        self.assertFalse(allowed)
        self.assertEqual(remaining, 0)
        self.assertGreater(retry_after, 0.0)

    def test_token_refill_replenishment(self):
        """Test that elapsed time correctly replenishes tokens up to capacity."""
        bucket = TokenBucket(capacity=5.0, refill_rate=10.0)  # 10 tokens per sec
        bucket.consume(5.0)
        self.assertLess(bucket.tokens, 1.0)
        time.sleep(0.3)  # should refill ~3 tokens
        allowed, remaining, _ = bucket.consume(1.0)
        self.assertTrue(allowed)

    def test_rfc_headers_generation(self):
        """Test that HTTP 429 responses contain proper RFC 6585 rate limiting headers."""
        limiter = APIRateLimiter(capacity=1.0, refill_rate=0.5)
        res1 = limiter.process_request("10.0.0.1")
        self.assertEqual(res1["status_code"], 200)
        self.assertIn("X-RateLimit-Limit", res1["headers"])
        self.assertIn("X-RateLimit-Remaining", res1["headers"])

        res2 = limiter.process_request("10.0.0.1")
        self.assertEqual(res2["status_code"], 429)
        self.assertIn("Retry-After", res2["headers"])
        self.assertFalse(res2["allowed"])

    def test_multi_client_isolation(self):
        """Test stateful client isolation: Client A quota exhaustion does not affect Client B."""
        limiter = APIRateLimiter(capacity=2.0, refill_rate=0.1)
        # Client A exhausts quota
        limiter.process_request("client_A")
        limiter.process_request("client_A")
        res_a = limiter.process_request("client_A")
        self.assertEqual(res_a["status_code"], 429)

        # Client B sends request and must succeed
        res_b = limiter.process_request("client_B")
        self.assertEqual(res_b["status_code"], 200)
        self.assertTrue(res_b["allowed"])

if __name__ == '__main__':
    unittest.main()
