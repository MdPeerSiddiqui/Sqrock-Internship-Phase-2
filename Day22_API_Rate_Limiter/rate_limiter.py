"""
PEER'S API Rate Limiting & Token Bucket Defense Suite v2.0
==========================================================
Stateful Client IP Throttling, DoS Mitigation & HTTP 429 Defense Engine
RFC 6585 (Additional HTTP Status Codes) & OWASP API Security Top 10 API4:2023

Author: Mohammed Peer Siddiqui
Company: Sqrock IT Solutions
Track: Phase 2 - Web Application Security & Defensive Automation (Day 22)
Monorepo: https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2
"""

import os
import sys
import time
import json
import threading
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

class TokenBucket:
    """
    Mathematical token bucket model for burst-tolerant rate limiting.
    Capacity (B): maximum burst size.
    Refill Rate (R): sustained token replenishment per second.
    """
    def __init__(self, capacity=10.0, refill_rate=2.0):
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self.tokens = float(capacity)
        self.last_refill = time.time()
        self.lock = threading.Lock()

    def _refill(self):
        now = time.time()
        elapsed = now - self.last_refill
        if elapsed > 0:
            added = elapsed * self.refill_rate
            self.tokens = min(self.capacity, self.tokens + added)
            self.last_refill = now

    def consume(self, cost=1.0):
        with self.lock:
            self._refill()
            if self.tokens >= cost:
                self.tokens -= cost
                remaining = int(self.tokens)
                return True, remaining, 0.0
            else:
                deficit = cost - self.tokens
                retry_after = round(deficit / self.refill_rate, 2)
                return False, 0, max(0.1, retry_after)


class APIRateLimiter:
    """
    Stateful API rate limiting middleware simulating edge reverse proxy throttling.
    Tracks client states by IP / API key and generates RFC-compliant HTTP headers.
    """
    def __init__(self, capacity=10.0, refill_rate=2.0):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.buckets = {}
        self.global_lock = threading.Lock()
        self.simulation_logs = []
        self.metrics = {
            "total_requests": 0,
            "allowed_requests": 0,
            "throttled_requests": 0,
            "unique_clients_tracked": 0
        }

    def get_bucket(self, client_id):
        with self.global_lock:
            if client_id not in self.buckets:
                self.buckets[client_id] = TokenBucket(self.capacity, self.refill_rate)
            return self.buckets[client_id]

    def process_request(self, client_id, cost=1.0):
        bucket = self.get_bucket(client_id)
        allowed, remaining, retry_after = bucket.consume(cost)

        self.metrics["total_requests"] += 1
        with self.global_lock:
            self.metrics["unique_clients_tracked"] = len(self.buckets)

        headers = {
            "X-RateLimit-Limit": str(int(self.capacity)),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(int(time.time() + (self.capacity - remaining) / self.refill_rate))
        }

        if allowed:
            self.metrics["allowed_requests"] += 1
            status_code = 200
            status_message = "OK"
        else:
            self.metrics["throttled_requests"] += 1
            status_code = 429
            status_message = "Too Many Requests"
            headers["Retry-After"] = str(int(retry_after if retry_after >= 1.0 else 1))

        event = {
            "timestamp": datetime.now().isoformat(),
            "client_id": client_id,
            "status_code": status_code,
            "status_message": status_message,
            "allowed": allowed,
            "remaining_tokens": remaining,
            "retry_after_seconds": retry_after,
            "headers": headers
        }
        self.simulation_logs.append(event)
        return event

    def simulate_burst(self, client_id="192.168.1.105", total_requests=15, delay_between_req=0.1):
        """Simulates an automated burst from a single client to demonstrate throttling."""
        results = []
        for i in range(1, total_requests + 1):
            res = self.process_request(client_id)
            results.append(res)
            time.sleep(delay_between_req)
        return results

    def print_cli_summary(self):
        """Renders Kali Linux style interactive rate limiter console."""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}" + "="*74)
        print(f"{Fore.CYAN}{Style.BRIGHT}  PEER'S API RATE LIMITING & TOKEN BUCKET DEFENSE SUITE v2.0")
        print(f"{Fore.CYAN}{Style.BRIGHT}  Stateful Client IP Throttling & HTTP 429 Mitigation Engine")
        print(f"{Fore.CYAN}{Style.BRIGHT}" + "="*74 + f"{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Bucket Capacity  : {Fore.YELLOW}{self.capacity} Tokens (Max Burst)")
        print(f"{Fore.WHITE}Refill Rate      : {Fore.GREEN}{self.refill_rate} Tokens/sec (Sustained Rate)")
        print(f"{Fore.WHITE}Execution Time   : {Fore.LIGHTBLACK_EX}{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")

        print(f"{Fore.YELLOW}{Style.BRIGHT}[+] LIVE TRAFFIC BURST SIMULATION (15 Rapid Requests from Single IP):{Style.RESET_ALL}")
        print("-" * 74)
        print(f"{'REQ #':<7} {'CLIENT IP':<16} {'STATUS':<14} {'REMAINING':<12} {'RETRY-AFTER':<14} {'ACTION'}")
        print("-" * 74)

        for idx, log in enumerate(self.simulation_logs[-15:], 1):
            sc = log["status_code"]
            if sc == 200:
                sc_str = f"{Fore.GREEN}{Style.BRIGHT}200 OK{Style.RESET_ALL}"
                action_str = f"{Fore.GREEN}ALLOWED"
                retry_str = "-"
            else:
                sc_str = f"{Fore.RED}{Style.BRIGHT}429 THROTTLED{Style.RESET_ALL}"
                action_str = f"{Fore.RED}BLOCKED (DoS Defended)"
                retry_str = f"{log['retry_after_seconds']}s"

            print(f"#{idx:<6} {log['client_id']:<16} {sc_str:<23} {log['remaining_tokens']:<12} {retry_str:<14} {action_str}")

        print(f"\n{Fore.CYAN}{Style.BRIGHT}" + "="*74)
        print(f"{Fore.CYAN}{Style.BRIGHT}  RATE LIMITING TELEMETRY & ATTACK MITIGATION METRICS")
        print(f"{Fore.CYAN}{Style.BRIGHT}" + "="*74 + f"{Style.RESET_ALL}")
        print(f"  Total Inquiries Evaluated : {Fore.WHITE}{self.metrics['total_requests']}")
        print(f"  Legitimate (Allowed)      : {Fore.GREEN}{self.metrics['allowed_requests']}")
        print(f"  Throttled (HTTP 429)      : {Fore.RED}{Style.BRIGHT}{self.metrics['throttled_requests']}{Style.RESET_ALL}")
        print(f"  Unique Clients Managed    : {Fore.CYAN}{self.metrics['unique_clients_tracked']}\n")

    def save_json(self, output_path="rate_limit_results/rate_limit_report.json"):
        """Saves machine-readable JSON rate limiting report."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        report = {
            "metadata": {
                "engine": "PEER'S API Rate Limiting & Token Bucket Defense Suite v2.0",
                "author": "Mohammed Peer Siddiqui",
                "company": "Sqrock IT Solutions",
                "timestamp": datetime.now().isoformat(),
                "standards": ["RFC 6585", "OWASP API Security Top 10 API4:2023"]
            },
            "configuration": {
                "capacity": self.capacity,
                "refill_rate": self.refill_rate
            },
            "metrics": self.metrics,
            "recent_events": self.simulation_logs
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4)
        return output_path

    def save_summary_text(self, output_path="rate_limit_results/rate_limit_summary.txt"):
        """Saves human-readable SOC analyst triage summary."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        lines = [
            "=" * 74,
            "PEER'S API RATE LIMITING & BURST THROTTLING SUMMARY",
            "Token Bucket Algorithm & HTTP 429 Too Many Requests Defense",
            "=" * 74,
            f"Generated At          : {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Configured Capacity   : {self.capacity} Tokens",
            f"Refill Rate           : {self.refill_rate} Tokens/sec",
            f"Total Evaluated       : {self.metrics['total_requests']}",
            f"Allowed (200 OK)      : {self.metrics['allowed_requests']}",
            f"Throttled (HTTP 429)  : {self.metrics['throttled_requests']}",
            "=" * 74,
            "",
            "SAMPLE RECENT HTTP 429 MITIGATION EVENTS:"
        ]
        for f in [x for x in self.simulation_logs if not x["allowed"]][:5]:
            lines.append(f"[THROTTLED 429] Client: {f['client_id']} | Tokens Remaining: {f['remaining_tokens']}")
            lines.append(f"    Headers Generated : {json.dumps(f['headers'])}")
            lines.append("-" * 74)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))
        return output_path


def main():
    import argparse
    parser = argparse.ArgumentParser(description="PEER'S API Rate Limiter v2.0")
    parser.add_argument("--capacity", type=float, default=10.0, help="Bucket capacity (max burst tokens)")
    parser.add_argument("--refill-rate", type=float, default=2.0, help="Refill rate (tokens per second)")
    parser.add_argument("--burst-count", type=int, default=15, help="Simulated rapid requests count")
    parser.add_argument("--json-out", default="rate_limit_results/rate_limit_report.json", help="JSON report path")
    parser.add_argument("--txt-out", default="rate_limit_results/rate_limit_summary.txt", help="TXT summary path")
    args = parser.parse_args()

    limiter = APIRateLimiter(capacity=args.capacity, refill_rate=args.refill_rate)
    limiter.simulate_burst(client_id="192.168.1.105", total_requests=args.burst_count, delay_between_req=0.05)
    limiter.print_cli_summary()
    limiter.save_json(args.json_out)
    limiter.save_summary_text(args.txt_out)
    print(f"{Fore.GREEN}[+] Rate limiting JSON saved to: {args.json_out}")
    print(f"{Fore.GREEN}[+] Summary text saved to: {args.txt_out}")

if __name__ == "__main__":
    main()
