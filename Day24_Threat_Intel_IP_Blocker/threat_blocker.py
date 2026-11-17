"""
PEER'S Automated Threat Intelligence IP Blocking Pipeline v2.0
==============================================================
Multi-Feed IoC Ingestion, Confidence Scoring & Automated Firewall Enforcement
NIST SP 800-150 (Guide to Cyber Threat Information Sharing) & MITRE ATT&CK Mitigation M1037

Author: Mohammed Peer Siddiqui
Company: Sqrock IT Solutions
Track: Phase 2 - Web Application Security & Defensive Automation (Day 24)
Monorepo: https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2
"""

import os
import sys
import ipaddress
import json
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

class ThreatIntelPipeline:
    """
    Automated threat intelligence ingestion, risk scoring, and firewall rule compiler.
    Transforms raw IoC feeds into production iptables and nftables policy drop lists.
    """

    def __init__(self, feed_path=None, threshold=75):
        self.feed_path = feed_path
        self.threshold = threshold
        self.raw_feed = []
        self.blocked_iocs = []
        self.allowed_iocs = []
        self.metrics = {
            "total_iocs_ingested": 0,
            "valid_ips": 0,
            "blocked_ips": 0,
            "monitored_allowed_ips": 0,
            "avg_confidence_score": 0.0
        }

    def validate_ip(self, ip_str):
        """Validates IPv4 format and ensures IP is a valid routable global address."""
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            return ip.version == 4
        except ValueError:
            return False

    def load_feed(self, filepath=None):
        """Ingests structured threat intelligence feed from JSON source."""
        path = filepath or self.feed_path
        if not path or not os.path.exists(path):
            raise FileNotFoundError(f"Threat feed '{path}' not found.")

        with open(path, 'r', encoding='utf-8') as f:
            self.raw_feed = json.load(f)

        self.blocked_iocs = []
        self.allowed_iocs = []
        scores = []

        for item in self.raw_feed:
            ip_str = item.get("ip")
            if not self.validate_ip(ip_str):
                continue

            self.metrics["valid_ips"] += 1
            score = item.get("confidence_score", 0)
            scores.append(score)

            if score >= self.threshold:
                self.blocked_iocs.append(item)
            else:
                self.allowed_iocs.append(item)

        self.metrics["total_iocs_ingested"] = len(self.raw_feed)
        self.metrics["blocked_ips"] = len(self.blocked_iocs)
        self.metrics["monitored_allowed_ips"] = len(self.allowed_iocs)
        self.metrics["avg_confidence_score"] = round(sum(scores) / len(scores), 1) if scores else 0.0

        return self.blocked_iocs

    def generate_iptables_rules(self):
        """Generates POSIX compliant Linux iptables shell script drop commands."""
        lines = [
            "#!/bin/bash",
            "# PEER'S Automated Threat Intelligence iptables Blocklist",
            f"# Generated At: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "# Standard: NIST SP 800-150 / MITRE ATT&CK M1037",
            "",
            "# Create dedicated threat block chain if not exists",
            "iptables -N THREAT_INTEL_BLOCK 2>/dev/null || true",
            "iptables -F THREAT_INTEL_BLOCK",
            ""
        ]
        for ioc in self.blocked_iocs:
            ip = ioc["ip"]
            threat = ioc["threat_type"].replace('"', '\\"')
            score = ioc["confidence_score"]
            lines.append(f"iptables -A THREAT_INTEL_BLOCK -s {ip} -j DROP -m comment --comment \"Sqrock: {threat} (Score: {score})\"")

        lines.extend([
            "",
            "# Link threat chain to INPUT filter",
            "iptables -C INPUT -j THREAT_INTEL_BLOCK 2>/dev/null || iptables -I INPUT 1 -j THREAT_INTEL_BLOCK",
            "echo \"[+] Successfully enforced iptables drop rules for threat intelligence IoCs.\""
        ])
        return "\n".join(lines)

    def generate_nftables_rules(self):
        """Generates modern Linux nftables declarative ruleset."""
        elements = ", ".join([f"{ioc['ip']}" for ioc in self.blocked_iocs])
        nft_content = f"""#!/usr/sbin/nft -f
# PEER'S Automated Threat Intelligence nftables Declarative Blocklist
# Generated At: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

table inet filter {{
    set threat_intel_blocklist {{
        type ipv4_addr
        flags interval
        elements = {{ {elements} }}
    }}

    chain input {{
        type filter hook input priority -10; policy accept;
        ip saddr @threat_intel_blocklist counter drop comment "Sqrock Automated Threat Intel Drop"
    }}
}}
"""
        return nft_content

    def save_firewall_scripts(self, output_dir="firewall_rules"):
        """Saves generated iptables and nftables configuration scripts."""
        os.makedirs(output_dir, exist_ok=True)
        iptables_path = os.path.join(output_dir, "iptables_blocklist.sh")
        nftables_path = os.path.join(output_dir, "nftables_blocklist.nft")

        with open(iptables_path, 'w', encoding='utf-8') as f:
            f.write(self.generate_iptables_rules())

        with open(nftables_path, 'w', encoding='utf-8') as f:
            f.write(self.generate_nftables_rules())

        return iptables_path, nftables_path

    def print_cli_summary(self):
        """Renders Kali Linux style interactive threat pipeline console."""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}" + "="*74)
        print(f"{Fore.CYAN}{Style.BRIGHT}  PEER'S THREAT INTELLIGENCE IP BLOCKING PIPELINE v2.0")
        print(f"{Fore.CYAN}{Style.BRIGHT}  IoC Ingestion, Confidence Risk Scoring & Automated Firewall Sync")
        print(f"{Fore.CYAN}{Style.BRIGHT}" + "="*74 + f"{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Threat Feed File : {Fore.YELLOW}{self.feed_path}")
        print(f"{Fore.WHITE}Block Threshold  : {Fore.RED}>= {self.threshold}% Confidence Score")
        print(f"{Fore.WHITE}Execution Time   : {Fore.LIGHTBLACK_EX}{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")

        print(f"{Fore.YELLOW}{Style.BRIGHT}[+] ENFORCED FIREWALL DROP RULES (CONFIDENCE >= {self.threshold}%):{Style.RESET_ALL}")
        print("-" * 74)
        print(f"{'STATUS':<10} {'IPV4 ADDRESS':<16} {'SCORE':<8} {'FEED SOURCE':<18} {'THREAT CLASSIFICATION'}")
        print("-" * 74)

        for ioc in self.blocked_iocs:
            status_str = f"{Fore.RED}{Style.BRIGHT}[DROP]{Style.RESET_ALL}"
            score_str = f"{Fore.RED}{Style.BRIGHT}{ioc['confidence_score']}%{Style.RESET_ALL}"
            print(f"{status_str:<18} {ioc['ip']:<16} {score_str:<16} {ioc['source']:<18} {Fore.WHITE}{ioc['threat_type']}")

        print(f"\n{Fore.YELLOW}{Style.BRIGHT}[+] ALLOWED / MONITORED IPS (CONFIDENCE < {self.threshold}%):{Style.RESET_ALL}")
        print("-" * 74)
        for ioc in self.allowed_iocs:
            status_str = f"{Fore.GREEN}{Style.BRIGHT}[ALLOW]{Style.RESET_ALL}"
            score_str = f"{Fore.GREEN}{ioc['confidence_score']}%{Style.RESET_ALL}"
            print(f"{status_str:<18} {ioc['ip']:<16} {score_str:<16} {ioc['source']:<18} {Fore.LIGHTBLACK_EX}{ioc['threat_type']}")

        print(f"\n{Fore.CYAN}{Style.BRIGHT}" + "="*74)
        print(f"{Fore.CYAN}{Style.BRIGHT}  PIPELINE INGESTION & ENFORCEMENT METRICS")
        print(f"{Fore.CYAN}{Style.BRIGHT}" + "="*74 + f"{Style.RESET_ALL}")
        print(f"  Total Ingested IoCs : {Fore.WHITE}{self.metrics['total_iocs_ingested']}")
        print(f"  Enforced Drop Rules : {Fore.RED}{Style.BRIGHT}{self.metrics['blocked_ips']}{Style.RESET_ALL}")
        print(f"  Allowed / Whitelist : {Fore.GREEN}{self.metrics['monitored_allowed_ips']}")
        print(f"  Average Threat Score: {Fore.YELLOW}{self.metrics['avg_confidence_score']}%\n")

    def save_json(self, output_path="firewall_rules/threat_intel_report.json"):
        """Saves machine-readable JSON telemetry report."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        report = {
            "metadata": {
                "engine": "PEER'S Threat Intelligence IP Blocking Pipeline v2.0",
                "author": "Mohammed Peer Siddiqui",
                "company": "Sqrock IT Solutions",
                "timestamp": datetime.now().isoformat(),
                "standards": ["NIST SP 800-150", "MITRE ATT&CK M1037"]
            },
            "metrics": self.metrics,
            "blocked_iocs": self.blocked_iocs,
            "allowed_iocs": self.allowed_iocs
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4)
        return output_path

    def save_summary_text(self, output_path="firewall_rules/threat_intel_summary.txt"):
        """Saves human-readable SOC analyst triage summary."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        lines = [
            "=" * 74,
            "PEER'S THREAT INTELLIGENCE FIREWALL ENFORCEMENT SUMMARY",
            "Automated IoC Risk Scoring & Drop Rule Synthesis",
            "=" * 74,
            f"Generated At          : {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Total IoCs Processed  : {self.metrics['total_iocs_ingested']}",
            f"Blocked Threat IPs    : {self.metrics['blocked_ips']}",
            f"Allowed / Whitelisted : {self.metrics['monitored_allowed_ips']}",
            "=" * 74,
            "",
            "ENFORCED FIREWALL DROP RULES:"
        ]
        for b in self.blocked_iocs:
            lines.append(f"[DROP] {b['ip']} | Confidence: {b['confidence_score']}% | Source: {b['source']}")
            lines.append(f"       Threat: {b['threat_type']} | ASN: {b['asn']} ({b['country']})")
            lines.append("-" * 74)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))
        return output_path


def main():
    import argparse
    parser = argparse.ArgumentParser(description="PEER'S Threat Intel Pipeline v2.0")
    parser.add_argument("--feed", default="feeds/threat_intel_feed.json", help="Path to threat feed JSON")
    parser.add_argument("--threshold", type=int, default=75, help="Confidence score threshold for blocking")
    parser.add_argument("--json-out", default="firewall_rules/threat_intel_report.json", help="JSON report path")
    parser.add_argument("--txt-out", default="firewall_rules/threat_intel_summary.txt", help="TXT summary path")
    args = parser.parse_args()

    pipeline = ThreatIntelPipeline(feed_path=args.feed, threshold=args.threshold)
    pipeline.load_feed()
    pipeline.print_cli_summary()
    pipeline.save_firewall_scripts()
    pipeline.save_json(args.json_out)
    pipeline.save_summary_text(args.txt_out)
    print(f"{Fore.GREEN}[+] Firewall scripts saved to: firewall_rules/")
    print(f"{Fore.GREEN}[+] Threat report JSON saved to: {args.json_out}")
    print(f"{Fore.GREEN}[+] Triage summary text saved to: {args.txt_out}")

if __name__ == "__main__":
    main()
