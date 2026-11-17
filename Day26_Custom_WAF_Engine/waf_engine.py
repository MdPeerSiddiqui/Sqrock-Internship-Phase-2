#!/usr/bin/env python3
"""
PEER'S Web Application Firewall (WAF) Core Engine (Day 26)
Sqrock IT Solutions Cybersecurity Internship Phase 2: Web Application Security & Defensive Automation

Author: Mohammed Peer Siddiqui
Role: Cybersecurity Intern
Company: Sqrock IT Solutions
Module: Layer 7 WAF Deep Packet & Middleware Inspection Engine

Defensive Capabilities:
- Deep URI, Parameter, Header, and Request Body Inspection
- Rule-based detection of OWASP Top 10 vulnerabilities (SQLi, XSS, Path Traversal, Command Injection)
- Scanner & Bot User-Agent Blocking (sqlmap, Nikto, Gobuster, etc.)
- Multi-tier recursive URL decoding for anti-evasion
- Structured JSON and forensic text security logging
"""

import os
import sys
import json
import re
import urllib.parse
from datetime import datetime, timezone
from colorama import init, Fore, Style

init(autoreset=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")
LOGS_DIR = os.path.join(BASE_DIR, "waf_logs")
DEFAULT_TRAFFIC_FILE = os.path.join(SAMPLES_DIR, "traffic_requests.json")
AUDIT_JSON_PATH = os.path.join(LOGS_DIR, "waf_audit_log.json")
BLOCKED_LOG_PATH = os.path.join(LOGS_DIR, "waf_blocked_events.log")

BANNER = f"""
{Fore.CYAN}{Style.BRIGHT}================================================================================
          PEER'S WEB APPLICATION FIREWALL (WAF) CORE ENGINE v2.0
      Sqrock IT Solutions | Internship Phase 2: Web App Security (Day 26)
      Candidate: Mohammed Peer Siddiqui  |  Status: ACTIVE DEFENSE
================================================================================{Style.RESET_ALL}
"""

# Enterprise Rule Definition Ledger
CORE_WAF_RULES = [
    {
        "id": "WAF-SQLI-001",
        "category": "SQL Injection (SQLi)",
        "severity": "CRITICAL",
        "score": 9.8,
        "pattern": re.compile(
            r"(?i)(\bUNION\b\s+(?:ALL\s+)?\bSELECT\b|'\s*OR\s*['\d]+=['\d]+|--\s*|\bDROP\b\s+TABLE\b|\bINSERT\b\s+INTO\b|\bSELECT\b\s+.*?\bFROM\b|;\s*SHUTDOWN\b)",
            re.IGNORECASE
        ),
        "description": "SQL Injection syntax detection (UNION, boolean tautology, schema manipulation)"
    },
    {
        "id": "WAF-XSS-001",
        "category": "Cross-Site Scripting (XSS)",
        "severity": "HIGH",
        "score": 8.8,
        "pattern": re.compile(
            r"(?i)(<\s*script[^>]*>|javascript\s*:|on(?:error|load|click|mouseover)\s*=|document\.(?:cookie|location)|alert\s*\(|<img[^>]+src=[^>]+onerror=)",
            re.IGNORECASE
        ),
        "description": "Cross-Site Scripting (script tags, event handlers, DOM manipulation)"
    },
    {
        "id": "WAF-TRAV-001",
        "category": "Path Traversal / LFI",
        "severity": "HIGH",
        "score": 8.5,
        "pattern": re.compile(
            r"(?i)(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/windows/win\.ini|boot\.ini|/proc/self/|windows/system32)",
            re.IGNORECASE
        ),
        "description": "Local File Inclusion and directory traversal escape patterns"
    },
    {
        "id": "WAF-CMDI-001",
        "category": "OS Command Injection",
        "severity": "CRITICAL",
        "score": 9.9,
        "pattern": re.compile(
            r"(?i)(;\s*(?:cat|ls|rm|whoami|nc|bash|sh|powershell|wget|curl)\b|\|\s*(?:cat|ls|whoami|nc)|`[^`]+`|\$\([^)]+\))",
            re.IGNORECASE
        ),
        "description": "Arbitrary OS command chaining via shell delimiters (; | & `$()``)"
    },
    {
        "id": "WAF-SCAN-001",
        "category": "Malicious Scanner / Tool",
        "severity": "MEDIUM",
        "score": 7.5,
        "pattern": re.compile(
            r"(?i)(sqlmap|nikto|nmap|masscan|nessus|gobuster|dirbuster|wpscan|acunetix|burpcollaborator)",
            re.IGNORECASE
        ),
        "description": "Automated security scanning tools and vulnerability probers"
    }
]


class WAFEngine:
    def __init__(self, rules=None):
        self.rules = rules if rules is not None else CORE_WAF_RULES
        os.makedirs(LOGS_DIR, exist_ok=True)
        self.stats = {
            "total_inspected": 0,
            "total_allowed": 0,
            "total_blocked": 0,
            "categories": {},
            "audit_trail": []
        }

    def decode_input(self, value):
        """Recursively decode URL-encoded and double-encoded inputs to prevent evasion."""
        if not isinstance(value, str):
            return str(value)
        decoded = value
        for _ in range(3):
            try:
                new_decoded = urllib.parse.unquote(decoded)
                if new_decoded == decoded:
                    break
                decoded = new_decoded
            except Exception:
                break
        return decoded

    def inspect_request(self, req):
        """
        Deep packet inspection of an incoming HTTP request dictionary:
        {
          "id": "REQ-001",
          "method": "GET",
          "path": "/products",
          "query": "id=1",
          "headers": {...},
          "body": "...",
          "client_ip": "192.168.1.100"
        }
        """
        req_id = req.get("id", "UNKNOWN-REQ")
        method = req.get("method", "GET").upper()
        path = req.get("path", "/")
        query = req.get("query", "")
        headers = req.get("headers", {})
        body = req.get("body", "")
        client_ip = req.get("client_ip", "0.0.0.0")

        self.stats["total_inspected"] += 1

        # Flatten headers into inspectable strings
        headers_str = " ".join([f"{k}: {v}" for k, v in headers.items()])
        user_agent = headers.get("User-Agent", "")

        # Targets to inspect
        targets = [
            ("PATH", self.decode_input(path)),
            ("QUERY", self.decode_input(query)),
            ("BODY", self.decode_input(body)),
            ("USER_AGENT", user_agent),
            ("HEADERS", self.decode_input(headers_str))
        ]

        matched_violations = []

        for rule in self.rules:
            rule_id = rule["id"]
            pattern = rule["pattern"]
            cat = rule["category"]
            sev = rule["severity"]
            score = rule["score"]

            for target_name, target_val in targets:
                if not target_val:
                    continue
                match = pattern.search(target_val)
                if match:
                    matched_violations.append({
                        "rule_id": rule_id,
                        "category": cat,
                        "severity": sev,
                        "score": score,
                        "target": target_name,
                        "matched_string": match.group(0),
                        "description": rule["description"]
                    })
                    break  # Avoid duplicate hits per rule

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        if matched_violations:
            self.stats["total_blocked"] += 1
            highest_score = max(v["score"] for v in matched_violations)
            top_category = matched_violations[0]["category"]
            self.stats["categories"][top_category] = self.stats["categories"].get(top_category, 0) + 1

            verdict = {
                "request_id": req_id,
                "timestamp": timestamp,
                "client_ip": client_ip,
                "method": method,
                "path": path,
                "status_code": 403,
                "action": "BLOCK",
                "risk_score": highest_score,
                "primary_category": top_category,
                "violations": matched_violations,
                "rationale": f"Request blocked due to {len(matched_violations)} Layer-7 security policy violation(s)."
            }
            self._log_blocked_event(verdict)
        else:
            self.stats["total_allowed"] += 1
            verdict = {
                "request_id": req_id,
                "timestamp": timestamp,
                "client_ip": client_ip,
                "method": method,
                "path": path,
                "status_code": 200,
                "action": "ALLOW",
                "risk_score": 0.0,
                "primary_category": "NONE",
                "violations": [],
                "rationale": "Clean request passed all Layer-7 firewall inspection checks."
            }

        self.stats["audit_trail"].append(verdict)
        return verdict

    def _log_blocked_event(self, verdict):
        try:
            with open(BLOCKED_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(f"[{verdict['timestamp']}] BLOCKED IP={verdict['client_ip']} METHOD={verdict['method']} "
                        f"PATH={verdict['path']} RULE={verdict['violations'][0]['rule_id']} "
                        f"CAT=\"{verdict['primary_category']}\" MATCH=\"{verdict['violations'][0]['matched_string']}\"\n")
        except Exception as e:
            print(f"[!] Warning: Failed to write to blocked log: {e}")

    def save_audit_report(self):
        report = {
            "metadata": {
                "system": "PEER'S Web Application Firewall (WAF) Engine",
                "organization": "Sqrock IT Solutions",
                "internship_track": "Phase 2: Web App Security & Defensive Automation",
                "candidate": "Mohammed Peer Siddiqui",
                "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            },
            "summary_metrics": {
                "total_inspected": self.stats["total_inspected"],
                "total_allowed": self.stats["total_allowed"],
                "total_blocked": self.stats["total_blocked"],
                "blocked_percentage": round((self.stats["total_blocked"] / max(1, self.stats["total_inspected"])) * 100, 2),
                "category_breakdown": self.stats["categories"]
            },
            "verdicts": self.stats["audit_trail"]
        }
        with open(AUDIT_JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        summary_txt = os.path.join(LOGS_DIR, "waf_execution_summary.txt")
        with open(summary_txt, "w", encoding="utf-8") as f:
            f.write("=" * 70 + "\n")
            f.write("SQROCK WAF ENGINE EXECUTION SUMMARY\n")
            f.write(f"Generated: {report['metadata']['generated_at']}\n")
            f.write("=" * 70 + "\n")
            f.write(f"Total Inspected: {self.stats['total_inspected']}\n")
            f.write(f"Total Allowed:   {self.stats['total_allowed']}\n")
            f.write(f"Total Blocked:   {self.stats['total_blocked']}\n")
            f.write("\nAttack Categories Detected:\n")
            for cat, count in self.stats["categories"].items():
                f.write(f" - {cat}: {count}\n")
            f.write("=" * 70 + "\n")

        return AUDIT_JSON_PATH


def display_rules():
    print(f"\n{Fore.YELLOW}[*] Active Core WAF Rule Sets & Signatures:{Style.RESET_ALL}")
    print("-" * 80)
    print(f"{'Rule ID':<14} | {'Category':<24} | {'Sev':<8} | {'Score':<5} | {'Description'}")
    print("-" * 80)
    for r in CORE_WAF_RULES:
        sev_color = Fore.RED if r["severity"] == "CRITICAL" else Fore.YELLOW
        print(f"{Fore.CYAN}{r['id']:<14}{Style.RESET_ALL} | {r['category']:<24} | {sev_color}{r['severity']:<8}{Style.RESET_ALL} | {r['score']:<5} | {r['description']}")
    print("-" * 80 + "\n")


def run_batch_inspection(engine, filepath=DEFAULT_TRAFFIC_FILE):
    if not os.path.exists(filepath):
        print(f"{Fore.RED}[!] Traffic file not found: {filepath}{Style.RESET_ALL}")
        return

    with open(filepath, "r", encoding="utf-8") as f:
        requests = json.load(f)

    print(f"\n{Fore.GREEN}[+] Ingesting traffic batch: {len(requests)} HTTP requests loaded from {os.path.basename(filepath)}...{Style.RESET_ALL}\n")
    print(f"{'ID':<8} | {'IP Address':<15} | {'Method':<6} | {'Path':<24} | {'Action':<7} | {'Status':<6} | {'Violation'}")
    print("-" * 90)

    for req in requests:
        res = engine.inspect_request(req)
        if res["action"] == "BLOCK":
            action_col = f"{Fore.RED}{Style.BRIGHT}BLOCK{Style.RESET_ALL}"
            status_col = f"{Fore.RED}403{Style.RESET_ALL}"
            violation_str = f"{res['primary_category']} ({res['violations'][0]['rule_id']})"
        else:
            action_col = f"{Fore.GREEN}{Style.BRIGHT}ALLOW{Style.RESET_ALL}"
            status_col = f"{Fore.GREEN}200{Style.RESET_ALL}"
            violation_str = "CLEAN (Passed)"

        short_path = res['path'] if len(res['path']) <= 24 else res['path'][:21] + "..."
        print(f"{res['request_id']:<8} | {res['client_ip']:<15} | {res['method']:<6} | {short_path:<24} | {action_col:<16} | {status_col:<15} | {violation_str}")

    print("-" * 90)
    audit_file = engine.save_audit_report()
    print(f"\n{Fore.GREEN}[+] Batch processing complete! Total: {engine.stats['total_inspected']} | Allowed: {engine.stats['total_allowed']} | Blocked: {engine.stats['total_blocked']}{Style.RESET_ALL}")
    print(f"[+] Audit JSON report saved to: {audit_file}")
    print(f"[+] Blocked events log saved to: {BLOCKED_LOG_PATH}\n")


def interactive_cli():
    print(BANNER)
    engine = WAFEngine()

    while True:
        print(f"{Fore.YELLOW}Select WAF Operations Menu Option:{Style.RESET_ALL}")
        print("  1) Run Automated Traffic Batch Inspection (Default Corpus)")
        print("  2) Inspect Custom Raw HTTP Request String")
        print("  3) Display Active Core WAF Rules & Threat Signatures")
        print("  4) View Blocked Security Incident Event Log")
        print("  5) Export Full WAF Audit Report (JSON & TXT)")
        print("  6) Exit WAF Console")

        choice = input(f"\n{Fore.CYAN}Enter Choice [1-6]: {Style.RESET_ALL}").strip()

        if choice == "1":
            run_batch_inspection(engine)
        elif choice == "2":
            print(f"\n{Fore.CYAN}[*] Custom Request Injection Simulation:{Style.RESET_ALL}")
            ip = input("Client IP [e.g. 10.0.0.99]: ").strip() or "10.0.0.99"
            method = input("HTTP Method [GET/POST]: ").strip().upper() or "GET"
            path = input("URL Path [e.g. /search]: ").strip() or "/search"
            query = input("Query String [e.g. q=test]: ").strip() or "q=test"
            body = input("Body payload (optional): ").strip()
            ua = input("User-Agent (optional): ").strip() or "Mozilla/5.0 SecurityTester"

            custom_req = {
                "id": "CUSTOM-01",
                "method": method,
                "path": path,
                "query": query,
                "headers": {"User-Agent": ua},
                "body": body,
                "client_ip": ip
            }
            res = engine.inspect_request(custom_req)
            if res["action"] == "BLOCK":
                print(f"\n{Fore.RED}{Style.BRIGHT}[403 FORBIDDEN] REQUEST BLOCKED BY WAF!{Style.RESET_ALL}")
                print(f"Primary Violation: {res['primary_category']}")
                print(f"Risk Score: {res['risk_score']} / 10.0")
                for v in res["violations"]:
                    print(f" - Rule: {v['rule_id']} | Target: {v['target']} | Matched: {v['matched_string']}")
            else:
                print(f"\n{Fore.GREEN}{Style.BRIGHT}[200 OK] REQUEST ALLOWED - CLEAN{Style.RESET_ALL}\n")
        elif choice == "3":
            display_rules()
        elif choice == "4":
            if os.path.exists(BLOCKED_LOG_PATH):
                print(f"\n{Fore.RED}[*] Showing Recent Blocked Incidents ({BLOCKED_LOG_PATH}):{Style.RESET_ALL}")
                with open(BLOCKED_LOG_PATH, "r", encoding="utf-8") as f:
                    print(f.read())
            else:
                print(f"\n{Fore.YELLOW}[*] No blocked incidents recorded yet.{Style.RESET_ALL}\n")
        elif choice == "5":
            audit_file = engine.save_audit_report()
            print(f"\n{Fore.GREEN}[+] WAF audit report exported to {audit_file}{Style.RESET_ALL}\n")
        elif choice == "6":
            print(f"\n{Fore.CYAN}[*] Exiting WAF Sentinel. Stay secure!{Style.RESET_ALL}\n")
            break
        else:
            print(f"{Fore.RED}[!] Invalid choice. Please enter 1-6.{Style.RESET_ALL}\n")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--batch":
        eng = WAFEngine()
        run_batch_inspection(eng)
    else:
        interactive_cli()
