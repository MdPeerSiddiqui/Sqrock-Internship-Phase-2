#!/usr/bin/env python3
"""
PEER'S SQL Injection (SQLi) Log Detection Engine - Web Attack Telemetry Parser
Sqrock IT Solutions - Cybersecurity Internship Phase 2 (Day 18)
Author: Mohammed Peer Siddiqui
License: MIT
"""

import os
import sys
import re
import json
import urllib.parse
from datetime import datetime
from collections import defaultdict
from colorama import init, Fore, Style

init(autoreset=True)

# Standard Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
ALERTS_DIR = os.path.join(BASE_DIR, "alerts")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
DEFAULT_LOG = os.path.join(LOGS_DIR, "web_access.log")
DEFAULT_JSON = os.path.join(ALERTS_DIR, "sqli_alerts.json")
DEFAULT_TXT = os.path.join(ALERTS_DIR, "sqli_triage_summary.txt")

os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(ALERTS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# Advanced SQL Injection Pattern Signatures
SQLI_SIGNATURES = {
    "UNION_BASED": {
        "pattern": re.compile(r"(?i)\bUNION\s+(ALL\s+)?SELECT\b"),
        "severity": "CRITICAL",
        "category": "In-Band Data Exfiltration",
        "description": "Appends malicious database result sets to legitimate query responses."
    },
    "BOOLEAN_BASED": {
        "pattern": re.compile(r"(?i)('|%27)\s*(OR|AND)\s*(\d+=\d+|'[^']*'='[^']*'|[a-z0-9_]+=[a-z0-9_]+)"),
        "severity": "HIGH",
        "category": "Authentication Bypass / Logical Tautology",
        "description": "Manipulates SQL Boolean logic to force unconditional TRUE evaluations."
    },
    "TIME_BASED_BLIND": {
        "pattern": re.compile(r"(?i)(WAITFOR\s+DELAY|pg_sleep\s*\(|sleep\s*\(|benchmark\s*\()"),
        "severity": "CRITICAL",
        "category": "Blind Inference Exploitation",
        "description": "Forces database thread sleep pauses to extract binary data bit-by-bit."
    },
    "STACKED_QUERIES": {
        "pattern": re.compile(r"(?i);\s*(DROP|ALTER|CREATE|INSERT|UPDATE|DELETE|SHUTDOWN)\b"),
        "severity": "CRITICAL",
        "category": "Destructive Data Modification",
        "description": "Executes subsequent administrative SQL commands terminated by semicolons."
    },
    "COMMENT_TRUNCATION": {
        "pattern": re.compile(r"(--|#|/\*|%23)"),
        "severity": "MEDIUM",
        "category": "Query Tail Truncation",
        "description": "Neutralizes remainder of backend query logic using inline SQL comments."
    },
    "METADATA_DISCOVERY": {
        "pattern": re.compile(r"(?i)\bFROM\s+information_schema\b"),
        "severity": "HIGH",
        "category": "Schema Enumeration",
        "description": "Probes relational metadata dictionaries for table and column listings."
    }
}


class SQLiLogDetector:
    """Enterprise Web Access Log Parser & SQL Injection Detection Engine."""

    def __init__(self, log_path=DEFAULT_LOG):
        self.log_path = log_path
        self.parsed_entries = []
        self.detected_alerts = []
        self.ip_attack_summary = defaultdict(list)

    def load_and_parse_logs(self, custom_path=None, mock_logs=None):
        """Parse raw web access logs into structured request objects."""
        raw_lines = []
        if mock_logs is not None:
            raw_lines = mock_logs
        else:
            target = custom_path or self.log_path
            if not os.path.exists(target):
                raise FileNotFoundError(f"Log file not found: {target}")
            with open(target, "r", encoding="utf-8") as f:
                raw_lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        # Common / Combined Log Format Regex:
        # IP - - [timestamp] "METHOD /path HTTP/1.1" status bytes "referer" "user-agent"
        log_re = re.compile(
            r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d+)\s+(?P<bytes>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
        )

        self.parsed_entries = []
        for line in raw_lines:
            m = log_re.match(line)
            if m:
                uri = m.group("uri")
                decoded_uri = urllib.parse.unquote(uri)
                self.parsed_entries.append({
                    "ip": m.group("ip"),
                    "timestamp": m.group("timestamp"),
                    "method": m.group("method"),
                    "raw_uri": uri,
                    "decoded_uri": decoded_uri,
                    "protocol": m.group("protocol"),
                    "status_code": int(m.group("status")),
                    "bytes": m.group("bytes"),
                    "referer": m.group("referer") or "-",
                    "user_agent": m.group("ua") or "-",
                    "raw_log": line
                })
            else:
                # Fallback simple line parser
                parts = line.split(" ")
                ip = parts[0] if parts else "0.0.0.0"
                decoded_uri = urllib.parse.unquote(line)
                self.parsed_entries.append({
                    "ip": ip,
                    "timestamp": datetime.now().isoformat(),
                    "method": "RAW",
                    "raw_uri": line,
                    "decoded_uri": decoded_uri,
                    "protocol": "HTTP/1.1",
                    "status_code": 0,
                    "bytes": "0",
                    "referer": "-",
                    "user_agent": "-",
                    "raw_log": line
                })

        return len(self.parsed_entries)

    def scan_for_sqli(self):
        """Evaluate decoded URI request parameters against multi-pattern SQLi signatures."""
        if not self.parsed_entries:
            self.load_and_parse_logs()

        self.detected_alerts = []
        self.ip_attack_summary = defaultdict(list)

        for entry in self.parsed_entries:
            matched_threats = []
            target_text = f"{entry['decoded_uri']} {entry['raw_log']}"

            for sig_key, sig_data in SQLI_SIGNATURES.items():
                m = sig_data["pattern"].search(target_text)
                if m:
                    matched_threats.append({
                        "signature_key": sig_key,
                        "matched_string": m.group(0),
                        "severity": sig_data["severity"],
                        "category": sig_data["category"],
                        "description": sig_data["description"]
                    })

            if matched_threats:
                # Highest severity priority
                sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
                matched_threats.sort(key=lambda x: sev_order.get(x["severity"], 99))
                top_threat = matched_threats[0]

                alert = {
                    "alert_id": f"ALRT-SQLI-{len(self.detected_alerts) + 1:03d}",
                    "timestamp": entry["timestamp"],
                    "source_ip": entry["ip"],
                    "method": entry["method"],
                    "target_endpoint": entry["raw_uri"].split("?")[0],
                    "raw_query_string": entry["decoded_uri"],
                    "http_status": entry["status_code"],
                    "primary_attack_type": top_threat["signature_key"],
                    "severity": top_threat["severity"],
                    "category": top_threat["category"],
                    "signature_matches": [t["signature_key"] for t in matched_threats],
                    "user_agent": entry["user_agent"],
                    "remediation": "Convert vulnerable endpoint query to parameterized Prepared Statements (PDO / parameterized ORM)."
                }
                self.detected_alerts.append(alert)
                self.ip_attack_summary[entry["ip"]].append(alert)

        return self.detected_alerts

    def get_prepared_statement_comparison(self):
        """Generate architectural comparison between vulnerable concatenated SQL and Prepared Statements."""
        return {
            "vulnerable_pattern": {
                "paradigm": "Unsanitized Dynamic String Concatenation",
                "code_sample": "cursor.execute(\"SELECT * FROM users WHERE user = '\" + input_user + \"' AND pass = '\" + input_pass + \"'\")",
                "execution_mechanics": "The database query parser evaluates user input as operational SQL grammar, allowing injected syntax (' OR 1=1) to modify the Abstract Syntax Tree (AST)."
            },
            "secure_pattern": {
                "paradigm": "Pre-Compiled Prepared Statements (Parameterized Queries)",
                "code_sample": "cursor.execute(\"SELECT * FROM users WHERE user = %s AND pass = %s\", (input_user, input_pass))",
                "execution_mechanics": "The database compiles the SQL statement template into a binary execution plan BEFORE parameters are bound. User input is treated strictly as literal data strings."
            }
        }

    def export_reports(self, json_path=DEFAULT_JSON, txt_path=DEFAULT_TXT):
        """Export structured JSON and analyst-facing triage briefings."""
        if not self.detected_alerts:
            self.scan_for_sqli()

        dossier = {
            "metadata": {
                "organization": "Sqrock IT Solutions",
                "suite": "PEER'S SQL Injection Log Detection Engine v2.0",
                "developer": "Mohammed Peer Siddiqui",
                "log_source": self.log_path,
                "audit_timestamp": datetime.now().isoformat(),
                "total_logs_analyzed": len(self.parsed_entries),
                "total_attacks_detected": len(self.detected_alerts),
                "unique_adversary_ips": len(self.ip_attack_summary)
            },
            "severity_breakdown": {
                "CRITICAL": sum(1 for a in self.detected_alerts if a["severity"] == "CRITICAL"),
                "HIGH": sum(1 for a in self.detected_alerts if a["severity"] == "HIGH"),
                "MEDIUM": sum(1 for a in self.detected_alerts if a["severity"] == "MEDIUM"),
                "LOW": sum(1 for a in self.detected_alerts if a["severity"] == "LOW")
            },
            "alerts": self.detected_alerts,
            "ip_threat_matrix": {ip: len(alerts) for ip, alerts in self.ip_attack_summary.items()},
            "prepared_statement_defense": self.get_prepared_statement_comparison()
        }

        # Write JSON
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(dossier, f, indent=2)

        # Write TXT
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("     SQROCK IT SOLUTIONS - SQL INJECTION LOG DETECTION AUDIT BRIEFING\n")
            f.write("=" * 80 + "\n")
            f.write(f"Analyzed Log Path      : {dossier['metadata']['log_source']}\n")
            f.write(f"Audit Timestamp        : {dossier['metadata']['audit_timestamp']}\n")
            f.write(f"Total Requests Scanned : {dossier['metadata']['total_logs_analyzed']}\n")
            f.write(f"Total Malicious Events : {dossier['metadata']['total_attacks_detected']}\n")
            f.write(f"Unique Attacker Hosts  : {dossier['metadata']['unique_adversary_ips']}\n")
            f.write(f"Critical Severity      : {dossier['severity_breakdown']['CRITICAL']}\n")
            f.write(f"High Severity          : {dossier['severity_breakdown']['HIGH']}\n")
            f.write("-" * 80 + "\n\n")

            f.write("--- 1. ACTIVE SQL INJECTION DETECTIONS ---\n")
            for a in self.detected_alerts:
                f.write(f"[{a['severity']}] {a['alert_id']} - {a['primary_attack_type']}\n")
                f.write(f"  Source IP     : {a['source_ip']} (Status: {a['http_status']})\n")
                f.write(f"  Target Route  : {a['method']} {a['target_endpoint']}\n")
                f.write(f"  Injected String: {a['raw_query_string']}\n")
                f.write(f"  User-Agent    : {a['user_agent']}\n")
                f.write(f"  Remediation   : {a['remediation']}\n\n")

            f.write("--- 2. ADVERSARY IP THREAT CONCENTRATION ---\n")
            for ip, count in dossier["ip_threat_matrix"].items():
                f.write(f"  Host: {ip:<18} -> {count} malicious attack payloads intercepted\n")
            f.write("\n" + "-" * 80 + "\n")

        return dossier


def print_banner():
    """Display Kali terminal banner."""
    print(Fore.CYAN + Style.BRIGHT + r"""
   _____  ____  _      _____   _____  ______ _______ ______ _____ _______ ____  _____  
  / ____|/ __ \| |    |_   _| |  __ \|  ____|__   __|  ____/ ____|__   __/ __ \|  __ \ 
 | (___ | |  | | |      | |   | |  | | |__     | |  | |__ | |       | | | |  | | |__) |
  \___ \| |  | | |      | |   | |  | |  __|    | |  |  __|| |       | | | |  | |  _  / 
  ____) | |__| | |____ _| |_  | |__| | |____   | |  | |___| |____   | | | |__| | | \ \ 
 |_____/ \___\_\______|_____| |_____/|______|  |_|  |______\_____|  |_|  \____/|_|  \_\
    """ + Style.RESET_ALL)
    print(Fore.YELLOW + " [*] Enterprise Web Access Telemetry Parser & SQLi Detection Engine v2.0")
    print(Fore.GREEN + " [*] Developer: Mohammed Peer Siddiqui | Sqrock IT Solutions Phase 2 (Day 18)")
    print(Fore.WHITE + " [*] Standards: OWASP Top 10 A03:2021 (Injection) | MITRE ATT&CK T1190 | CWE-89\n")


def run_interactive_menu():
    """CLI driver loop."""
    detector = SQLiLogDetector()
    detector.load_and_parse_logs()
    detector.scan_for_sqli()

    while True:
        print_banner()
        print(Fore.LIGHTBLUE_EX + " [=== MASTER SQLI LOG DETECTION MENU ===]")
        print(Fore.WHITE + " [1] Ingest & Parse Web Server Access Logs")
        print(Fore.WHITE + " [2] Run Multi-Signature SQLi Threat Correlation")
        print(Fore.WHITE + " [3] Inspect Attacker IP Threat Distribution")
        print(Fore.WHITE + " [4] Review Prepared Statements vs Dynamic Concatenation Analysis")
        print(Fore.WHITE + " [5] Export SQLi Incident Triage Audits (JSON & TXT)")
        print(Fore.WHITE + " [6] Exit Suite\n")

        try:
            choice = input(Fore.CYAN + " sqli-parser@sqrock-soc:~$ " + Style.RESET_ALL).strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting SQLi Detector...")
            break

        if choice == "1":
            print(Fore.YELLOW + f"\n[*] Ingesting access telemetry from: {detector.log_path}")
            count = detector.load_and_parse_logs()
            print(Fore.GREEN + f"[+] Successfully parsed {count} web server request transactions.\n")
            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == "2":
            print(Fore.YELLOW + "\n[*] Scanning query strings and URI parameters against SQLi signatures...")
            alerts = detector.scan_for_sqli()
            print(Fore.GREEN + f"[+] Scan complete! Intercepted {len(alerts)} malicious SQLi event(s):\n")

            for a in alerts:
                sev_col = Fore.RED if a["severity"] == "CRITICAL" else Fore.YELLOW
                print(f" {sev_col}[{a['severity']}] {Fore.WHITE}{a['alert_id']} - {a['primary_attack_type']}")
                print(f"   {Fore.CYAN}Source IP    : {Style.RESET_ALL}{a['source_ip']} | {Fore.LIGHTBLUE_EX}Status: {a['http_status']}")
                print(f"   {Fore.WHITE}Target Route : {a['method']} {a['target_endpoint']}")
                print(f"   {Fore.RED}Injected SQL : {a['raw_query_string'][:70]}...")
                print(f"   {Fore.LIGHTBLACK_EX}User-Agent   : {a['user_agent']}\n")
            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == "3":
            print(Fore.YELLOW + "\n[=== ATTACKER IP THREAT CONCENTRATION MATRIX ===]\n")
            for ip, alert_list in detector.ip_attack_summary.items():
                print(Fore.RED + f"[!] Source Host: {ip}")
                print(Fore.WHITE + f"    Total Exploit Payloads : {len(alert_list)}")
                attack_types = set([a["primary_attack_type"] for a in alert_list])
                print(Fore.YELLOW + f"    Observed Vectors       : {', '.join(attack_types)}\n")
            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == "4":
            print(Fore.YELLOW + "\n[=== ARCHITECTURAL ANALYSIS: PREPARED STATEMENTS DEFENSE ===]\n")
            comp = detector.get_prepared_statement_comparison()
            print(Fore.RED + f"[-] Vulnerable Dynamic Concatenation:")
            print(Fore.WHITE + f"    {comp['vulnerable_pattern']['code_sample']}")
            print(Fore.LIGHTBLACK_EX + f"    Impact: {comp['vulnerable_pattern']['execution_mechanics']}\n")

            print(Fore.GREEN + f"[+] Secure Parameterized Prepared Statements:")
            print(Fore.WHITE + f"    {comp['secure_pattern']['code_sample']}")
            print(Fore.LIGHTBLACK_EX + f"    Defense: {comp['secure_pattern']['execution_mechanics']}\n")
            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == "5":
            print(Fore.YELLOW + "\n[*] Compiling formal SQLi Incident Triage Audits...")
            detector.export_reports()
            print(Fore.GREEN + f"[+] JSON Report exported: {DEFAULT_JSON}")
            print(Fore.GREEN + f"[+] TXT Dossier exported : {DEFAULT_TXT}\n")
            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == "6":
            print(Fore.CYAN + "\n[*] Shutting down SQLi Detection console. Goodbye!\n")
            break
        else:
            print(Fore.RED + "\n[!] Invalid choice. Please select 1-6.\n")


if __name__ == "__main__":
    if len(sys.argv) > 1 and "--batch" in sys.argv:
        auditor = SQLiLogDetector()
        auditor.load_and_parse_logs()
        auditor.scan_for_sqli()
        auditor.export_reports()
        print("[+] Headless SQLi Detection run complete.")
    else:
        run_interactive_menu()
