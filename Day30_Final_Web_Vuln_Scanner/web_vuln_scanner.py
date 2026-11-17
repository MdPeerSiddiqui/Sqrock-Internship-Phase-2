#!/usr/bin/env python3
"""
PEER'S Automated Web Vulnerability Scanner - Capstone Final Project (Day 30)
Sqrock IT Solutions Cybersecurity Internship Phase 2: Web Application Security & Defensive Automation

Author: Mohammed Peer Siddiqui
Role: Cybersecurity Intern
Company: Sqrock IT Solutions
Module: Capstone Unified Modular Web Vulnerability Assessment & Penetration Testing Engine

Architectural Modules:
1. Target Reconnaissance & Technology Stack Fingerprinting
2. HTTP Security Header Deep Audit (Day 16)
3. Network Attack Surface & Port Exposure Scanner (Day 17)
4. Sensitive Directory & Backup File Discovery Fuzzer (Day 20)
5. Web Application Injection Prober (SQLi & XSS) (Day 18, 21, 26)
6. Composite Risk Scoring & Compliance Evaluation Engine
"""

import os
import sys
import json
from datetime import datetime, timezone
from colorama import init, Fore, Style

init(autoreset=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")
RESULTS_DIR = os.path.join(BASE_DIR, "audit_results")
TARGETS_FILE = os.path.join(SAMPLES_DIR, "scan_targets.json")
AUDIT_JSON_PATH = os.path.join(RESULTS_DIR, "final_audit_report.json")
SUMMARY_TXT_PATH = os.path.join(RESULTS_DIR, "scan_executive_summary.txt")

BANNER = f"""
{Fore.CYAN}{Style.BRIGHT}================================================================================
     PEER'S CAPSTONE AUTOMATED WEB VULNERABILITY SCANNER v2.0
   Sqrock IT Solutions | Internship Phase 2 Capstone Project (Day 30)
   Candidate: Mohammed Peer Siddiqui  |  Status: ACTIVE AUDIT
================================================================================{Style.RESET_ALL}
"""

MANDATORY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]


class WebVulnerabilityScanner:
    def __init__(self, targets_file=TARGETS_FILE):
        self.targets_file = targets_file
        os.makedirs(RESULTS_DIR, exist_ok=True)
        self.targets = self._load_targets()
        self.scan_results = []

    def _load_targets(self):
        if os.path.exists(self.targets_file):
            with open(self.targets_file, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    def audit_target(self, target_data):
        """Execute all 5 modular auditing phases against target."""
        target_url = target_data.get("target_url")
        hostname = target_data.get("hostname")
        ip = target_data.get("ip_address")

        findings = []

        # Module 1: Recon & Banner Information Leakage
        headers = target_data.get("mock_headers", {})
        server_banner = headers.get("Server", "Unknown")
        powered_by = headers.get("X-Powered-By")
        if "Apache" in server_banner or "PHP" in str(powered_by):
            findings.append({
                "id": "VULN-RECON-01",
                "module": "Reconnaissance & Fingerprinting",
                "title": "Server Technology & Version Information Leakage",
                "severity": "LOW",
                "cvss_score": 3.5,
                "target": f"{hostname} (Server: {server_banner}, X-Powered-By: {powered_by})",
                "description": "Web server discloses exact vendor and version strings, assisting attacker exploit targeting.",
                "remediation": "Disable ServerTokens and expose generic headers (Server: webserver)."
            })

        # Module 2: Security Header Analysis (Day 16)
        missing_headers = [h for h in MANDATORY_HEADERS if h not in headers]
        if missing_headers:
            findings.append({
                "id": "VULN-HDR-02",
                "module": "HTTP Security Headers",
                "title": f"Missing Essential Security Headers ({len(missing_headers)} missing)",
                "severity": "MEDIUM",
                "cvss_score": 5.8,
                "target": target_url,
                "description": f"Missing headers: {', '.join(missing_headers)}. Increases exposure to XSS, Clickjacking, and MIME confusion.",
                "remediation": "Configure web server or reverse proxy to inject all 6 mandatory security headers."
            })

        # Module 3: Network Attack Surface & Port Exposure (Day 17)
        open_ports = target_data.get("mock_open_ports", [])
        risky_ports = [p for p in open_ports if p not in (80, 443)]
        if risky_ports:
            findings.append({
                "id": "VULN-NET-03",
                "module": "Port Exposure & Attack Surface",
                "title": f"Non-Standard Administrative Ports Open ({risky_ports})",
                "severity": "MEDIUM",
                "cvss_score": 6.2,
                "target": f"{ip}:{risky_ports}",
                "description": f"Target exposes open ports {risky_ports} directly to ingress traffic.",
                "remediation": "Restrict administrative ports to VPN or internal management subnets via border firewall."
            })

        # Module 4: Sensitive Directory & Backup Fuzzer (Day 20)
        dirs = target_data.get("mock_directories", {})
        exposed_sensitive = [k for k, v in dirs.items() if v == 200 and k in ("/.env", "/backup.sql", "/.git/")]
        if exposed_sensitive:
            findings.append({
                "id": "VULN-DIR-04",
                "module": "Directory & File Fuzzing",
                "title": f"Critical Information Disclosure: Exposed Sensitive Files ({', '.join(exposed_sensitive)})",
                "severity": "CRITICAL",
                "cvss_score": 9.6,
                "target": f"{target_url}{exposed_sensitive[0]}",
                "description": "Environment credentials, database backup dumps, or source repositories are publicly accessible.",
                "remediation": "Block access to dotfiles and SQL dumps via web server configuration."
            })

        # Module 5: Application Web Injection Prober (SQLi & XSS) (Day 18, 21, 26)
        endpoints = target_data.get("mock_endpoints", [])
        for ep in endpoints:
            if ep.get("vuln_sqli"):
                findings.append({
                    "id": "VULN-INJ-05",
                    "module": "Application Injection Prober",
                    "title": "SQL Injection Vulnerability in Search Parameter ('q')",
                    "severity": "CRITICAL",
                    "cvss_score": 9.8,
                    "target": f"{ep.get('url')}?q=",
                    "description": "Parameter is concatenated directly into SQL queries without parameterization.",
                    "remediation": "Use prepared statements and ORM parameterized queries."
                })
            if ep.get("vuln_xss"):
                findings.append({
                    "id": "VULN-XSS-06",
                    "module": "Application Injection Prober",
                    "title": "Reflected Cross-Site Scripting (XSS) in Parameter ('q')",
                    "severity": "HIGH",
                    "cvss_score": 8.5,
                    "target": f"{ep.get('url')}?q=",
                    "description": "User input in search parameter is reflected without context-aware HTML entity encoding.",
                    "remediation": "Implement strict HTML encoding and enforce Content-Security-Policy."
                })

        # Module 6: Risk Calculation
        total_vulns = len(findings)
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        total_cvss = 0.0

        for f in findings:
            sev = f["severity"]
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            total_cvss += f["cvss_score"]

        # Composite Security Score (100 - cumulative deductions, clamped 0 - 100)
        # Deductions: Critical -25 each, High -15 each, Medium -8 each, Low -3 each
        deductions = (sev_counts["CRITICAL"] * 25) + (sev_counts["HIGH"] * 15) + (sev_counts["MEDIUM"] * 8) + (sev_counts["LOW"] * 3)
        security_score = max(0, 100 - deductions)

        if security_score >= 85:
            posture = "SECURE / HARDENED"
        elif security_score >= 65:
            posture = "ACCEPTABLE (Minor Flaws)"
        elif security_score >= 40:
            posture = "ELEVATED RISK"
        else:
            posture = "CRITICAL EXPOSURE"

        audit_entry = {
            "target_id": target_data.get("id"),
            "target_url": target_url,
            "hostname": hostname,
            "ip_address": ip,
            "environment": target_data.get("environment"),
            "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "security_score": security_score,
            "security_posture": posture,
            "total_findings": total_vulns,
            "severity_breakdown": sev_counts,
            "findings": findings
        }

        self.scan_results.append(audit_entry)
        return audit_entry

    def save_reports(self):
        """Export Capstone audit results to JSON and TXT."""
        report = {
            "metadata": {
                "system": "PEER'S Capstone Automated Web Vulnerability Scanner",
                "organization": "Sqrock IT Solutions",
                "internship_track": "Phase 2: Web App Security & Defensive Automation (Capstone Day 30)",
                "candidate": "Mohammed Peer Siddiqui",
                "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            },
            "targets_scanned": len(self.scan_results),
            "audits": self.scan_results
        }

        with open(AUDIT_JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        with open(SUMMARY_TXT_PATH, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("SQROCK CAPSTONE AUTOMATED WEB VULNERABILITY SCANNER - AUDIT SUMMARY\n")
            f.write(f"Generated: {report['metadata']['generated_at']}\n")
            f.write("=" * 80 + "\n\n")
            for a in self.scan_results:
                f.write(f"Target:          {a['target_url']} ({a['ip_address']})\n")
                f.write(f"Environment:     {a['environment']}\n")
                f.write(f"Security Score:  {a['security_score']} / 100 ({a['security_posture']})\n")
                f.write(f"Total Findings:  {a['total_findings']}\n")
                f.write(f"Breakdown:       Critical: {a['severity_breakdown']['CRITICAL']} | High: {a['severity_breakdown']['HIGH']} | Med: {a['severity_breakdown']['MEDIUM']} | Low: {a['severity_breakdown']['LOW']}\n")
                f.write("-" * 80 + "\n")

        return AUDIT_JSON_PATH, SUMMARY_TXT_PATH


def print_audit_findings(audit_entry):
    print(f"\n{Fore.YELLOW}[*] Target Audit Results: {audit_entry['target_url']}{Style.RESET_ALL}")
    print(f"  Security Score:   {Fore.RED if audit_entry['security_score'] < 50 else Fore.GREEN}{Style.BRIGHT}{audit_entry['security_score']} / 100 ({audit_entry['security_posture']}){Style.RESET_ALL}")
    print(f"  Total Findings:   {audit_entry['total_findings']} vulnerabilities identified across 5 security modules")
    print("-" * 95)
    print(f"{'Finding ID':<14} | {'Module':<24} | {'Severity':<9} | {'CVSS':<5} | {'Vulnerability Title'}")
    print("-" * 95)
    for f in audit_entry["findings"]:
        sev = f["severity"]
        if sev == "CRITICAL":
            sev_col = f"{Fore.RED}{Style.BRIGHT}{sev:<9}{Style.RESET_ALL}"
        elif sev == "HIGH":
            sev_col = f"{Fore.RED}{sev:<9}{Style.RESET_ALL}"
        elif sev == "MEDIUM":
            sev_col = f"{Fore.YELLOW}{sev:<9}{Style.RESET_ALL}"
        else:
            sev_col = f"{Fore.GREEN}{sev:<9}{Style.RESET_ALL}"

        print(f"{Fore.CYAN}{f['id']:<14}{Style.RESET_ALL} | {f['module']:<24} | {sev_col} | {f['cvss_score']:<5} | {f['title']}")
    print("-" * 95 + "\n")


def interactive_cli():
    print(BANNER)
    scanner = WebVulnerabilityScanner()

    while True:
        print(f"{Fore.YELLOW}Select Capstone Scanner Menu Option:{Style.RESET_ALL}")
        print("  1) Execute Full Audit Scan: Staging Web Portal (Target 1 - Vulnerable)")
        print("  2) Execute Full Audit Scan: Production Hardened Gateway (Target 2)")
        print("  3) Display Audit Findings for All Scanned Targets")
        print("  4) View Executive Security Risk Scoreboard")
        print("  5) Export Capstone Audit Telemetry (JSON & TXT)")
        print("  6) Exit Capstone Console")

        choice = input(f"\n{Fore.CYAN}Enter Choice [1-6]: {Style.RESET_ALL}").strip()

        if choice == "1":
            t1 = scanner.targets[0]
            print(f"\n{Fore.CYAN}[*] Launching Comprehensive Capstone Audit on {t1['target_url']}...{Style.RESET_ALL}")
            res = scanner.audit_target(t1)
            print_audit_findings(res)

        elif choice == "2":
            if len(scanner.targets) > 1:
                t2 = scanner.targets[1]
                print(f"\n{Fore.CYAN}[*] Launching Comprehensive Capstone Audit on {t2['target_url']}...{Style.RESET_ALL}")
                res = scanner.audit_target(t2)
                print_audit_findings(res)
            else:
                print(f"{Fore.RED}[!] Target 2 not found in targets list.{Style.RESET_ALL}\n")

        elif choice == "3":
            if not scanner.scan_results:
                print(f"{Fore.YELLOW}[*] No scans executed yet. Running automatic audit on Target 1...{Style.RESET_ALL}")
                scanner.audit_target(scanner.targets[0])
            for r in scanner.scan_results:
                print_audit_findings(r)

        elif choice == "4":
            print(f"\n{Fore.CYAN}[*] Capstone Executive Risk Scoreboard:{Style.RESET_ALL}")
            print("-" * 80)
            print(f"{'Target URL':<40} | {'Score':<8} | {'Posture':<20} | {'Vulns'}")
            print("-" * 80)
            for r in scanner.scan_results:
                score_col = Fore.RED if r["security_score"] < 50 else Fore.GREEN
                print(f"{r['target_url']:<40} | {score_col}{r['security_score']:<8}{Style.RESET_ALL} | {r['security_posture']:<20} | {r['total_findings']}")
            print("-" * 80 + "\n")

        elif choice == "5":
            j_path, t_path = scanner.save_reports()
            print(f"\n{Fore.GREEN}[+] Capstone audit reports exported successfully:{Style.RESET_ALL}")
            print(f"  - Full Audit JSON: {j_path}")
            print(f"  - Executive TXT:   {t_path}\n")

        elif choice == "6":
            print(f"\n{Fore.CYAN}[*] Exiting Capstone Scanner. Internship Phase 2 Complete!{Style.RESET_ALL}\n")
            break
        else:
            print(f"{Fore.RED}[!] Invalid choice. Please enter 1-6.{Style.RESET_ALL}\n")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--scan":
        sc = WebVulnerabilityScanner()
        for t in sc.targets:
            sc.audit_target(t)
        j, t = sc.save_reports()
        print(f"[+] Capstone scan complete. Reports saved to {j} and {t}")
    else:
        interactive_cli()
