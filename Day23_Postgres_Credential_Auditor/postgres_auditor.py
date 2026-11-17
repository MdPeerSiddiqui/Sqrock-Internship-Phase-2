"""
PEER'S PostgreSQL Database Credential & Configuration Auditor v2.0
===================================================================
Automated pg_hba.conf Security Analysis, Default Credential Testing & Hardening
CIS PostgreSQL 15 Benchmark v1.0.0 & NIST SP 800-53 (AC-2, IA-5)

Author: Mohammed Peer Siddiqui
Company: Sqrock IT Solutions
Track: Phase 2 - Web Application Security & Defensive Automation (Day 23)
Monorepo: https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2
"""

import os
import sys
import re
import json
import math
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

class PostgresSecurityAuditor:
    """
    Comprehensive security auditor for PostgreSQL databases:
    - Analyzes pg_hba.conf client authentication records
    - Checks default and weak credential dictionary pairs
    - Calculates password Shannon entropy and NIST SP 800-63B complexity
    """

    KNOWN_DEFAULT_CREDENTIALS = [
        ("postgres", "postgres"),
        ("postgres", "root"),
        ("postgres", "admin"),
        ("postgres", "password"),
        ("postgres", "123456"),
        ("admin", "admin"),
        ("app_user", "app_pass"),
        ("readonly", "readonly")
    ]

    METHOD_RISK_MAP = {
        "trust": ("CRITICAL", "Allows unauthenticated connections without password check; complete security bypass."),
        "password": ("HIGH", "Transmits password in cleartext over the wire, vulnerable to network packet sniffing."),
        "md5": ("MEDIUM", "Uses legacy MD5 hash vulnerable to rainbow table collisions and pass-the-hash attacks."),
        "ident": ("MEDIUM", "Relies on client OS username spoofable over non-secure local networks."),
        "scram-sha-256": ("SAFE", "Modern cryptographic salted challenge-response authentication (RFC 7677 compliant)."),
        "peer": ("SAFE", "Validates kernel-level local Unix socket UID/GID credentials."),
        "cert": ("SAFE", "Cryptographic client SSL certificate validation.")
    }

    def __init__(self, pghba_path=None, dict_path=None):
        self.pghba_path = pghba_path
        self.dict_path = dict_path
        self.hba_findings = []
        self.credential_findings = []
        self.metrics = {
            "hba_rules_evaluated": 0,
            "critical_hba_violations": 0,
            "credentials_tested": 0,
            "default_credentials_flagged": 0,
            "weak_passwords_identified": 0
        }

    def audit_pghba(self, filepath=None):
        """Audits pg_hba.conf entries against CIS PostgreSQL Benchmark recommendations."""
        path = filepath or self.pghba_path
        if not path or not os.path.exists(path):
            raise FileNotFoundError(f"pg_hba.conf file '{path}' not found.")

        self.hba_findings = []
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue

            parts = stripped.split()
            con_type = parts[0]

            # Schema: local DATABASE USER METHOD [OPTIONS]
            # Schema: host/hostssl/hostnossl DATABASE USER ADDRESS METHOD [OPTIONS]
            if con_type == "local":
                db = parts[1] if len(parts) > 1 else "all"
                user = parts[2] if len(parts) > 2 else "all"
                address = "local_socket"
                method = parts[3] if len(parts) > 3 else "trust"
            elif con_type in ["host", "hostssl", "hostnossl"]:
                db = parts[1] if len(parts) > 1 else "all"
                user = parts[2] if len(parts) > 2 else "all"
                address = parts[3] if len(parts) > 3 else "0.0.0.0/0"
                method = parts[4] if len(parts) > 4 else "trust"
            else:
                continue

            self.metrics["hba_rules_evaluated"] += 1
            severity, impact = self.METHOD_RISK_MAP.get(
                method.lower(), ("HIGH", "Unknown or non-standard authentication method.")
            )

            is_wide_open = address in ["0.0.0.0/0", "::/0", "all"]
            if is_wide_open and severity in ["CRITICAL", "HIGH"]:
                impact += " Furthermore, rule permits connections from entire global IP address space (0.0.0.0/0)."

            if severity in ["CRITICAL", "HIGH"]:
                self.metrics["critical_hba_violations"] += 1

            self.hba_findings.append({
                "line": idx,
                "raw_rule": stripped,
                "type": con_type,
                "database": db,
                "user": user,
                "address": address,
                "method": method,
                "severity": severity,
                "description": impact,
                "remediation": "Replace with 'hostssl ... scram-sha-256' and restrict address to specific subnet CIDRs."
            })

        return self.hba_findings

    def calculate_entropy(self, password):
        """Calculates Shannon entropy in bits for password strength assessment."""
        if not password:
            return 0.0
        charset_size = 0
        if re.search(r'[a-z]', password): charset_size += 26
        if re.search(r'[A-Z]', password): charset_size += 26
        if re.search(r'[0-9]', password): charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password): charset_size += 32
        return round(len(password) * math.log2(max(1, charset_size)), 2)

    def audit_credentials(self, dict_path=None):
        """Evaluates database credential pairs for default, dictionary, and low-entropy values."""
        path = dict_path or self.dict_path
        pairs = []
        if path and os.path.exists(path):
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and ":" in stripped and not stripped.startswith('#'):
                        u, p = stripped.split(":", 1)
                        pairs.append((u.strip(), p.strip()))
        else:
            pairs = self.KNOWN_DEFAULT_CREDENTIALS

        self.credential_findings = []
        for username, password in pairs:
            self.metrics["credentials_tested"] += 1
            entropy = self.calculate_entropy(password)
            is_default = (username, password) in self.KNOWN_DEFAULT_CREDENTIALS or username == password

            if is_default or password in ["123456", "password", "root", "admin"]:
                severity = "CRITICAL"
                self.metrics["default_credentials_flagged"] += 1
                desc = "Known default or trivial credential pair. Vulnerable to automated brute-force spray."
            elif len(password) < 12 or entropy < 40.0:
                severity = "HIGH"
                self.metrics["weak_passwords_identified"] += 1
                desc = f"Weak password complexity (Entropy: {entropy} bits). Fails NIST SP 800-63B standards."
            else:
                severity = "SAFE"
                desc = f"Strong credential entropy ({entropy} bits). Compliant with enterprise standards."

            self.credential_findings.append({
                "username": username,
                "password_sample": password[:2] + "****" if len(password) > 2 else "****",
                "entropy_bits": entropy,
                "severity": severity,
                "is_default": is_default,
                "description": desc,
                "remediation": "Enforce minimum 16-character alphanumeric passphrase with SCRAM-SHA-256 hashing."
            })

        return self.credential_findings

    def print_cli_summary(self):
        """Renders Kali Linux style interactive database audit console."""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}" + "="*74)
        print(f"{Fore.CYAN}{Style.BRIGHT}  PEER'S POSTGRESQL DATABASE CREDENTIAL & CONFIGURATION AUDITOR v2.0")
        print(f"{Fore.CYAN}{Style.BRIGHT}  CIS PostgreSQL 15 Benchmark | NIST SP 800-53 (AC-2, IA-5) Compliance")
        print(f"{Fore.CYAN}{Style.BRIGHT}" + "="*74 + f"{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Target pg_hba.conf: {Fore.YELLOW}{self.pghba_path}")
        print(f"{Fore.WHITE}Evaluated Rules   : {Fore.GREEN}{len(self.hba_findings)}")
        print(f"{Fore.WHITE}Credentials Tested: {Fore.CYAN}{len(self.credential_findings)}")
        print(f"{Fore.WHITE}Audit Timestamp   : {Fore.LIGHTBLACK_EX}{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")

        print(f"{Fore.YELLOW}{Style.BRIGHT}[+] PG_HBA.CONF AUTHENTICATION RULES AUDIT:{Style.RESET_ALL}")
        print("-" * 74)
        for h in self.hba_findings:
            sev = h["severity"]
            if sev == "CRITICAL":
                sev_str = f"{Fore.RED}{Style.BRIGHT}[CRITICAL]{Style.RESET_ALL}"
            elif sev == "HIGH":
                sev_str = f"{Fore.LIGHTRED_EX}{Style.BRIGHT}[HIGH]    {Style.RESET_ALL}"
            elif sev == "MEDIUM":
                sev_str = f"{Fore.YELLOW}{Style.BRIGHT}[MEDIUM]  {Style.RESET_ALL}"
            else:
                sev_str = f"{Fore.GREEN}{Style.BRIGHT}[SAFE]    {Style.RESET_ALL}"

            print(f"{sev_str} Line {h['line']:<3}: {Fore.WHITE}{h['raw_rule']}")
            print(f"   {Fore.LIGHTBLACK_EX}Impact: {h['description']}")
            print(f"   {Fore.CYAN}Fix   : {h['remediation']}\n")

        print(f"{Fore.YELLOW}{Style.BRIGHT}[+] DATABASE CREDENTIAL COMPLEXITY & DEFAULT AUDIT:{Style.RESET_ALL}")
        print("-" * 74)
        for c in self.credential_findings:
            sev = c["severity"]
            if sev == "CRITICAL":
                sev_str = f"{Fore.RED}{Style.BRIGHT}[CRITICAL]{Style.RESET_ALL}"
            elif sev == "HIGH":
                sev_str = f"{Fore.LIGHTRED_EX}{Style.BRIGHT}[HIGH]    {Style.RESET_ALL}"
            else:
                sev_str = f"{Fore.GREEN}{Style.BRIGHT}[SAFE]    {Style.RESET_ALL}"

            print(f"{sev_str} User: {Fore.YELLOW}{c['username']:<10}{Style.RESET_ALL} Masked: {c['password_sample']:<8} Entropy: {c['entropy_bits']} bits")
            print(f"   {Fore.LIGHTBLACK_EX}{c['description']}\n")

        print(f"{Fore.CYAN}{Style.BRIGHT}" + "="*74)
        print(f"{Fore.CYAN}{Style.BRIGHT}  COMPLIANCE POSTURE & METRICS SUMMARY")
        print(f"{Fore.CYAN}{Style.BRIGHT}" + "="*74 + f"{Style.RESET_ALL}")
        print(f"  HBA Rules Checked          : {Fore.WHITE}{self.metrics['hba_rules_evaluated']}")
        print(f"  Critical HBA Violations    : {Fore.RED}{Style.BRIGHT}{self.metrics['critical_hba_violations']}{Style.RESET_ALL}")
        print(f"  Default Credentials Leaked : {Fore.RED}{Style.BRIGHT}{self.metrics['default_credentials_flagged']}{Style.RESET_ALL}")
        print(f"  Weak Passwords Identified  : {Fore.YELLOW}{self.metrics['weak_passwords_identified']}")
        status = f"{Fore.RED}[NON-COMPLIANT - IMMEDIATE HARDENING REQUIRED]" if (self.metrics['critical_hba_violations'] > 0 or self.metrics['default_credentials_flagged'] > 0) else f"{Fore.GREEN}[COMPLIANT]"
        print(f"  PostgreSQL Security Status : {status}\n")

    def save_json(self, output_path="audit_results/postgres_audit_report.json"):
        """Saves machine-readable JSON security report."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        report = {
            "metadata": {
                "engine": "PEER'S PostgreSQL Database Credential & Configuration Auditor v2.0",
                "author": "Mohammed Peer Siddiqui",
                "company": "Sqrock IT Solutions",
                "timestamp": datetime.now().isoformat(),
                "standards": ["CIS PostgreSQL 15 Benchmark v1.0.0", "NIST SP 800-53 AC-2 / IA-5"]
            },
            "metrics": self.metrics,
            "hba_findings": self.hba_findings,
            "credential_findings": self.credential_findings
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4)
        return output_path

    def save_summary_text(self, output_path="audit_results/postgres_audit_summary.txt"):
        """Saves human-readable SOC analyst triage summary."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        lines = [
            "=" * 74,
            "PEER'S POSTGRESQL DATABASE SECURITY AUDIT SUMMARY",
            "CIS PostgreSQL 15 Benchmark & Default Credential Verification",
            "=" * 74,
            f"Generated At           : {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"HBA Rules Checked      : {self.metrics['hba_rules_evaluated']}",
            f"Critical HBA Issues    : {self.metrics['critical_hba_violations']}",
            f"Default Credentials    : {self.metrics['default_credentials_flagged']}",
            "=" * 74,
            "",
            "CRITICAL HBA VIOLATIONS:"
        ]
        for h in [x for x in self.hba_findings if x["severity"] in ["CRITICAL", "HIGH"]]:
            lines.append(f"Line {h['line']}: {h['raw_rule']}")
            lines.append(f"    Impact : {h['description']}")
            lines.append(f"    Fix    : {h['remediation']}")
            lines.append("-" * 74)

        lines.append("")
        lines.append("FLAGGED INSECURE CREDENTIALS:")
        for c in [x for x in self.credential_findings if x["severity"] in ["CRITICAL", "HIGH"]]:
            lines.append(f"User: {c['username']} | Entropy: {c['entropy_bits']} bits | Severity: {c['severity']}")
            lines.append(f"    {c['description']}")
            lines.append("-" * 74)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))
        return output_path


def main():
    import argparse
    parser = argparse.ArgumentParser(description="PEER'S PostgreSQL Security Auditor v2.0")
    parser.add_argument("--hba", default="samples/pg_hba.conf.insecure", help="Path to pg_hba.conf")
    parser.add_argument("--dict", default="samples/credentials_dictionary.txt", help="Path to credentials dictionary")
    parser.add_argument("--json-out", default="audit_results/postgres_audit_report.json", help="JSON report path")
    parser.add_argument("--txt-out", default="audit_results/postgres_audit_summary.txt", help="TXT summary path")
    args = parser.parse_args()

    auditor = PostgresSecurityAuditor(pghba_path=args.hba, dict_path=args.dict)
    auditor.audit_pghba()
    auditor.audit_credentials()
    auditor.print_cli_summary()
    auditor.save_json(args.json_out)
    auditor.save_summary_text(args.txt_out)
    print(f"{Fore.GREEN}[+] Database audit JSON saved to: {args.json_out}")
    print(f"{Fore.GREEN}[+] Summary text saved to: {args.txt_out}")

if __name__ == "__main__":
    main()
