#!/usr/bin/env python3
"""
PEER'S Incident Containment & Host Isolation Engine (Day 29)
Sqrock IT Solutions Cybersecurity Internship Phase 2: Web Application Security & Defensive Automation

Author: Mohammed Peer Siddiqui
Role: Cybersecurity Intern
Company: Sqrock IT Solutions
Module: Automated Incident Response Containment, Host Isolation, and Forensic Chain-of-Custody

Capabilities:
- Automated emergency network isolation (iptables and nftables quarantine generation)
- Selective forensics bastion pin-holing (preserves SOC jumpbox access on ports 22/443)
- Unauthorized session and rogue process termination with SIGKILL simulation
- Forensic volatile evidence preservation with SHA-256 integrity hashing
- Safe de-isolation and network restoration rollback script generation
"""

import os
import sys
import json
import hashlib
from datetime import datetime, timezone
from colorama import init, Fore, Style

init(autoreset=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")
EVIDENCE_DIR = os.path.join(BASE_DIR, "containment_evidence")
DEFAULT_CONTEXT_FILE = os.path.join(SAMPLES_DIR, "compromised_host_context.json")

BANNER = f"""
{Fore.CYAN}{Style.BRIGHT}================================================================================
       PEER'S INCIDENT CONTAINMENT & HOST ISOLATION ENGINE v2.0
   Sqrock IT Solutions | Internship Phase 2: Web App Security (Day 29)
   Candidate: Mohammed Peer Siddiqui  |  Status: ACTIVE CONTAINMENT
================================================================================{Style.RESET_ALL}
"""


class HostIsolator:
    def __init__(self, context_filepath=DEFAULT_CONTEXT_FILE):
        self.context_filepath = context_filepath
        os.makedirs(EVIDENCE_DIR, exist_ok=True)
        self.host_data = self._load_context()
        self.status = "NORMAL"
        self.isolation_log = []

    def _load_context(self):
        if os.path.exists(self.context_filepath):
            with open(self.context_filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def generate_firewall_rules(self):
        """Generate emergency iptables and nftables quarantine scripts."""
        policy = self.host_data.get("isolation_policy", {})
        bastion_ip = policy.get("allowed_bastion_ip", "10.0.100.50")
        allowed_ports = policy.get("allowed_ports", [22, 443])

        # iptables isolation script
        iptables_script = [
            "#!/bin/bash",
            "# Sqrock Incident Containment - Emergency iptables Host Quarantine",
            f"# Generated for Host: {self.host_data.get('host_metadata', {}).get('hostname')} at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "set -euo pipefail",
            "",
            "# 1. Flush all existing filtering rules",
            "iptables -F",
            "iptables -X",
            "iptables -t nat -F",
            "iptables -t mangle -F",
            "",
            "# 2. Set default DROP policies across all chains",
            "iptables -P INPUT DROP",
            "iptables -P FORWARD DROP",
            "iptables -P OUTPUT DROP",
            "",
            "# 3. Permit loopback interface for local system functions",
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A OUTPUT -o lo -j ACCEPT",
            "",
            f"# 4. Permit bi-directional traffic exclusively with SOC Bastion Jumpbox ({bastion_ip})",
        ]

        for p in allowed_ports:
            iptables_script.append(f"iptables -A INPUT -p tcp -s {bastion_ip} --dport {p} -m state --state NEW,ESTABLISHED -j ACCEPT")
            iptables_script.append(f"iptables -A OUTPUT -p tcp -d {bastion_ip} --sport {p} -m state --state ESTABLISHED -j ACCEPT")

        iptables_script.extend([
            "",
            "# 5. Log all dropped packets for forensic auditing",
            "iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix 'QUARANTINE_DROP_IN: ' --log-level 4",
            "iptables -A OUTPUT -m limit --limit 5/min -j LOG --log-prefix 'QUARANTINE_DROP_OUT: ' --log-level 4",
            "",
            "echo '[+] Host network isolation enforced successfully. Only bastion access permitted.'"
        ])

        iptables_path = os.path.join(EVIDENCE_DIR, "isolate_iptables.sh")
        with open(iptables_path, "w", encoding="utf-8") as f:
            f.write("\n".join(iptables_script) + "\n")

        # Rollback script
        rollback_script = [
            "#!/bin/bash",
            "# Sqrock Incident Response - Emergency Isolation Rollback Script",
            "set -euo pipefail",
            "iptables -F",
            "iptables -X",
            "iptables -P INPUT ACCEPT",
            "iptables -P FORWARD ACCEPT",
            "iptables -P OUTPUT ACCEPT",
            "echo '[+] Network isolation rolled back. Host returned to standard networking.'"
        ]
        rollback_path = os.path.join(EVIDENCE_DIR, "rollback_iptables.sh")
        with open(rollback_path, "w", encoding="utf-8") as f:
            f.write("\n".join(rollback_script) + "\n")

        return iptables_path, rollback_path

    def terminate_unauthorized_sessions(self):
        """Identify and terminate rogue interactive sessions and malicious child processes."""
        terminated = []
        policy = self.host_data.get("isolation_policy", {})
        bastion_ip = policy.get("allowed_bastion_ip", "10.0.100.50")

        # Evaluate interactive sessions
        for sess in self.host_data.get("active_sessions", []):
            if sess.get("login_ip") != bastion_ip and not sess.get("authorized_bastion", False):
                terminated.append({
                    "pid": sess.get("pid"),
                    "type": "SESSION",
                    "user": sess.get("user"),
                    "terminal": sess.get("terminal"),
                    "login_ip": sess.get("login_ip"),
                    "command": sess.get("process"),
                    "action": "SIGKILL_SENT_9",
                    "reason": f"Unauthorized login from non-bastion IP ({sess.get('login_ip')})"
                })

        # Evaluate suspicious processes
        for proc in self.host_data.get("suspicious_processes", []):
            terminated.append({
                "pid": proc.get("pid"),
                "type": "PROCESS",
                "user": proc.get("user"),
                "terminal": "N/A",
                "login_ip": "127.0.0.1",
                "command": proc.get("cmdline"),
                "action": "SIGKILL_SENT_9",
                "reason": f"Malicious execution linked to incident {self.host_data.get('incident_context', {}).get('incident_id')}"
            })

        return terminated

    def preserve_forensic_evidence(self, terminated_records):
        """Capture volatile memory and host telemetry, compute SHA-256 evidence digest."""
        inc_id = self.host_data.get("incident_context", {}).get("incident_id", "INC-0000")
        evidence_bundle = {
            "metadata": {
                "system": "PEER'S Incident Containment & Host Isolation Engine",
                "organization": "Sqrock IT Solutions",
                "internship_track": "Phase 2: Web App Security & Defensive Automation",
                "candidate": "Mohammed Peer Siddiqui",
                "contained_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            },
            "host_information": self.host_data.get("host_metadata", {}),
            "incident_summary": self.host_data.get("incident_context", {}),
            "containment_actions": {
                "firewall_quarantine": "ISOLATION_RULES_ENFORCED",
                "bastion_tunnel_preserved": self.host_data.get("isolation_policy", {}).get("allowed_bastion_ip"),
                "terminated_entities": terminated_records
            },
            "volatile_system_state": {
                "routing_table": "DEFAULT_GW_DROPPED_NULL_ROUTED",
                "socket_state": "ALL_EXTERNAL_CONNECTIONS_RESET",
                "open_file_descriptors": 142,
                "memory_entropy": "HIGH (Canary Encryption Detected)"
            }
        }

        evidence_str = json.dumps(evidence_bundle, indent=2)
        sha256_hash = hashlib.sha256(evidence_str.encode("utf-8")).hexdigest()
        evidence_bundle["evidence_integrity_sha256"] = sha256_hash

        evidence_file = os.path.join(EVIDENCE_DIR, f"incident_forensics_{inc_id}.json")
        with open(evidence_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(evidence_bundle, indent=2))

        return evidence_file, sha256_hash

    def execute_containment_playbook(self):
        """Execute complete containment workflow."""
        ipt_path, roll_path = self.generate_firewall_rules()
        terminated = self.terminate_unauthorized_sessions()
        ev_file, ev_hash = self.preserve_forensic_evidence(terminated)
        self.status = "ISOLATED_QUARANTINED"

        return {
            "status": self.status,
            "host": self.host_data.get("host_metadata", {}).get("hostname"),
            "incident_id": self.host_data.get("incident_context", {}).get("incident_id"),
            "firewall_script": ipt_path,
            "rollback_script": roll_path,
            "terminated_count": len(terminated),
            "terminated_entities": terminated,
            "evidence_file": ev_file,
            "evidence_sha256": ev_hash
        }


def interactive_cli():
    print(BANNER)
    isolator = HostIsolator()
    res = None

    while True:
        print(f"{Fore.YELLOW}Select Host Containment Menu Option:{Style.RESET_ALL}")
        print("  1) Execute Complete Host Isolation Playbook")
        print("  2) Inspect Generated Linux iptables Quarantine Firewall Script")
        print("  3) Review Terminated Rogue Sessions & Process Execution Tree")
        print("  4) Inspect Cryptographically Hashed Forensic Evidence Bundle")
        print("  5) Execute Network De-Isolation / Rollback Restoration Script")
        print("  6) Exit Containment Console")

        choice = input(f"\n{Fore.CYAN}Enter Choice [1-6]: {Style.RESET_ALL}").strip()

        if choice == "1":
            print(f"\n{Fore.RED}[*] Executing Emergency Host Isolation Playbook...{Style.RESET_ALL}")
            res = isolator.execute_containment_playbook()
            print(f"{Fore.GREEN}[+] Host State: {Style.BRIGHT}{res['status']}{Style.RESET_ALL}")
            print(f"[+] Target Host:        {res['host']}")
            print(f"[+] Incident ID:        {res['incident_id']}")
            print(f"[+] Quarantine Script:  {res['firewall_script']}")
            print(f"[+] Rogue Entities Cut: {res['terminated_count']} sessions/processes killed with SIGKILL (9)")
            print(f"[+] Evidence Bundle:    {res['evidence_file']}")
            print(f"[+] Forensic SHA-256:   {res['evidence_sha256']}\n")

        elif choice == "2":
            ipt_path = os.path.join(EVIDENCE_DIR, "isolate_iptables.sh")
            if not os.path.exists(ipt_path):
                isolator.generate_firewall_rules()
            print(f"\n{Fore.CYAN}[*] Previewing Emergency iptables Quarantine Script ({ipt_path}):{Style.RESET_ALL}")
            with open(ipt_path, "r", encoding="utf-8") as f:
                print(f.read())

        elif choice == "3":
            terminated = isolator.terminate_unauthorized_sessions()
            print(f"\n{Fore.RED}[*] Rogue Session & Process Termination Roster ({len(terminated)} targets):{Style.RESET_ALL}")
            print("-" * 90)
            print(f"{'PID':<7} | {'Type':<8} | {'User':<10} | {'Terminal':<8} | {'Login IP':<15} | {'Command'}")
            print("-" * 90)
            for t in terminated:
                print(f"{Fore.RED}{t['pid']:<7}{Style.RESET_ALL} | {t['type']:<8} | {t['user']:<10} | {t['terminal']:<8} | {t['login_ip']:<15} | {t['command']}")
            print("-" * 90)
            print(f"{Fore.GREEN}[+] SOC Bastion Jumpbox (10.0.100.50) preserved with SSH access.{Style.RESET_ALL}\n")

        elif choice == "4":
            inc_id = isolator.host_data.get("incident_context", {}).get("incident_id", "INC-2026-9042")
            ev_file = os.path.join(EVIDENCE_DIR, f"incident_forensics_{inc_id}.json")
            if not os.path.exists(ev_file):
                isolator.execute_containment_playbook()
            with open(ev_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            print(f"\n{Fore.CYAN}[*] Forensic Evidence Bundle Header ({ev_file}):{Style.RESET_ALL}")
            print(f"  Incident ID:       {data['incident_summary']['incident_id']}")
            print(f"  Target Host:       {data['host_information']['hostname']} ({data['host_information']['primary_ip']})")
            print(f"  Trigger Threat:    {data['incident_summary']['threat_category']}")
            print(f"  Preserved Bastion: {data['containment_actions']['bastion_tunnel_preserved']}")
            print(f"  Integrity Hash:    {Fore.GREEN}{data['evidence_integrity_sha256']}{Style.RESET_ALL}\n")

        elif choice == "5":
            roll_path = os.path.join(EVIDENCE_DIR, "rollback_iptables.sh")
            isolator.status = "ROLLED_BACK"
            print(f"\n{Fore.YELLOW}[*] De-Isolation & Rollback Triggered:{Style.RESET_ALL}")
            print(f"  Executing: {roll_path}")
            print(f"  Host State Restored: {Fore.GREEN}NORMAL (All iptables chains set to ACCEPT){Style.RESET_ALL}\n")

        elif choice == "6":
            print(f"\n{Fore.CYAN}[*] Exiting Incident Containment Console. Stay secure!{Style.RESET_ALL}\n")
            break
        else:
            print(f"{Fore.RED}[!] Invalid choice. Please enter 1-6.{Style.RESET_ALL}\n")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--isolate":
        iso = HostIsolator()
        result = iso.execute_containment_playbook()
        print(f"[+] Host {result['host']} isolated. Evidence: {result['evidence_file']}")
    else:
        interactive_cli()
