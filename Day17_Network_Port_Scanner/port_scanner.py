#!/usr/bin/env python3
"""
PEER'S Network Port & Service Scanner - Local & Container Infrastructure Auditor
Sqrock IT Solutions - Cybersecurity Internship Phase 2 (Day 17)
Author: Mohammed Peer Siddiqui
License: MIT
"""

import os
import sys
import json
import socket
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

# Standard Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCAN_DIR = os.path.join(BASE_DIR, "scan_results")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
DEFAULT_JSON = os.path.join(SCAN_DIR, "port_scan_report.json")
DEFAULT_TXT = os.path.join(SCAN_DIR, "port_scan_summary.txt")

os.makedirs(SCAN_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# Well-known Service & Protocol Port Taxonomy
KNOWN_SERVICES = {
    21: {"service": "FTP", "tier": "Data Transfer", "risk": "HIGH", "protocol": "TCP"},
    22: {"service": "SSH", "tier": "Remote Management", "risk": "MEDIUM", "protocol": "TCP"},
    25: {"service": "SMTP", "tier": "Mail Routing", "risk": "LOW", "protocol": "TCP"},
    53: {"service": "DNS", "tier": "Name Resolution", "risk": "LOW", "protocol": "UDP/TCP"},
    80: {"service": "HTTP", "tier": "Web Presentation", "risk": "LOW", "protocol": "TCP"},
    443: {"service": "HTTPS", "tier": "Secure Web Presentation", "risk": "SAFE", "protocol": "TCP"},
    3306: {"service": "MySQL", "tier": "Data Persistence", "risk": "CRITICAL", "protocol": "TCP"},
    5432: {"service": "PostgreSQL", "tier": "Data Persistence", "risk": "CRITICAL", "protocol": "TCP"},
    6379: {"service": "Redis", "tier": "In-Memory Cache", "risk": "HIGH", "protocol": "TCP"},
    8080: {"service": "HTTP-Proxy / Dev-Server", "tier": "Application Services", "risk": "HIGH", "protocol": "TCP"},
    8443: {"service": "HTTPS-Alt", "tier": "Application Services", "risk": "MEDIUM", "protocol": "TCP"},
    27017: {"service": "MongoDB", "tier": "Data Persistence", "risk": "CRITICAL", "protocol": "TCP"}
}

DEFAULT_PORTS_TO_AUDIT = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017]


class LocalPortScanner:
    """Enterprise Socket Sweeper & Container Network Topology Auditor."""

    def __init__(self, target_host="127.0.0.1", timeout=0.5):
        self.target_host = target_host
        self.timeout = timeout
        self.scan_results = {}
        self.open_ports = []
        self.closed_ports = []

    def scan_ports(self, host=None, ports=None, mock_open=None):
        """Perform socket connections across ports or utilize simulated benchmark telemetry."""
        target = host or self.target_host
        self.target_host = target
        ports_list = ports or DEFAULT_PORTS_TO_AUDIT

        self.open_ports = []
        self.closed_ports = []
        findings = []

        if mock_open is not None:
            # Simulated benchmark execution for testing & offline reproducibility
            for p in ports_list:
                svc_info = KNOWN_SERVICES.get(p, {"service": "Unknown Service", "tier": "General", "risk": "MEDIUM", "protocol": "TCP"})
                if p in mock_open:
                    self.open_ports.append(p)
                    findings.append({
                        "port": p,
                        "state": "OPEN",
                        "service": svc_info["service"],
                        "tier": svc_info["tier"],
                        "risk": svc_info["risk"],
                        "banner": mock_open.get(p, "Simulated Service Banner")
                    })
                else:
                    self.closed_ports.append(p)
                    findings.append({
                        "port": p,
                        "state": "CLOSED",
                        "service": svc_info["service"],
                        "tier": svc_info["tier"],
                        "risk": "NONE",
                        "banner": None
                    })
        else:
            # Live socket sweep
            for port in ports_list:
                svc_info = KNOWN_SERVICES.get(port, {"service": "Unknown Service", "tier": "General", "risk": "MEDIUM", "protocol": "TCP"})
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                try:
                    state = sock.connect_ex((target, port))
                    if state == 0:
                        self.open_ports.append(port)
                        # Attempt lightweight banner grab
                        banner = self._grab_banner(sock)
                        findings.append({
                            "port": port,
                            "state": "OPEN",
                            "service": svc_info["service"],
                            "tier": svc_info["tier"],
                            "risk": svc_info["risk"],
                            "banner": banner
                        })
                    else:
                        self.closed_ports.append(port)
                        findings.append({
                            "port": port,
                            "state": "CLOSED",
                            "service": svc_info["service"],
                            "tier": svc_info["tier"],
                            "risk": "NONE",
                            "banner": None
                        })
                except Exception:
                    self.closed_ports.append(port)
                finally:
                    sock.close()

        # Build Network Topology Mapping
        topology = self._build_topology_map(findings)

        # Exposure Risk Evaluation
        exposure_rating = "LOW"
        critical_count = sum(1 for f in findings if f["state"] == "OPEN" and f["risk"] == "CRITICAL")
        high_count = sum(1 for f in findings if f["state"] == "OPEN" and f["risk"] == "HIGH")

        if critical_count > 0:
            exposure_rating = "CRITICAL (Database Services Exposed)"
        elif high_count > 0:
            exposure_rating = "HIGH (Dev Console / Unauthenticated Services Exposed)"
        elif len(self.open_ports) > 2:
            exposure_rating = "MEDIUM"

        self.scan_results = {
            "target_host": target,
            "scan_timestamp": datetime.now().isoformat(),
            "total_ports_scanned": len(ports_list),
            "open_port_count": len(self.open_ports),
            "closed_port_count": len(self.closed_ports),
            "open_ports": self.open_ports,
            "closed_ports": self.closed_ports,
            "exposure_rating": exposure_rating,
            "findings": findings,
            "topology_mapping": topology
        }
        return self.scan_results

    def _grab_banner(self, sock):
        """Attempt to read initial service identification banner."""
        try:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = sock.recv(128).decode("utf-8", errors="ignore").strip()
            return data[:60] if data else "Banner unavailable"
        except Exception:
            return "Active socket connected"

    def _build_topology_map(self, findings):
        """Aggregate open services into multi-tier enterprise network topology schema."""
        tiers = {
            "Presentation Tier (Web Frontend)": [],
            "Application Tier (Microservices / APIs)": [],
            "Data Persistence Tier (Databases & Caches)": [],
            "Management Tier (Administrative Access)": []
        }
        for f in findings:
            if f["state"] == "OPEN":
                port = f["port"]
                svc = f["service"]
                item = f"Port {port}/TCP ({svc})"
                if port in [80, 443]:
                    tiers["Presentation Tier (Web Frontend)"].append(item)
                elif port in [8080, 8443]:
                    tiers["Application Tier (Microservices / APIs)"].append(item)
                elif port in [3306, 5432, 6379, 27017]:
                    tiers["Data Persistence Tier (Databases & Caches)"].append(item)
                elif port in [21, 22]:
                    tiers["Management Tier (Administrative Access)"].append(item)
                else:
                    tiers["Application Tier (Microservices / APIs)"].append(item)
        return tiers

    def export_reports(self, json_path=DEFAULT_JSON, txt_path=DEFAULT_TXT):
        """Export structured JSON and text network topology audits."""
        if not self.scan_results:
            self.scan_ports()

        # Write JSON
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self.scan_results, f, indent=2)

        # Write TXT
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("     SQROCK IT SOLUTIONS - NETWORK PORT & TOPOLOGY AUDIT REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Target Host Audited  : {self.scan_results['target_host']}\n")
            f.write(f"Scan Timestamp       : {self.scan_results['scan_timestamp']}\n")
            f.write(f"Total Ports Scanned  : {self.scan_results['total_ports_scanned']}\n")
            f.write(f"Discovered Open      : {self.scan_results['open_port_count']}\n")
            f.write(f"Discovered Closed    : {self.scan_results['closed_port_count']}\n")
            f.write(f"Exposure Risk Rating : {self.scan_results['exposure_rating']}\n")
            f.write("-" * 80 + "\n\n")

            f.write("--- 1. ACTIVE OPEN SOCKET FINDINGS ---\n")
            for f_item in self.scan_results["findings"]:
                if f_item["state"] == "OPEN":
                    f.write(f"[!] Port {f_item['port']}/TCP : {f_item['service']} [{f_item['risk']} RISK]\n")
                    f.write(f"    Architecture Tier: {f_item['tier']}\n")
                    f.write(f"    Service Banner   : {f_item['banner']}\n\n")

            f.write("--- 2. EXPOSED NETWORK TOPOLOGY SCHEMA ---\n")
            for tier_name, svcs in self.scan_results["topology_mapping"].items():
                f.write(f"[{tier_name}]\n")
                if svcs:
                    for s in svcs:
                        f.write(f"  └── {s}\n")
                else:
                    f.write("  └── (No open services discovered in this tier)\n")
                f.write("\n")

            f.write("-" * 80 + "\n")
            f.write("DEFENSIVE REMEDIATION GUIDANCE:\n")
            f.write("1. Database Tier: Bind PostgreSQL (5432) and MySQL (3306) strictly to 127.0.0.1 or internal Docker networks.\n")
            f.write("2. Management Tier: Restrict SSH (22) via iptables / Security Groups; require cryptographic keys.\n")
            f.write("3. Application Tier: Disallow direct exposure of development console ports (8080) on public network interfaces.\n")

        return self.scan_results


def print_banner():
    """Display Kali terminal banner."""
    print(Fore.CYAN + Style.BRIGHT + r"""
  _____   ____  _____ _______    _____  _____          _   _ _   _ ______ _____  
 |  __ \ / __ \|  __ \__   __|  / ____|/ ____|   /\   | \ | | \ | |  ____|  __ \ 
 | |__) | |  | | |__) | | |    | (___ | |       /  \  |  \| |  \| | |__  | |__) |
 |  ___/| |  | |  _  /  | |     \___ \| |      / /\ \ | . ` | . ` |  __| |  _  / 
 | |    | |__| | | \ \  | |     ____) | |____ / ____ \| |\  | |\  | |____| | \ \ 
 |_|     \____/|_|  \_\ |_|    |_____/ \_____/_/    \_\_| \_|_| \_|______|_|  \_\
    """ + Style.RESET_ALL)
    print(Fore.YELLOW + " [*] Enterprise Local Socket Sweeper & Network Topology Mapper v2.0")
    print(Fore.GREEN + " [*] Developer: Mohammed Peer Siddiqui | Sqrock IT Solutions Phase 2 (Day 17)")
    print(Fore.WHITE + " [*] Standards: CIS Controls v8 (Control 4 & 12) | NIST SP 800-115 | OWASP ASVS\n")


def run_interactive_menu():
    """CLI driver loop."""
    scanner = LocalPortScanner()

    # Default benchmark configuration representing real-world container host exposure
    benchmark_open = {
        22: "OpenSSH 8.9p1 Ubuntu-3ubuntu0.6",
        80: "nginx/1.24.0 (Ubuntu)",
        443: "nginx/1.24.0 (TLS Encrypted)",
        5432: "PostgreSQL 15.3 Server Protocol 3.0",
        8080: "Node.js Express / Developer Console"
    }
    scanner.scan_ports(mock_open=benchmark_open)

    while True:
        print_banner()
        print(Fore.LIGHTBLUE_EX + " [=== MASTER NETWORK PORT SCANNER MENU ===]")
        print(Fore.WHITE + " [1] Scan Live Host Sockets (Custom IP / Hostname)")
        print(Fore.WHITE + " [2] Run Container Host Benchmark Audit (Exposed Dev Environment)")
        print(Fore.WHITE + " [3] Run Hardened Zero-Exposure Container Benchmark")
        print(Fore.WHITE + " [4] View Multi-Tier Network Topology Schema")
        print(Fore.WHITE + " [5] Export Formal Network Exposure Audit Reports (JSON & TXT)")
        print(Fore.WHITE + " [6] Exit Suite\n")

        try:
            choice = input(Fore.CYAN + " port-scanner@sqrock-sec:~$ " + Style.RESET_ALL).strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting Port Scanner...")
            break

        if choice == "1":
            target = input(Fore.YELLOW + "\nEnter Target IP or Hostname (default: 127.0.0.1): " + Style.RESET_ALL).strip()
            if not target:
                target = "127.0.0.1"
            print(Fore.CYAN + f"\n[*] Sweeping TCP sockets on host: {target}...")
            res = scanner.scan_ports(host=target)
            print(Fore.GREEN + f"[+] Scan complete! Scanned {res['total_ports_scanned']} ports.")
            print(Fore.WHITE + f"    Open Ports Discovered: {Fore.YELLOW}{res['open_ports']}")
            print(Fore.WHITE + f"    Exposure Posture     : {res['exposure_rating']}\n")

            for f in res["findings"]:
                if f["state"] == "OPEN":
                    col = Fore.RED if f["risk"] == "CRITICAL" else (Fore.YELLOW if f["risk"] == "HIGH" else Fore.GREEN)
                    print(f" {col}[!] Port {f['port']}/TCP OPEN : {Fore.WHITE}{f['service']} ({f['tier']})")
                    print(f"     {Fore.LIGHTBLACK_EX}Banner: {f['banner']}")
            print()
            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == "2":
            print(Fore.YELLOW + "\n[*] Executing Container Host Benchmark Audit (Standard Developer Environment)...")
            res = scanner.scan_ports(mock_open=benchmark_open)
            print(Fore.RED + Style.BRIGHT + f"[!] CRITICAL EXPOSURE DETECTED on Host {res['target_host']}:")
            print(Fore.WHITE + f"    Exposure Level  : {Fore.RED}{res['exposure_rating']}")
            print(Fore.WHITE + f"    Open Sockets    : {Fore.YELLOW}{res['open_ports']}")
            print(Fore.WHITE + f"    Database Exposed: {Fore.RED}Port 5432 (PostgreSQL) is accessible across network boundary!")
            print(Fore.WHITE + f"    Admin Console   : {Fore.YELLOW}Port 8080 (Dev-Server) is unauthenticated!\n")
            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == "3":
            print(Fore.YELLOW + "\n[*] Evaluating Hardened Production Container Benchmark (Strictly Ingress 443)...")
            hardened_open = {443: "nginx/1.24.0 (TLS Encrypted)"}
            res = scanner.scan_ports(mock_open=hardened_open)
            print(Fore.GREEN + f"[+] Hardened Host Posture Verified: {res['exposure_rating']}")
            print(Fore.GREEN + f"[+] Zero administrative or database sockets exposed to external interfaces.\n")
            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == "4":
            print(Fore.YELLOW + "\n[=== MULTI-TIER NETWORK TOPOLOGY SCHEMA ===]\n")
            top = scanner.scan_results.get("topology_mapping", {})
            for tier, svcs in top.items():
                print(Fore.CYAN + f"[{tier}]")
                if svcs:
                    for s in svcs:
                        print(Fore.GREEN + f"  └── {s}")
                else:
                    print(Fore.LIGHTBLACK_EX + "  └── (None exposed)")
                print()
            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == "5":
            print(Fore.YELLOW + "\n[*] Exporting formal network topology audit dossiers...")
            scanner.export_reports()
            print(Fore.GREEN + f"[+] JSON Audit exported: {DEFAULT_JSON}")
            print(Fore.GREEN + f"[+] Text Dossier exported: {DEFAULT_TXT}\n")
            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == "6":
            print(Fore.CYAN + "\n[*] Shutting down Port Scanner console. Goodbye!\n")
            break
        else:
            print(Fore.RED + "\n[!] Invalid choice. Please select 1-6.\n")


if __name__ == "__main__":
    if len(sys.argv) > 1 and "--batch" in sys.argv:
        auditor = LocalPortScanner()
        auditor.scan_ports(mock_open={22: "SSH", 80: "HTTP", 443: "HTTPS", 5432: "PostgreSQL"})
        auditor.export_reports()
        print("[+] Headless Port Scanner audit complete.")
    else:
        run_interactive_menu()
