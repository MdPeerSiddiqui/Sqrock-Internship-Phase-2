"""
PEER'S Docker Container Misconfiguration Scanner v2.0
======================================================
Automated Static Analysis Engine for Dockerfile & Container Hardening
CIS Docker Benchmark v1.6.0 & NIST SP 800-190 Compliant

Author: Mohammed Peer Siddiqui
Company: Sqrock IT Solutions
Track: Phase 2 - Web Application Security & Defensive Automation (Day 19)
Monorepo: https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2
"""

import os
import sys
import re
import json
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

class DockerSecurityScanner:
    """
    Static analysis security engine for auditing Dockerfiles against
    CIS Docker Benchmark, NIST SP 800-190, and OWASP Container Security standards.
    """
    
    CIS_RULES = {
        "DOCKER_USER_ROOT": {
            "title": "Container Running as Root User",
            "cis_id": "CIS 4.1",
            "nist_id": "NIST SP 800-190 S3.1",
            "severity": "CRITICAL",
            "description": "Container executes as root (UID 0), granting full host root equivalency in unconfined namespaces and increasing breakout risk.",
            "remediation": "Declare a non-privileged user and group using 'USER nonroot:nonroot' or explicit numeric UID (e.g. 'USER 10001:10001')."
        },
        "DOCKER_TAG_LATEST": {
            "title": "Unpinned Base Image (:latest or untagged)",
            "cis_id": "CIS 4.2",
            "nist_id": "NIST SP 800-190 S3.2",
            "severity": "HIGH",
            "description": "Base image references :latest or lacks specific version pinning, exposing the build to supply chain drift and breaking changes.",
            "remediation": "Pin base image to explicit semantic version or cryptographic digest (e.g. 'python:3.11.8-slim-bookworm@sha256:...')."
        },
        "DOCKER_EXPOSE_SSH": {
            "title": "Dangerous Port Exposure (SSH Port 22)",
            "cis_id": "CIS 4.3",
            "nist_id": "NIST SP 800-190 S3.3",
            "severity": "CRITICAL",
            "description": "Container exposes SSH port 22. Containers should follow single-responsibility microservice architecture; remote management via SSH breaks immutability.",
            "remediation": "Remove 'EXPOSE 22' and uninstall OpenSSH server daemons. Use container orchestrator exec commands (e.g., 'docker exec' or 'kubectl exec') for debugging."
        },
        "DOCKER_HARDCODED_SECRET": {
            "title": "Hardcoded Secrets in Environment Variables",
            "cis_id": "CIS 4.4",
            "nist_id": "NIST SP 800-190 S3.4",
            "severity": "CRITICAL",
            "description": "Sensitive credentials (passwords, API tokens, AWS keys) detected directly in ENV/ARG instructions, permanently baked into layer history.",
            "remediation": "Remove secret values from Dockerfile. Ingest secrets dynamically at runtime via Docker Secrets, Kubernetes Secrets, or HashiCorp Vault."
        },
        "DOCKER_INSECURE_ADD": {
            "title": "Use of ADD Instead of COPY for Untrusted Remote Archives",
            "cis_id": "CIS 4.9",
            "nist_id": "NIST SP 800-190 S3.5",
            "severity": "MEDIUM",
            "description": "Instruction uses ADD with remote URLs or local archives. ADD features automatic tar extraction and remote downloads that can lead to MITM or zip bombs.",
            "remediation": "Replace 'ADD' with 'COPY' for local files. For remote downloads, use 'curl' or 'wget' with checksum verification within a RUN directive."
        },
        "DOCKER_MISSING_HEALTHCHECK": {
            "title": "Missing Container HEALTHCHECK Directive",
            "cis_id": "CIS 4.6",
            "nist_id": "NIST SP 800-190 S3.6",
            "severity": "LOW",
            "description": "Dockerfile does not define a HEALTHCHECK mechanism. Orchestrators cannot automatically detect crashed, deadlocked, or hung application services.",
            "remediation": "Define a HEALTHCHECK instruction (e.g. 'HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8080/health || exit 1')."
        },
        "DOCKER_DEPRECATED_MAINTAINER": {
            "title": "Deprecated MAINTAINER Instruction",
            "cis_id": "CIS 4.10",
            "nist_id": "NIST SP 800-190 S3.7",
            "severity": "LOW",
            "description": "The MAINTAINER directive is deprecated in modern OCI and Docker build specifications.",
            "remediation": "Replace 'MAINTAINER' with standard OCI label 'LABEL maintainer=\"...\"'."
        },
        "DOCKER_SUDO_INSTALLED": {
            "title": "Privilege Escalation Tools (sudo) Installed",
            "cis_id": "CIS 4.8",
            "nist_id": "NIST SP 800-190 S3.8",
            "severity": "HIGH",
            "description": "Package management commands install 'sudo', allowing potential privilege escalation pathways inside the container.",
            "remediation": "Do not install sudo or su binaries in production containers. Design workloads to run under strict least-privilege principles."
        }
    }

    SECRET_KEYWORD_REGEX = re.compile(
        r'(?i)(password|secret|key|token|credential|api[_-]?key|aws_secret)',
        re.IGNORECASE
    )

    def __init__(self, target_dockerfile=None):
        self.target_dockerfile = target_dockerfile
        self.parsed_lines = []
        self.findings = []
        self.summary_stats = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "SAFE": 0,
            "TOTAL_RULES_EVALUATED": len(self.CIS_RULES)
        }

    def parse_dockerfile(self, filepath=None):
        """Parse Dockerfile into normalized line items and multi-line instruction blocks."""
        path = filepath or self.target_dockerfile
        if not path or not os.path.exists(path):
            raise FileNotFoundError(f"Dockerfile target '{path}' does not exist.")

        self.parsed_lines = []
        current_instruction = None
        current_line_num = 0
        current_args = []

        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue

            # Check if line continues from previous
            if stripped.endswith('\\'):
                clean_chunk = stripped[:-1].strip()
                if current_instruction:
                    current_args.append(clean_chunk)
                else:
                    parts = clean_chunk.split(None, 1)
                    current_instruction = parts[0].upper()
                    current_line_num = idx
                    current_args.append(parts[1] if len(parts) > 1 else "")
                continue

            if current_instruction:
                current_args.append(stripped)
                full_args = " ".join(current_args)
                self.parsed_lines.append({
                    "line": current_line_num,
                    "instruction": current_instruction,
                    "args": full_args,
                    "raw": f"{current_instruction} {full_args}"
                })
                current_instruction = None
                current_args = []
            else:
                parts = stripped.split(None, 1)
                inst = parts[0].upper()
                args = parts[1] if len(parts) > 1 else ""
                self.parsed_lines.append({
                    "line": idx,
                    "instruction": inst,
                    "args": args,
                    "raw": stripped
                })

        return self.parsed_lines

    def audit(self, filepath=None):
        """Execute full static security analysis on the parsed instructions."""
        self.parse_dockerfile(filepath)
        self.findings = []

        has_user_directive = False
        last_user = None
        has_healthcheck = False
        multi_stage_targets = []

        for item in self.parsed_lines:
            inst = item["instruction"]
            args = item["args"]
            line = item["line"]

            # 1. Base Image Tag Check (FROM)
            if inst == "FROM":
                # Check for multi-stage alias (AS name)
                parts = args.split()
                image_spec = parts[0]
                if len(parts) >= 3 and parts[1].upper() == "AS":
                    multi_stage_targets.append(parts[2])

                # Check if unpinned or :latest
                if ":" not in image_spec or image_spec.endswith(":latest"):
                    self._add_finding("DOCKER_TAG_LATEST", line, item["raw"], {
                        "detected_image": image_spec,
                        "risk": "Using latest or unpinned base image allows unexpected breaking changes or compromised layers."
                    })

            # 2. User Execution Context (USER)
            elif inst == "USER":
                has_user_directive = True
                last_user = args.strip()
                if last_user in ["root", "0", "0:0"]:
                    self._add_finding("DOCKER_USER_ROOT", line, item["raw"], {
                        "configured_user": last_user,
                        "risk": "Explicit root user directive enables full container privileges."
                    })

            # 3. Dangerous Ports (EXPOSE)
            elif inst == "EXPOSE":
                ports = [p.split('/')[0] for p in args.split()]
                if "22" in ports:
                    self._add_finding("DOCKER_EXPOSE_SSH", line, item["raw"], {
                        "exposed_ports": ports,
                        "risk": "SSH server exposed inside container violates single-responsibility principle and invites brute-force attacks."
                    })

            # 4. Insecure Secrets (ENV / ARG)
            elif inst in ["ENV", "ARG"]:
                # Check if key contains secret keyword and has an assigned literal value
                if "=" in args or " " in args:
                    if self.SECRET_KEYWORD_REGEX.search(args):
                        self._add_finding("DOCKER_HARDCODED_SECRET", line, item["raw"], {
                            "declaration": args,
                            "risk": "Hardcoded credentials in image metadata can be extracted with 'docker history'."
                        })

            # 5. Insecure ADD instruction
            elif inst == "ADD":
                if "http://" in args.lower() or "https://" in args.lower() or any(args.endswith(ext) for ext in [".tar", ".gz", ".zip", ".tar.gz"]):
                    self._add_finding("DOCKER_INSECURE_ADD", line, item["raw"], {
                        "add_payload": args,
                        "risk": "ADD directive with remote URL or auto-extract archive risks MITM injection or zip bombs."
                    })

            # 6. Sudo installation check in RUN
            elif inst == "RUN":
                if re.search(r'\b(sudo|doas)\b', args, re.IGNORECASE):
                    self._add_finding("DOCKER_SUDO_INSTALLED", line, item["raw"], {
                        "command": args,
                        "risk": "Installing sudo provides unnecessary privilege escalation vectors within the container."
                    })

            # 7. Deprecated MAINTAINER
            elif inst == "MAINTAINER":
                self._add_finding("DOCKER_DEPRECATED_MAINTAINER", line, item["raw"], {
                    "maintainer": args,
                    "risk": "MAINTAINER instruction is obsolete; use LABEL maintainer instead."
                })

            # 8. Healthcheck detection
            elif inst == "HEALTHCHECK":
                has_healthcheck = True

        # Post-scan global checks:
        # If no USER instruction was ever declared, container defaults to ROOT
        if not has_user_directive:
            self._add_finding("DOCKER_USER_ROOT", 1, "MISSING_USER_DIRECTIVE", {
                "configured_user": "default (root UID 0)",
                "risk": "No USER directive declared. Container defaults to executing as root."
            })

        # If no HEALTHCHECK directive found
        if not has_healthcheck:
            self._add_finding("DOCKER_MISSING_HEALTHCHECK", 1, "MISSING_HEALTHCHECK_DIRECTIVE", {
                "status": "Not configured",
                "risk": "No HEALTHCHECK instruction declared; container availability cannot be dynamically verified."
            })

        # Calculate summary statistics
        self.summary_stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0, "TOTAL_RULES_EVALUATED": len(self.CIS_RULES)}
        for f in self.findings:
            sev = f["severity"]
            if sev in self.summary_stats:
                self.summary_stats[sev] += 1

        return self.findings

    def _add_finding(self, rule_key, line_num, raw_instruction, context_data):
        rule = self.CIS_RULES[rule_key]
        self.findings.append({
            "rule_id": rule_key,
            "title": rule["title"],
            "cis_id": rule["cis_id"],
            "nist_id": rule["nist_id"],
            "severity": rule["severity"],
            "line": line_num,
            "raw_instruction": raw_instruction,
            "context": context_data,
            "description": rule["description"],
            "remediation": rule["remediation"]
        })

    def print_cli_summary(self):
        """Render polished Kali Linux style interactive audit console."""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}" + "="*74)
        print(f"{Fore.CYAN}{Style.BRIGHT}  PEER'S DOCKER CONTAINER MISCONFIGURATION SCANNER v2.0")
        print(f"{Fore.CYAN}{Style.BRIGHT}  CIS Docker Benchmark v1.6.0 | NIST SP 800-190 Compliance")
        print(f"{Fore.CYAN}{Style.BRIGHT}" + "="*74 + f"{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Target Dockerfile : {Fore.YELLOW}{self.target_dockerfile}")
        print(f"{Fore.WHITE}Parsed Statements : {Fore.GREEN}{len(self.parsed_lines)}")
        print(f"{Fore.WHITE}Evaluation Time   : {Fore.CYAN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")

        print(f"{Fore.YELLOW}{Style.BRIGHT}[+] SECURITY FINDINGS & POLICY VIOLATIONS:{Style.RESET_ALL}")
        print("-" * 74)

        if not self.findings:
            print(f"{Fore.GREEN}{Style.BRIGHT}[PASS] ZERO MISCONFIGURATIONS DETECTED! DOCKERFILE IS HARDENED.")
        else:
            for idx, finding in enumerate(self.findings, 1):
                sev = finding["severity"]
                if sev == "CRITICAL":
                    sev_color = f"{Fore.RED}{Style.BRIGHT}[CRITICAL]"
                elif sev == "HIGH":
                    sev_color = f"{Fore.LIGHTRED_EX}{Style.BRIGHT}[HIGH]    "
                elif sev == "MEDIUM":
                    sev_color = f"{Fore.YELLOW}{Style.BRIGHT}[MEDIUM]  "
                else:
                    sev_color = f"{Fore.BLUE}{Style.BRIGHT}[LOW]     "

                print(f"{sev_color} {Style.BRIGHT}{finding['title']}{Style.RESET_ALL} (Line {finding['line']})")
                print(f"   {Fore.WHITE}Standard  : {Fore.CYAN}{finding['cis_id']} | {finding['nist_id']}")
                print(f"   {Fore.WHITE}Instruction: {Fore.LIGHTBLACK_EX}{finding['raw_instruction']}")
                print(f"   {Fore.WHITE}Impact    : {finding['description']}")
                print(f"   {Fore.GREEN}Fix       : {finding['remediation']}\n")

        print(f"{Fore.CYAN}{Style.BRIGHT}" + "="*74)
        print(f"{Fore.CYAN}{Style.BRIGHT}  COMPLIANCE POSTURE & METRICS SUMMARY")
        print(f"{Fore.CYAN}{Style.BRIGHT}" + "="*74 + f"{Style.RESET_ALL}")
        print(f"  CRITICAL Severities : {Fore.RED}{Style.BRIGHT}{self.summary_stats['CRITICAL']}{Style.RESET_ALL}")
        print(f"  HIGH Severities     : {Fore.LIGHTRED_EX}{Style.BRIGHT}{self.summary_stats['HIGH']}{Style.RESET_ALL}")
        print(f"  MEDIUM Severities   : {Fore.YELLOW}{Style.BRIGHT}{self.summary_stats['MEDIUM']}{Style.RESET_ALL}")
        print(f"  LOW Severities      : {Fore.BLUE}{Style.BRIGHT}{self.summary_stats['LOW']}{Style.RESET_ALL}")
        print(f"  Total Rules Checked : {Fore.WHITE}{self.summary_stats['TOTAL_RULES_EVALUATED']}")
        
        status = f"{Fore.RED}[NON-COMPLIANT]" if (self.summary_stats['CRITICAL'] > 0 or self.summary_stats['HIGH'] > 0) else f"{Fore.GREEN}[COMPLIANT]"
        print(f"  Overall Compliance  : {status}\n")

    def save_json(self, output_path="audits/docker_audit_report.json"):
        """Save structured security audit report in JSON format."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        report = {
            "metadata": {
                "engine": "PEER'S Docker Container Misconfiguration Scanner v2.0",
                "author": "Mohammed Peer Siddiqui",
                "company": "Sqrock IT Solutions",
                "target_file": self.target_dockerfile,
                "timestamp": datetime.now().isoformat(),
                "standards": ["CIS Docker Benchmark v1.6.0", "NIST SP 800-190"]
            },
            "summary_stats": self.summary_stats,
            "findings_count": len(self.findings),
            "findings": self.findings
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4)
        return output_path

    def save_summary_text(self, output_path="audits/docker_audit_summary.txt"):
        """Save human-readable security executive audit summary."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        lines = [
            "=" * 74,
            "PEER'S DOCKER CONTAINER MISCONFIGURATION AUDIT SUMMARY",
            "CIS Docker Benchmark v1.6.0 & NIST SP 800-190 Compliance",
            "=" * 74,
            f"Target Dockerfile : {self.target_dockerfile}",
            f"Generated At      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Total Findings    : {len(self.findings)}",
            f"Severity Counts   : CRITICAL: {self.summary_stats['CRITICAL']} | HIGH: {self.summary_stats['HIGH']} | MEDIUM: {self.summary_stats['MEDIUM']} | LOW: {self.summary_stats['LOW']}",
            "=" * 74,
            ""
        ]
        for idx, f in enumerate(self.findings, 1):
            lines.append(f"[{idx}] {f['severity']} - {f['title']} (Line {f['line']})")
            lines.append(f"    Standards   : {f['cis_id']} | {f['nist_id']}")
            lines.append(f"    Instruction : {f['raw_instruction']}")
            lines.append(f"    Description : {f['description']}")
            lines.append(f"    Remediation : {f['remediation']}")
            lines.append("-" * 74)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))
        return output_path


def main():
    import argparse
    parser = argparse.ArgumentParser(description="PEER'S Docker Container Misconfiguration Scanner v2.0")
    parser.add_argument("--dockerfile", default="samples/Dockerfile.vulnerable", help="Path to target Dockerfile")
    parser.add_argument("--json-out", default="audits/docker_audit_report.json", help="Path for JSON audit export")
    parser.add_argument("--txt-out", default="audits/docker_audit_summary.txt", help="Path for TXT audit export")
    args = parser.parse_args()

    scanner = DockerSecurityScanner(args.dockerfile)
    scanner.audit()
    scanner.print_cli_summary()
    scanner.save_json(args.json_out)
    scanner.save_summary_text(args.txt_out)
    print(f"{Fore.GREEN}[+] Audit JSON saved to: {args.json_out}")
    print(f"{Fore.GREEN}[+] Summary text saved to: {args.txt_out}")

if __name__ == "__main__":
    main()
