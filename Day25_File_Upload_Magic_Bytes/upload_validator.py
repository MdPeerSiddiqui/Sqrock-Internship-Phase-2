"""
PEER'S File Upload Vulnerability & Magic Bytes Security Validator v2.0
======================================================================
Binary Magic Bytes Inspection, Extension Spoofing & Polyglot Malware Defense
OWASP Top 10 A04:2021 (Insecure Design) | CWE-434 (Unrestricted File Upload)

Author: Mohammed Peer Siddiqui
Company: Sqrock IT Solutions
Track: Phase 2 - Web Application Security & Defensive Automation (Day 25)
Monorepo: https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2
"""

import os
import sys
import re
import json
import hashlib
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

class FileUploadValidator:
    """
    Enterprise-grade file upload security validation engine:
    - Validates binary magic byte headers (signatures)
    - Detects extension spoofing and double-extensions (shell.php.png)
    - Scans for embedded polyglot executable scripts (<?php, <script>)
    - Computes cryptographic SHA-256 hashes and generates safe quarantine names
    """

    MAGIC_SIGNATURES = {
        "png": [(b'\x89PNG\r\n\x1a\n', "image/png")],
        "jpg": [(b'\xff\xd8\xff', "image/jpeg")],
        "jpeg": [(b'\xff\xd8\xff', "image/jpeg")],
        "gif": [(b'GIF87a', "image/gif"), (b'GIF89a', "image/gif")],
        "pdf": [(b'%PDF', "application/pdf")],
        "zip": [(b'PK\x03\x04', "application/zip")]
    }

    BANNED_EXTENSIONS = {
        "php", "php3", "php4", "php5", "phtml", "jsp", "asp", "aspx",
        "exe", "sh", "bash", "bat", "cmd", "py", "pl", "cgi", "jar"
    }

    POLYGLOT_SIGNATURES = [
        (re.compile(rb'(?i)<\?php', re.IGNORECASE), "Embedded PHP Script Execution Block"),
        (re.compile(rb'(?i)<\s*script\b', re.IGNORECASE), "Embedded Client-Side HTML/JavaScript Tag"),
        (re.compile(rb'(?i)<%', re.IGNORECASE), "Embedded ASP/JSP Directive Block"),
        (re.compile(rb'(?i)eval\s*\(', re.IGNORECASE), "Dynamic Code Evaluation Function (eval)"),
        (re.compile(rb'(?i)(system|passthru|shell_exec|popen)\s*\(', re.IGNORECASE), "Command Execution Sink"),
        (re.compile(rb'#!/bin/(bash|sh)', re.IGNORECASE), "Unix Shell Script Interpreter Shebang")
    ]

    def __init__(self, target_dir=None):
        self.target_dir = target_dir
        self.findings = []
        self.metrics = {
            "total_files_audited": 0,
            "allowed_files": 0,
            "rejected_malicious_files": 0,
            "magic_byte_mismatches": 0,
            "double_extensions_detected": 0,
            "polyglot_malware_detected": 0
        }

    def validate_file(self, filepath):
        """Conducts deep forensic validation on a single file upload."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File '{filepath}' not found.")

        filename = os.path.basename(filepath)
        file_size = os.path.getsize(filepath)
        violations = []
        severity = "SAFE"
        verdict = "ALLOWED"

        # 1. Filename & Extension Sanitization
        lower_name = filename.lower()
        parts = lower_name.split('.')
        ext = parts[-1] if len(parts) > 1 else ""

        # Check for banned direct executable extension
        if ext in self.BANNED_EXTENSIONS:
            violations.append(f"Direct executable extension detected: .{ext}")
            severity = "CRITICAL"

        # Check for double extension spoofing (e.g. shell.php.png)
        if len(parts) > 2:
            inner_extensions = parts[1:-1]
            for inner in inner_extensions:
                if inner in self.BANNED_EXTENSIONS:
                    violations.append(f"Double-extension spoofing detected: .{inner}.{ext}")
                    severity = "CRITICAL"
                    self.metrics["double_extensions_detected"] += 1

        # Check for null byte injection
        if "%00" in lower_name or "\x00" in filename:
            violations.append("Null-byte (%00) path truncation attempt detected")
            severity = "CRITICAL"

        # 2. Binary Magic Bytes (Signature) Inspection
        with open(filepath, 'rb') as f:
            header = f.read(32)
            f.seek(0)
            full_content = f.read()

        sha256_hash = hashlib.sha256(full_content).hexdigest()

        # Compare magic bytes with claimed extension
        if ext in self.MAGIC_SIGNATURES:
            valid_signatures = self.MAGIC_SIGNATURES[ext]
            matched = False
            for sig, mime in valid_signatures:
                if header.startswith(sig):
                    matched = True
                    detected_mime = mime
                    break
            if not matched:
                violations.append(f"Magic bytes header mismatch: claimed .{ext} but signature was invalid or spoofed")
                severity = "CRITICAL"
                self.metrics["magic_byte_mismatches"] += 1
                detected_mime = "application/octet-stream (Spoofed)"
        else:
            detected_mime = "application/octet-stream"
            if ext not in self.BANNED_EXTENSIONS:
                violations.append(f"Unapproved file extension: .{ext}")
                severity = "HIGH"

        # 3. Polyglot Malware & Embedded Executable Inspection
        for pattern, desc in self.POLYGLOT_SIGNATURES:
            if pattern.search(full_content):
                violations.append(f"Polyglot attack detected: {desc}")
                severity = "CRITICAL"
                self.metrics["polyglot_malware_detected"] += 1

        if violations:
            verdict = "REJECTED"
            self.metrics["rejected_malicious_files"] += 1
        else:
            self.metrics["allowed_files"] += 1

        self.metrics["total_files_audited"] += 1

        # Safe quarantine target name
        quarantine_name = f"{sha256_hash[:16]}.{ext if ext in self.MAGIC_SIGNATURES else 'quarantine'}"

        result = {
            "filename": filename,
            "filepath": filepath,
            "file_size_bytes": file_size,
            "sha256": sha256_hash,
            "claimed_extension": ext,
            "detected_mime": detected_mime,
            "verdict": verdict,
            "severity": severity,
            "violations": violations,
            "quarantine_name": quarantine_name
        }
        self.findings.append(result)
        return result

    def validate_directory(self, dir_path=None):
        """Scans all files in target samples directory."""
        path = dir_path or self.target_dir
        if not path or not os.path.exists(path):
            raise FileNotFoundError(f"Target directory '{path}' not found.")

        self.findings = []
        for root, _, files in os.walk(path):
            for file in sorted(files):
                full_p = os.path.join(root, file)
                self.validate_file(full_p)
        return self.findings

    def print_cli_summary(self):
        """Renders Kali Linux style interactive file upload validator console."""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}" + "="*74)
        print(f"{Fore.CYAN}{Style.BRIGHT}  PEER'S FILE UPLOAD & MAGIC BYTES SECURITY VALIDATOR v2.0")
        print(f"{Fore.CYAN}{Style.BRIGHT}  Binary Header Inspection, Double Extension & Polyglot Malware Defense")
        print(f"{Fore.CYAN}{Style.BRIGHT}" + "="*74 + f"{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Target Directory : {Fore.YELLOW}{self.target_dir}")
        print(f"{Fore.WHITE}Audited Files    : {Fore.GREEN}{self.metrics['total_files_audited']}")
        print(f"{Fore.WHITE}Audit Timestamp  : {Fore.LIGHTBLACK_EX}{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")

        print(f"{Fore.YELLOW}{Style.BRIGHT}[+] FILE UPLOAD SECURITY INSPECTION LEDGER:{Style.RESET_ALL}")
        print("-" * 74)
        print(f"{'VERDICT':<10} {'SIZE':<8} {'CLAIMED':<8} {'FILE NAME':<26} {'SECURITY REASON / VIOLATION'}")
        print("-" * 74)

        for f in self.findings:
            if f["verdict"] == "ALLOWED":
                v_str = f"{Fore.GREEN}{Style.BRIGHT}[ALLOWED]{Style.RESET_ALL}"
                r_str = f"{Fore.GREEN}Verified valid magic bytes & clean content"
            else:
                v_str = f"{Fore.RED}{Style.BRIGHT}[BLOCKED]{Style.RESET_ALL}"
                r_str = f"{Fore.RED}{'; '.join(f['violations'])}"

            print(f"{v_str:<18} {f['file_size_bytes']:<8} .{f['claimed_extension']:<7} {Fore.WHITE}{f['filename']:<26} {r_str}")

        print(f"\n{Fore.CYAN}{Style.BRIGHT}" + "="*74)
        print(f"{Fore.CYAN}{Style.BRIGHT}  DEFENSIVE METRICS & QUARANTINE SUMMARY")
        print(f"{Fore.CYAN}{Style.BRIGHT}" + "="*74 + f"{Style.RESET_ALL}")
        print(f"  Total Uploads Evaluated     : {Fore.WHITE}{self.metrics['total_files_audited']}")
        print(f"  Approved Safe Artifacts     : {Fore.GREEN}{self.metrics['allowed_files']}")
        print(f"  Rejected Malicious Uploads  : {Fore.RED}{Style.BRIGHT}{self.metrics['rejected_malicious_files']}{Style.RESET_ALL}")
        print(f"  Magic Bytes Mismatches      : {Fore.YELLOW}{self.metrics['magic_byte_mismatches']}")
        print(f"  Double Extensions Detected  : {Fore.YELLOW}{self.metrics['double_extensions_detected']}")
        print(f"  Polyglot Malware Blocked    : {Fore.RED}{self.metrics['polyglot_malware_detected']}\n")

    def save_json(self, output_path="validation_results/file_upload_report.json"):
        """Saves machine-readable JSON security report."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        report = {
            "metadata": {
                "engine": "PEER'S File Upload Vulnerability & Magic Bytes Security Validator v2.0",
                "author": "Mohammed Peer Siddiqui",
                "company": "Sqrock IT Solutions",
                "timestamp": datetime.now().isoformat(),
                "standards": ["OWASP Top 10 A04:2021", "CWE-434"]
            },
            "metrics": self.metrics,
            "findings": self.findings
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4)
        return output_path

    def save_summary_text(self, output_path="validation_results/file_upload_summary.txt"):
        """Saves human-readable SOC analyst triage summary."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        lines = [
            "=" * 74,
            "PEER'S FILE UPLOAD SECURITY INSPECTION SUMMARY",
            "Binary Magic Bytes, Extension Spoofing & Polyglot Defense",
            "=" * 74,
            f"Generated At           : {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Total Files Audited    : {self.metrics['total_files_audited']}",
            f"Approved Safe Files    : {self.metrics['allowed_files']}",
            f"Rejected Malicious     : {self.metrics['rejected_malicious_files']}",
            "=" * 74,
            "",
            "DETAILED EVALUATION FINDINGS:"
        ]
        for f in self.findings:
            lines.append(f"[{f['verdict']}] {f['filename']} ({f['file_size_bytes']} bytes) - Severity: {f['severity']}")
            lines.append(f"    SHA-256    : {f['sha256']}")
            lines.append(f"    Claimed Ext: .{f['claimed_extension']} | Detected MIME: {f['detected_mime']}")
            if f["violations"]:
                lines.append(f"    Violations : {'; '.join(f['violations'])}")
            lines.append(f"    Quarantine : {f['quarantine_name']}")
            lines.append("-" * 74)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))
        return output_path


def main():
    import argparse
    parser = argparse.ArgumentParser(description="PEER'S File Upload Validator v2.0")
    parser.add_argument("--dir", default="samples", help="Path to sample files directory")
    parser.add_argument("--json-out", default="validation_results/file_upload_report.json", help="JSON report path")
    parser.add_argument("--txt-out", default="validation_results/file_upload_summary.txt", help="TXT summary path")
    args = parser.parse_args()

    validator = FileUploadValidator(target_dir=args.dir)
    validator.validate_directory()
    validator.print_cli_summary()
    validator.save_json(args.json_out)
    validator.save_summary_text(args.txt_out)
    print(f"{Fore.GREEN}[+] Validation JSON saved to: {args.json_out}")
    print(f"{Fore.GREEN}[+] Summary text saved to: {args.txt_out}")

if __name__ == "__main__":
    main()
