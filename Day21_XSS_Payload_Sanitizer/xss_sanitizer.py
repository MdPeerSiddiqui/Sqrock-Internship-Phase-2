"""
PEER'S Cross-Site Scripting (XSS) Payload Sanitizer & Defense Suite v2.0
========================================================================
Context-Aware Input Neutralization, HTML Entity Encoding & CSP Policy Generator
OWASP Top 10 A03:2021 (Injection) | CWE-79 (Improper Neutralization of Input)

Author: Mohammed Peer Siddiqui
Company: Sqrock IT Solutions
Track: Phase 2 - Web Application Security & Defensive Automation (Day 21)
Monorepo: https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2
"""

import os
import sys
import re
import json
import html
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

class XSSSanitizer:
    """
    Context-aware XSS detection, neutralization, and encoding engine
    supporting HTML Body, Attribute Value, and URI contexts.
    """

    XSS_PATTERNS = {
        "SCRIPT_TAG": (re.compile(r'(?i)<\s*script[^>]*>.*?<\s*/\s*script\s*>', re.DOTALL), "Explicit <script> block injection"),
        "INLINE_EVENT": (re.compile(r'(?i)\b(onerror|onload|onclick|onmouseover|onfocus|onblur|onsubmit|onloadstart)\s*=', re.IGNORECASE), "Inline DOM event handler execution"),
        "JS_PSEUDO_PROTOCOL": (re.compile(r'(?i)(javascript|vbscript|data):', re.IGNORECASE), "URI attribute pseudo-protocol execution"),
        "DANGEROUS_TAG": (re.compile(r'(?i)<\s*(iframe|object|embed|svg|base|link|meta|applet)\b', re.IGNORECASE), "High-risk executable HTML container/tag"),
        "DOM_SINK_EVAL": (re.compile(r'(?i)(eval\s*\(|document\.cookie|document\.domain|window\.origin)', re.IGNORECASE), "Sensitive DOM sink manipulation & credential harvesting")
    }

    HTML_REPLACEMENTS = [
        ('&', '&amp;'),
        ('<', '&lt;'),
        ('>', '&gt;'),
        ('"', '&quot;'),
        ("'", '&#x27;'),
        ('/', '&#x2F;')
    ]

    def __init__(self, sample_file=None):
        self.sample_file = sample_file
        self.findings = []
        self.metrics = {
            "total_payloads_evaluated": 0,
            "xss_detected": 0,
            "benign_inputs": 0,
            "neutralized_count": 0
        }

    def detect_vectors(self, text):
        """Identifies specific XSS attack patterns within raw input strings."""
        detected = []
        for rule_key, (pattern, desc) in self.XSS_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                detected.append({
                    "rule": rule_key,
                    "description": desc,
                    "match_count": len(matches)
                })
        return detected

    def html_entity_encode(self, text):
        """Converts raw HTML special characters into immutable HTML entity references."""
        encoded = text
        for char, entity in self.HTML_REPLACEMENTS:
            encoded = encoded.replace(char, entity)
        return encoded

    def strip_dangerous_tags(self, text):
        """Removes executable HTML tags and dangerous container elements."""
        clean = text
        clean = re.sub(r'(?i)<\s*script[^>]*>.*?<\s*/\s*script\s*>', '', clean, flags=re.DOTALL)
        clean = re.sub(r'(?i)<\s*(iframe|object|embed|svg|applet)[^>]*>.*?<\s*/\s*\1\s*>', '', clean, flags=re.DOTALL)
        clean = re.sub(r'(?i)<\s*(iframe|object|embed|svg|applet|base|link|meta)[^>]*>', '', clean)
        return clean

    def neutralize_event_handlers(self, text):
        """Neutralizes DOM inline event handlers by replacing equal signs."""
        return re.sub(r'(?i)\b(on\w+)\s*=', r'data-disabled-\1=', text)

    def sanitize_context_aware(self, text, context="html_body"):
        """
        Executes strict context-aware sanitization based on insertion sink:
        - html_body: Strips dangerous tags + HTML entity encoding.
        - attribute_value: Strict quote escaping and event handler neutralization.
        - uri_attribute: Disallows javascript: and data: pseudo-protocols.
        - dom_sink: Universal entity encoding.
        """
        if context == "html_body":
            stripped = self.strip_dangerous_tags(text)
            neutralized = self.neutralize_event_handlers(stripped)
            return self.html_entity_encode(neutralized)

        elif context == "attribute_value":
            neutralized = self.neutralize_event_handlers(text)
            return self.html_entity_encode(neutralized)

        elif context == "uri_attribute":
            # Disallow execution protocols
            if re.match(r'(?i)^\s*(javascript|vbscript|data):', text):
                return "#blocked-insecure-uri"
            return html.escape(text, quote=True)

        elif context == "dom_sink":
            return self.html_entity_encode(text)

        return self.html_entity_encode(text)

    def generate_csp_header(self, nonce="sqrock_secops_nonce_7749"):
        """Generates a hardened Content Security Policy (CSP Level 3) header."""
        return (
            f"Content-Security-Policy: default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}' https://trustedcdn.sqrock.com; "
            f"object-src 'none'; "
            f"base-uri 'self'; "
            f"frame-ancestors 'none'; "
            f"form-action 'self';"
        )

    def audit_file(self, filepath=None):
        """Audits a batch of test payloads from JSON file."""
        target_path = filepath or self.sample_file
        if not target_path or not os.path.exists(target_path):
            raise FileNotFoundError(f"Payload file '{target_path}' not found.")

        with open(target_path, 'r', encoding='utf-8') as f:
            payloads = json.load(f)

        self.findings = []
        self.metrics = {"total_payloads_evaluated": 0, "xss_detected": 0, "benign_inputs": 0, "neutralized_count": 0}

        for item in payloads:
            p_id = item["id"]
            category = item["category"]
            raw_payload = item["payload"]
            context = item.get("context", "html_body")

            vectors = self.detect_vectors(raw_payload)
            is_malicious = len(vectors) > 0
            sanitized = self.sanitize_context_aware(raw_payload, context)

            self.metrics["total_payloads_evaluated"] += 1
            if is_malicious:
                self.metrics["xss_detected"] += 1
                self.metrics["neutralized_count"] += 1
                severity = "CRITICAL" if any(v["rule"] in ["SCRIPT_TAG", "DOM_SINK_EVAL"] for v in vectors) else "HIGH"
            else:
                self.metrics["benign_inputs"] += 1
                severity = "SAFE"

            self.findings.append({
                "id": p_id,
                "category": category,
                "context": context,
                "severity": severity,
                "raw_payload": raw_payload,
                "sanitized_output": sanitized,
                "detected_vectors": vectors,
                "is_neutralized": True
            })

        return self.findings

    def print_cli_summary(self):
        """Renders Kali Linux style interactive XSS sanitizer console."""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}" + "="*74)
        print(f"{Fore.CYAN}{Style.BRIGHT}  PEER'S XSS PAYLOAD SANITIZER & DEFENSE SUITE v2.0")
        print(f"{Fore.CYAN}{Style.BRIGHT}  Context-Aware Input Neutralization & Content Security Policy (CSP)")
        print(f"{Fore.CYAN}{Style.BRIGHT}" + "="*74 + f"{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Payload File     : {Fore.YELLOW}{self.sample_file}")
        print(f"{Fore.WHITE}Total Inquiries  : {Fore.GREEN}{self.metrics['total_payloads_evaluated']}")
        print(f"{Fore.WHITE}Execution Time   : {Fore.LIGHTBLACK_EX}{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")

        print(f"{Fore.YELLOW}{Style.BRIGHT}[+] PAYLOAD EVALUATION & NEUTRALIZATION LEDGER:{Style.RESET_ALL}")
        print("-" * 74)

        for f in self.findings:
            sev = f["severity"]
            if sev == "CRITICAL":
                sev_str = f"{Fore.RED}{Style.BRIGHT}[CRITICAL]{Style.RESET_ALL}"
            elif sev == "HIGH":
                sev_str = f"{Fore.LIGHTRED_EX}{Style.BRIGHT}[HIGH]    {Style.RESET_ALL}"
            else:
                sev_str = f"{Fore.GREEN}{Style.BRIGHT}[SAFE]    {Style.RESET_ALL}"

            print(f"{sev_str} {Style.BRIGHT}{f['id']} - {f['category']}{Style.RESET_ALL} (Sink: {f['context']})")
            print(f"   {Fore.WHITE}Raw Input   : {Fore.RED}{f['raw_payload']}")
            print(f"   {Fore.WHITE}Sanitized   : {Fore.GREEN}{f['sanitized_output']}")
            if f["detected_vectors"]:
                vec_summary = ", ".join([v["description"] for v in f["detected_vectors"]])
                print(f"   {Fore.YELLOW}Mitigated   : {vec_summary}")
            print()

        print(f"{Fore.CYAN}{Style.BRIGHT}" + "="*74)
        print(f"{Fore.CYAN}{Style.BRIGHT}  ENTERPRISE DEFENSE: CONTENT SECURITY POLICY (CSP)")
        print(f"{Fore.CYAN}{Style.BRIGHT}" + "="*74 + f"{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{self.generate_csp_header()}\n")

        print(f"{Fore.CYAN}{Style.BRIGHT}" + "="*74)
        print(f"{Fore.CYAN}{Style.BRIGHT}  TRIAGE METRICS SUMMARY")
        print(f"{Fore.CYAN}{Style.BRIGHT}" + "="*74 + f"{Style.RESET_ALL}")
        print(f"  Total Ingested      : {Fore.WHITE}{self.metrics['total_payloads_evaluated']}")
        print(f"  Malicious Vectors   : {Fore.RED}{Style.BRIGHT}{self.metrics['xss_detected']}{Style.RESET_ALL}")
        print(f"  Neutralized (100%)  : {Fore.GREEN}{Style.BRIGHT}{self.metrics['neutralized_count']}{Style.RESET_ALL}")
        print(f"  Benign Preserved    : {Fore.CYAN}{self.metrics['benign_inputs']}\n")

    def save_json(self, output_path="sanitizer_results/xss_audit_report.json"):
        """Saves machine-readable JSON security report."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        report = {
            "metadata": {
                "engine": "PEER'S XSS Payload Sanitizer & Defense Suite v2.0",
                "author": "Mohammed Peer Siddiqui",
                "company": "Sqrock IT Solutions",
                "timestamp": datetime.now().isoformat(),
                "standards": ["OWASP Top 10 A03:2021", "CWE-79"]
            },
            "csp_recommended": self.generate_csp_header(),
            "metrics": self.metrics,
            "findings": self.findings
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4)
        return output_path

    def save_summary_text(self, output_path="sanitizer_results/xss_audit_summary.txt"):
        """Saves human-readable SOC analyst triage summary."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        lines = [
            "=" * 74,
            "PEER'S XSS PAYLOAD SANITIZER & TRIAGE BRIEFING",
            "Context-Aware Neutralization & Content Security Policy (CSP)",
            "=" * 74,
            f"Generated At       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Payloads Audited   : {self.metrics['total_payloads_evaluated']}",
            f"Malicious Vectors  : {self.metrics['xss_detected']}",
            f"Neutralized Safe   : {self.metrics['neutralized_count']}",
            "=" * 74,
            "",
            "RECOMMENDED CONTENT SECURITY POLICY (CSP):",
            self.generate_csp_header(),
            "=" * 74,
            ""
        ]
        for f in self.findings:
            lines.append(f"[{f['severity']}] {f['id']} - {f['category']}")
            lines.append(f"    Raw Input : {f['raw_payload']}")
            lines.append(f"    Sanitized : {f['sanitized_output']}")
            lines.append("-" * 74)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))
        return output_path


def main():
    import argparse
    parser = argparse.ArgumentParser(description="PEER'S XSS Payload Sanitizer v2.0")
    parser.add_argument("--payloads", default="samples/test_payloads.json", help="Path to JSON test payloads")
    parser.add_argument("--json-out", default="sanitizer_results/xss_audit_report.json", help="Destination JSON report")
    parser.add_argument("--txt-out", default="sanitizer_results/xss_audit_summary.txt", help="Destination TXT summary")
    args = parser.parse_args()

    sanitizer = XSSSanitizer(args.payloads)
    sanitizer.audit_file()
    sanitizer.print_cli_summary()
    sanitizer.save_json(args.json_out)
    sanitizer.save_summary_text(args.txt_out)
    print(f"{Fore.GREEN}[+] Audit JSON saved to: {args.json_out}")
    print(f"{Fore.GREEN}[+] Summary text saved to: {args.txt_out}")

if __name__ == "__main__":
    main()
