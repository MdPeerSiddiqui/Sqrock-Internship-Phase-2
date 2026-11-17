# Day 21: Cross-Site Scripting (XSS) Payload Sanitizer & Defense Suite

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![Security Standard](https://img.shields.io/badge/OWASP-Top%2010%20A03%3A2021%20Injection-red.svg?style=for-the-badge&logo=owasp)](https://owasp.org/Top10/A03_2021-Injection/)
[![CWE Standard](https://img.shields.io/badge/CWE-79%20Cross--Site%20Scripting-orange.svg?style=for-the-badge)](https://cwe.mitre.org/data/definitions/79.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Unit Tests](https://img.shields.io/badge/Unit%20Tests-6%2F6%20Passed-brightgreen.svg?style=for-the-badge)](tests/test_xss_sanitizer.py)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Windows-black.svg?style=for-the-badge&logo=linux)](https://www.kali.org/)

> **Phase 2 Deliverable (Week 5 — Day 1)**  
> **Company:** Sqrock IT Solutions  
> **Track:** Alpha 2 Internship — Web Application Security & Defensive Automation  
> **Developer:** Mohammed Peer Siddiqui  
> **Monorepo Repository:** [https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2](https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2)

---

## 📌 Executive Overview

Cross-Site Scripting (**CWE-79 / OWASP Top 10 A03:2021**) occurs when web applications reflect or persist unvalidated user inputs directly into browser DOM execution contexts. If an attacker injects unescaped markup or scripts, the browser executes the payload within the security context of the victim's session—enabling cookie theft (`document.cookie`), CSRF token harvesting, DOM defacement, and keystroke logging.

**PEER'S XSS Payload Sanitizer & Defense Suite v2.0** is an enterprise-grade input neutralization and defense-in-depth framework developed for **Day 21** of the Sqrock IT Solutions Cybersecurity Internship (Phase 2). Addressing the limitations of naive character strippers, the engine applies **context-aware sanitization** across HTML body, attribute value, and URI sinks, while pairing output encoding with automated **Content Security Policy (CSP Level 3)** header generation.

```
+========================================================================+
|             PEER'S XSS PAYLOAD SANITIZER & DEFENSE SUITE v2.0          |
+========================================================================+
|                                                                        |
|  [Ingestion: Untrusted User Input / Query / Form / JSON Payloads]      |
|          |                                                             |
|          v                                                             |
|  [Sink Context Router & Attack Heuristic Analyzer]                     |
|     - Detects <script>, inline on*, javascript:, SVG, and DOM sinks    |
|          |                                                             |
|          v                                                             |
|  [Context-Aware Sanitization & Entity Encoding Engine]                 |
|   +------------------------------------------------------------------+ |
|   | 1. HTML Body Context:      Strip tags (<script>) + Entity Encode | |
|   | 2. Attribute Value Context:Convert on* to data-disabled-* + Quote | |
|   | 3. URI Attribute Context:  Block javascript: & data: protocols   | |
|   | 4. DOM Sink Context:       Universal entity reference encoding   | |
|   +------------------------------------------------------------------+ |
|          |                                                             |
|          +-----------------------------+-------------------------------+
|          |                             |                               |
|          v                             v                               v
|  [Enterprise CSP Generator]     [Machine-Readable JSON]      [7-Page PDF Report]
|   - Content-Security-Policy     - sanitizer_results/report   - Day21_Report
|   - Strict nonce-based defense  - sanitizer_results/summary  - Verified 7 Pages
+========================================================================+
```

---

## 🎯 Context-Aware Sanitization Taxonomy

| Injection Sink | Example Attack Vector | Bypass Vulnerability | Sanitization & Defense Strategy |
|:---|:---|:---|:---|
| **HTML Body** | `<script>alert(document.cookie)</script>` | RCE in browser context | Complete tag excision + HTML entity encoding (`&lt;`, `&gt;`, `&amp;`). |
| **Inline Event** | `<img src=x onerror="alert('XSS')">` | DOM event trigger | Neutralize to `data-disabled-onerror` + entity encode attributes. |
| **Attribute Breakout**| `" onfocus="alert(1)" autofocus="` | Breaking out of quotes | HTML quote entity encoding (`&quot;`, `&#x27;`) + event disabling. |
| **URI Attribute** | `<a href="javascript:alert(1)">` | Protocol handler execution | Disallow and block `javascript:`, `data:`, and `vbscript:` schemes. |
| **DOM innerHTML** | `<iframe src="javascript:alert(1)">` | Direct DOM insertion | Encode special characters; migrate to safe API `textContent`. |

---

## 🛠️ Project Structure

```
Day21_XSS_Payload_Sanitizer/
├── reports/
│   ├── screenshots/                    # 6 High-resolution Kali Linux terminal proofs
│   │   ├── 01_kali_init_banner.png
│   │   ├── 02_master_menu.png
│   │   ├── 03_payload_batch_ingestion.png
│   │   ├── 04_live_sanitization_sweep.png
│   │   ├── 05_csp_policy_generator.png
│   │   └── 06_github_repo_overview.png
│   └── Day21_XSS_Sanitizer_Report_Sqrock_MdPeerSiddiqui.pdf # 7-page executive report
├── samples/
│   └── test_payloads.json              # 7 Multi-vector test payloads (Reflected, Stored, DOM)
├── sanitizer_results/
│   ├── xss_audit_report.json           # Machine-readable structured security report
│   └── xss_audit_summary.txt           # SOC analyst executive triage briefing
├── scripts/
│   ├── generate_terminal_screens.py    # Headless PIL terminal visual generator
│   └── generate_day21_pdf.py           # Multi-page ReportLab PDF compiler
├── tests/
│   └── test_xss_sanitizer.py           # 6 automated PyUnit test cases
├── xss_sanitizer.py                    # Core context-aware sanitization engine
└── README.md                           # Master documentation
```

---

## 🚀 Quickstart Guide

### 1. Ingest & Sanitize Sample Attack Payloads
```powershell
python xss_sanitizer.py --payloads samples/test_payloads.json
```

### 2. Generate Enterprise Content Security Policy (CSP) Header
```powershell
python -c "from xss_sanitizer import XSSSanitizer; print(XSSSanitizer().generate_csp_header())"
```

### 3. Run Automated Unit Tests (100% Pass)
```powershell
python -m unittest tests/test_xss_sanitizer.py -v
```

### 4. Regenerate Executive 7-Page PDF Report
```powershell
python scripts/generate_day21_pdf.py
```

---

## 🛡️ Remediation: Context-Aware Escaping & CSP Level 3

### ❌ Insecure Code (Direct HTML Concatenation):
```python
# VULNERABLE: Direct string interpolation into DOM sink
return f"<div>Hello, {user_input}!</div>"
```

### ✅ Hardened Code (HTML Entity Escaping):
```python
import html
# SECURE: Universal entity conversion of dangerous characters
safe_input = html.escape(user_input, quote=True)
return f"<div>Hello, {safe_input}!</div>"
```

### 🛡️ Layer 2 Defense: Hardened Content Security Policy (CSP Level 3):
```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-sqrock_secops_nonce_7749' https://trustedcdn.sqrock.com; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self';
```

---

## 🧪 Unit Testing Results
```
test_benign_text_preservation (TestXSSSanitizer) ... ok
test_csp_header_generation (TestXSSSanitizer) ... ok
test_event_handler_neutralization (TestXSSSanitizer) ... ok
test_html_entity_encoding (TestXSSSanitizer) ... ok
test_javascript_pseudo_protocol (TestXSSSanitizer) ... ok
test_script_tag_stripping (TestXSSSanitizer) ... ok

----------------------------------------------------------------------
Ran 6 tests in 0.002s

OK
```

---

## 💼 LinkedIn Captions (Phase 2 - Day 21)

### Option 1: Technical & DevSecOps Engineering Focus
```text
🚀 Day 21 of my Cybersecurity Internship at Sqrock IT Solutions: Cross-Site Scripting (XSS) Payload Sanitizer & Defense Suite

Cross-Site Scripting (OWASP A03 / CWE-79) cannot be solved with naive blacklist string filters. Web browsers parse HTML, attributes, and URIs through completely different lexical state machines.

Today, I engineered PEER'S XSS Payload Sanitizer v2.0:
🛡️ Built context-aware sanitization routing across HTML Body, Attribute Value, URI Attribute, and DOM Sinks.
🔍 Neutralizes inline event handlers (onerror, onload) to data-disabled-* attributes while excising dangerous script tags.
🔒 Blocks javascript: and data: pseudo-protocols across hyperlinked components.
⚡ Automatically generates cryptographic nonce-based Content Security Policy (CSP Level 3) headers ensuring browser-level execution barriers.

Complete codebase, 6 unit tests, and 7-page executive report pushed to my Phase 2 monorepo:
🔗 GitHub: https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2

#XSS #AppSec #Cybersecurity #WebSecurity #CSP #DevSecOps #SqrockITSolutions #Python
```

### Option 2: Executive & Blue Team Strategy Focus
```text
🛡️ Building Defense-in-Depth Against Cross-Site Scripting: Day 21 at Sqrock IT Solutions

Session hijacking and credential harvesting via XSS remain prominent threats in web application ecosystems. Today's focus was on engineering multi-layered input and output security controls:

✅ Developed an automated XSS neutralization engine mapped to OWASP Top 10 A03:2021 and CWE-79.
✅ Implemented context-aware HTML entity encoding to ensure complete neutralization across distinct browser sinks.
✅ Combined input sanitization with strict Content Security Policy (CSP Level 3) directives to render injected scripts inert.
✅ Backed by 6 unit tests and an authoritative 7-page executive compliance lab report.

Explore the repository:
🔗 https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2

#ApplicationSecurity #BlueTeam #InformationSecurity #SecureCoding #CybersecurityInternship #Sqrock
```
