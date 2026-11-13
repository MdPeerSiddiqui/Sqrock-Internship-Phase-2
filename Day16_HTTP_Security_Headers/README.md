# Day 16: HTTP Security Header Analysis & CSP Defense Engine

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![Security Standard](https://img.shields.io/badge/OWASP-A05%3A2021%20Security%20Misconfiguration-red.svg?style=for-the-badge&logo=owasp)](https://owasp.org/)
[![RFC Standard](https://img.shields.io/badge/RFC-6797%20(HSTS)%20%7C%207034%20(XFO)-orange.svg?style=for-the-badge)](https://tools.ietf.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Unit Tests](https://img.shields.io/badge/Unit%20Tests-6%2F6%20Passed-brightgreen.svg?style=for-the-badge)](tests/test_header_analyzer.py)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Windows-black.svg?style=for-the-badge&logo=linux)](https://www.kali.org/)

> **Phase 2 Deliverable (Week 4 — Day 1)**  
> **Company:** Sqrock IT Solutions  
> **Track:** Alpha 2 Internship — Web Application Security & Defensive Automation  
> **Developer:** Mohammed Peer Siddiqui  
> **Monorepo Repository:** [https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2](https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2)

---

## 📌 Executive Overview

HTTP response headers provide instructions to client browsers on policy execution parameters. When web applications omit or misconfigure these cryptographic parameters, client browsers default to permissive behaviors—rendering applications vulnerable to **Cross-Site Scripting (XSS)**, **Clickjacking (UI Redressing)**, **SSL-Stripping / Man-in-the-Middle (MitM)**, and **MIME-confusion exploits**. According to OWASP Top 10 (A05:2021 - Security Misconfiguration), improper header configurations represent one of the most common attack vectors in enterprise infrastructure.

**PEER'S HTTP Security Header Analyzer v2.0** is an enterprise-grade web security auditing and scoring engine built for **Day 16** of the Sqrock IT Solutions Cybersecurity Internship (Phase 2). It performs deep static and dynamic response header audits, evaluates directive hygiene (such as CSP `script-src` and HSTS `max-age`), computes a quantitative 0-100 Posture Score, assigns standardized letter grades (A+ through F), and outputs actionable JSON and text remediation dossiers.

```
+========================================================================+
|             PEER'S HTTP SECURITY HEADER ANALYZER v2.0                  |
+========================================================================+
|                                                                        |
|  [Target Web Endpoint / Simulated Server Response Telemetry]          |
|          |                                                             |
|          v                                                             |
|  [HTTP Ingestion & Header Normalization Core]                          |
|     - Case-insensitive indexing, canonical RFC resolution              |
|          |                                                             |
|          v                                                             |
|  [Cryptographic Evaluation Engine (OWASP A05:2021 Weights)]            |
|   +------------------------------------------------------------------+ |
|   | 1. Strict-Transport-Security (25 pts) -> max-age, subdomains     | |
|   | 2. Content-Security-Policy   (30 pts) -> default-src, no unsafe | |
|   | 3. X-Frame-Options           (15 pts) -> DENY / SAMEORIGIN       | |
|   | 4. X-Content-Type-Options    (10 pts) -> nosniff                 | |
|   | 5. Referrer-Policy           (10 pts) -> strict-origin           | |
|   | 6. Permissions-Policy        (10 pts) -> camera/mic/geo disabled | |
|   +------------------------------------------------------------------+ |
|          |                                                             |
|          +-----------------------------+-------------------------------+
|          |                             |                               |
|          v                             v                               v
|  [Information Disclosure Check] [Quantitative Scoring]    [Formal Audit Export]
|   - Strip Server & X-Powered-By  - Score 0-100, Grade A-F  - JSON & TXT Dossiers
+========================================================================+
```

---

## 🎯 Evaluated Security Headers & Technical Specifications

| Header Name | Weight | Primary Vulnerability Mitigated | Best Practice Recommendation | RFC / Standard |
|:---|:---:|:---|:---|:---|
| **Strict-Transport-Security** | `25 pts` | SSL-Stripping, Man-in-the-Middle | `max-age=31536000; includeSubDomains; preload` | RFC 6797 |
| **Content-Security-Policy** | `30 pts` | Cross-Site Scripting (XSS), Data Exfiltration | `default-src 'self'; script-src 'self'; object-src 'none';` | W3C CSP Level 3 |
| **X-Frame-Options** | `15 pts` | Clickjacking / UI Redressing | `DENY` or `SAMEORIGIN` | RFC 7034 |
| **X-Content-Type-Options** | `10 pts` | MIME-Sniffing / Type Confusion | `nosniff` | Fetch Standard |
| **Referrer-Policy** | `10 pts` | Sensitive URL Parameter Leakage | `strict-origin-when-cross-origin` | W3C Referrer Policy |
| **Permissions-Policy** | `10 pts` | Unauthorized Browser Hardware Access | `geolocation=(), microphone=(), camera=()` | W3C Feature Policy |

---

## 🔬 Content-Security-Policy (CSP) Defense Breakdown

Content-Security-Policy provides declarative instructions to client browsers restricting resource origins:
* **`default-src 'self'`**: Sets a strict fallback policy blocking all resource loading from third-party origins unless explicitly permitted.
* **`script-src 'self'`**: Neutralizes inline script injection (`<script>alert(1)</script>`) and disables dangerous dynamic code evaluation (`eval()`).
* **`object-src 'none'`**: Completely eliminates legacy plugin attack surfaces (Flash, Java Applets, ActiveX).
* **`frame-ancestors 'none'`**: Modern CSP replacement for `X-Frame-Options` that prevents embedding inside unauthorized framing contexts.

---

## 🛠️ Project Structure

```
Day16_HTTP_Security_Headers/
├── audit_results/
│   ├── header_audit_report.json        # Structured machine-readable posture audit
│   └── header_audit_summary.txt        # SOC analyst executive briefing
├── reports/
│   ├── screenshots/                    # 6 High-resolution Kali Linux terminal proofs
│   │   ├── 01_kali_init_banner.png
│   │   ├── 02_master_menu.png
│   │   ├── 03_hardened_audit_grade_a.png
│   │   ├── 04_vulnerable_server_grade_f.png
│   │   ├── 05_csp_deep_dive_analysis.png
│   │   └── 06_github_repo_overview.png
│   └── Day16_HTTP_Security_Header_Report_Sqrock_MdPeerSiddiqui.pdf # 7-page executive report
├── scripts/
│   ├── generate_terminal_screens.py    # Headless PIL terminal visual generator
│   └── generate_day16_pdf.py           # Multi-page ReportLab PDF compiler
├── tests/
│   └── test_header_analyzer.py         # 6 automated PyUnit test cases
├── header_analyzer.py                  # Core HTTP inspection and scoring engine
└── README.md                           # Master documentation
```

---

## 🚀 Quickstart Guide

### 1. Run Automated Unit Tests
Verify all parsing rules, CSP warnings, and scoring algorithms:

```bash
python -m unittest tests/test_header_analyzer.py -v
```

Output:
```
test_csp_unsafe_inline_warning ... ok
test_hardened_headers_grade_a ... ok
test_hsts_subdomain_and_maxage_checks ... ok
test_information_disclosure_detection ... ok
test_report_export ... ok
test_vulnerable_empty_headers_grade_f ... ok

----------------------------------------------------------------------
Ran 6 tests in 0.003s

OK
```

### 2. Launch Interactive Command Line Interface
Launch the interactive Kali terminal console:

```bash
python header_analyzer.py
```

Console options:
- `[1] Audit Custom Target URL` - Connects to target URL, performs TLS handshake, and grades headers.
- `[2] Run Hardened Production Benchmark Audit` - Validates full A+ security header compliance (100/100).
- `[3] Run Legacy Vulnerable Server Simulation` - Simulates unhardened server with zero headers (Grade F).
- `[4] Inspect Content-Security-Policy (CSP) Directives Breakdown` - Deep dive into directive defense mechanisms.
- `[5] Export Formal Security Header Audit Reports` - Generates JSON and TXT dossiers.
- `[6] Exit Suite`

---

## 🛡️ Reverse Proxy Hardening Snippets

### Nginx (`nginx.conf`)
```nginx
# Enforce cryptographic transport and boundary security
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

# Strip technology disclosure
server_tokens off;
```

---

## ⚖️ License
Distributed under the MIT License. See [LICENSE](../LICENSE) for full legal text.

**Author:** Mohammed Peer Siddiqui  
**Internship:** Sqrock IT Solutions Cybersecurity Internship Phase 2 (Day 16)
