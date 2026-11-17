# Day 20: Web Directory Brute-Force & Content Discovery Fuzzer

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![Security Standard](https://img.shields.io/badge/OWASP-Top%2010%20A01%3A2021%20Broken%20Access-red.svg?style=for-the-badge&logo=owasp)](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
[![Security Standard](https://img.shields.io/badge/OWASP-Top%2010%20A05%3A2021%20Security%20Misconfig-orange.svg?style=for-the-badge&logo=owasp)](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Unit Tests](https://img.shields.io/badge/Unit%20Tests-6%2F6%20Passed-brightgreen.svg?style=for-the-badge)](tests/test_dir_fuzzer.py)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Windows-black.svg?style=for-the-badge&logo=linux)](https://www.kali.org/)

> **Phase 2 Deliverable (Week 4 — Day 5)**  
> **Company:** Sqrock IT Solutions  
> **Track:** Alpha 2 Internship — Web Application Security & Defensive Automation  
> **Developer:** Mohammed Peer Siddiqui  
> **Monorepo Repository:** [https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2](https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2)

---

## 📌 Executive Overview

Web applications frequently suffer from high-impact information disclosure when sensitive configuration files, version control trees, database dumps, and unlinked administrative panels remain accessible in the public webroot. Because traditional web vulnerability crawlers rely on traversing hyperlinked DOM structures, hidden endpoints remain completely invisible unless systematically enumerated through dictionary-based **directory brute-forcing (fuzzing)**.

**PEER'S Web Directory Brute-Force & Content Discovery Fuzzing Engine v2.0** is an enterprise-grade multi-threaded content discovery and differential HTTP status code analysis platform built for **Day 20** of the Sqrock IT Solutions Cybersecurity Internship (Phase 2). Operating across customizable wordlists, the engine dispatches concurrent HTTP requests, evaluates status codes (200 OK exposed assets, 403 Forbidden ACL-gated paths, 401 Unauthorized authentication portals, and 404 Discarded endpoints), applies rate limiting and jitter to bypass defensive thresholds, and exports structured machine-readable security telemetry.

```
+========================================================================+
|             PEER'S WEB DIRECTORY FUZZING ENGINE v2.0                   |
+========================================================================+
|                                                                        |
|  [Target Target: Web Application / Microservice APIs (127.0.0.1:8080)] |
|          |                                                             |
|          v                                                             |
|  [Dictionary Ingestion & Path Normalization]                           |
|     - Strips leading slashes, URL decodes, seeds worker threads        |
|          |                                                             |
|          v                                                             |
|  [Concurrent Worker Thread Pool (ThreadPoolExecutor + Jitter)]         |
|     - Dispatches concurrent HTTP HEAD/GET probes                       |
|     - User-Agent identification & rate-limiting delay controls         |
|          |                                                             |
|          v                                                             |
|  [Differential HTTP Status Code Triage Engine]                         |
|   +------------------------------------------------------------------+ |
|   | [200 OK]  -> Critical Leak (.env, backup.sql) or Public Asset   | |
|   | [403 FOR] -> Access Denied (Proves existence of admin/.git)     | |
|   | [401 UNA] -> Authentication Required (Dashboard/Private)         | |
|   | [404 NOT] -> Missing (Discarded & Suppressed)                    | |
|   +------------------------------------------------------------------+ |
|          |                                                             |
|          +-----------------------------+-------------------------------+
|          |                             |                               |
|          v                             v                               v
|  [Machine-Readable JSON]        [Human SOC Triage Summary]   [7-Page PDF Report]
|   - fuzz_results/fuzz_report    - fuzz_results/fuzz_summary   - Day20_Report
+========================================================================+
```

---

## 🎯 Differential HTTP Status Code Taxonomy

| Status Code | HTTP Definition | Reconnaissance Significance | Risk Severity | Immediate Defensive Action |
|:---:|:---|:---|:---:|:---|
| **200 OK** | Resource Exposed | Target endpoint is directly readable. | `CRITICAL` / `HIGH` | Purge dotfiles (`.env`, `.git`) and `.sql` dumps from public webroot. |
| **403 Forbidden** | Access Prohibited | Confirms endpoint exists on filesystem behind an ACL. | `HIGH` | Reconfigure web server to return uniform `404` instead of `403`. |
| **401 Unauthorized** | Challenge Required | Endpoint exists and requires basic or bearer auth. | `MEDIUM` | Enforce multi-factor authentication and strict brute-force lockout. |
| **301 / 302** | Redirect | Discloses internal backend URL routing paths. | `LOW` | Validate redirect sanitization to prevent open redirect vulnerabilities. |
| **404 Not Found** | Missing | Endpoint does not exist on filesystem. | `NONE` | Discarded automatically to eliminate analyst alert fatigue. |

---

## 🛠️ Project Structure

```
Day20_Web_Directory_Fuzzer/
├── fuzz_results/
│   ├── fuzz_report.json                # Machine-readable structured discovery telemetry
│   └── fuzz_summary.txt                # SOC analyst executive triage briefing
├── reports/
│   ├── screenshots/                    # 6 High-resolution Kali Linux terminal proofs
│   │   ├── 01_kali_init_banner.png
│   │   ├── 02_master_menu.png
│   │   ├── 03_wordlist_ingestion.png
│   │   ├── 04_differential_status_live.png
│   │   ├── 05_critical_exposure_alert.png
│   │   └── 06_github_repo_overview.png
│   └── Day20_Web_Directory_Fuzzing_Report_Sqrock_MdPeerSiddiqui.pdf # 7-page executive report
├── scripts/
│   ├── generate_terminal_screens.py    # Headless PIL terminal visual generator
│   └── generate_day20_pdf.py           # Multi-page ReportLab PDF compiler
├── tests/
│   └── test_dir_fuzzer.py              # 6 automated PyUnit test cases
├── wordlists/
│   └── common_dirs.txt                 # Normalized 16 high-risk directory paths
├── dir_fuzzer.py                       # Core multi-threaded discovery & triage engine
└── README.md                           # Master documentation
```

---

## 🚀 Quickstart Guide

### 1. Execute Directory Discovery Sweep
```powershell
python dir_fuzzer.py --url http://127.0.0.1:8080 --wordlist wordlists/common_dirs.txt
```

### 2. Run with Custom Concurrency and Rate Limiting
```powershell
python dir_fuzzer.py --threads 8 --delay 0.05
```

### 3. Run Automated Unit Tests (100% Pass)
```powershell
python -m unittest tests/test_dir_fuzzer.py -v
```

### 4. Regenerate Executive 7-Page PDF Report
```powershell
python scripts/generate_day20_pdf.py
```

---

## 🛡️ Remediation: Webroot Hygiene & Nginx Masking

### ❌ Vulnerable Web Server Configuration:
```nginx
# VULNERABLE: Direct access allows downloading sensitive files
location / {
    try_files $uri $uri/ =404;
}
```

### ✅ Hardened Nginx Defense Configuration:
```nginx
# 1. Deny and mask all dotfiles (.git, .env) as 404 Not Found
location ~ /\. {
    return 404;
}

# 2. Block direct access to database dumps and backups
location ~* \.(sql|bak|old|tar|gz|zip)$ {
    return 404;
}

# 3. Apply edge rate limiting to throttle brute-force sweeps
limit_req zone=fuzz_mitigation burst=10 nodelay;
```

---

## 🧪 Unit Testing Results
```
test_critical_asset_identification (TestDirectoryFuzzer) ... ok
test_json_and_txt_reporting (TestDirectoryFuzzer) ... ok
test_status_401_authentication_handling (TestDirectoryFuzzer) ... ok
test_status_403_differentiation (TestDirectoryFuzzer) ... ok
test_status_404_discarding (TestDirectoryFuzzer) ... ok
test_wordlist_loading (TestDirectoryFuzzer) ... ok

----------------------------------------------------------------------
Ran 6 tests in 0.019s

OK
```

---

## 💼 LinkedIn Captions (Phase 2 - Day 20)

### Option 1: Technical & Offensive Recon Focus
```text
🚀 Day 20 of my Cybersecurity Internship at Sqrock IT Solutions: Web Directory Brute-Force & Content Discovery Fuzzer

Web applications often harbor hidden attack surfaces—accidental database dumps (/backup.sql), exposed environment secrets (/.env), or unlinked administrative consoles (/admin)—that remain invisible to standard web crawlers.

Today, I engineered PEER'S Web Directory Fuzzing Suite v2.0:
⚡ Built a multi-threaded discovery engine utilizing Python's ThreadPoolExecutor with rate-limiting jitter.
🔍 Implemented differential HTTP status code analysis: separating 200 OK critical leaks, 403 Forbidden ACL-gated paths, 401 Unauthorized authentication barriers, and suppressing 404 noise.
🛡️ Formulated defense-in-depth web server configurations (Nginx uniform 404 masking and Fail2Ban auto-jailing).
📊 Dispatches machine-readable JSON telemetry alongside human-readable incident briefings.

Complete codebase, 6 unit tests, and 7-page executive report pushed to my Phase 2 monorepo:
🔗 GitHub: https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2

#WebSecurity #Recon #DirectoryFuzzing #AppSec #Cybersecurity #SqrockITSolutions #Python #OWASP
```

### Option 2: Executive & Blue Team Hardening Focus
```text
🛡️ Eliminating Unlinked Webroot Exposures: Day 20 at Sqrock IT Solutions

Hidden configuration files and forgotten database dumps left in public web directories represent instant breaches waiting to happen. Today's focus was on automated asset enumeration and server hardening:

✅ Developed an automated content discovery scanner targeting OWASP Top 10 A01:2021 (Broken Access Control) and A05:2021 (Security Misconfiguration).
✅ Validated differential status analysis to detect resources confirming filesystem presence (403 Forbidden) and exposed secrets (200 OK).
✅ Authored an enterprise webroot hygiene playbook enforcing uniform 404 response masking and automated rate throttling.
✅ Backed by 6 unit tests and an authoritative 7-page executive engineering report.

Explore the repository:
🔗 https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2

#ApplicationSecurity #BlueTeam #WebHardening #DevSecOps #CybersecurityInternship #Sqrock
```
