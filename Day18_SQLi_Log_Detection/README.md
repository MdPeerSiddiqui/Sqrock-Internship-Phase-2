# Day 18: SQL Injection Log Detection & Query Analysis Engine

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![Security Standard](https://img.shields.io/badge/OWASP-Top%2010%20A03%3A2021%20Injection-red.svg?style=for-the-badge&logo=owasp)](https://owasp.org/Top10/A03_2021-Injection/)
[![CWE Standard](https://img.shields.io/badge/CWE-89%20SQL%20Injection-orange.svg?style=for-the-badge)](https://cwe.mitre.org/data/definitions/89.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Unit Tests](https://img.shields.io/badge/Unit%20Tests-6%2F6%20Passed-brightgreen.svg?style=for-the-badge)](tests/test_sqli_detector.py)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Windows-black.svg?style=for-the-badge&logo=linux)](https://www.kali.org/)

> **Phase 2 Deliverable (Week 4 — Day 3)**  
> **Company:** Sqrock IT Solutions  
> **Track:** Alpha 2 Internship — Web Application Security & Defensive Automation  
> **Developer:** Mohammed Peer Siddiqui  
> **Monorepo Repository:** [https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2](https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2)

---

## 📌 Executive Overview

SQL Injection (**CWE-89 / OWASP Top 10 A03:2021**) remains one of the most destructive and prevalent web application attack vectors in enterprise networks. Vulnerable data access layers that concatenate untrusted user input directly into structured database queries allow malicious actors to manipulate execution flow, bypass authentication gates, extract confidential datasets (`UNION SELECT`), execute denial-of-service database lockups (`pg_sleep`), or corrupt core database schemas.

**PEER'S SQL Injection Log Detection & Query Analysis Engine v2.0** is an enterprise-grade SIEM log triaging and AST query security audit suite developed for **Day 18** of the Sqrock IT Solutions Cybersecurity Internship (Phase 2). Operating across standard W3C, Apache Combined, Nginx, and cloud access logs, the engine inspects URI parameters and POST payloads for 5 distinct SQLi attack archetypes:
1. **Classic Authentication Bypass / Tautology** (`' OR 1=1--`, `' OR 'x'='x'`)
2. **Schema & Data Extraction** (`UNION ALL SELECT ... FROM information_schema.tables`)
3. **Stacked Query Execution** (`; DROP TABLE users;`, `; UPDATE accounts SET balance=999999`)
4. **Time-Based Blind Injections** (`WAITFOR DELAY '0:0:5'`, `SLEEP(5)`, `pg_sleep(10)`)
5. **Comment Truncation Sequences** (`--`, `/*...*/`, `#`)

In addition to defensive log correlation, the platform provides automated static analysis comparing vulnerable dynamic string interpolation against parameterized **Prepared Statements** (PostgreSQL `$1`, SQLite/MySQL `?`).

```
+========================================================================+
|               PEER'S SQLi LOG DETECTION ENGINE v2.0                    |
+========================================================================+
|                                                                        |
|  [Ingestion: Web Server Access Logs (Apache / Nginx / W3C)]            |
|          |                                                             |
|          v                                                             |
|  [URL Decoding & Input Normalization Engine]                           |
|     - Resolves double URL encoding, hex escapes, whitespace obfuscation|
|          |                                                             |
|          v                                                             |
|  [Multi-Pattern Regex Signature Correlation Engine]                    |
|   +------------------------------------------------------------------+ |
|   | 1. Tautology Detection:       (?i)('\s*or\s+1\s*=\s*1|'=\s*')   | |
|   | 2. Union Extraction:         (?i)union(\s+all)?\s+select        | |
|   | 3. Stacked Commands:         ;\s*(drop|alter|insert|delete|update)|
|   | 4. Time-Based Blind:         (?i)(waitfor\s+delay|sleep|pg_sleep) |
|   | 5. Comment Truncation:       (--|#|/\*.*?\*/)                   | |
|   +------------------------------------------------------------------+ |
|          |                                                             |
|          +-----------------------------+-------------------------------+
|          |                             |                               |
|          v                             v                               v
|  [Risk Alert Dispatch]          [Prepared Statement Audit]   [Executive PDF Report]
|   - alerts/sqli_alerts.json     - Vulnerable vs Parameterized - Day18_Report (7 pgs)
|   - alerts/sqli_triage_summary.txt  Architecture Benchmark   - Verified 7 Pages
+========================================================================+
```

---

## 🎯 Attack Signatures & Detection Taxonomy

| Attack Vector | Regex Signature Pattern | Example Payload | Risk Severity | Target Database |
|:---|:---|:---|:---:|:---|
| **Tautology Bypass** | `(?i)('\s*or\s+1\s*=\s*1\|'=\s*')` | `admin' OR 1=1--` | `CRITICAL` | Universal |
| **Union Extraction** | `(?i)union(\s+all)?\s+select` | `' UNION SELECT null, username, password FROM users--` | `CRITICAL` | MySQL / Postgres / Oracle |
| **Stacked Commands** | `;\s*(drop\|alter\|insert\|delete\|update)` | `1; DROP TABLE audit_logs;` | `CRITICAL` | MSSQL / PostgreSQL |
| **Time-Based Blind** | `(?i)(waitfor\s+delay\|sleep\s*\(\d+\)\|pg_sleep)` | `' OR pg_sleep(5)--` | `HIGH` | Postgres / MySQL / MSSQL |
| **Comment Truncation**| `(--\|#\|/\*.*?\*/)` | `' OR 'a'='a' /* comment */` | `MEDIUM` | Universal |

---

## 🛠️ Project Structure

```
Day18_SQLi_Log_Detection/
├── alerts/
│   ├── sqli_alerts.json                # Machine-readable SIEM alert telemetry
│   └── sqli_triage_summary.txt         # SOC analyst human-readable triage report
├── logs/
│   └── web_access.log                  # Sample Apache/Nginx web server access logs
├── reports/
│   ├── screenshots/                    # 6 High-resolution Kali Linux terminal proofs
│   │   ├── 01_kali_init_banner.png
│   │   ├── 02_master_menu.png
│   │   ├── 03_log_ingestion_parsing.png
│   │   ├── 04_sqli_threat_alerts.png
│   │   ├── 05_prepared_statements_analysis.png
│   │   └── 06_github_repo_overview.png
│   └── Day18_SQLi_Log_Detection_Report_Sqrock_MdPeerSiddiqui.pdf # 7-page executive report
├── scripts/
│   ├── generate_terminal_screens.py    # Headless PIL terminal visual generator
│   └── generate_day18_pdf.py           # Multi-page ReportLab PDF compiler
├── tests/
│   └── test_sqli_detector.py           # 6 automated PyUnit test cases
├── sqli_detector.py                    # Core SQLi detection & triage engine
└── README.md                           # Master documentation
```

---

## 🚀 Quickstart Guide

### 1. Ingest & Analyze Web Access Logs
```powershell
python sqli_detector.py --log logs/web_access.log
```

### 2. Run Prepared Statement Defense Benchmark
```powershell
python sqli_detector.py --demo-defense
```

### 3. Run Automated Unit Tests (100% Pass)
```powershell
python -m unittest tests/test_sqli_detector.py -v
```

### 4. Regenerate Executive 7-Page PDF Report
```powershell
python scripts/generate_day18_pdf.py
```

---

## 🛡️ Remediation: Parameterized Queries (Prepared Statements)

### ❌ Insecure Code (Dynamic Query Concatenation):
```python
# VULNERABLE: Direct string interpolation allows input to alter query syntax
cursor.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")
```

### ✅ Secure Code (Parameterized Query):
```python
# SECURE: Database engine treats input strictly as literal values
cursor.execute(
    "SELECT * FROM users WHERE username = %s AND password = %s",
    (username, password)
)
```

---

## 🧪 Unit Testing Results
```
test_benign_log_filtering (test_sqli_detector.TestSQLiDetector.test_benign_log_filtering) ... ok
test_log_ingestion (test_sqli_detector.TestSQLiDetector.test_log_ingestion) ... ok
test_prepared_statement_defense (test_sqli_detector.TestSQLiDetector.test_prepared_statement_defense) ... ok
test_report_generation (test_sqli_detector.TestSQLiDetector.test_report_generation) ... ok
test_stacked_query_detection (test_sqli_detector.TestSQLiDetector.test_stacked_query_detection) ... ok
test_union_sqli_detection (test_sqli_detector.TestSQLiDetector.test_union_sqli_detection) ... ok

----------------------------------------------------------------------
Ran 6 tests in 0.005s

OK
```

---

## 💼 LinkedIn Captions (Phase 2 - Day 18)

### Option 1: Technical & Engineering Focus
```text
🚀 Day 18 of my Cybersecurity Internship at Sqrock IT Solutions: SQL Injection Log Detection & Query Analysis Engine

When web applications dynamically concatenate untrusted user inputs into SQL statements, attackers can bypass authentication gates (' OR 1=1--) or exfiltrate private databases (UNION SELECT).

Today, I engineered PEER'S SQLi Log Detection Suite v2.0:
🔍 Ingests raw Apache/Nginx web server access logs and normalizes URL-encoded attack strings.
🎯 Uses signature correlation regex engines targeting Tautologies, UNION extractions, Stacked Queries, and Time-Based Blind delays.
📊 Generates real-time SIEM-ready JSON telemetry and incident triage summaries.
🛡️ Demonstrates defense-in-depth code refactoring replacing vulnerable f-string queries with Parameterized Prepared Statements.

Complete codebase, 6 unit tests, and 7-page executive report pushed to my Phase 2 monorepo:
🔗 GitHub: https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2

#Cybersecurity #SQLi #DefensiveSecurity #SIEM #Python #AppSec #SqrockITSolutions #InfoSec
```

### Option 2: Executive & Blue Team Strategy Focus
```text
🛡️ Building Automated Defensive Security Pipelines: Day 18 at Sqrock IT Solutions

SQL Injection (CWE-89) continues to plague production environments despite being preventable. Today’s mission was focused on automated detection and proactive mitigation:

✅ Developed an automated SIEM log inspection parser to detect SQLi attack attempts in real-time.
✅ Implemented multi-vector threat categorization with risk severity scoring (Critical, High, Medium).
✅ Validated architectural resilience through Parameterized Queries (Prepared Statements) ensuring complete separation of code and data.
✅ Backed by 6 unit tests and an executive 7-page PDF compliance lab report.

Explore the complete implementation in my Phase 2 Monorepo:
🔗 https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2

#ApplicationSecurity #BlueTeam #SOC #SQLInjection #SecureCoding #CybersecurityInternship #Sqrock
```
