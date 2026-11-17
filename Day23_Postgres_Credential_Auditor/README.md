# Day 23: Postgres Database Credential Auditing & Configuration Hardening

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![Security Standard](https://img.shields.io/badge/CIS%20Benchmark-PostgreSQL%2015%20v1.0.0-blue.svg?style=for-the-badge)](https://www.cisecurity.org/)
[![NIST Standard](https://img.shields.io/badge/NIST-SP%20800--53%20AC--2%20%2F%20IA--5-red.svg?style=for-the-badge&logo=nist)](https://csrc.nist.gov/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Unit Tests](https://img.shields.io/badge/Unit%20Tests-6%2F6%20Passed-brightgreen.svg?style=for-the-badge)](tests/test_postgres_auditor.py)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Windows-black.svg?style=for-the-badge&logo=linux)](https://www.kali.org/)

> **Phase 2 Deliverable (Week 5 — Day 3)**  
> **Company:** Sqrock IT Solutions  
> **Track:** Alpha 2 Internship — Web Application Security & Defensive Automation  
> **Developer:** Mohammed Peer Siddiqui  
> **Monorepo Repository:** [https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2](https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2)

---

## 📌 Executive Overview

Relational database clusters are prime targets for cyberattacks. Configuration oversights—such as allowing unauthenticated client logins (`trust` authentication), binding datastore listener daemons to global IPv4 ranges (`0.0.0.0/0`), and maintaining default superuser credentials (`postgres:postgres`)—lead directly to catastrophic corporate data exfiltration, database ransomware, and regulatory penalties.

**PEER'S PostgreSQL Database Credential & Configuration Auditor v2.0** is an enterprise-grade database security audit platform built for **Day 23** of the Sqrock IT Solutions Cybersecurity Internship (Phase 2). Operating across `pg_hba.conf` client authentication tables and database credential matrices, the engine parses rules against the **CIS PostgreSQL 15 Benchmark v1.0.0** and **NIST SP 800-53 (AC-2, IA-5)**, performs dictionary credential testing, calculates password Shannon entropy, and outputs structured compliance telemetry.

```
+========================================================================+
|         PEER'S POSTGRESQL DATABASE SECURITY AUDITOR v2.0               |
+========================================================================+
|                                                                        |
|  [Target Target: PostgreSQL 15 Database Cluster (pg_hba.conf & Auth)]  |
|          |                                                             |
|          v                                                             |
|  [pg_hba.conf Client Authentication Parser]                            |
|     - Evaluates connection type, database, user, CIDR, and method      |
|          |                                                             |
|          v                                                             |
|  [CIS PostgreSQL 15 Benchmark Rules Engine]                            |
|   +------------------------------------------------------------------+ |
|   | [METHOD: trust]         -> CRITICAL: Zero password authentication| |
|   | [METHOD: password]      -> HIGH: Cleartext credential transmission|
|   | [METHOD: md5]           -> MEDIUM: Obsolete collision-prone hash | |
|   | [METHOD: scram-sha-256] -> SAFE: Modern salted challenge-response| |
|   | [METHOD: peer]          -> SAFE: Local Unix domain socket kernel | |
|   | [CIDR: 0.0.0.0/0]       -> CRITICAL: Unrestricted global exposure| |
|   +------------------------------------------------------------------+ |
|          |                                                             |
|          +-----------------------------+-------------------------------+
|          |                             |                               |
|          v                             v                               v
|  [Credential Dictionary Audit]  [Machine-Readable JSON]      [7-Page PDF Report]
|   - Shannon Entropy Calculation - audit_results/postgres_report - Day23_Report
|   - Flags Default Accounts      - audit_results/postgres_summary - Verified 7 Pgs
+========================================================================+
```

---

## 🎯 PostgreSQL Client Authentication Methods Matrix

| Authentication Method | Severity | Cryptographic Mechanics | CIS Benchmark Policy | Recommended Action |
|:---|:---:|:---|:---:|:---|
| **trust** | `CRITICAL` | Allows connection without password verification. | `BANNED` | Replace immediately with `scram-sha-256`. |
| **password** | `HIGH` | Transmits cleartext credentials over the wire. | `BANNED` | Enforce TLS 1.3 encryption and SCRAM. |
| **md5** | `MEDIUM` | Vulnerable to rainbow table cracking and pass-the-hash. | `DEPRECATED` | Migrate users to SCRAM-SHA-256 hashes. |
| **peer** | `SAFE` | Validates local Unix domain socket kernel UID/GID. | `APPROVED` | Retain for local `postgres` administrator. |
| **scram-sha-256** | `SAFE` | Salted challenge-response (RFC 7677). | `MANDATORY` | Gold standard for network database connections. |

---

## 🛠️ Project Structure

```
Day23_Postgres_Credential_Auditor/
├── audit_results/
│   ├── postgres_audit_report.json      # Machine-readable structured compliance report
│   └── postgres_audit_summary.txt      # SOC analyst executive triage briefing
├── reports/
│   ├── screenshots/                    # 6 High-resolution Kali Linux terminal proofs
│   │   ├── 01_kali_init_banner.png
│   │   ├── 02_master_menu.png
│   │   ├── 03_pghba_insecure_audit.png
│   │   ├── 04_default_credential_testing.png
│   │   ├── 05_hardened_pghba_benchmark.png
│   │   └── 06_github_repo_overview.png
│   └── Day23_Postgres_Credential_Audit_Report_Sqrock_MdPeerSiddiqui.pdf # 7-page executive report
├── samples/
│   ├── credentials_dictionary.txt      # Default and weak database credential pairs
│   ├── pg_hba.conf.insecure            # Unhardened baseline with trust and 0.0.0.0/0
│   └── pg_hba.conf.hardened            # Hardened production configuration (SCRAM + SSL)
├── scripts/
│   ├── generate_terminal_screens.py    # Headless PIL terminal visual generator
│   └── generate_day23_pdf.py           # Multi-page ReportLab PDF compiler
├── tests/
│   └── test_postgres_auditor.py        # 6 automated PyUnit test cases
├── postgres_auditor.py                 # Core database security & credential audit engine
└── README.md                           # Master documentation
```

---

## 🚀 Quickstart Guide

### 1. Audit Insecure Development `pg_hba.conf`
```powershell
python postgres_auditor.py --hba samples/pg_hba.conf.insecure --dict samples/credentials_dictionary.txt
```

### 2. Audit Hardened Production `pg_hba.conf`
```powershell
python postgres_auditor.py --hba samples/pg_hba.conf.hardened
```

### 3. Run Automated Unit Tests (100% Pass)
```powershell
python -m unittest tests/test_postgres_auditor.py -v
```

### 4. Regenerate Executive 7-Page PDF Report
```powershell
python scripts/generate_day23_pdf.py
```

---

## 🛡️ Remediation: Hardened `pg_hba.conf` Specification

### ❌ Insecure Configuration (`pg_hba.conf.insecure`):
```text
# VULNERABLE: Direct global access without authentication
local   all   all             trust
host    all   all   0.0.0.0/0 trust
```

### ✅ Hardened Production Configuration (`pg_hba.conf.hardened`):
```text
# SECURE: Enforce local peer authentication & SCRAM-SHA-256 over SSL
local   all   postgres               peer
local   all   all                    scram-sha-256
hostssl all   app_user  10.0.1.0/24  scram-sha-256
hostssl all   all       127.0.0.1/32 scram-sha-256
```

---

## 🧪 Unit Testing Results
```
test_default_credential_detection (TestPostgresAuditor) ... ok
test_entropy_calculation_accuracy (TestPostgresAuditor) ... ok
test_hardened_pghba_compliance (TestPostgresAuditor) ... ok
test_insecure_global_cidr_detection (TestPostgresAuditor) ... ok
test_insecure_trust_method_detection (TestPostgresAuditor) ... ok
test_json_and_txt_reporting (TestPostgresAuditor) ... ok

----------------------------------------------------------------------
Ran 6 tests in 0.012s

OK
```

---

## 💼 LinkedIn Captions (Phase 2 - Day 23)

### Option 1: Technical & Database Security Focus
```text
🚀 Day 23 of my Cybersecurity Internship at Sqrock IT Solutions: PostgreSQL Database Credential Auditing & Configuration Hardening

Relational databases store core enterprise assets. Leaving 'trust' authentication enabled or binding listener daemons to 0.0.0.0/0 invites catastrophic unauthenticated data theft.

Today, I engineered PEER'S PostgreSQL Security Auditor v2.0:
🛡️ Built a static analysis parser for pg_hba.conf aligned with the CIS PostgreSQL 15 Benchmark v1.0.0 and NIST SP 800-53 (AC-2, IA-5).
🔍 Detects insecure 'trust' rules, deprecated MD5 hashing, and global wildcard network bindings (0.0.0.0/0).
🔑 Implemented automated dictionary credential testing and Shannon entropy calculations.
⚡ Configured production hardening templates enforcing SCRAM-SHA-256 (RFC 7677), TLS 1.3 encryption (hostssl), and Unix socket peer validation.

Complete codebase, 6 unit tests, and 7-page executive report pushed to my Phase 2 monorepo:
🔗 GitHub: https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2

#DatabaseSecurity #PostgreSQL #CISBenchmark #AppSec #Cybersecurity #DevSecOps #SqrockITSolutions #Python
```

### Option 2: Executive & Blue Team Strategy Focus
```text
🛡️ Hardening Critical Enterprise Datastores: Day 23 at Sqrock IT Solutions

Database misconfigurations and default credentials remain major attack vectors for data breaches and ransomware. Today's focus was on automated compliance auditing and database access control:

✅ Engineered an automated security inspection engine for PostgreSQL client authentication (pg_hba.conf).
✅ Validated transition from legacy MD5 hashing to cryptographic SCRAM-SHA-256 salted challenge-response authentication.
✅ Formulated network access isolation guidelines restricting database traffic strictly to encrypted private subnets.
✅ Backed by 6 unit tests and an authoritative 7-page executive engineering report.

Explore the repository:
🔗 https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2

#DatabaseHardening #InformationSecurity #BlueTeam #Postgres #CloudSecurity #CybersecurityInternship #Sqrock
```
