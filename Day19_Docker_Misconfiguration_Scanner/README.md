# Day 19: Docker Container Misconfiguration Scanner

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![Security Standard](https://img.shields.io/badge/CIS%20Benchmark-Docker%20v1.6.0-blue.svg?style=for-the-badge)](https://www.cisecurity.org/)
[![NIST Standard](https://img.shields.io/badge/NIST-SP%20800--190%20Container%20Security-red.svg?style=for-the-badge&logo=nist)](https://csrc.nist.gov/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Unit Tests](https://img.shields.io/badge/Unit%20Tests-6%2F6%20Passed-brightgreen.svg?style=for-the-badge)](tests/test_dockerfile_scanner.py)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Windows-black.svg?style=for-the-badge&logo=linux)](https://www.kali.org/)

> **Phase 2 Deliverable (Week 4 — Day 4)**  
> **Company:** Sqrock IT Solutions  
> **Track:** Alpha 2 Internship — Web Application Security & Defensive Automation  
> **Developer:** Mohammed Peer Siddiqui  
> **Monorepo Repository:** [https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2](https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2)

---

## 📌 Executive Overview

In microservice ecosystems and cloud-native Kubernetes deployments, container configurations directly dictate host security boundaries. Because containers share the host Linux kernel via cgroups and namespaces, running containers as the root user (`USER root` or undeclared user contexts) enables threat actors who exploit application-tier vulnerabilities to execute container breakouts and claim host node root equivalence. Furthermore, anti-patterns such as installing OpenSSH daemons, running unpinned `:latest` base images, and baking static credentials directly into `ENV` build layers expose production infrastructure to severe operational hazards.

**PEER'S Docker Container Misconfiguration Scanner v2.0** is an enterprise-grade static analysis and compliance auditing platform built for **Day 19** of the Sqrock IT Solutions Cybersecurity Internship (Phase 2). Operating across Dockerfiles and OCI build instructions, the engine tokenizes syntax, extracts abstract syntax trees (AST), evaluates instructions against the **CIS Docker Benchmark v1.6.0** and **NIST Special Publication 800-190 (Application Container Security Guide)**, and dispatches structured machine-readable security telemetry.

```
+========================================================================+
|         PEER'S DOCKER CONTAINER MISCONFIGURATION SCANNER v2.0          |
+========================================================================+
|                                                                        |
|  [Target Target: Dockerfile / OCI Container Build Specifications]      |
|          |                                                             |
|          v                                                             |
|  [Lexical Normalization & AST Instruction Parser]                      |
|     - Normalizes line continuations (\), strips comments, tokens       |
|          |                                                             |
|          v                                                             |
|  [CIS Docker Benchmark & NIST SP 800-190 Rule Engine]                  |
|   +------------------------------------------------------------------+ |
|   | [CIS 4.1] Non-Root User Context (Bans root UID 0)                | |
|   | [CIS 4.2] Specific Version Tags (Bans untagged & :latest)        | |
|   | [CIS 4.3] SSH Daemon Exposure (Bans EXPOSE 22)                   | |
|   | [CIS 4.4] Secret Keyword Heuristics (Bans hardcoded ENV/ARG keys)| |
|   | [CIS 4.6] Automated Healthcheck Directive Verification           | |
|   | [CIS 4.9] Archive Injection Protection (Bans remote ADD URLs)    | |
|   +------------------------------------------------------------------+ |
|          |                                                             |
|          +-----------------------------+-------------------------------+
|          |                             |                               |
|          v                             v                               v
|  [Machine-Readable JSON]        [Human SOC Triage Summary]   [7-Page PDF Report]
|   - audits/docker_audit_report   - audits/docker_audit_summary - Day19_Report
+========================================================================+
```

---

## 🎯 CIS Docker Benchmark Ruleset Matrix

| CIS ID | Standard Reference | Evaluated Directive | Severity | Security Risk & Justification |
|:---:|:---|:---|:---:|:---|
| **4.1** | NIST SP 800-190 S3.1 | `USER nonroot` | `CRITICAL` | Eliminates host root equivalency and kernel breakout risks. |
| **4.2** | NIST SP 800-190 S3.2 | `FROM image:tag` | `HIGH` | Prevents supply chain drift and breaking upstream modifications. |
| **4.3** | NIST SP 800-190 S3.3 | `EXPOSE 22` | `CRITICAL` | Eliminates unnecessary SSH daemon surface; enforces orchestrator exec. |
| **4.4** | NIST SP 800-190 S3.4 | `ENV KEY=VALUE` | `CRITICAL` | Prevents permanent credential baking in immutable layer history. |
| **4.6** | NIST SP 800-190 S3.6 | `HEALTHCHECK` | `LOW` | Guarantees container orchestrator can detect hung or crashed services. |
| **4.8** | NIST SP 800-190 S3.8 | `RUN sudo ...` | `HIGH` | Prevents local privilege escalation tools inside production containers. |
| **4.9** | NIST SP 800-190 S3.5 | `ADD url dest` | `MEDIUM` | Replaces remote fetch with verified checksum download routines. |

---

## 🛠️ Project Structure

```
Day19_Docker_Misconfiguration_Scanner/
├── audits/
│   ├── docker_audit_report.json        # Machine-readable structured compliance report
│   └── docker_audit_summary.txt        # SOC analyst executive audit briefing
├── reports/
│   ├── screenshots/                    # 6 High-resolution Kali Linux terminal proofs
│   │   ├── 01_kali_init_banner.png
│   │   ├── 02_master_menu.png
│   │   ├── 03_dockerfile_parsing.png
│   │   ├── 04_cis_violations_detected.png
│   │   ├── 05_hardened_container_benchmark.png
│   │   └── 06_github_repo_overview.png
│   └── Day19_Docker_Misconfiguration_Report_Sqrock_MdPeerSiddiqui.pdf # 7-page executive report
├── samples/
│   ├── Dockerfile.vulnerable           # Unhardened development test container
│   ├── Dockerfile.hardened             # Remediated multi-stage production container
│   └── Dockerfile.minimal              # Baseline Node.js container
├── scripts/
│   ├── generate_terminal_screens.py    # Headless PIL terminal visual generator
│   └── generate_day19_pdf.py           # Multi-page ReportLab PDF compiler
├── tests/
│   └── test_dockerfile_scanner.py      # 6 automated PyUnit test cases
├── dockerfile_scanner.py               # Core static analysis & CIS audit engine
└── README.md                           # Master documentation
```

---

## 🚀 Quickstart Guide

### 1. Audit Vulnerable Development Dockerfile
```powershell
python dockerfile_scanner.py --dockerfile samples/Dockerfile.vulnerable
```

### 2. Audit Hardened Production Multi-Stage Container
```powershell
python dockerfile_scanner.py --dockerfile samples/Dockerfile.hardened
```

### 3. Run Automated Unit Tests (100% Pass)
```powershell
python -m unittest tests/test_dockerfile_scanner.py -v
```

### 4. Regenerate Executive 7-Page PDF Report
```powershell
python scripts/generate_day19_pdf.py
```

---

## 🛡️ Remediation: Hardened Multi-Stage Build

### ❌ Insecure Dockerfile (`Dockerfile.vulnerable`):
```dockerfile
FROM ubuntu:latest
ENV DB_PASSWORD="SuperSecretPassword123!"
RUN apt-get update && apt-get install -y openssh-server sudo
EXPOSE 22
ADD https://insecure-cdn.example.com/payload.tar.gz /app/payload.tar.gz
USER root
CMD ["/usr/sbin/sshd", "-D"]
```

### ✅ Hardened Production Dockerfile (`Dockerfile.hardened`):
```dockerfile
# Stage 1: Build dependency artifacts
FROM python:3.11.8-slim-bookworm AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Hardened unprivileged runtime
FROM python:3.11.8-slim-bookworm AS runner
WORKDIR /app
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -d /app appuser
COPY --from=builder /root/.local /home/appuser/.local
COPY --chown=appuser:appgroup app.py .
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1
ENTRYPOINT ["python", "app.py"]
```

---

## 🧪 Unit Testing Results
```
test_dangerous_ssh_port_exposure (TestDockerfileScanner) ... ok
test_hardcoded_secret_detection (TestDockerfileScanner) ... ok
test_hardened_dockerfile_compliance (TestDockerfileScanner) ... ok
test_json_and_txt_report_export (TestDockerfileScanner) ... ok
test_root_user_detection (TestDockerfileScanner) ... ok
test_unpinned_base_image_detection (TestDockerfileScanner) ... ok

----------------------------------------------------------------------
Ran 6 tests in 0.011s

OK
```

---

## 💼 LinkedIn Captions (Phase 2 - Day 19)

### Option 1: Technical & DevSecOps Engineering Focus
```text
🚀 Day 19 of my Cybersecurity Internship at Sqrock IT Solutions: Docker Container Misconfiguration Scanner

Containers share the host Linux kernel directly. Running a container as root (UID 0), exposing SSH daemons, or hardcoding credentials into ENV directives exposes cloud environments to catastrophic breakouts and supply chain drift.

Today, I built PEER'S Docker Container Misconfiguration Scanner v2.0:
🔍 Ingests Dockerfiles, normalizes line continuations, and parses AST instruction blocks.
🛡️ Audits configurations against the CIS Docker Benchmark v1.6.0 & NIST SP 800-190.
🎯 Detects Root Execution (CIS 4.1), Unpinned Tags (CIS 4.2), Exposed SSH Ports (CIS 4.3), Hardcoded Layer Secrets (CIS 4.4), and Insecure ADD Directives (CIS 4.9).
⚡ Generates structured JSON reports, human triage summaries, and demonstrates multi-stage build remediation reducing findings to zero.

Complete codebase, 6 unit tests, and 7-page executive compliance report pushed to my Phase 2 monorepo:
🔗 GitHub: https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2

#DockerSecurity #DevSecOps #CISBenchmark #ContainerHardening #Cybersecurity #SqrockITSolutions #Python
```

### Option 2: Executive & Cloud Infrastructure Strategy Focus
```text
🛡️ Shifting Security Left in Cloud-Native Fleets: Day 19 at Sqrock IT Solutions

Default container build files are often riddled with invisible vulnerabilities that bypass traditional firewalls. Today's focus was on static container hardening before artifacts ever reach production:

✅ Engineered an automated Dockerfile static analysis engine mapped directly to CIS Benchmark v1.6.0.
✅ Enforced principle of least privilege: transitioning workloads from root execution to dedicated non-root UID 10001 service accounts.
✅ Validated defense-in-depth through multi-stage build separation, runtime secret injection, and automated health checking.
✅ Verified with 6 unit tests and compiled into an authoritative 7-page executive engineering report.

Explore the repository and technical artifacts:
🔗 https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2

#CloudSecurity #ContainerSecurity #DevSecOps #Kubernetes #Infosec #AppSec #Sqrock
```
