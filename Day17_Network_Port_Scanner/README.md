# Day 17: Local Network Port & Service Scanning Engine

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![Security Standard](https://img.shields.io/badge/CIS%20Controls-v8%20Control%204%20%26%2012-blue.svg?style=for-the-badge)](https://www.cisecurity.org/)
[![NIST Standard](https://img.shields.io/badge/NIST-SP%20800--115-red.svg?style=for-the-badge&logo=nist)](https://csrc.nist.gov/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Unit Tests](https://img.shields.io/badge/Unit%20Tests-6%2F6%20Passed-brightgreen.svg?style=for-the-badge)](tests/test_port_scanner.py)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Windows-black.svg?style=for-the-badge&logo=linux)](https://www.kali.org/)

> **Phase 2 Deliverable (Week 4 — Day 2)**  
> **Company:** Sqrock IT Solutions  
> **Track:** Alpha 2 Internship — Web Application Security & Defensive Automation  
> **Developer:** Mohammed Peer Siddiqui  
> **Monorepo Repository:** [https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2](https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2)

---

## 📌 Executive Overview

In containerized cloud environments and microservice infrastructures, default configuration oversights frequently expose critical backend datastores and administrative management interfaces directly to host network boundaries. When developers map container ports indiscriminately (e.g., `-p 5432:5432` or `-p 8080:8080`), database persistence engines and unauthenticated internal APIs become globally accessible across local and adjacent subnets.

**PEER'S Network Port & Service Scanner v2.0** is an enterprise-grade socket sweeping and infrastructure topology auditing platform built for **Day 17** of the Sqrock IT Solutions Cybersecurity Internship (Phase 2). Operating across standard TCP stream sockets using POSIX `connect_ex` primitives, the engine discovers active listening daemons, captures service identification banners, maps open endpoints into a standardized four-tier network architecture, and flags critical attack surface expansions in accordance with **CIS Controls v8 (Controls 4 & 12)** and **NIST SP 800-115**.

```
+========================================================================+
|             PEER'S NETWORK PORT & SERVICE SCANNER v2.0                 |
+========================================================================+
|                                                                        |
|  [Target Host Endpoint: 127.0.0.1 / Container Bridge IP]               |
|          |                                                             |
|          v                                                             |
|  [Non-Blocking TCP Stream Socket Sweeper (connect_ex)]                 |
|     - Sweep Ports: 22, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017    |
|          |                                                             |
|          v                                                             |
|  [Active Service Fingerprinting & Banner Grabber]                      |
|     - Identifies daemons: OpenSSH, Nginx, PostgreSQL, Express, Redis    |
|          |                                                             |
|          v                                                             |
|  [Enterprise Multi-Tier Topology Aggregator]                           |
|   +------------------------------------------------------------------+ |
|   | [Tier 1: Presentation] -> Port 80 (HTTP), 443 (HTTPS)            | |
|   | [Tier 2: Application]  -> Port 8080 (Dev-Server/APIs)            | |
|   | [Tier 3: Persistence]  -> Port 5432 (Postgres), 3306 (MySQL)    | |
|   | [Tier 4: Management]   -> Port 22 (SSH Remote Shell)             | |
|   +------------------------------------------------------------------+ |
|          |                                                             |
|          +-----------------------------+-------------------------------+
|          |                             |                               |
|          v                             v                               v
|  [Risk Exposure Scoring]        [Topology JSON & TXT]        [7-Page PDF Report]
|   - CRITICAL / HIGH / LOW       - scan_results/port_scan     - Day17_Report
+========================================================================+
```

---

## 🎯 Port Taxonomy & Exposure Risk Analysis

| Port / Protocol | Identified Service | Architecture Tier | Exposure Risk | Defensive Action Required |
|:---|:---|:---|:---:|:---|
| **22/TCP** | OpenSSH | Management Tier | `MEDIUM` | Enforce key-based authentication; restrict to VPN allowlist. |
| **80/TCP** | HTTP (Nginx/Apache) | Web Presentation | `LOW` | Enforce immediate HTTP-to-HTTPS (301 Permanent) redirect. |
| **443/TCP** | HTTPS (TLS 1.3) | Secure Presentation | `SAFE` | Primary authorized entrypoint; maintain TLS certificate hygiene. |
| **3306/TCP** | MySQL Database | Data Persistence | `CRITICAL` | Disallow external binding; isolate to internal database network. |
| **5432/TCP** | PostgreSQL Database | Data Persistence | `CRITICAL` | Set `listen_addresses = 'localhost'`; remove host port mapping. |
| **6379/TCP** | Redis In-Memory Cache| In-Memory Cache | `HIGH` | Enforce authentication password; disable public interface binding. |
| **8080/TCP** | Node.js / Express | Application Services | `HIGH` | Remove `-p 8080:8080`; route exclusively through reverse proxy. |

---

## 🛠️ Project Structure

```
Day17_Network_Port_Scanner/
├── scan_results/
│   ├── port_scan_report.json           # Machine-readable structured network posture
│   └── port_scan_summary.txt           # SOC analyst executive topology briefing
├── reports/
│   ├── screenshots/                    # 6 High-resolution Kali Linux terminal proofs
│   │   ├── 01_kali_init_banner.png
│   │   ├── 02_master_menu.png
│   │   ├── 03_socket_sweep_live.png
│   │   ├── 04_container_exposure_audit.png
│   │   ├── 05_topology_schema_mapping.png
│   │   └── 06_github_repo_overview.png
│   └── Day17_Network_Port_Scan_Report_Sqrock_MdPeerSiddiqui.pdf # 7-page executive report
├── scripts/
│   ├── generate_terminal_screens.py    # Headless PIL terminal visual generator
│   └── generate_day17_pdf.py           # Multi-page ReportLab PDF compiler
├── tests/
│   └── test_port_scanner.py            # 6 automated PyUnit test cases
├── port_scanner.py                     # Core socket sweeper & topology mapper
└── README.md                           # Master documentation
```

---

## 🚀 Quickstart Guide

### 1. Run Automated Unit Tests
Verify all socket logic, topology mapping, and exposure algorithms:

```bash
python -m unittest tests/test_port_scanner.py -v
```

Output:
```
test_database_critical_exposure_rating ... ok
test_default_ports_configuration ... ok
test_hardened_host_rating ... ok
test_network_topology_tier_mapping ... ok
test_report_export_json_txt ... ok
test_simulated_scan_detection ... ok

----------------------------------------------------------------------
Ran 6 tests in 0.002s

OK
```

### 2. Launch Interactive Command Line Interface
Launch the interactive Kali terminal console:

```bash
python port_scanner.py
```

Console options:
- `[1] Scan Live Host Sockets` - Connects to target IP/hostname and scans default ports.
- `[2] Run Container Host Benchmark Audit` - Evaluates exposed container developer host (Postgres 5432 + Node.js 8080).
- `[3] Run Hardened Zero-Exposure Container Benchmark` - Validates secure container posture (Ingress 443 only).
- `[4] View Multi-Tier Network Topology Schema` - Displays ASCII mapping of presentation, app, persistence, and management tiers.
- `[5] Export Formal Network Exposure Audit Reports` - Generates JSON and TXT dossiers.
- `[6] Exit Suite`

---

## 🛡️ Container Microsegmentation Blueprint

### Remediated `docker-compose.yml`
```yaml
version: '3.8'

services:
  web_proxy:
    image: nginx:alpine
    ports:
      - "443:443"  # Only public entrypoint permitted
    networks:
      - frontend_net
      - backend_net

  api_backend:
    image: my-express-api:v1
    expose:
      - "8080"    # Accessible inside backend_net ONLY, no host mapping
    networks:
      - backend_net
      - db_net

  database:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    networks:
      - db_net    # Completely isolated from frontend and host interfaces

networks:
  frontend_net:
    driver: bridge
  backend_net:
    driver: bridge
    internal: true
  db_net:
    driver: bridge
    internal: true
```

---

## ⚖️ License
Distributed under the MIT License. See [LICENSE](../LICENSE) for full legal text.

**Author:** Mohammed Peer Siddiqui  
**Internship:** Sqrock IT Solutions Cybersecurity Internship Phase 2 (Day 17)
