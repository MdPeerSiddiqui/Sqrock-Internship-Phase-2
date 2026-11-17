# Day 24: Automated Threat Intel IP Blocking Pipeline

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![Security Standard](https://img.shields.io/badge/NIST-SP%20800--150%20Threat%20Info%20Sharing-blue.svg?style=for-the-badge)](https://csrc.nist.gov/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-M1037%20Filter%20Network%20Traffic-red.svg?style=for-the-badge)](https://attack.mitre.org/mitigations/M1037/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Unit Tests](https://img.shields.io/badge/Unit%20Tests-6%2F6%20Passed-brightgreen.svg?style=for-the-badge)](tests/test_threat_blocker.py)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Windows-black.svg?style=for-the-badge&logo=linux)](https://www.kali.org/)

> **Phase 2 Deliverable (Week 5 — Day 4)**  
> **Company:** Sqrock IT Solutions  
> **Track:** Alpha 2 Internship — Web Application Security & Defensive Automation  
> **Developer:** Mohammed Peer Siddiqui  
> **Monorepo Repository:** [https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2](https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2)

---

## 📌 Executive Overview

Security Operations Centers (SOCs) face thousands of automated network inquiries daily from distributed command-and-control (C2) botnets, bulletproof proxies, and vulnerability scanners. Manually compiling firewall drop rules is too slow to stop modern automated adversaries. In accordance with **NIST SP 800-150 (Guide to Cyber Threat Information Sharing)** and **MITRE ATT&CK Mitigation M1037 (Filter Network Traffic)**, defensive pipelines must automate threat feed ingestion, filter indicators through confidence scoring heuristics, and dynamically enforce firewall drop rules.

**PEER'S Automated Threat Intelligence IP Blocking Pipeline v2.0** is an enterprise-grade threat ingestion and firewall orchestration platform developed for **Day 24** of the Sqrock IT Solutions Cybersecurity Internship (Phase 2). Operating across multi-source reputation feeds (AlienVault OTX, AbuseIPDB, Cisco Talos, Emerging Threats), the engine filters indicators through risk confidence matrices (blocking IPs >= 75% score), verifies critical infrastructure whitelists, and compiles production Linux **iptables** and **nftables** drop policies.

```
+========================================================================+
|         PEER'S THREAT INTELLIGENCE IP BLOCKING PIPELINE v2.0           |
+========================================================================+
|                                                                        |
|  [Ingestion: Multi-Source Threat Feeds (OTX, AbuseIPDB, Talos, STIX)]  |
|          |                                                             |
|          v                                                             |
|  [IPv4 Normalization & Global Whitelist Check]                         |
|     - Validates routable IPv4 addresses, exempts Cloudflare/Google DNS |
|          |                                                             |
|          v                                                             |
|  [Risk Confidence Scoring & Threshold Filter]                          |
|   +----------------------------------+-------------------------------+ |
|   | [CONFIDENCE >= 75%]              | [CONFIDENCE < 75%]            | |
|   |   - Enforce Automated Drop       |   - Log & Monitor in SIEM     | |
|   |   - Route to Firewall Compiler   |   - Suppress active blocking  | |
|   +----------------------------------+-------------------------------+ |
|          |                                                             |
|          +-----------------------------+-------------------------------+
|          |                             |                               |
|          v                             v                               v
|  [Firewall Drop Scripts]        [Telemetry JSON Report]      [7-Page PDF Report]
|   - iptables_blocklist.sh       - firewall_rules/report      - Day24_Report
|   - nftables_blocklist.nft      - firewall_rules/summary     - Verified 7 Pgs
+========================================================================+
```

---

## 🎯 Threat Confidence Scoring & Action Matrix

| Confidence Score Tier | Threat Level | Observed Threat Profile | Automated Enforcement Action |
|:---:|:---|:---|:---|
| **85 – 100%** | `CRITICAL` | Active Cobalt Strike C2, Mirai DDoS node, ransomware drop host. | Immediate automated drop in `iptables` and `nftables`. |
| **75 – 84%** | `HIGH` | Repeated SSH/SQLi brute-force daemon, bulletproof Tor proxy. | Enforce edge firewall drop + 24-hour quarantine timer. |
| **50 – 74%** | `MEDIUM` | Unverified port probe, single scanner inquiry. | Log & Monitor in SIEM; alert on anomalous behavior. |
| **01 – 49%** | `LOW` | Stale scanner entry, single transient connection. | Permit traffic; do not alert. |
| **Whitelist** | `SAFE` | Public Anycast DNS (1.1.1.1, 8.8.8.8), CDN origin edge. | Explicitly Allow (Protected against accidental block). |

---

## 🛠️ Project Structure

```
Day24_Threat_Intel_IP_Blocker/
├── feeds/
│   └── threat_intel_feed.json          # Multi-source threat intelligence IoC feed
├── firewall_rules/
│   ├── iptables_blocklist.sh           # Synthesized Linux iptables drop script
│   ├── nftables_blocklist.nft          # Synthesized declarative Linux nftables set
│   ├── threat_intel_report.json        # Machine-readable structured telemetry report
│   └── threat_intel_summary.txt        # SOC analyst executive triage briefing
├── reports/
│   ├── screenshots/                    # 6 High-resolution Kali Linux terminal proofs
│   │   ├── 01_kali_init_banner.png
│   │   ├── 02_master_menu.png
│   │   ├── 03_threat_feed_ingestion.png
│   │   ├── 04_enforced_firewall_rules.png
│   │   ├── 05_iptables_nftables_rules.png
│   │   └── 06_github_repo_overview.png
│   └── Day24_Threat_Intel_Pipeline_Report_Sqrock_MdPeerSiddiqui.pdf # 7-page executive report
├── scripts/
│   ├── generate_terminal_screens.py    # Headless PIL terminal visual generator
│   └── generate_day24_pdf.py           # Multi-page ReportLab PDF compiler
├── tests/
│   └── test_threat_blocker.py          # 6 automated PyUnit test cases
├── threat_blocker.py                   # Core threat pipeline & firewall rule generator
└── README.md                           # Master documentation
```

---

## 🚀 Quickstart Guide

### 1. Ingest Threat Feed & Compile Firewall Drop Rules
```powershell
python threat_blocker.py --feed feeds/threat_intel_feed.json --threshold 75
```

### 2. Inspect Generated Declarative `nftables` Script
```powershell
cat firewall_rules/nftables_blocklist.nft
```

### 3. Run Automated Unit Tests (100% Pass)
```powershell
python -m unittest tests/test_threat_blocker.py -v
```

### 4. Regenerate Executive 7-Page PDF Report
```powershell
python scripts/generate_day24_pdf.py
```

---

## 🛡️ Firewall Output Samples

### 1. Linux `iptables` Drop Chain (`iptables_blocklist.sh`):
```bash
#!/bin/bash
iptables -N THREAT_INTEL_BLOCK 2>/dev/null || true
iptables -F THREAT_INTEL_BLOCK
iptables -A THREAT_INTEL_BLOCK -s 45.154.255.89 -j DROP -m comment --comment "Sqrock: Cobalt Strike C2 (Score: 98)"
iptables -A THREAT_INTEL_BLOCK -s 103.145.13.24 -j DROP -m comment --comment "Sqrock: Mirai DDoS (Score: 92)"
iptables -C INPUT -j THREAT_INTEL_BLOCK 2>/dev/null || iptables -I INPUT 1 -j THREAT_INTEL_BLOCK
```

### 2. Declarative Linux `nftables` Set (`nftables_blocklist.nft`):
```nft
table inet filter {
    set threat_intel_blocklist {
        type ipv4_addr; flags interval;
        elements = { 45.154.255.89, 103.145.13.24, 185.220.101.5, 194.26.29.112, 91.240.118.170 }
    }
    chain input {
        type filter hook input priority -10; policy accept;
        ip saddr @threat_intel_blocklist counter drop comment "Sqrock Automated Threat Intel Drop";
    }
}
```

---

## 🧪 Unit Testing Results
```
test_confidence_threshold_filtering (TestThreatBlocker) ... ok
test_feed_ingestion (TestThreatBlocker) ... ok
test_ip_address_validation (TestThreatBlocker) ... ok
test_iptables_rule_generation (TestThreatBlocker) ... ok
test_json_and_txt_reporting (TestThreatBlocker) ... ok
test_nftables_syntax_generation (TestThreatBlocker) ... ok

----------------------------------------------------------------------
Ran 6 tests in 0.007s

OK
```

---

## 💼 LinkedIn Captions (Phase 2 - Day 24)

### Option 1: Technical & DevSecOps Engineering Focus
```text
🚀 Day 24 of my Cybersecurity Internship at Sqrock IT Solutions: Automated Threat Intel IP Blocking Pipeline

Manually translating threat intelligence into firewall rules creates dangerous dwell times that attackers exploit. In accordance with NIST SP 800-150 and MITRE ATT&CK M1037, perimeter defenses must automatically adapt to incoming IoC feeds.

Today, I engineered PEER'S Threat Intelligence Pipeline v2.0:
🔍 Ingests multi-source IoC reputation feeds (AlienVault OTX, AbuseIPDB, Cisco Talos, Emerging Threats).
🎯 Applies risk confidence scoring matrices (threshold >= 75%) while protecting public infrastructure via strict whitelisting.
🛡️ Automatically compiles production-ready Linux iptables drop scripts and high-performance kernel-space nftables declarative sets.
📊 Outputs structured machine-readable JSON telemetry and SOC incident briefings.

Complete codebase, 6 unit tests, and 7-page executive report pushed to my Phase 2 monorepo:
🔗 GitHub: https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2

#ThreatIntelligence #Firewall #iptables #nftables #Cybersecurity #SOC #SqrockITSolutions #Python
```

### Option 2: Executive & Blue Team Strategy Focus
```text
🛡️ Automating Cyber Defense at the Network Edge: Day 24 at Sqrock IT Solutions

Threat actors leverage automated botnets and distributed infrastructure to probe perimeters in seconds. Today's focus was on engineering automated threat response pipelines:

✅ Developed an automated Threat Intelligence ingestion and confidence scoring engine mapped to MITRE ATT&CK M1037.
✅ Automated the compilation of firewall drop rules across iptables and nftables to eliminate SOC dwell time.
✅ Implemented infrastructure safeguards to prevent self-inflicted outages on trusted DNS and CDN proxies.
✅ Verified with 6 unit tests and compiled into an authoritative 7-page executive engineering report.

Explore the repository:
🔗 https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2

#InformationSecurity #BlueTeam #IncidentResponse #ThreatIntel #NetworkSecurity #CybersecurityInternship #Sqrock
```
