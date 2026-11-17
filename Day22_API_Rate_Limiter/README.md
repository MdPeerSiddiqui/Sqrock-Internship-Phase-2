# Day 22: API Rate Limiting & Token Bucket Defense Suite

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![Security Standard](https://img.shields.io/badge/OWASP-API%20Top%2010%20API4%3A2023%20Rate%20Limiting-red.svg?style=for-the-badge&logo=owasp)](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
[![RFC Standard](https://img.shields.io/badge/RFC-6585%20HTTP%20429-orange.svg?style=for-the-badge)](https://datatracker.ietf.org/doc/html/rfc6585)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Unit Tests](https://img.shields.io/badge/Unit%20Tests-6%2F6%20Passed-brightgreen.svg?style=for-the-badge)](tests/test_rate_limiter.py)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Windows-black.svg?style=for-the-badge&logo=linux)](https://www.kali.org/)

> **Phase 2 Deliverable (Week 5 — Day 2)**  
> **Company:** Sqrock IT Solutions  
> **Track:** Alpha 2 Internship — Web Application Security & Defensive Automation  
> **Developer:** Mohammed Peer Siddiqui  
> **Monorepo Repository:** [https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2](https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2)

---

## 📌 Executive Overview

Cloud microservices and REST/GraphQL APIs are primary targets for automated botnet abuse, including credential stuffing, inventory scraping, and denial-of-service (DoS) resource exhaustion. Without defensive rate limiting controls (**OWASP API Security Top 10 API4:2023: Unrestricted Resource Consumption**), unconstrained client requests saturate backend thread pools, deplete database connection limits, and trigger application outages.

**PEER'S API Rate Limiting & Token Bucket Defense Suite v2.0** is an enterprise-grade stateful rate regulation and throttling platform built for **Day 22** of the Sqrock IT Solutions Cybersecurity Internship (Phase 2). Implementing the continuous mathematical **Token Bucket Algorithm**, the middleware maintains burst capacity ($B$) and sustained refill kinetics ($R$), isolates quotas per client IP / API key, throttles excessive requests with **HTTP 429 Too Many Requests**, and delivers comprehensive **RFC 6585** telemetry (`Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`).

```
+========================================================================+
|             PEER'S API RATE LIMITING DEFENSE SUITE v2.0                |
+========================================================================+
|                                                                        |
|  [Ingestion: Incoming Client Request (IP: 192.168.1.105 / API Key)]    |
|          |                                                             |
|          v                                                             |
|  [Stateful Client Bucket Retrieval & Mathematical Replenishment]       |
|     - delta_t = now - last_refill                                      |
|     - tokens = min(capacity, tokens + delta_t * refill_rate)           |
|          |                                                             |
|          v                                                             |
|  [Token Quota Evaluation (Cost = 1.0 Token)]                           |
|   +----------------------------------+-------------------------------+ |
|   | [TOKENS >= 1.0]                  | [TOKENS < 1.0]                | |
|   |   - tokens = tokens - 1.0        |   - Calculate deficit time    | |
|   |   - Response: 200 OK             |   - Response: 429 THROTTLED   | |
|   |   - Action: Request Permitted    |   - Action: Injects Retry-After|
|   +----------------------------------+-------------------------------+ |
|          |                                                             |
|          +-----------------------------+-------------------------------+
|          |                             |                               |
|          v                             v                               v
|  [Telemetry JSON Report]        [SOC Triage Summary]         [7-Page PDF Report]
|   - rate_limit_results/report   - rate_limit_results/summary  - Day22_Report
+========================================================================+
```

---

## 🎯 Algorithm Architecture Comparison

| Algorithm Model | Burst Tolerance | Memory Footprint | Refill Mechanics | Best Production Fit |
|:---|:---:|:---:|:---:|:---|
| **Token Bucket** | `EXCELLENT` ($B$) | $O(1)$ per client | Continuous time replenishment | Microservice APIs & Web Gateways |
| **Leaky Bucket** | `ZERO` (FIFO) | $O(\text{Queue})$ | Constant drain rate | Egress network traffic shaping |
| **Fixed Window** | `POOR` (2x boundary) | $O(1)$ global | Hard counter reset | Coarse application-level caps |
| **Sliding Log** | `PERFECT` | $O(N)$ requests | Exact window log calculation | Low-frequency sensitive authentication |

---

## 🛠️ Project Structure

```
Day22_API_Rate_Limiter/
├── rate_limit_results/
│   ├── rate_limit_report.json          # Machine-readable structured throttling telemetry
│   └── rate_limit_summary.txt          # SOC analyst executive triage briefing
├── reports/
│   ├── screenshots/                    # 6 High-resolution Kali Linux terminal proofs
│   │   ├── 01_kali_init_banner.png
│   │   ├── 02_master_menu.png
│   │   ├── 03_token_bucket_state.png
│   │   ├── 04_burst_throttling_live.png
│   │   ├── 05_http_429_header_inspection.png
│   │   └── 06_github_repo_overview.png
│   └── Day22_API_Rate_Limiting_Report_Sqrock_MdPeerSiddiqui.pdf # 7-page executive report
├── scripts/
│   ├── generate_terminal_screens.py    # Headless PIL terminal visual generator
│   └── generate_day22_pdf.py           # Multi-page ReportLab PDF compiler
├── tests/
│   └── test_rate_limiter.py            # 6 automated PyUnit test cases
├── rate_limiter.py                     # Core Token Bucket & client IP throttling engine
└── README.md                           # Master documentation
```

---

## 🚀 Quickstart Guide

### 1. Execute Live Traffic Burst Simulation
```powershell
python rate_limiter.py --capacity 10 --refill-rate 2 --burst-count 15
```

### 2. Inspect Client Token Bucket State
```powershell
python -c "from rate_limiter import APIRateLimiter; r = APIRateLimiter(10, 2); print(r.get_bucket('192.168.1.105').__dict__)"
```

### 3. Run Automated Unit Tests (100% Pass)
```powershell
python -m unittest tests/test_rate_limiter.py -v
```

### 4. Regenerate Executive 7-Page PDF Report
```powershell
python scripts/generate_day22_pdf.py
```

---

## 🛡️ Remediation: Production Edge Nginx Throttling

```nginx
# 1. Define rate limit memory zone (10MB holds ~160,000 unique client IPs)
limit_req_zone $binary_remote_addr zone=api_auth:10m rate=5r/s;

# 2. Protect sensitive authentication endpoints
location /api/v1/auth/ {
    limit_req zone=api_auth burst=10 nodelay;
    limit_req_status 429;
    proxy_pass http://backend_api_cluster;
}
```

---

## 🧪 Unit Testing Results
```
test_multi_client_isolation (TestRateLimiter) ... ok
test_rfc_headers_generation (TestRateLimiter) ... ok
test_token_bucket_initial_capacity (TestRateLimiter) ... ok
test_token_consumption_allowed (TestRateLimiter) ... ok
test_token_exhaustion_throttled (TestRateLimiter) ... ok
test_token_refill_replenishment (TestRateLimiter) ... ok

----------------------------------------------------------------------
Ran 6 tests in 0.303s

OK
```

---

## 💼 LinkedIn Captions (Phase 2 - Day 22)

### Option 1: Technical & Systems Architecture Focus
```text
🚀 Day 22 of my Cybersecurity Internship at Sqrock IT Solutions: API Rate Limiting & Token Bucket Defense Suite

Without rate limiting controls (OWASP API Top 10 API4:2023), automated credential stuffing botnets and distributed DoS attacks can easily saturate backend database connections and crash application pods.

Today, I engineered PEER'S API Rate Limiter v2.0:
⚡ Implemented the continuous mathematical Token Bucket algorithm, supporting burst capacity (B=10) and steady refill replenishment (R=2 tokens/sec).
🔒 Enforces stateful client IP tracking with thread-safe lock primitives.
📡 Injects RFC 6585 compliance telemetry (HTTP 429 Too Many Requests, Retry-After, and X-RateLimit-* headers).
🛡️ Formulated edge reverse proxy configurations using Nginx limit_req and distributed Redis Lua scripts.

Complete codebase, 6 unit tests, and 7-page executive report pushed to my Phase 2 monorepo:
🔗 GitHub: https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2

#APISecurity #RateLimiting #TokenBucket #Cybersecurity #AppSec #DoS #SqrockITSolutions #Python
```

### Option 2: Executive & Blue Team Strategy Focus
```text
🛡️ Defending Cloud APIs Against Denial-of-Service: Day 22 at Sqrock IT Solutions

Unrestricted resource consumption can cripple production cloud infrastructure in seconds. Today's focus was on engineering stateful rate regulation and traffic governance:

✅ Implemented Token Bucket rate limiting middleware mapped to RFC 6585 and OWASP API4:2023.
✅ Validated traffic burst handling: permitting legitimate surges while mathematically choking sustained DoS traffic with HTTP 429.
✅ Implemented multi-client state isolation ensuring bad actors cannot impact neighboring tenant quotas.
✅ Verified with 6 unit tests and an authoritative 7-page executive engineering report.

Explore the repository:
🔗 https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2

#CloudSecurity #APIProtection #BlueTeam #DevSecOps #CybersecurityInternship #Sqrock
```
