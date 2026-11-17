# Day 26: Custom Web Application Firewall (WAF) Engine

**Candidate:** Mohammed Peer Siddiqui  
**Internship Track:** Phase 2: Web Application Security & Defensive Automation  
**Company:** Sqrock IT Solutions  
**Status:** Completed & Verified (100% Pass Rate)

---

## 📌 Executive Overview
Layer 7 web application vulnerabilities (SQL Injection, Cross-Site Scripting, Path Traversal, and OS Command Injection) consistently bypass traditional Layer 3/4 packet-filtering firewalls. To safeguard enterprise web infrastructure, defense-in-depth requires inline Layer 7 deep packet inspection capable of analyzing HTTP requests before execution by backend services.

**PEER'S WAF Sentinel Engine** is an enterprise-grade Web Application Firewall built to inspect HTTP request URIs, query strings, request headers (e.g. User-Agents), and payload bodies. Featuring recursive URL decoding for anti-evasion, deterministic regex rule matching, and automated HTTP 403 Forbidden policy drops, WAF Sentinel protects against OWASP Top 10 web injection vectors with sub-millisecond inspection latency.

---

## 🛠️ Key Architectural Features
1. **Layer 7 Deep Packet Inspection:** Inspects URI path, query parameters, User-Agent, headers, and request body.
2. **OWASP Top 10 Core Rule Set:** Compiled regex engines for SQLi (`UNION SELECT`, boolean tautologies), XSS (`<script>`, event handlers), Path Traversal (`../../etc/passwd`), and OS Command Injection (`; cat /etc/shadow`).
3. **Automated Reconnaissance Filter:** Fingerprints and blocks malicious vulnerability scanners and automated tools (`sqlmap`, `nikto`, `gobuster`, `nmap`).
4. **Recursive Anti-Evasion Decoder:** Neutralizes multi-tier URL encoding and hex obfuscation bypass attempts.
5. **Real-Time Forensic Audit Logging:** Generates synchronous RFC 5424-compatible event logs (`waf_blocked_events.log`) and structured JSON telemetry (`waf_audit_log.json`).
6. **Continuous Verification Suite:** Comprehensive 6-point automated PyUnit test suite validating all security boundaries.

---

## 🚀 Installation & Usage

### 1. Execute Interactive Terminal CLI
```bash
python Day26_Custom_WAF_Engine/waf_engine.py
```

### 2. Run Automated Traffic Batch Inspection
```bash
python Day26_Custom_WAF_Engine/waf_engine.py --batch
```

### 3. Run Automated PyUnit Test Suite
```bash
python -m unittest Day26_Custom_WAF_Engine/tests/test_waf_engine.py -v
```

### 4. Generate Executive 7-Page PDF Report
```bash
python Day26_Custom_WAF_Engine/scripts/generate_day26_pdf.py
```

---

## 🧪 Automated Unit Test Results
```
test_clean_request_allowed (tests.test_waf_engine.TestWAFEngine.test_clean_request_allowed) ... ok
test_malicious_scanner_user_agent_blocked (tests.test_waf_engine.TestWAFEngine.test_malicious_scanner_user_agent_blocked) ... ok
test_os_command_injection_blocked (tests.test_waf_engine.TestWAFEngine.test_os_command_injection_blocked) ... ok
test_path_traversal_blocked (tests.test_waf_engine.TestWAFEngine.test_path_traversal_blocked) ... ok
test_sqli_union_select_blocked (tests.test_waf_engine.TestWAFEngine.test_sqli_union_select_blocked) ... ok
test_xss_script_tag_blocked (tests.test_waf_engine.TestWAFEngine.test_xss_script_tag_blocked) ... ok

----------------------------------------------------------------------
Ran 6 tests in 0.017s

OK
```

---

## 📊 Empirical Execution Artifacts
- **Screenshots:** All 6 high-definition Kali Linux terminal screenshots located in `reports/screenshots/`.
- **Audit PDF:** Verified 7-page executive engineering report available at `reports/Day26_Custom_WAF_Report_Sqrock_MdPeerSiddiqui.pdf`.
- **Validation Telemetry:** Structured JSON and TXT audit summaries saved in `waf_logs/`.
