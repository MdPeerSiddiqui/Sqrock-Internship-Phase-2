# Day 30: Capstone Final Project: Automated Web Vulnerability Scanner

**Candidate:** Mohammed Peer Siddiqui  
**Internship Track:** Phase 2: Web Application Security & Defensive Automation (Capstone Project)  
**Company:** Sqrock IT Solutions  
**Status:** Completed & Verified (100% Pass Rate)

---

## 📌 Executive Overview
Securing enterprise web applications against sophisticated multi-vector attacks requires an end-to-end, full-spectrum assessment framework. Single-point vulnerability checks provide incomplete visibility; true security assurance requires evaluating external attack surfaces, transport-layer configurations, directory disclosures, and web application injection flaws in unison.

**PEER'S Capstone Automated Web Vulnerability Scanner** is the culmination and technical synthesis of the entire **Phase 2 Curriculum (Days 16–30)**. The scanner is architected as a modular, high-performance CLI penetration testing engine that sequentially executes:
1. **Target Reconnaissance & Technology Fingerprinting** (detects server banner leakage).
2. **HTTP Security Header Audit** (evaluates CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
3. **Network Attack Surface & Port Exposure Scanner** (probes administrative and database ports).
4. **Sensitive Directory & Backup File Fuzzer** (discovers exposed `/.env`, `/backup.sql`, `/.git/`).
5. **Application Web Injection Prober** (identifies active SQLi and reflected XSS vulnerabilities).
6. **Composite CVSS Risk Scoring Engine** (calculates overall web security posture on a 0–100 scale).

---

## 🛠️ Key Architectural Features
1. **Integrated 5-Phase Auditing Pipeline:** Combines network discovery, configuration auditing, directory fuzzing, and dynamic application penetration testing.
2. **Deterministic Risk Deduction Engine:** Computes an objective 0–100 Security Score with severity weighting (Critical -25, High -15, Med -8, Low -3).
3. **Multi-Target Comparative Analysis:** Contrasts vulnerable staging portals with production-hardened gateways.
4. **Dual Telemetry Reporting:** Exports machine-readable structured JSON (`final_audit_report.json`) and formatted executive summaries (`scan_executive_summary.txt`).
5. **Continuous Verification Suite:** Comprehensive 6-point automated PyUnit test suite validating all 5 auditing modules and scoring algorithms.

---

## 🚀 Installation & Usage

### 1. Execute Interactive Terminal CLI
```bash
python Day30_Final_Web_Vuln_Scanner/web_vuln_scanner.py
```

### 2. Run Headless Capstone Audit Scan
```bash
python Day30_Final_Web_Vuln_Scanner/web_vuln_scanner.py --scan
```

### 3. Run Automated PyUnit Test Suite
```bash
python -m unittest Day30_Final_Web_Vuln_Scanner/tests/test_web_vuln_scanner.py -v
```

### 4. Generate Executive 7-Page PDF Report
```bash
python Day30_Final_Web_Vuln_Scanner/scripts/generate_day30_pdf.py
```

---

## 🧪 Automated Unit Test Results
```
test_application_injection_detection (tests.test_web_vuln_scanner.TestWebVulnerabilityScanner.test_application_injection_detection) ... ok
test_composite_security_scoring_and_report_export (tests.test_web_vuln_scanner.TestWebVulnerabilityScanner.test_composite_security_scoring_and_report_export) ... ok
test_port_exposure_auditing (tests.test_web_vuln_scanner.TestWebVulnerabilityScanner.test_port_exposure_auditing) ... ok
test_recon_banner_disclosure (tests.test_web_vuln_scanner.TestWebVulnerabilityScanner.test_recon_banner_disclosure) ... ok
test_security_header_auditing (tests.test_web_vuln_scanner.TestWebVulnerabilityScanner.test_security_header_auditing) ... ok
test_sensitive_directory_fuzzing (tests.test_web_vuln_scanner.TestWebVulnerabilityScanner.test_sensitive_directory_fuzzing) ... ok

----------------------------------------------------------------------
Ran 6 tests in 0.007s

OK
```

---

## 📊 Empirical Execution Artifacts
- **Screenshots:** All 6 high-definition Kali Linux terminal screenshots located in `reports/screenshots/`.
- **Audit PDF:** Verified 7-page executive engineering report available at `reports/Day30_Final_Web_Vulnerability_Scan_Report_Sqrock_MdPeerSiddiqui.pdf`.
- **Validation Telemetry:** Structured JSON and TXT audit summaries saved in `audit_results/`.
