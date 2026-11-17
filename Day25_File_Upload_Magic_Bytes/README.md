# Day 25: File Upload Vulnerability & Magic Bytes Validator

**Candidate:** Mohammed Peer Siddiqui  
**Internship Track:** Phase 2: Web Application Security & Defensive Automation  
**Company:** Sqrock IT Solutions  
**Status:** Completed & Verified (100% Pass Rate)

---

## 📌 Executive Overview
Unrestricted file upload vulnerabilities (CWE-434 / OWASP Top 10 A04:2021) represent an existential threat to modern web architectures. Adversaries routinely leverage HTTP `Content-Type` header spoofing and double-extension tactics (`backdoor.php.png`) to inject executable web shells into web roots, gaining immediate Remote Code Execution (RCE).

**PEER'S Upload Sentinel Engine** provides an enterprise-grade deep file inspection and defense-in-depth pipeline. It bypasses unreliable client-controlled metadata by enforcing **Magic Byte (File Signature) binary header analysis**, deep stream regex pattern scanning for embedded polyglots (e.g. PHP shellcode within valid JPEG EXIF blocks), and automated SHA-256 cryptographic quarantine sandboxing.

---

## 🛠️ Key Architectural Features
1. **Magic Byte Binary Header Verification:** Directly parses the raw binary file stream (PNG, JPEG, GIF, PDF, ZIP/DOCX) to prevent MIME-spoofing attacks.
2. **Polyglot Payload Scanner:** Analyzes the full file stream for prohibited executable signatures (`<?php`, `eval()`, `<script>`, `system()`).
3. **Automated Cryptographic Quarantine:** Relocates malicious assets into an isolated sandbox, strips execution bits, and hashes the file using SHA-256 (`quarantine_<digest>.bin`).
4. **Interactive CLI & Batch Mode:** High-contrast Colorama terminal interface with multi-file sweep automation and detailed JSON/TXT telemetry reporting.
5. **Continuous Verification Suite:** Comprehensive 6-point automated PyUnit test suite validating all security boundaries.

---

## 🚀 Installation & Usage

### 1. Execute Interactive Terminal CLI
```bash
python Day25_File_Upload_Magic_Bytes/upload_validator.py
```

### 2. Run Automated PyUnit Test Suite
```bash
python -m unittest Day25_File_Upload_Magic_Bytes/tests/test_upload_validator.py -v
```

### 3. Generate Executive 7-Page PDF Report
```bash
python Day25_File_Upload_Magic_Bytes/scripts/generate_day25_pdf.py
```

---

## 🧪 Automated Unit Test Results
```
test_banned_extension_block (tests.test_upload_validator.TestUploadValidator.test_banned_extension_block) ... ok
test_legitimate_pdf_pass (tests.test_upload_validator.TestUploadValidator.test_legitimate_pdf_pass) ... ok
test_legitimate_png_pass (tests.test_upload_validator.TestUploadValidator.test_legitimate_png_pass) ... ok
test_polyglot_malware_quarantine (tests.test_upload_validator.TestUploadValidator.test_polyglot_malware_quarantine) ... ok
test_sha256_quarantine_hashing (tests.test_upload_validator.TestUploadValidator.test_sha256_quarantine_hashing) ... ok
test_spoofed_webshell_block (tests.test_upload_validator.TestUploadValidator.test_spoofed_webshell_block) ... ok

----------------------------------------------------------------------
Ran 6 tests in 0.006s

OK
```

---

## 📊 Empirical Execution Artifacts
- **Screenshots:** All 6 high-definition Kali Linux terminal screenshots located in `reports/screenshots/`.
- **Audit PDF:** Verified 7-page executive engineering report available at `reports/Day25_File_Upload_Security_Report_Sqrock_MdPeerSiddiqui.pdf`.
- **Validation Telemetry:** Structured JSON and TXT audit summaries saved in `validation_results/`.
