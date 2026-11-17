# Day 28: SIEM Alert Trigger Automation via Webhooks

**Candidate:** Mohammed Peer Siddiqui  
**Internship Track:** Phase 2: Web Application Security & Defensive Automation  
**Company:** Sqrock IT Solutions  
**Status:** Completed & Verified (100% Pass Rate)

---

## 📌 Executive Overview
Minimizing Mean Time to Respond (MTTR) during active security breaches requires automated, instantaneous dispatch of alerts to incident responders and SOAR platforms. However, naive webhook implementations expose organizations to alert storm denial-of-service and spoofed webhook injections.

**PEER'S SIEM Webhook Dispatcher** bridges defensive security sensors with incident operations by formatting and dispatching authenticated security alerts to **Slack Block Kit**, **Microsoft Teams MessageCards**, **Discord Embeds**, and **Generic SIEM HTTP Event Collectors (Splunk/Elastic)**. The pipeline features **HMAC-SHA256 non-repudiation signing** (`X-Hub-Signature-256`) and a **Token Bucket rate limiter** (60 req/min, burst=10) to completely eliminate alert storms.

---

## 🛠️ Key Architectural Features
1. **Multi-Channel Schema Transformation:** Generates native JSON payloads tailored to Slack Block Kit, Microsoft Teams, Discord Embeds, and RFC 5424 / CEF SIEM HEC formats.
2. **Cryptographic Non-Repudiation (HMAC-SHA256):** Digitally signs all outgoing alert bodies with `sha256=<hex_digest>`, allowing receivers to verify alert integrity.
3. **Token Bucket Alert Storm Guard:** Enforces sustained rate limits (60/min) and burst allowances (10 tokens), mitigating alert floods with RFC 6585 `THROTTLED_429` status.
4. **Interactive CLI & Batch Automation:** High-contrast Colorama terminal interface for testing dispatch across channels, verifying HMAC signatures, and reviewing telemetry.
5. **Continuous Verification Suite:** Comprehensive 6-point automated PyUnit test suite validating all formatting, signing, and rate limiting logic.

---

## 🚀 Installation & Usage

### 1. Execute Interactive Terminal CLI
```bash
python Day28_SIEM_Webhook_Automation/webhook_dispatcher.py
```

### 2. Run Headless Batch Dispatch
```bash
python Day28_SIEM_Webhook_Automation/webhook_dispatcher.py --batch
```

### 3. Run Automated PyUnit Test Suite
```bash
python -m unittest Day28_SIEM_Webhook_Automation/tests/test_webhook_dispatcher.py -v
```

### 4. Generate Executive 7-Page PDF Report
```bash
python Day28_SIEM_Webhook_Automation/scripts/generate_day28_pdf.py
```

---

## 🧪 Automated Unit Test Results
```
test_discord_embed_formatting (tests.test_webhook_dispatcher.TestWebhookDispatcher.test_discord_embed_formatting) ... ok
test_dispatch_audit_telemetry_export (tests.test_webhook_dispatcher.TestWebhookDispatcher.test_dispatch_audit_telemetry_export) ... ok
test_hmac_sha256_generation_and_verification (tests.test_webhook_dispatcher.TestWebhookDispatcher.test_hmac_sha256_generation_and_verification) ... ok
test_slack_block_kit_formatting (tests.test_webhook_dispatcher.TestWebhookDispatcher.test_slack_block_kit_formatting) ... ok
test_teams_message_card_formatting (tests.test_webhook_dispatcher.TestWebhookDispatcher.test_teams_message_card_formatting) ... ok
test_token_bucket_rate_throttling (tests.test_webhook_dispatcher.TestWebhookDispatcher.test_token_bucket_rate_throttling) ... ok

----------------------------------------------------------------------
Ran 6 tests in 0.016s

OK
```

---

## 📊 Empirical Execution Artifacts
- **Screenshots:** All 6 high-definition Kali Linux terminal screenshots located in `reports/screenshots/`.
- **Audit PDF:** Verified 7-page executive engineering report available at `reports/Day28_SIEM_Webhook_Automation_Report_Sqrock_MdPeerSiddiqui.pdf`.
- **Validation Telemetry:** Structured JSON and TXT audit summaries saved in `webhook_logs/`.
