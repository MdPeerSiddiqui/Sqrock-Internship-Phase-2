# Day 29: Incident Containment & Host Isolation Scripting

**Candidate:** Mohammed Peer Siddiqui  
**Internship Track:** Phase 2: Web Application Security & Defensive Automation  
**Company:** Sqrock IT Solutions  
**Status:** Completed & Verified (100% Pass Rate)

---

## 📌 Executive Overview
Active critical cybersecurity compromises—such as ransomware execution, credential theft, and persistent C2 beaconing—require immediate, automated containment to prevent lateral network propagation. However, completely powering down compromised hosts destroys ephemeral memory forensics, preventing investigators from determining the root cause.

**PEER'S Incident Containment & Host Isolation Engine** provides a rapid-response containment playbook. It dynamically applies an **emergency Netfilter (iptables/nftables) quarantine policy** (setting default DROP across all chains), null-routes external egress, pin-holes bi-directional access exclusively to the authorized SOC Bastion Jumpbox (`10.0.100.50` on ports 22/443), revokes unauthorized interactive shell sessions with `SIGKILL (9)`, and preserves volatile host forensic evidence in a cryptographically sealed SHA-256 JSON bundle.

---

## 🛠️ Key Architectural Features
1. **Emergency Network Quarantine:** Instantly resets iptables firewall rules to drop all unauthorized inbound and outbound traffic, eliminating lateral movement.
2. **Forensic Bastion Pin-Hole:** Preserves bi-directional SSH/HTTPS access exclusively for the authorized SOC Jumpbox (`10.0.100.50`), maintaining forensic access.
3. **Automated Session Revocation:** Identifies non-bastion interactive terminal sessions and suspicious child processes, terminating them immediately via `SIGKILL`.
4. **Forensic Evidence Sealing:** Serializes volatile process trees, socket states, and metadata into `incident_forensics_<id>.json` sealed with a courtroom-admissible SHA-256 digest.
5. **Safe Rollback Playbook:** Automatically generates verified `rollback_iptables.sh` scripts to restore normal enterprise connectivity upon incident resolution.
6. **Continuous Verification Suite:** Comprehensive 6-point automated PyUnit test suite validating all quarantine, pin-hole, and termination workflows.

---

## 🚀 Installation & Usage

### 1. Execute Interactive Terminal CLI
```bash
python Day29_Incident_Host_Isolation/host_isolator.py
```

### 2. Run Headless Containment Playbook
```bash
python Day29_Incident_Host_Isolation/host_isolator.py --isolate
```

### 3. Run Automated PyUnit Test Suite
```bash
python -m unittest Day29_Incident_Host_Isolation/tests/test_host_isolator.py -v
```

### 4. Generate Executive 7-Page PDF Report
```bash
python Day29_Incident_Host_Isolation/scripts/generate_day29_pdf.py
```

---

## 🧪 Automated Unit Test Results
```
test_bastion_tunnel_pinholing (tests.test_host_isolator.TestHostIsolator.test_bastion_tunnel_pinholing) ... ok
test_containment_rollback_generation (tests.test_host_isolator.TestHostIsolator.test_containment_rollback_generation) ... ok
test_context_ingestion (tests.test_host_isolator.TestHostIsolator.test_context_ingestion) ... ok
test_firewall_rule_generation (tests.test_host_isolator.TestHostIsolator.test_firewall_rule_generation) ... ok
test_forensic_evidence_preservation (tests.test_host_isolator.TestHostIsolator.test_forensic_evidence_preservation) ... ok
test_rogue_session_termination (tests.test_host_isolator.TestHostIsolator.test_rogue_session_termination) ... ok

----------------------------------------------------------------------
Ran 6 tests in 0.011s

OK
```

---

## 📊 Empirical Execution Artifacts
- **Screenshots:** All 6 high-definition Kali Linux terminal screenshots located in `reports/screenshots/`.
- **Audit PDF:** Verified 7-page executive engineering report available at `reports/Day29_Host_Isolation_Report_Sqrock_MdPeerSiddiqui.pdf`.
- **Validation Telemetry:** Quarantine scripts and forensic evidence bundles saved in `containment_evidence/`.
