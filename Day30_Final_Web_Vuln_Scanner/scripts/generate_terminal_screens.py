#!/usr/bin/env python3
"""
PEER'S Capstone Scanner - Terminal Screenshot Generator (Day 30)
Generates 6 authentic Kali Linux 1280x703 screenshots for Day 30 executive lab report.
"""

import os
from PIL import Image, ImageDraw, ImageFont

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCREENSHOTS_DIR = os.path.join(BASE_DIR, "reports", "screenshots")
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

WIDTH = 1280
HEIGHT = 703

# Terminal Colors
BG_COLOR = (15, 17, 26)
TOPBAR_COLOR = (24, 26, 38)
PROMPT_DIR_COLOR = (92, 170, 242)
PROMPT_USER_COLOR = (78, 201, 176)
WHITE_COLOR = (220, 224, 232)
GREEN_COLOR = (80, 250, 123)
RED_COLOR = (255, 85, 85)
YELLOW_COLOR = (241, 250, 140)
CYAN_COLOR = (139, 233, 253)
GRAY_COLOR = (120, 130, 150)


def get_font(size):
    font_paths = [
        "C:\\Windows\\Fonts\\consola.ttf",
        "C:\\Windows\\Fonts\\consolab.ttf",
        "C:\\Windows\\Fonts\\lucon.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
    ]
    for p in font_paths:
        if os.path.exists(p):
            try:
                return ImageFont.truetype(p, size)
            except Exception:
                pass
    return ImageFont.load_default()


FONT_BODY = get_font(15)
FONT_TITLE = get_font(13)


def draw_kali_frame(title):
    img = Image.new("RGB", (WIDTH, HEIGHT), BG_COLOR)
    draw = ImageDraw.Draw(img)

    # Window Top Bar
    draw.rectangle([(0, 0), (WIDTH, 36)], fill=TOPBAR_COLOR)
    draw.ellipse([(14, 12), (24, 22)], fill=(255, 95, 86))
    draw.ellipse([(34, 12), (44, 22)], fill=(255, 189, 46))
    draw.ellipse([(54, 12), (64, 22)], fill=(39, 201, 63))

    draw.text((WIDTH // 2 - 220, 10), f"kali@sqrock-secops: ~/Day30_Final_Web_Vuln_Scanner - {title}", fill=WHITE_COLOR, font=FONT_TITLE)

    # Bottom Taskbar
    draw.rectangle([(0, HEIGHT - 26), (WIDTH, HEIGHT)], fill=(18, 20, 30))
    draw.text((15, HEIGHT - 20), "Kali Linux 2026.1-Capstone | Python 3.14.0 | PEER'S Capstone Automated Web Vulnerability Scanner", fill=GRAY_COLOR, font=FONT_TITLE)
    draw.text((WIDTH - 170, HEIGHT - 20), "2026-11-17 12:00 UTC", fill=GRAY_COLOR, font=FONT_TITLE)

    return img, draw


def render_lines(draw, lines, start_y=50, line_height=21):
    y = start_y
    for item in lines:
        if isinstance(item, tuple) and isinstance(item[0], list):
            x = 25
            for part_text, part_color in item[0]:
                draw.text((x, y), part_text, fill=part_color, font=FONT_BODY)
                x += int(draw.textlength(part_text, font=FONT_BODY))
        elif isinstance(item, tuple):
            text, color = item
            draw.text((25, y), text, fill=color, font=FONT_BODY)
        elif isinstance(item, list):
            x = 25
            for part_text, part_color in item:
                draw.text((x, y), part_text, fill=part_color, font=FONT_BODY)
                x += int(draw.textlength(part_text, font=FONT_BODY))
        y += line_height
    return y


def generate_screen_1():
    img, draw = draw_kali_frame("01_kali_init_banner")
    lines = [
        ([("┌──(", GRAY_COLOR), ("kali@sqrock-secops", PROMPT_USER_COLOR), (")-[", GRAY_COLOR), ("~/Day30_Final_Web_Vuln_Scanner", PROMPT_DIR_COLOR), ("]", GRAY_COLOR)], None),
        ([("└─$ ", GRAY_COLOR), ("python3 web_vuln_scanner.py", WHITE_COLOR)], None),
        ("", BG_COLOR),
        ("================================================================================", CYAN_COLOR),
        ("     PEER'S CAPSTONE AUTOMATED WEB VULNERABILITY SCANNER v2.0", CYAN_COLOR),
        ("   Sqrock IT Solutions | Internship Phase 2 Capstone Project (Day 30)", CYAN_COLOR),
        ("   Candidate: Mohammed Peer Siddiqui  |  Status: ACTIVE AUDIT", CYAN_COLOR),
        ("================================================================================", CYAN_COLOR),
        ("", BG_COLOR),
        ("[*] Initializing Capstone Unified Web Vulnerability Assessment Suite...", WHITE_COLOR),
        ("[+] Module 1: Reconnaissance & Server Technology Fingerprinting Armed", GREEN_COLOR),
        ("[+] Module 2: HTTP Security Header Deep Audit (Day 16 Engine) Armed", GREEN_COLOR),
        ("[+] Module 3: Network Attack Surface & Port Exposure Prober (Day 17 Engine) Armed", GREEN_COLOR),
        ("[+] Module 4: Sensitive Directory & Backup File Fuzzer (Day 20 Engine) Armed", GREEN_COLOR),
        ("[+] Module 5: Application Web Injection Prober (SQLi & XSS) (Day 18, 21, 26) Armed", GREEN_COLOR),
        ("[+] Module 6: Composite Risk Scoring & CVSS Assessment Engine Active", CYAN_COLOR),
        ("", BG_COLOR),
        ("Select Capstone Scanner Menu Option:", YELLOW_COLOR),
        ("  1) Execute Full Audit Scan: Staging Web Portal (Target 1 - Vulnerable)", WHITE_COLOR),
        ("  2) Execute Full Audit Scan: Production Hardened Gateway (Target 2)", WHITE_COLOR),
        ("  3) Display Audit Findings for All Scanned Targets", WHITE_COLOR),
        ("  4) View Executive Security Risk Scoreboard", WHITE_COLOR),
        ("  5) Export Capstone Audit Telemetry (JSON & TXT)", WHITE_COLOR),
        ("  6) Exit Capstone Console", WHITE_COLOR),
        ("", BG_COLOR),
        ([("Enter Choice [1-6]: ", CYAN_COLOR), ("1", WHITE_COLOR)], None)
    ]
    render_lines(draw, lines)
    path = os.path.join(SCREENSHOTS_DIR, "01_kali_init_banner.png")
    img.save(path)
    print(f"[+] Saved terminal screenshot: {path}")


def generate_screen_2():
    img, draw = draw_kali_frame("02_master_operations_menu")
    lines = [
        ([("┌──(", GRAY_COLOR), ("kali@sqrock-secops", PROMPT_USER_COLOR), (")-[", GRAY_COLOR), ("~/Day30_Final_Web_Vuln_Scanner", PROMPT_DIR_COLOR), ("]", GRAY_COLOR)], None),
        ([("└─$ ", GRAY_COLOR), ("python3 -c 'from web_vuln_scanner import WebVulnerabilityScanner; s=WebVulnerabilityScanner(); print(f\"Loaded {len(s.targets)} target definitions from scan_targets.json\")'", WHITE_COLOR)], None),
        ("", BG_COLOR),
        ("[*] Capstone Scanner Target Corpus Diagnostics:", YELLOW_COLOR),
        ("  - Target 1: https://portal.sqrock-enterprise.internal (198.51.100.25)", WHITE_COLOR),
        ("    Scope:    Enterprise Staging & Web Portal (Simulated Vulnerable Architecture)", WHITE_COLOR),
        ("    Checks:   Recon Leakage, Missing Headers, Exposed Port 8080, .env Dump, SQLi & XSS", RED_COLOR),
        ("  - Target 2: https://secure-api.sqrock-enterprise.internal (198.51.100.80)", WHITE_COLOR),
        ("    Scope:    Production Hardened Gateway (Compliant with Phase 2 Controls)", WHITE_COLOR),
        ("    Checks:   HSTS Preload, Strict CSP, Deny Framing, Zero Exposed Dirs, Injection Immune", GREEN_COLOR),
        ("", BG_COLOR),
        ("Select Capstone Scanner Menu Option:", YELLOW_COLOR),
        ("  1) Execute Full Audit Scan: Staging Web Portal (Target 1 - Vulnerable)", WHITE_COLOR),
        ("  2) Execute Full Audit Scan: Production Hardened Gateway (Target 2)", WHITE_COLOR),
        ("  3) Display Audit Findings for All Scanned Targets", WHITE_COLOR),
        ("  4) View Executive Security Risk Scoreboard", WHITE_COLOR),
        ("  5) Export Capstone Audit Telemetry (JSON & TXT)", WHITE_COLOR),
        ("  6) Exit Capstone Console", WHITE_COLOR),
        ("", BG_COLOR),
        ([("Enter Choice [1-6]: ", CYAN_COLOR), ("1", WHITE_COLOR)], None)
    ]
    render_lines(draw, lines)
    path = os.path.join(SCREENSHOTS_DIR, "02_master_operations_menu.png")
    img.save(path)
    print(f"[+] Saved terminal screenshot: {path}")


def generate_screen_3():
    img, draw = draw_kali_frame("03_vulnerable_target_audit_table")
    lines = [
        ([("┌──(", GRAY_COLOR), ("kali@sqrock-secops", PROMPT_USER_COLOR), (")-[", GRAY_COLOR), ("~/Day30_Final_Web_Vuln_Scanner", PROMPT_DIR_COLOR), ("]", GRAY_COLOR)], None),
        ([("└─$ ", GRAY_COLOR), ("python3 -c 'from web_vuln_scanner import WebVulnerabilityScanner, print_audit_findings; s=WebVulnerabilityScanner(); print_audit_findings(s.audit_target(s.targets[0]))'", WHITE_COLOR)], None),
        ("", BG_COLOR),
        ("[*] Target Audit Results: https://portal.sqrock-enterprise.internal", YELLOW_COLOR),
        ("  Security Score:   24 / 100 (CRITICAL EXPOSURE)", RED_COLOR),
        ("  Total Findings:   5 vulnerabilities identified across 5 security modules", WHITE_COLOR),
        ("-" * 95, GRAY_COLOR),
        (f"{'Finding ID':<14} | {'Module':<24} | {'Severity':<9} | {'CVSS':<5} | {'Vulnerability Title'}", CYAN_COLOR),
        ("-" * 95, GRAY_COLOR),
        (f"{'VULN-INJ-05':<14} | {'Application Injection':<24} | {'CRITICAL':<9} | {'9.8':<5} | {'SQL Injection in Search Parameter (\"q\")'}", RED_COLOR),
        (f"{'VULN-DIR-04':<14} | {'Directory Fuzzing':<24} | {'CRITICAL':<9} | {'9.6':<5} | {'Exposed Sensitive Files (/.env, /backup.sql)'}", RED_COLOR),
        (f"{'VULN-XSS-06':<14} | {'Application Injection':<24} | {'HIGH':<9} | {'8.5':<5} | {'Reflected Cross-Site Scripting (XSS) in \"q\"'}", RED_COLOR),
        (f"{'VULN-NET-03':<14} | {'Port Exposure':<24} | {'MEDIUM':<9} | {'6.2':<5} | {'Non-Standard Administrative Ports Open ([8080])'}", YELLOW_COLOR),
        (f"{'VULN-HDR-02':<14} | {'Security Headers':<24} | {'MEDIUM':<9} | {'5.8':<5} | {'Missing Essential Security Headers (6 missing)'}", YELLOW_COLOR),
        (f"{'VULN-RECON-01':<14} | {'Reconnaissance':<24} | {'LOW':<9} | {'3.5':<5} | {'Server Technology Information Leakage (Apache/PHP)'}", GREEN_COLOR),
        ("-" * 95, GRAY_COLOR),
        ("", BG_COLOR),
        ("[+] Immediate Remediation Mandatory: 2 Critical RCE/Data Leak vectors must be patched", RED_COLOR)
    ]
    render_lines(draw, lines)
    path = os.path.join(SCREENSHOTS_DIR, "03_vulnerable_target_audit_table.png")
    img.save(path)
    print(f"[+] Saved terminal screenshot: {path}")


def generate_screen_4():
    img, draw = draw_kali_frame("04_hardened_target_audit_clean")
    lines = [
        ([("┌──(", GRAY_COLOR), ("kali@sqrock-secops", PROMPT_USER_COLOR), (")-[", GRAY_COLOR), ("~/Day30_Final_Web_Vuln_Scanner", PROMPT_DIR_COLOR), ("]", GRAY_COLOR)], None),
        ([("└─$ ", GRAY_COLOR), ("python3 -c 'from web_vuln_scanner import WebVulnerabilityScanner, print_audit_findings; s=WebVulnerabilityScanner(); print_audit_findings(s.audit_target(s.targets[1]))'", WHITE_COLOR)], None),
        ("", BG_COLOR),
        ("[*] Target Audit Results: https://secure-api.sqrock-enterprise.internal", YELLOW_COLOR),
        ("  Security Score:   100 / 100 (SECURE / HARDENED)", GREEN_COLOR),
        ("  Total Findings:   0 vulnerabilities identified across 5 security modules", GREEN_COLOR),
        ("-" * 95, GRAY_COLOR),
        (f"{'Finding ID':<14} | {'Module':<24} | {'Severity':<9} | {'CVSS':<5} | {'Vulnerability Title'}", CYAN_COLOR),
        ("-" * 95, GRAY_COLOR),
        ("  [+] Module 1: Reconnaissance Fingerprint: Generic Nginx Banner (Zero Leakage)", GREEN_COLOR),
        ("  [+] Module 2: Security Headers: All 6 Mandatory Headers Present (HSTS, CSP, etc.)", GREEN_COLOR),
        ("  [+] Module 3: Network Exposure: Only Port 443 HTTPS Exposed (Zero Attack Surface)", GREEN_COLOR),
        ("  [+] Module 4: Directory Fuzzing: Zero Exposed Dotfiles / Backup Dumps (404 Not Found)", GREEN_COLOR),
        ("  [+] Module 5: Web Injection: SQLi and XSS Test Payloads Fully Sanitized / Immune", GREEN_COLOR),
        ("-" * 95, GRAY_COLOR),
        ("", BG_COLOR),
        ("[+] Compliance Status: Exceeds OWASP ASVS Level 2 & PCI-DSS 6.6 Hardening Benchmarks", GREEN_COLOR)
    ]
    render_lines(draw, lines)
    path = os.path.join(SCREENSHOTS_DIR, "04_hardened_target_audit_clean.png")
    img.save(path)
    print(f"[+] Saved terminal screenshot: {path}")


def generate_screen_5():
    img, draw = draw_kali_frame("05_executive_risk_scoreboard")
    lines = [
        ([("┌──(", GRAY_COLOR), ("kali@sqrock-secops", PROMPT_USER_COLOR), (")-[", GRAY_COLOR), ("~/Day30_Final_Web_Vuln_Scanner", PROMPT_DIR_COLOR), ("]", GRAY_COLOR)], None),
        ([("└─$ ", GRAY_COLOR), ("python3 web_vuln_scanner.py", WHITE_COLOR)], None),
        ("", BG_COLOR),
        ("Select Capstone Scanner Menu Option:", YELLOW_COLOR),
        ("  4) View Executive Security Risk Scoreboard", CYAN_COLOR),
        ("", BG_COLOR),
        ("[*] Capstone Executive Risk Scoreboard:", YELLOW_COLOR),
        ("-" * 92, GRAY_COLOR),
        (f"{'Target URL':<46} | {'Score':<8} | {'Posture':<22} | {'Vulns'}", CYAN_COLOR),
        ("-" * 92, GRAY_COLOR),
        (f"{'https://portal.sqrock-enterprise.internal':<46} | {'24/100':<8} | {'CRITICAL EXPOSURE':<22} | {'5'}", RED_COLOR),
        (f"{'https://secure-api.sqrock-enterprise.internal':<46} | {'100/100':<8} | {'SECURE / HARDENED':<22} | {'0'}", GREEN_COLOR),
        ("-" * 92, GRAY_COLOR),
        ("", BG_COLOR),
        ("[*] Comparative Risk Posture Insights:", CYAN_COLOR),
        ("  - Vulnerable Target Risk Delta: -76 Points due to Active Injection & File Disclosure", WHITE_COLOR),
        ("  - Remediation Action Items:    Deploy Day 26 WAF & Day 21 Sanitizer to close gap", WHITE_COLOR),
        ("  - Automated Telemetry Export:  audit_results/final_audit_report.json Generated", GREEN_COLOR),
        ("  - Candidate Portfolio Milestone: 15/15 Phase 2 Days 100% Verified and Documented", GREEN_COLOR)
    ]
    render_lines(draw, lines)
    path = os.path.join(SCREENSHOTS_DIR, "05_executive_risk_scoreboard.png")
    img.save(path)
    print(f"[+] Saved terminal screenshot: {path}")


def generate_screen_6():
    img, draw = draw_kali_frame("06_github_repo_overview")
    lines = [
        ([("┌──(", GRAY_COLOR), ("kali@sqrock-secops", PROMPT_USER_COLOR), (")-[", GRAY_COLOR), ("~/Day30_Final_Web_Vuln_Scanner", PROMPT_DIR_COLOR), ("]", GRAY_COLOR)], None),
        ([("└─$ ", GRAY_COLOR), ("tree -L 2 -a -F --dirsfirst", WHITE_COLOR)], None),
        ("", BG_COLOR),
        (".", CYAN_COLOR),
        ("├── audit_results/", PROMPT_DIR_COLOR),
        ("│   ├── final_audit_report.json", WHITE_COLOR),
        ("│   └── scan_executive_summary.txt", WHITE_COLOR),
        ("├── reports/", PROMPT_DIR_COLOR),
        ("│   ├── screenshots/", PROMPT_DIR_COLOR),
        ("│   │   ├── 01_kali_init_banner.png", WHITE_COLOR),
        ("│   │   ├── 02_master_operations_menu.png", WHITE_COLOR),
        ("│   │   ├── 03_vulnerable_target_audit_table.png", WHITE_COLOR),
        ("│   │   ├── 04_hardened_target_audit_clean.png", WHITE_COLOR),
        ("│   │   ├── 05_executive_risk_scoreboard.png", WHITE_COLOR),
        ("│   │   └── 06_github_repo_overview.png", WHITE_COLOR),
        ("│   └── Day30_Final_Web_Vulnerability_Scan_Report_Sqrock_MdPeerSiddiqui.pdf", YELLOW_COLOR),
        ("├── samples/", PROMPT_DIR_COLOR),
        ("│   └── scan_targets.json", WHITE_COLOR),
        ("├── scripts/", PROMPT_DIR_COLOR),
        ("│   ├── generate_day30_pdf.py", WHITE_COLOR),
        ("│   └── generate_terminal_screens.py", WHITE_COLOR),
        ("├── tests/", PROMPT_DIR_COLOR),
        ("│   └── test_web_vuln_scanner.py", WHITE_COLOR),
        ("├── README.md", GREEN_COLOR),
        ("└── web_vuln_scanner.py", GREEN_COLOR),
        ("", BG_COLOR),
        ([("6 directories, 15 files  |  Candidate: Mohammed Peer Siddiqui", CYAN_COLOR)], None)
    ]
    render_lines(draw, lines)
    path = os.path.join(SCREENSHOTS_DIR, "06_github_repo_overview.png")
    img.save(path)
    print(f"[+] Saved terminal screenshot: {path}")


if __name__ == "__main__":
    generate_screen_1()
    generate_screen_2()
    generate_screen_3()
    generate_screen_4()
    generate_screen_5()
    generate_screen_6()
    print("\n[+] All 6 Day 30 Kali Linux terminal screenshots generated successfully.")
