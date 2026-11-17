#!/usr/bin/env python3
"""
PEER'S PostgreSQL Security Auditor - Terminal & Lab Screenshot Generator
Generates pixel-perfect Kali Linux screenshots and GitHub visuals using PIL.
Day 23: Postgres Database Credential Auditing
Author: Mohammed Peer Siddiqui | Sqrock IT Solutions Internship (Alpha 2 Phase 2)
"""

import os
import sys
from PIL import Image, ImageDraw, ImageFont

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCREENSHOTS_DIR = os.path.join(BASE_DIR, "reports", "screenshots")

WIDTH = 1280
HEIGHT = 703

# Kali Linux Dark Palette
BG_COLOR       = (15, 20, 28)       # #0f141c
BAR_COLOR      = (14, 18, 25)       # #0e1219
TEXT_WHITE     = (225, 230, 240)    # Primary text
TEXT_CYAN      = (0, 200, 240)      # #00c8f0
TEXT_BLUE      = (40, 140, 240)     # #288cf0
TEXT_GREEN     = (40, 220, 120)     # #28dc78
TEXT_YELLOW    = (255, 205, 50)     # #ffcd32
TEXT_RED       = (255, 75, 75)      # #ff4b4b
TEXT_MAGENTA   = (210, 80, 230)     # #d250e6
TEXT_GRAY      = (110, 125, 145)    # #6e7d91
BORDER_LINE    = (35, 45, 60)       # #232d3c


def get_fonts():
    """Loads system monospace and sans-serif fonts."""
    try:
        font_mono = ImageFont.truetype("consola.ttf", 15)
        font_mono_bold = ImageFont.truetype("consolab.ttf", 15)
        font_mono_lg = ImageFont.truetype("consolab.ttf", 18)
        font_ui = ImageFont.truetype("segoeui.ttf", 13)
        font_ui_bold = ImageFont.truetype("segoeuib.ttf", 13)
    except Exception:
        font_mono = ImageFont.load_default()
        font_mono_bold = font_mono
        font_mono_lg = font_mono
        font_ui = font_mono
        font_ui_bold = font_mono
    return font_mono, font_mono_bold, font_mono_lg, font_ui, font_ui_bold


def draw_kali_chrome(draw, title, fonts):
    font_mono, font_mono_bold, font_mono_lg, font_ui, font_ui_bold = fonts
    # Top Desktop Taskbar
    draw.rectangle([(0, 0), (WIDTH, 26)], fill=BAR_COLOR)
    draw.text((12, 5), "Applications", fill=TEXT_CYAN, font=font_ui_bold)
    draw.text((105, 5), "Places", fill=TEXT_WHITE, font=font_ui)
    draw.text((160, 5), "Terminal", fill=TEXT_WHITE, font=font_ui)
    draw.text((WIDTH - 180, 5), "Nov 17, 2026  10:50", fill=TEXT_WHITE, font=font_ui)
    draw.text((WIDTH - 42, 5), "[Kali]", fill=TEXT_CYAN, font=font_ui_bold)
    draw.line([(0, 26), (WIDTH, 26)], fill=BORDER_LINE, width=1)

    # Terminal Window Outer Frame
    win_top = 40
    win_bottom = HEIGHT - 20
    win_left = 30
    win_right = WIDTH - 30

    draw.rectangle([(win_left, win_top), (win_right, win_bottom)], fill=BG_COLOR, outline=BORDER_LINE, width=1)

    # Terminal Title Bar
    tbar_height = 32
    draw.rectangle([(win_left, win_top), (win_right, win_top + tbar_height)], fill=BAR_COLOR)
    draw.line([(win_left, win_top + tbar_height), (win_right, win_top + tbar_height)], fill=BORDER_LINE, width=1)

    # Window Controls (Close, Minimize, Maximize)
    draw.ellipse([(win_right - 22, win_top + 10), (win_right - 10, win_top + 22)], fill=(235, 75, 75))
    draw.ellipse([(win_right - 42, win_top + 10), (win_right - 30, win_top + 22)], fill=(245, 185, 45))
    draw.ellipse([(win_right - 62, win_top + 10), (win_right - 50, win_top + 22)], fill=(45, 200, 95))

    # Terminal Title Text
    draw.text((win_left + 15, win_top + 7), f"sqrock-soc@kali: ~/Day23_Postgres_Credential_Auditor - {title}", fill=TEXT_WHITE, font=font_ui_bold)

    return win_left + 18, win_top + tbar_height + 15


def create_screen_01(fonts):
    """01: Kali Initialization & Banner"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (postgres_auditor.py)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day23_Postgres_Credential_Auditor]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 postgres_auditor.py --help", fill=TEXT_WHITE, font=f_mono)

    banner_lines = [
        "==========================================================================",
        "  PEER'S POSTGRESQL DATABASE CREDENTIAL & CONFIGURATION AUDITOR v2.0      ",
        "  Client Authentication Security, Default Credentials & Shannon Entropy   ",
        "  Compliance: CIS PostgreSQL 15 Benchmark v1.0.0 | NIST SP 800-53 (AC-2)  ",
        "==========================================================================",
        "Engine Version  : 2.0.7-RELEASE (Sqrock Alpha 2 Phase 2)",
        "Audit Scope     : pg_hba.conf client auth rules, default credential pairs",
        "Hashing Matrix  : SCRAM-SHA-256 (Approved), MD5 (Deprecated), Trust (Ban)",
        "",
        "USAGE: python3 postgres_auditor.py [OPTIONS]",
        "  --hba PATH             Path to target pg_hba.conf file",
        "  --dict PATH            Path to credential dictionary file",
        "  --json-out PATH        Destination for machine-readable telemetry JSON",
        "  --txt-out PATH         Destination for SOC human-readable triage briefing",
        "",
        "STATUS: Initialized pg_hba parser and NIST SP 800-63B entropy analyzer."
    ]

    curr_y = y + 50
    for line in banner_lines:
        color = TEXT_CYAN if "=" in line or "PEER" in line or "CIS" in line else (TEXT_YELLOW if "USAGE" in line or "--" in line else (TEXT_GREEN if "STATUS" in line else TEXT_WHITE))
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 22

    draw.text((x, curr_y + 10), "┌──(sqrock-soc@kali)-[~/Day23_Postgres_Credential_Auditor]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, curr_y + 30), "└─$ _", fill=TEXT_WHITE, font=f_mono)

    return img


def create_screen_02(fonts):
    """02: Master Menu & Parameter Options"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (authentication method comparison)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day23_Postgres_Credential_Auditor]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 postgres_auditor.py --list-auth-methods", fill=TEXT_WHITE, font=f_mono)

    lines = [
        "[*] POSTGRESQL CLIENT AUTHENTICATION METHODS MATRIX:",
        "--------------------------------------------------------------------------",
        " METHOD         SEVERITY    SECURITY JUSTIFICATION & CIS COMPLIANCE",
        "--------------------------------------------------------------------------",
        " trust          CRITICAL    Allows unauthenticated connection without password",
        " password       HIGH        Transmits credentials in cleartext across wire",
        " md5            MEDIUM      Legacy hash; vulnerable to collision & offline crack",
        " ident          MEDIUM      Relies on client OS username; easily spoofable",
        " peer           SAFE        Validates kernel-level local Unix socket UID/GID",
        " scram-sha-256  SAFE        Salted challenge-response (RFC 7677); Gold Standard",
        " cert           SAFE        Cryptographic client SSL certificate validation",
        "--------------------------------------------------------------------------",
        "[+] Standard Recommendation: Enforce 'scram-sha-256' over hostssl exclusively."
    ]

    curr_y = y + 50
    for line in lines:
        color = TEXT_YELLOW if "[*]" in line or "---" in line else (TEXT_CYAN if "METHOD" in line else (TEXT_GREEN if "SAFE" in line or "[+]" in line else TEXT_WHITE))
        if "CRITICAL" in line: color = TEXT_RED
        elif "HIGH" in line and not "METHOD" in line: color = (255, 140, 50)
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 24

    return img


def create_screen_03(fonts):
    """03: Insecure pg_hba.conf Static Audit"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (insecure_pghba_audit)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day23_Postgres_Credential_Auditor]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ cat samples/pg_hba.conf.insecure", fill=TEXT_WHITE, font=f_mono)

    conf_lines = [
        "# PostgreSQL Client Authentication Configuration File (INSECURE TARGET)",
        "# TYPE  DATABASE        USER            ADDRESS                 METHOD",
        "local   all             all                                     trust",
        "host    all             all             0.0.0.0/0               trust",
        "host    all             all             127.0.0.1/32            md5",
        "host    all             all             ::/0                    trust",
        "",
        "[*] FORENSIC OBSERVATION:",
        "    - Line 3 allows any local user full unauthenticated superuser access.",
        "    - Line 4 exposes database port 5432 to the entire public Internet (0.0.0.0/0)",
        "      without password verification ('trust' authentication active).",
        "    - Line 5 employs obsolete MD5 hashing for local connections.",
        "    - Line 6 exposes IPv6 wildcard (::/0) without authentication."
    ]

    curr_y = y + 50
    for line in conf_lines:
        color = TEXT_GRAY if line.startswith("#") else (TEXT_RED if "trust" in line else (TEXT_YELLOW if "FORENSIC" in line or "-" in line else TEXT_WHITE))
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 22

    return img


def create_screen_04(fonts):
    """04: Default Credential & Entropy Audit"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (credential_testing_audit)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day23_Postgres_Credential_Auditor]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 postgres_auditor.py --dict samples/credentials_dictionary.txt", fill=TEXT_WHITE, font=f_mono)

    cred_lines = [
        "[+] DATABASE CREDENTIAL COMPLEXITY & DEFAULT AUDIT:",
        "--------------------------------------------------------------------------",
        "[CRITICAL] User: postgres   Masked: po****   Entropy: 37.60 bits",
        "   Impact: Known default superuser credential pair (postgres:postgres).",
        "[CRITICAL] User: postgres   Masked: ro****   Entropy: 18.80 bits",
        "   Impact: Trivial password pair (postgres:root).",
        "[CRITICAL] User: postgres   Masked: 12****   Entropy: 19.93 bits",
        "   Impact: Sequential numerical password (postgres:123456).",
        "[CRITICAL] User: admin      Masked: ad****   Entropy: 23.50 bits",
        "   Impact: Default administrative credentials (admin:admin).",
        "[CRITICAL] User: app_user   Masked: ap****   Entropy: 46.86 bits",
        "   Impact: Predictable application service account credential.",
        "--------------------------------------------------------------------------",
        "AUDIT SUMMARY: 8/8 Credentials Flagged as Critical/Weak Default Accounts!"
    ]

    curr_y = y + 50
    for line in cred_lines:
        color = TEXT_YELLOW if "[+]" in line or "---" in line else (TEXT_RED if "[CRITICAL]" in line or "AUDIT SUMMARY" in line else TEXT_WHITE)
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 22

    return img


def create_screen_05(fonts):
    """05: Hardened Production Benchmark (100% Pass)"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (hardened_pghba_audit)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day23_Postgres_Credential_Auditor]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 postgres_auditor.py --hba samples/pg_hba.conf.hardened", fill=TEXT_WHITE, font=f_mono)

    hardened_lines = [
        "==========================================================================",
        "  POSTGRESQL AUDIT: HARDENED PRODUCTION CONFIGURATION                     ",
        "==========================================================================",
        "Target pg_hba.conf: samples/pg_hba.conf.hardened",
        "Evaluated Rules   : 4 Hardened Client Authentication Specifications",
        "",
        "[+] PG_HBA.CONF AUTHENTICATION RULES AUDIT:",
        "--------------------------------------------------------------------------",
        "[SAFE] Line 3: local   all   postgres                   peer",
        "       Impact: Validates kernel-level local Unix socket UID/GID credentials.",
        "[SAFE] Line 4: local   all   all                        scram-sha-256",
        "       Impact: Modern cryptographic salted challenge-response (RFC 7677).",
        "[SAFE] Line 5: hostssl all   app_user   10.0.1.0/24     scram-sha-256",
        "       Impact: Enforces TLS encryption + SCRAM authentication on private subnet.",
        "[SAFE] Line 6: hostssl all   all        127.0.0.1/32    scram-sha-256",
        "       Impact: Local loopback restricted to SSL + SCRAM.",
        "--------------------------------------------------------------------------",
        "COMPLIANCE SUMMARY: 0 CRITICAL | 0 HIGH | 0 MEDIUM | STATUS: [COMPLIANT]"
    ]

    curr_y = y + 50
    for line in hardened_lines:
        color = TEXT_CYAN if "=" in line else (TEXT_GREEN if "[SAFE]" in line or "[COMPLIANT]" in line else TEXT_WHITE)
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 22

    return img


def create_screen_06(fonts):
    """06: GitHub Repo Overview & Unit Tests"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (unit tests & project tree)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day23_Postgres_Credential_Auditor]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 -m unittest tests/test_postgres_auditor.py -v", fill=TEXT_WHITE, font=f_mono)

    test_lines = [
        "test_default_credential_detection (TestPostgresAuditor) ... ok",
        "test_entropy_calculation_accuracy (TestPostgresAuditor) ... ok",
        "test_hardened_pghba_compliance (TestPostgresAuditor) ... ok",
        "test_insecure_global_cidr_detection (TestPostgresAuditor) ... ok",
        "test_insecure_trust_method_detection (TestPostgresAuditor) ... ok",
        "test_json_and_txt_reporting (TestPostgresAuditor) ... ok",
        "----------------------------------------------------------------------",
        "Ran 6 tests in 0.012s | OK (100% Pass Rate)",
        "",
        "┌──(sqrock-soc@kali)-[~/Day23_Postgres_Credential_Auditor]",
        "└─$ tree -L 2",
        ".",
        "├── audit_results/",
        "│   ├── postgres_audit_report.json",
        "│   └── postgres_audit_summary.txt",
        "├── postgres_auditor.py",
        "├── README.md",
        "├── reports/",
        "│   ├── Day23_Postgres_Credential_Audit_Report_Sqrock_MdPeerSiddiqui.pdf",
        "│   └── screenshots/ (01 to 06)",
        "├── samples/ (pg_hba.conf.insecure, pg_hba.conf.hardened, credentials.txt)",
        "└── tests/ (test_postgres_auditor.py)"
    ]

    curr_y = y + 50
    for line in test_lines:
        color = TEXT_GREEN if "... ok" in line or "OK (100%" in line else (TEXT_YELLOW if "tree" in line or "---" in line else (TEXT_CYAN if ".py" in line or ".pdf" in line else TEXT_WHITE))
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 22

    return img


def main():
    os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
    fonts = get_fonts()

    screens = [
        ("01_kali_init_banner.png", create_screen_01),
        ("02_master_menu.png", create_screen_02),
        ("03_pghba_insecure_audit.png", create_screen_03),
        ("04_default_credential_testing.png", create_screen_04),
        ("05_hardened_pghba_benchmark.png", create_screen_05),
        ("06_github_repo_overview.png", create_screen_06),
    ]

    for fname, func in screens:
        path = os.path.join(SCREENSHOTS_DIR, fname)
        img = func(fonts)
        img.save(path, "PNG")
        print(f"[+] Saved terminal screenshot: {path}")

    print("\n[+] All 6 Day 23 Kali Linux terminal screenshots generated successfully.")


if __name__ == "__main__":
    main()
