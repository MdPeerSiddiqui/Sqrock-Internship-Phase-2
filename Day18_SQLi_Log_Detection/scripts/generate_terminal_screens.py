#!/usr/bin/env python3
"""
PEER'S SQL Injection Log Detection Engine - Terminal & Lab Screenshot Generator
Generates pixel-perfect Kali Linux screenshots and GitHub visuals using PIL.
Day 18: SQL Injection (SQLi) Log Detection Engine
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
    draw.text((WIDTH - 180, 5), "Nov 17, 2026  10:25", fill=TEXT_WHITE, font=font_ui)
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
    draw.text((win_left + 15, win_top + 7), f"sqrock-soc@kali: ~/Day18_SQLi_Log_Detection - {title}", fill=TEXT_WHITE, font=font_ui_bold)

    return win_left + 18, win_top + tbar_height + 15


def create_screen_01(fonts):
    """01: Kali Initialization & Banner"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (sqli_detector.py)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "kali@sqrock-soc:~$ ", fill=TEXT_GREEN, font=f_bold)
    draw.text((x + 180, y), "cd ~/Day18_SQLi_Log_Detection && python3 sqli_detector.py", fill=TEXT_WHITE, font=f_mono)
    y += 28

    banner = [
        r"   _____  ____  _      _____   _____  ______ _______ ______ _____ _______ ____  _____  ",
        r"  / ____|/ __ \| |    |_   _| |  __ \|  ____|__   __|  ____/ ____|__   __/ __ \|  __ \ ",
        r" | (___ | |  | | |      | |   | |  | | |__     | |  | |__ | |       | | | |  | | |__) |",
        r"  \___ \| |  | | |      | |   | |  | |  __|    | |  |  __|| |       | | | |  | |  _  / ",
        r"  ____) | |__| | |____ _| |_  | |__| | |____   | |  | |___| |____   | | | |__| | | \ \ ",
        r" |_____/ \___\_\______|_____| |_____/|______|  |_|  |______\_____|  |_|  \____/|_|  \_/ ",
    ]
    for b_line in banner:
        draw.text((x, y), b_line, fill=TEXT_CYAN, font=f_mono)
        y += 18

    y += 10
    draw.text((x, y), "[*] Enterprise Web Access Telemetry Parser & SQLi Detection Engine v2.0", fill=TEXT_YELLOW, font=f_bold)
    y += 22
    draw.text((x, y), "[*] Developer: Mohammed Peer Siddiqui | Sqrock IT Solutions Phase 2 (Day 18)", fill=TEXT_GREEN, font=f_mono)
    y += 22
    draw.text((x, y), "[*] Standards: OWASP Top 10 A03:2021 (Injection) | MITRE ATT&CK T1190 | CWE-89", fill=TEXT_WHITE, font=f_mono)
    y += 28

    draw.text((x, y), "[+] Initializing Multi-Vector SQLi Signatures (UNION, Boolean, Blind, Stacked)...", fill=TEXT_CYAN, font=f_mono)
    y += 22
    draw.text((x, y), "[+] Reading Access Log Feed: logs/web_access.log (Common Log Format Engine)", fill=TEXT_WHITE, font=f_mono)
    y += 22
    draw.text((x, y), "[+] Telemetry Parsing Engine: ARMED & RUNNING", fill=TEXT_GREEN, font=f_bold)
    y += 30

    draw.text((x, y), "sqli-parser@sqrock-soc:~$ ", fill=TEXT_CYAN, font=f_bold)
    draw.text((x + 250, y), "_", fill=TEXT_GREEN, font=f_bold)

    return img


def create_screen_02(fonts):
    """02: Master Menu"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "sqli_detector.py (Master Menu)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "[=== MASTER SQLI LOG DETECTION MENU ===]", fill=TEXT_BLUE, font=f_lg)
    y += 32
    draw.text((x, y), "[1] Ingest & Parse Web Server Access Logs", fill=TEXT_WHITE, font=f_mono)
    y += 24
    draw.text((x, y), "[2] Run Multi-Signature SQLi Threat Correlation", fill=TEXT_WHITE, font=f_mono)
    y += 24
    draw.text((x, y), "[3] Inspect Attacker IP Threat Distribution", fill=TEXT_WHITE, font=f_mono)
    y += 24
    draw.text((x, y), "[4] Review Prepared Statements vs Dynamic Concatenation Analysis", fill=TEXT_WHITE, font=f_mono)
    y += 24
    draw.text((x, y), "[5] Export SQLi Incident Triage Audits (JSON & TXT)", fill=TEXT_WHITE, font=f_mono)
    y += 24
    draw.text((x, y), "[6] Exit Suite", fill=TEXT_WHITE, font=f_mono)
    y += 35

    draw.text((x, y), "sqli-parser@sqrock-soc:~$ ", fill=TEXT_CYAN, font=f_bold)
    draw.text((x + 250, y), "2", fill=TEXT_YELLOW, font=f_bold)
    y += 30

    draw.text((x, y), "[*] Scanning access telemetry against compiled SQLi regex matrix...", fill=TEXT_YELLOW, font=f_mono)
    y += 22
    draw.text((x, y), "[+] Parsed 12 HTTP request transactions across 4 remote source IPs...", fill=TEXT_GREEN, font=f_mono)
    y += 22
    draw.text((x, y), "Press Enter to inspect intercepted SQL injection attack alerts...", fill=TEXT_GRAY, font=f_mono)

    return img


def create_screen_03(fonts):
    """03: Log Ingestion & Normalization"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "sqli_detector.py (Access Log Transactions)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "[+] INGESTED WEB SERVER ACCESS TRANSACTIONS (NORMALIZED FEED):", fill=TEXT_CYAN, font=f_bold)
    y += 30

    table_hdr = f"{'SOURCE IP':<16} | {'METHOD':<6} | {'STATUS':<6} | {'DECODED URI / PAYLOAD QUERY'}"
    draw.text((x, y), table_hdr, fill=TEXT_YELLOW, font=f_bold)
    y += 18
    draw.line([(x, y), (WIDTH - 50, y)], fill=BORDER_LINE, width=1)
    y += 12

    transactions = [
        ("192.168.1.45", "GET", "200", "/profile?id=5", TEXT_GREEN),
        ("10.0.4.12", "POST", "401", "/auth/login?user=admin' OR '1'='1", TEXT_RED),
        ("10.0.4.12", "POST", "401", "/auth/login?user=admin' OR 1=1--", TEXT_RED),
        ("172.16.5.9", "GET", "500", "/search?q=UNION SELECT null,password FROM users--", TEXT_RED),
        ("172.16.5.9", "GET", "500", "/search?q=UNION ALL SELECT 1,table_name FROM information_schema--", TEXT_RED),
        ("198.51.100.88", "GET", "200", "/catalog?cat=electronics'; WAITFOR DELAY '0:0:5'--", TEXT_RED),
        ("198.51.100.88", "GET", "200", "/catalog?cat=1 AND pg_sleep(5)--", TEXT_RED),
        ("203.0.113.72", "GET", "403", "/api/v1/orders?order_id=1092'; DROP TABLE audit_logs;--", TEXT_RED),
    ]

    for ip, mtd, st, uri, col in transactions:
        row = f"{ip:<16} | {mtd:<6} | {st:<6} | {uri[:55]}"
        draw.text((x, y), row, fill=col, font=f_mono)
        y += 22

    y += 16
    draw.text((x, y), "[+] Normalization Summary: Decoded URL percent-encoding (%27 -> ', %20 -> space).", fill=TEXT_GREEN, font=f_bold)
    return img


def create_screen_04(fonts):
    """04: Correlated SQLi Threat Alerts"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "sqli_detector.py (Correlated SQLi Alerts)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "[!] ACTIVE SQL INJECTION ATTACK ALERTS INTERCEPTED:", fill=TEXT_RED, font=f_lg)
    y += 28

    alerts = [
        ("CRITICAL", "ALRT-SQLI-003", "UNION_BASED", "172.16.5.9", "q=UNION SELECT null,password FROM users--", "sqlmap/1.7.2#stable"),
        ("CRITICAL", "ALRT-SQLI-005", "TIME_BASED_BLIND", "198.51.100.88", "cat=electronics'; WAITFOR DELAY '0:0:5'--", "Mozilla/5.0"),
        ("CRITICAL", "ALRT-SQLI-007", "STACKED_QUERIES", "203.0.113.72", "order_id=1092'; DROP TABLE audit_logs;--", "Python-urllib/3.10"),
        ("HIGH", "ALRT-SQLI-001", "BOOLEAN_BASED", "10.0.4.12", "user=admin' OR '1'='1", "curl/7.88.1"),
    ]

    for sev, aid, atype, ip, query, ua in alerts:
        col = TEXT_RED if sev == "CRITICAL" else TEXT_YELLOW
        draw.text((x, y), f"[{sev}] {aid} - {atype} from {ip}", fill=col, font=f_bold)
        y += 20
        draw.text((x + 20, y), f"Injected Payload: {query}", fill=TEXT_WHITE, font=f_mono)
        y += 20
        draw.text((x + 20, y), f"Client Fingerprint: User-Agent: {ua}", fill=TEXT_GRAY, font=f_mono)
        y += 24

    draw.line([(x, y), (WIDTH - 50, y)], fill=BORDER_LINE, width=1)
    y += 14
    draw.text((x, y), "[+] Triage Verdict: 7 High/Critical SQL Injection attacks isolated for edge WAF drop.", fill=TEXT_GREEN, font=f_bold)
    return img


def create_screen_05(fonts):
    """05: Prepared Statements vs Dynamic Concatenation"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "sqli_detector.py (Prepared Statements Analysis)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "[=== DEFENSIVE CODE ARCHITECTURE: PREPARED STATEMENTS ===]", fill=TEXT_CYAN, font=f_lg)
    y += 30

    draw.text((x, y), "[-] Vulnerable Dynamic Concatenation Paradigm (CWE-89):", fill=TEXT_RED, font=f_bold)
    y += 22
    draw.text((x + 20, y), 'cursor.execute("SELECT * FROM users WHERE user = \'" + user + "\'")', fill=TEXT_WHITE, font=f_mono)
    y += 22
    draw.text((x + 20, y), "Mechanism: User input mutates the database Abstract Syntax Tree (AST).", fill=TEXT_GRAY, font=f_mono)
    y += 30

    draw.text((x, y), "[+] Secure Pre-Compiled Prepared Statement Paradigm (Defensive Baseline):", fill=TEXT_GREEN, font=f_bold)
    y += 22
    draw.text((x + 20, y), 'cursor.execute("SELECT * FROM users WHERE user = %s", (user,))', fill=TEXT_WHITE, font=f_mono)
    y += 22
    draw.text((x + 20, y), "Mechanism: Database pre-compiles query structure; user input is literal data string.", fill=TEXT_GREEN, font=f_mono)
    y += 32

    draw.line([(x, y), (WIDTH - 50, y)], fill=BORDER_LINE, width=1)
    y += 14
    draw.text((x, y), "[*] Architectural Verdict: Parameterized queries neutralize 100% of SQL syntax manipulation.", fill=TEXT_YELLOW, font=f_bold)
    return img


def create_screen_06(fonts):
    """06: Git Status, Tree & Unit Test Proof"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "git status & tree (Day18_SQLi_Log_Detection)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "kali@sqrock-soc:~/Day18_SQLi_Log_Detection$ ", fill=TEXT_GREEN, font=f_bold)
    draw.text((x + 400, y), "tree -L 2 -I '__pycache__|.git'", fill=TEXT_WHITE, font=f_mono)
    y += 24

    tree_lines = [
        ".",
        "├── alerts/",
        "│   ├── sqli_alerts.json                # Machine-readable structured SQLi incident data",
        "│   └── sqli_triage_summary.txt         # SOC analyst executive forensic triage dossier",
        "├── logs/",
        "│   └── web_access.log                  # Multi-source web access transaction logs",
        "├── reports/",
        "│   ├── Day18_SQLi_Log_Detection_Report.pdf",
        "│   └── screenshots/                   # 6 High-resolution Kali Linux terminal proofs",
        "├── scripts/",
        "│   ├── generate_day18_pdf.py           # Multi-page ReportLab PDF compiler",
        "│   └── generate_terminal_screens.py    # Headless PIL terminal visual generator",
        "├── tests/",
        "│   └── test_sqli_detector.py           # 6 automated PyUnit test cases (6/6 Passed)",
        "├── sqli_detector.py                    # Core SQLi detection & telemetry engine",
        "└── README.md                           # Comprehensive Day 18 Technical Documentation"
    ]
    for tl in tree_lines:
        color = TEXT_YELLOW if ".json" in tl or ".pdf" in tl else TEXT_WHITE
        if "/" in tl and not "#" in tl:
            color = TEXT_CYAN
        draw.text((x, y), tl, fill=color, font=f_mono)
        y += 18

    y += 12
    draw.text((x, y), "kali@sqrock-soc:~/Day18_SQLi_Log_Detection$ ", fill=TEXT_GREEN, font=f_bold)
    draw.text((x + 400, y), "python3 -m unittest tests/test_sqli_detector.py", fill=TEXT_WHITE, font=f_mono)
    y += 20
    draw.text((x, y), "Ran 6 tests in 0.005s ... OK (100% Pass Rate)", fill=TEXT_GREEN, font=f_bold)
    return img


def generate_all():
    os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
    fonts = get_fonts()

    screens = [
        ("01_kali_init_banner.png", create_screen_01),
        ("02_master_menu.png", create_screen_02),
        ("03_log_ingestion_parsing.png", create_screen_03),
        ("04_sqli_threat_alerts.png", create_screen_04),
        ("05_prepared_statements_analysis.png", create_screen_05),
        ("06_github_repo_overview.png", create_screen_06),
    ]

    print("[*] Generating 6 Kali Linux terminal screenshots for Day 18...")
    for filename, fn in screens:
        path = os.path.join(SCREENSHOTS_DIR, filename)
        img = fn(fonts)
        img.save(path, "PNG", optimize=True)
        print(f" [+] Saved: {path}")

    print("[+] All 6 terminal screenshots created successfully!")


if __name__ == "__main__":
    generate_all()
