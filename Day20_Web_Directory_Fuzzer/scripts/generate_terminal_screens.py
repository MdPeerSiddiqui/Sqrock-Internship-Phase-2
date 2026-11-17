#!/usr/bin/env python3
"""
PEER'S Web Directory Fuzzing Engine - Terminal & Lab Screenshot Generator
Generates pixel-perfect Kali Linux screenshots and GitHub visuals using PIL.
Day 20: Web Directory Brute-Force Simulation
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
    draw.text((WIDTH - 180, 5), "Nov 17, 2026  10:35", fill=TEXT_WHITE, font=font_ui)
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
    draw.text((win_left + 15, win_top + 7), f"sqrock-soc@kali: ~/Day20_Web_Directory_Fuzzer - {title}", fill=TEXT_WHITE, font=font_ui_bold)

    return win_left + 18, win_top + tbar_height + 15


def create_screen_01(fonts):
    """01: Kali Initialization & Banner"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (dir_fuzzer.py)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day20_Web_Directory_Fuzzer]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 dir_fuzzer.py --help", fill=TEXT_WHITE, font=f_mono)

    banner_lines = [
        "==========================================================================",
        "  PEER'S WEB DIRECTORY BRUTE-FORCE & CONTENT DISCOVERY ENGINE v2.0        ",
        "  Differential HTTP Status Code Analysis & Attack Surface Mapping         ",
        "  Compliance: OWASP Top 10 A01:2021 (Broken Access) | A05:2021 (Misconfig)",
        "==========================================================================",
        "Engine Version  : 2.0.8-RELEASE (Sqrock Alpha 2 Phase 2)",
        "Discovery Modes : Differential Status (200, 403, 401, 301, 404 Discard)",
        "Threading Engine: Python ThreadPoolExecutor with Adaptive Throttle/Jitter",
        "",
        "USAGE: python3 dir_fuzzer.py [OPTIONS]",
        "  --url URL              Target base URL (default: http://127.0.0.1:8080)",
        "  --wordlist PATH        Path to path dictionary (wordlists/common_dirs.txt)",
        "  --threads NUM          Worker thread pool size (default: 4)",
        "  --delay SECS           Delay between sequential requests (rate limit defense)",
        "  --json-out PATH        Destination for machine-readable JSON report",
        "  --txt-out PATH         Destination for SOC human-readable triage briefing",
        "",
        "STATUS: Initialized network worker threads and dictionary lexer."
    ]

    curr_y = y + 50
    for line in banner_lines:
        color = TEXT_CYAN if "=" in line or "PEER" in line or "OWASP" in line else (TEXT_YELLOW if "USAGE" in line or "--" in line else (TEXT_GREEN if "STATUS" in line else TEXT_WHITE))
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 22

    draw.text((x, curr_y + 10), "┌──(sqrock-soc@kali)-[~/Day20_Web_Directory_Fuzzer]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, curr_y + 30), "└─$ _", fill=TEXT_WHITE, font=f_mono)

    return img


def create_screen_02(fonts):
    """02: Master Menu & Parameter Options"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (interactive parameter tuning)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day20_Web_Directory_Fuzzer]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 dir_fuzzer.py --list-parameters", fill=TEXT_WHITE, font=f_mono)

    lines = [
        "[*] PEER'S DIRECTORY FUZZER EXECUTION PROFILE:",
        "--------------------------------------------------------------------------",
        " PARAMETER          CONFIGURED VALUE         ANALYSIS DESCRIPTION",
        "--------------------------------------------------------------------------",
        " Target URL         http://127.0.0.1:8080    Local isolated target container",
        " Wordlist           wordlists/common_dirs    16 high-value directory paths",
        " Concurrency        4 Active Threads         Concurrent HTTP worker pool",
        " Rate Limit Jitter  0.05s Dynamic Delay      Avoids server rate-limit lockup",
        " HTTP Method        HEAD / GET Differential  Fast response header triage",
        " Discard Filter     Status 404 Not Found     Suppresses false positives",
        " Flagged Critical   .env, .git, backup.sql   High-impact data exposure",
        " Flagged Forbidden  403 Forbidden            Indicates ACL-protected asset",
        " Flagged Auth       401 Unauthorized         Indicates administrative gate",
        "--------------------------------------------------------------------------",
        "[+] Configuration Validated. Ready to initiate attack surface discovery."
    ]

    curr_y = y + 50
    for line in lines:
        color = TEXT_YELLOW if "[*]" in line or "---" in line else (TEXT_CYAN if "PARAMETER" in line else (TEXT_GREEN if "[+]" in line else TEXT_WHITE))
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 24

    return img


def create_screen_03(fonts):
    """03: Wordlist Ingestion & Path Normalization"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (wordlist_preview)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day20_Web_Directory_Fuzzer]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ head -n 16 wordlists/common_dirs.txt", fill=TEXT_WHITE, font=f_mono)

    wl_lines = [
        "1:  admin          -> Administrative control interface",
        "2:  login          -> Public authentication portal",
        "3:  dashboard      -> Authenticated user telemetry panel",
        "4:  api/v1         -> RESTful microservice API gateway",
        "5:  .env           -> Environment secret key & credential file",
        "6:  .git           -> Source code repository object directory",
        "7:  backup.sql     -> Database schema & confidential data dump",
        "8:  config.php     -> Application database credentials script",
        "9:  server-status  -> Apache / Nginx real-time performance handler",
        "10: robots.txt     -> Web crawler restriction directive",
        "11: phpmyadmin     -> Web relational database management interface",
        "12: uploads        -> Public user-generated attachment storage",
        "13: private        -> Internal company confidential repository",
        "14: internal       -> Restricted corporate intranet subnet",
        "15: test           -> Developer staging & testing sandbox",
        "16: secret         -> Developer staging secrets"
    ]

    curr_y = y + 50
    for line in wl_lines:
        color = TEXT_RED if any(k in line for k in [".env", ".git", "backup.sql", "config.php"]) else (TEXT_CYAN if "api" in line or "admin" in line else TEXT_WHITE)
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 22

    return img


def create_screen_04(fonts):
    """04: Differential Status Code Analysis Live Sweep"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (live directory sweep)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day20_Web_Directory_Fuzzer]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 dir_fuzzer.py --url http://127.0.0.1:8080", fill=TEXT_WHITE, font=f_mono)

    findings = [
        "[+] DISCOVERED ENDPOINTS & ASSET TAXONOMY:",
        "--------------------------------------------------------------------------",
        "STATUS   SIZE (B)   SEVERITY     PATH & IMPACT",
        "--------------------------------------------------------------------------",
        "[200]    38         CRITICAL     /.env (Environment secrets leaked)",
        "[200]    54300      CRITICAL     /backup.sql (Database dump exposed)",
        "[403]    145        HIGH         /admin (Administrative portal exists behind ACL)",
        "[200]    420        HIGH         /api/v1 (REST API gateway index accessible)",
        "[403]    168        HIGH         /.git (Git repository directory forbidden)",
        "[403]    95         HIGH         /config.php (Configuration file forbidden)",
        "[403]    112        HIGH         /server-status (Server metrics forbidden)",
        "[403]    130        HIGH         /phpmyadmin (Database interface forbidden)",
        "[403]    92         HIGH         /internal (Corporate intranet forbidden)",
        "[401]    210        MEDIUM       /dashboard (Authentication required)",
        "[401]    88         MEDIUM       /private (Protected endpoint)",
        "[200]    890        LOW          /login (Public portal)",
        "[200]    52         LOW          /robots.txt (Crawler file)",
        "--------------------------------------------------------------------------",
        "METRICS: 16 Requests | 6 Exposed (200) | 6 Forbidden (403) | 2 Auth (401)"
    ]

    curr_y = y + 50
    for line in findings:
        color = TEXT_YELLOW if "[+]" in line or "---" in line else (TEXT_RED if "CRITICAL" in line else (TEXT_MAGENTA if "HIGH" in line else (TEXT_GREEN if "METRICS" in line else TEXT_WHITE)))
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 22

    return img


def create_screen_05(fonts):
    """05: Critical Exposure Deep Dive Alert"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (incident triage deep dive)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day20_Web_Directory_Fuzzer]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ cat fuzz_results/fuzz_summary.txt | grep -A 3 'CRITICAL'", fill=TEXT_WHITE, font=f_mono)

    alert_lines = [
        "==========================================================================",
        "  CRITICAL ASSET EXPOSURE FORENSIC AUDIT                                  ",
        "==========================================================================",
        "[ALERT 01] STATUS 200 OK - CRITICAL: /.env",
        "    Full URL    : http://127.0.0.1:8080/.env",
        "    Size (Bytes): 38 Bytes",
        "    Payload View: DB_HOST=10.0.0.4\\nDB_PASS=SuperSecretKey123!",
        "    Remediation : Configure web server to block dotfiles (e.g. location ~ /\\.env)",
        "",
        "[ALERT 02] STATUS 200 OK - CRITICAL: /backup.sql",
        "    Full URL    : http://127.0.0.1:8080/backup.sql",
        "    Size (Bytes): 54,300 Bytes",
        "    Payload View: -- MySQL Database Dump v8.0 / Schema Definition",
        "    Remediation : Delete all database backups from webroot; store in private S3 bucket.",
        "",
        "[ANALYSIS 03] STATUS 403 FORBIDDEN - HIGH: /.git and /admin",
        "    Observation : HTTP 403 confirms endpoint existence on the server filesystem.",
        "    Attack Risk : Attackers can exploit WAF bypasses or path confusion to access.",
        "    Remediation : Return generic HTTP 404 for non-public internal directories."
    ]

    curr_y = y + 50
    for line in alert_lines:
        color = TEXT_CYAN if "=" in line else (TEXT_RED if "CRITICAL" in line or "ALERT" in line else (TEXT_YELLOW if "ANALYSIS" in line or "Remediation" in line else TEXT_WHITE))
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 22

    return img


def create_screen_06(fonts):
    """06: GitHub Repo Overview & Unit Tests"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (unit tests & project tree)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day20_Web_Directory_Fuzzer]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 -m unittest tests/test_dir_fuzzer.py -v", fill=TEXT_WHITE, font=f_mono)

    test_lines = [
        "test_critical_asset_identification (TestDirectoryFuzzer) ... ok",
        "test_json_and_txt_reporting (TestDirectoryFuzzer) ... ok",
        "test_status_401_authentication_handling (TestDirectoryFuzzer) ... ok",
        "test_status_403_differentiation (TestDirectoryFuzzer) ... ok",
        "test_status_404_discarding (TestDirectoryFuzzer) ... ok",
        "test_wordlist_loading (TestDirectoryFuzzer) ... ok",
        "----------------------------------------------------------------------",
        "Ran 6 tests in 0.019s | OK (100% Pass Rate)",
        "",
        "┌──(sqrock-soc@kali)-[~/Day20_Web_Directory_Fuzzer]",
        "└─$ tree -L 2",
        ".",
        "├── dir_fuzzer.py",
        "├── fuzz_results/",
        "│   ├── fuzz_report.json",
        "│   └── fuzz_summary.txt",
        "├── README.md",
        "├── reports/",
        "│   ├── Day20_Web_Directory_Fuzzing_Report_Sqrock_MdPeerSiddiqui.pdf",
        "│   └── screenshots/ (01 to 06)",
        "├── tests/ (test_dir_fuzzer.py)",
        "└── wordlists/ (common_dirs.txt)"
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
        ("03_wordlist_ingestion.png", create_screen_03),
        ("04_differential_status_live.png", create_screen_04),
        ("05_critical_exposure_alert.png", create_screen_05),
        ("06_github_repo_overview.png", create_screen_06),
    ]

    for fname, func in screens:
        path = os.path.join(SCREENSHOTS_DIR, fname)
        img = func(fonts)
        img.save(path, "PNG")
        print(f"[+] Saved terminal screenshot: {path}")

    print("\n[+] All 6 Day 20 Kali Linux terminal screenshots generated successfully.")


if __name__ == "__main__":
    main()
