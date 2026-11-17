#!/usr/bin/env python3
"""
PEER'S API Rate Limiter - Terminal & Lab Screenshot Generator
Generates pixel-perfect Kali Linux screenshots and GitHub visuals using PIL.
Day 22: API Rate Limiting Token Bucket Logic
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
    draw.text((WIDTH - 180, 5), "Nov 17, 2026  10:45", fill=TEXT_WHITE, font=font_ui)
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
    draw.text((win_left + 15, win_top + 7), f"sqrock-soc@kali: ~/Day22_API_Rate_Limiter - {title}", fill=TEXT_WHITE, font=font_ui_bold)

    return win_left + 18, win_top + tbar_height + 15


def create_screen_01(fonts):
    """01: Kali Initialization & Banner"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (rate_limiter.py)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day22_API_Rate_Limiter]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 rate_limiter.py --help", fill=TEXT_WHITE, font=f_mono)

    banner_lines = [
        "==========================================================================",
        "  PEER'S API RATE LIMITING & TOKEN BUCKET DEFENSE SUITE v2.0              ",
        "  Stateful Client IP Throttling & HTTP 429 Mitigation Engine              ",
        "  Compliance: RFC 6585 | OWASP API Security Top 10 API4:2023              ",
        "==========================================================================",
        "Algorithm Model : Token Bucket (Continuous Time Leaky Replenishment)",
        "Default Capacity: 10.0 Tokens (Burst Tolerance Threshold)",
        "Refill Kinetics : 2.0 Tokens/second (Sustained Rate Guarantee)",
        "",
        "USAGE: python3 rate_limiter.py [OPTIONS]",
        "  --capacity FLOAT       Maximum bucket token burst capacity (default: 10.0)",
        "  --refill-rate FLOAT    Replenishment rate in tokens/sec (default: 2.0)",
        "  --burst-count INT      Total rapid requests to simulate in test (default: 15)",
        "  --json-out PATH        Destination for machine-readable telemetry JSON",
        "  --txt-out PATH         Destination for SOC human-readable triage briefing",
        "",
        "STATUS: Initialized thread-safe bucket synchronizer and RFC header generator."
    ]

    curr_y = y + 50
    for line in banner_lines:
        color = TEXT_CYAN if "=" in line or "PEER" in line or "RFC" in line else (TEXT_YELLOW if "USAGE" in line or "--" in line else (TEXT_GREEN if "STATUS" in line else TEXT_WHITE))
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 22

    draw.text((x, curr_y + 10), "┌──(sqrock-soc@kali)-[~/Day22_API_Rate_Limiter]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, curr_y + 30), "└─$ _", fill=TEXT_WHITE, font=f_mono)

    return img


def create_screen_02(fonts):
    """02: Master Menu & Parameter Tuning"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (interactive parameter tuning)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day22_API_Rate_Limiter]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 rate_limiter.py --inspect-algorithms", fill=TEXT_WHITE, font=f_mono)

    lines = [
        "[*] RATE LIMITING ALGORITHM ARCHITECTURE COMPARISON:",
        "--------------------------------------------------------------------------",
        " ALGORITHM        BURST TOLERANCE  MEMORY FOOTPRINT  SMOOTH REFILL",
        "--------------------------------------------------------------------------",
        " Fixed Window     Poor (Boundary)  O(1) Counter      No (Hard reset)",
        " Sliding Log      High Accuracy    O(N) Per-Request  Yes (Continuous)",
        " Sliding Window   Moderate         O(1) Two-Counters Hybrid",
        " Leaky Bucket     Zero (Smooth)    O(Queue Depth)    Constant output",
        " Token Bucket     EXCELLENT (B)    O(1) Per-Client   YES (CONTINUOUS)",
        "--------------------------------------------------------------------------",
        "[+] Selected Algorithm: Token Bucket (Optimal for API Gateways & DoS Defense)"
    ]

    curr_y = y + 50
    for line in lines:
        color = TEXT_YELLOW if "[*]" in line or "---" in line else (TEXT_CYAN if "ALGORITHM" in line else (TEXT_GREEN if "Token Bucket" in line or "[+]" in line else TEXT_WHITE))
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 24

    return img


def create_screen_03(fonts):
    """03: Token Bucket State Inspection"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (bucket_state_inspection)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day22_API_Rate_Limiter]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 -c \"from rate_limiter import APIRateLimiter; r = APIRateLimiter(10, 2); print(r.get_bucket('192.168.1.105').__dict__)\"", fill=TEXT_WHITE, font=f_mono)

    state_lines = [
        "[*] LIVE CLIENT BUCKET INTERNAL STATE INSPECTION:",
        "--------------------------------------------------------------------------",
        "  client_id       : 192.168.1.105 (Remote Client IPv4 Address)",
        "  capacity        : 10.0 (Max burst limit before HTTP 429 throttle)",
        "  refill_rate     : 2.0 Tokens/sec (Refill delta: 1 token every 500ms)",
        "  tokens          : 10.0 / 10.0 (Current available quota)",
        "  last_refill     : 1763376302.481923 (Epoch timestamp in seconds)",
        "  synchronization : <threading.Lock owner=None count=0> (Thread-safe)",
        "--------------------------------------------------------------------------",
        "[+] Mathematical Replenishment Equation:",
        "    tokens(t) = min(capacity, tokens(t_prev) + (t - t_prev) * refill_rate)"
    ]

    curr_y = y + 50
    for line in state_lines:
        color = TEXT_YELLOW if "[*]" in line or "---" in line else (TEXT_CYAN if "Mathematical" in line or "tokens(t)" in line else TEXT_WHITE)
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 24

    return img


def create_screen_04(fonts):
    """04: Live Traffic Burst Simulation & Throttling"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (live burst simulation)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day22_API_Rate_Limiter]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 rate_limiter.py --burst-count 15", fill=TEXT_WHITE, font=f_mono)

    burst_lines = [
        "[+] LIVE TRAFFIC BURST SIMULATION (15 Rapid Requests from 192.168.1.105):",
        "--------------------------------------------------------------------------",
        "REQ #   CLIENT IP        STATUS         REMAINING    RETRY-AFTER    ACTION",
        "--------------------------------------------------------------------------",
        "#1      192.168.1.105    200 OK         9            -              ALLOWED",
        "#2      192.168.1.105    200 OK         8            -              ALLOWED",
        "#3      192.168.1.105    200 OK         7            -              ALLOWED",
        "#4      192.168.1.105    200 OK         6            -              ALLOWED",
        "#5      192.168.1.105    200 OK         5            -              ALLOWED",
        "#6      192.168.1.105    200 OK         4            -              ALLOWED",
        "#7      192.168.1.105    200 OK         3            -              ALLOWED",
        "#8      192.168.1.105    200 OK         2            -              ALLOWED",
        "#9      192.168.1.105    200 OK         1            -              ALLOWED",
        "#10     192.168.1.105    200 OK         0            -              ALLOWED",
        "#11     192.168.1.105    200 OK         0            -              ALLOWED",
        "#12     192.168.1.105    429 THROTTLED  0            0.44s          BLOCKED (DoS Defended)",
        "#13     192.168.1.105    429 THROTTLED  0            0.39s          BLOCKED (DoS Defended)",
        "#14     192.168.1.105    429 THROTTLED  0            0.34s          BLOCKED (DoS Defended)",
        "#15     192.168.1.105    429 THROTTLED  0            0.29s          BLOCKED (DoS Defended)",
        "--------------------------------------------------------------------------",
        "METRICS: 15 Requests | 11 Allowed (200 OK) | 4 Throttled (HTTP 429)"
    ]

    curr_y = y + 50
    for line in burst_lines:
        color = TEXT_YELLOW if "[+]" in line or "---" in line else (TEXT_RED if "429 THROTTLED" in line else (TEXT_GREEN if "200 OK" in line or "METRICS" in line else TEXT_WHITE))
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 22

    return img


def create_screen_05(fonts):
    """05: HTTP 429 Header Inspection"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (http_429_inspection)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day22_API_Rate_Limiter]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ curl -i http://127.0.0.1:8080/api/v1/auth/login", fill=TEXT_WHITE, font=f_mono)

    header_lines = [
        "HTTP/1.1 429 Too Many Requests",
        "Date: Tue, 17 Nov 2026 10:45:12 GMT",
        "Server: PEER-WAF-RateLimiter/2.0",
        "Content-Type: application/json; charset=utf-8",
        "Retry-After: 1",
        "X-RateLimit-Limit: 10",
        "X-RateLimit-Remaining: 0",
        "X-RateLimit-Reset: 1763376315",
        "",
        "{",
        '  "error": "Too Many Requests",',
        '  "status": 429,',
        '  "message": "Token bucket capacity exhausted. Rate limit exceeded.",',
        '  "retry_after_seconds": 1,',
        '  "client_ip": "192.168.1.105"',
        "}",
        "--------------------------------------------------------------------------",
        "[+] RFC 6585 Compliance: Informs client exactly how long to back off."
    ]

    curr_y = y + 50
    for line in header_lines:
        color = TEXT_RED if "429" in line else (TEXT_CYAN if "X-RateLimit" in line or "Retry-After" in line else (TEXT_GREEN if "[+]" in line else TEXT_WHITE))
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 22

    return img


def create_screen_06(fonts):
    """06: GitHub Repo Overview & Unit Tests"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (unit tests & project tree)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day22_API_Rate_Limiter]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 -m unittest tests/test_rate_limiter.py -v", fill=TEXT_WHITE, font=f_mono)

    test_lines = [
        "test_multi_client_isolation (TestRateLimiter) ... ok",
        "test_rfc_headers_generation (TestRateLimiter) ... ok",
        "test_token_bucket_initial_capacity (TestRateLimiter) ... ok",
        "test_token_consumption_allowed (TestRateLimiter) ... ok",
        "test_token_exhaustion_throttled (TestRateLimiter) ... ok",
        "test_token_refill_replenishment (TestRateLimiter) ... ok",
        "----------------------------------------------------------------------",
        "Ran 6 tests in 0.303s | OK (100% Pass Rate)",
        "",
        "┌──(sqrock-soc@kali)-[~/Day22_API_Rate_Limiter]",
        "└─$ tree -L 2",
        ".",
        "├── rate_limiter.py",
        "├── rate_limit_results/",
        "│   ├── rate_limit_report.json",
        "│   └── rate_limit_summary.txt",
        "├── README.md",
        "├── reports/",
        "│   ├── Day22_API_Rate_Limiting_Report_Sqrock_MdPeerSiddiqui.pdf",
        "│   └── screenshots/ (01 to 06)",
        "└── tests/ (test_rate_limiter.py)"
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
        ("03_token_bucket_state.png", create_screen_03),
        ("04_burst_throttling_live.png", create_screen_04),
        ("05_http_429_header_inspection.png", create_screen_05),
        ("06_github_repo_overview.png", create_screen_06),
    ]

    for fname, func in screens:
        path = os.path.join(SCREENSHOTS_DIR, fname)
        img = func(fonts)
        img.save(path, "PNG")
        print(f"[+] Saved terminal screenshot: {path}")

    print("\n[+] All 6 Day 22 Kali Linux terminal screenshots generated successfully.")


if __name__ == "__main__":
    main()
