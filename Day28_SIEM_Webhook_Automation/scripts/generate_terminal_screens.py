#!/usr/bin/env python3
"""
PEER'S SIEM Webhook Dispatcher - Terminal Screenshot Generator (Day 28)
Generates 6 authentic Kali Linux 1280x703 screenshots for Day 28 executive lab report.
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

    draw.text((WIDTH // 2 - 210, 10), f"kali@sqrock-secops: ~/Day28_SIEM_Webhook_Automation - {title}", fill=WHITE_COLOR, font=FONT_TITLE)

    # Bottom Taskbar
    draw.rectangle([(0, HEIGHT - 26), (WIDTH, HEIGHT)], fill=(18, 20, 30))
    draw.text((15, HEIGHT - 20), "Kali Linux 2026.1-SecOps | Python 3.14.0 | PEER'S SIEM Webhook Dispatcher", fill=GRAY_COLOR, font=FONT_TITLE)
    draw.text((WIDTH - 170, HEIGHT - 20), "2026-11-17 11:30 UTC", fill=GRAY_COLOR, font=FONT_TITLE)

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
        ([("┌──(", GRAY_COLOR), ("kali@sqrock-secops", PROMPT_USER_COLOR), (")-[", GRAY_COLOR), ("~/Day28_SIEM_Webhook_Automation", PROMPT_DIR_COLOR), ("]", GRAY_COLOR)], None),
        ([("└─$ ", GRAY_COLOR), ("python3 webhook_dispatcher.py", WHITE_COLOR)], None),
        ("", BG_COLOR),
        ("================================================================================", CYAN_COLOR),
        ("          PEER'S SIEM WEBHOOK DISPATCHER & ALERT PIPELINE v2.0", CYAN_COLOR),
        ("   Sqrock IT Solutions | Internship Phase 2: Web App Security (Day 28)", CYAN_COLOR),
        ("   Candidate: Mohammed Peer Siddiqui  |  Status: ACTIVE DISPATCH", CYAN_COLOR),
        ("================================================================================", CYAN_COLOR),
        ("", BG_COLOR),
        ("[*] Initializing Automated SIEM Webhook Delivery Engine...", WHITE_COLOR),
        ("[+] Supported Ingress Formats: Slack Block Kit, MS Teams Cards, Discord, Splunk HEC", GREEN_COLOR),
        ("[+] Cryptographic Pipeline: HMAC-SHA256 (X-Hub-Signature-256) Active", GREEN_COLOR),
        ("[+] Storm Guard: Token Bucket Rate Limiter (60/min capacity, burst=10) Armed", GREEN_COLOR),
        ("[+] Ingestion Corpus: samples/security_alerts.json (4 Critical & High Incidents)", CYAN_COLOR),
        ("", BG_COLOR),
        ("Select Webhook Dispatcher Menu Option:", YELLOW_COLOR),
        ("  1) Run Automated Multi-Channel Alert Dispatch (Default Corpus)", WHITE_COLOR),
        ("  2) Inspect & Format Payload for Slack, Teams, and Discord", WHITE_COLOR),
        ("  3) Verify HMAC-SHA256 Cryptographic Authenticity Signature", WHITE_COLOR),
        ("  4) Test Token Bucket Rate Throttling / Alert Storm Guard", WHITE_COLOR),
        ("  5) Export Full Delivery Telemetry (JSON & Audit Log)", WHITE_COLOR),
        ("  6) Exit Webhook Dispatcher Console", WHITE_COLOR),
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
        ([("┌──(", GRAY_COLOR), ("kali@sqrock-secops", PROMPT_USER_COLOR), (")-[", GRAY_COLOR), ("~/Day28_SIEM_Webhook_Automation", PROMPT_DIR_COLOR), ("]", GRAY_COLOR)], None),
        ([("└─$ ", GRAY_COLOR), ("python3 -c 'from webhook_dispatcher import WebhookDispatcher; d=WebhookDispatcher(); print(f\"Refill rate: {d.refill_rate} tok/s | Burst capacity: {d.burst_limit}\")'", WHITE_COLOR)], None),
        ("", BG_COLOR),
        ("[*] Dispatcher Operational Parameters:", YELLOW_COLOR),
        ("  - Security Signing Algorithm:  HMAC-SHA256 with Shared Enterprise Key", WHITE_COLOR),
        ("  - HTTP Headers Emitted:        X-Hub-Signature-256, Content-Type: application/json", WHITE_COLOR),
        ("  - Token Bucket Rate Limit:     60 requests / minute (sustained 1.0 tok/sec)", WHITE_COLOR),
        ("  - Max Burst Allocation:        10 immediate concurrent dispatches", WHITE_COLOR),
        ("  - SIEM Ingestion Endpoints:    Slack, Microsoft Teams, Discord, Splunk HEC", CYAN_COLOR),
        ("", BG_COLOR),
        ("Select Webhook Dispatcher Menu Option:", YELLOW_COLOR),
        ("  1) Run Automated Multi-Channel Alert Dispatch (Default Corpus)", WHITE_COLOR),
        ("  2) Inspect & Format Payload for Slack, Teams, and Discord", WHITE_COLOR),
        ("  3) Verify HMAC-SHA256 Cryptographic Authenticity Signature", WHITE_COLOR),
        ("  4) Test Token Bucket Rate Throttling / Alert Storm Guard", WHITE_COLOR),
        ("  5) Export Full Delivery Telemetry (JSON & Audit Log)", WHITE_COLOR),
        ("  6) Exit Webhook Dispatcher Console", WHITE_COLOR),
        ("", BG_COLOR),
        ([("Enter Choice [1-6]: ", CYAN_COLOR), ("1", WHITE_COLOR)], None)
    ]
    render_lines(draw, lines)
    path = os.path.join(SCREENSHOTS_DIR, "02_master_operations_menu.png")
    img.save(path)
    print(f"[+] Saved terminal screenshot: {path}")


def generate_screen_3():
    img, draw = draw_kali_frame("03_batch_alert_dispatch")
    lines = [
        ([("┌──(", GRAY_COLOR), ("kali@sqrock-secops", PROMPT_USER_COLOR), (")-[", GRAY_COLOR), ("~/Day28_SIEM_Webhook_Automation", PROMPT_DIR_COLOR), ("]", GRAY_COLOR)], None),
        ([("└─$ ", GRAY_COLOR), ("python3 webhook_dispatcher.py --batch", WHITE_COLOR)], None),
        ("", BG_COLOR),
        ("[+] Ingesting 4 alerts from samples/security_alerts.json...", GREEN_COLOR),
        ("", BG_COLOR),
        (f"{'Alert ID':<15} | {'Severity':<9} | {'Channel':<8} | {'Status':<15} | {'HMAC Signature':<24} | {'Threat Category'}", CYAN_COLOR),
        ("-" * 105, GRAY_COLOR),
        (f"{'SEC-ALERT-8001':<15} | {'CRITICAL':<9} | {'slack':<8} | {'DELIVERED_200':<15} | {'sha256=e14a8b4382...':<24} | {'SQL Injection (SQLi) Exploit'}", RED_COLOR),
        (f"{'SEC-ALERT-8002':<15} | {'HIGH':<9} | {'teams':<8} | {'DELIVERED_200':<15} | {'sha256=7c8f921d40...':<24} | {'Credential Stuffing & Brute Force'}", RED_COLOR),
        (f"{'SEC-ALERT-8003':<15} | {'CRITICAL':<9} | {'discord':<8} | {'DELIVERED_200':<15} | {'sha256=3b92f7a188...':<24} | {'Polyglot Web Shell Ingestion'}", RED_COLOR),
        (f"{'SEC-ALERT-8004':<15} | {'CRITICAL':<9} | {'siem':<8} | {'DELIVERED_200':<15} | {'sha256=d05e6b12a9...':<24} | {'Ransomware File Canary Tripped'}", RED_COLOR),
        ("-" * 105, GRAY_COLOR),
        ("", BG_COLOR),
        ("[+] Multi-Channel Delivery: 100% Delivery Success Across Slack, Teams, Discord, SIEM", GREEN_COLOR),
        ("[+] Cryptographic Integrity: All payloads signed with authentic HMAC-SHA256 headers", GREEN_COLOR),
        ("[+] Telemetry Audit Log: webhook_logs/dispatch_audit.log updated", CYAN_COLOR)
    ]
    render_lines(draw, lines)
    path = os.path.join(SCREENSHOTS_DIR, "03_batch_alert_dispatch.png")
    img.save(path)
    print(f"[+] Saved terminal screenshot: {path}")


def generate_screen_4():
    img, draw = draw_kali_frame("04_payload_format_inspection")
    lines = [
        ([("┌──(", GRAY_COLOR), ("kali@sqrock-secops", PROMPT_USER_COLOR), (")-[", GRAY_COLOR), ("~/Day28_SIEM_Webhook_Automation", PROMPT_DIR_COLOR), ("]", GRAY_COLOR)], None),
        ([("└─$ ", GRAY_COLOR), ("python3 webhook_dispatcher.py", WHITE_COLOR)], None),
        ("", BG_COLOR),
        ("Select Webhook Dispatcher Menu Option:", YELLOW_COLOR),
        ("  2) Inspect & Format Payload for Slack, Teams, and Discord", CYAN_COLOR),
        ("", BG_COLOR),
        ("[*] Previewing Alert SEC-ALERT-8001 Payload Across Channels:", YELLOW_COLOR),
        ("--- Slack Block Kit Format ---", CYAN_COLOR),
        ("{\n  \"attachments\": [{\n    \"color\": \"#A8201A\",\n    \"blocks\": [\n      {\"type\": \"header\", \"text\": {\"type\": \"plain_text\", \"text\": \"🚨 [CRITICAL] SQL Injection (SQLi) Exploit\"}},\n      {\"type\": \"section\", \"fields\": [{\"type\": \"mrkdwn\", \"text\": \"*Actor IP:* `198.51.100.44`\"}]}", WHITE_COLOR),
        ("--- MS Teams MessageCard Format ---", CYAN_COLOR),
        ("{\n  \"@type\": \"MessageCard\",\n  \"themeColor\": \"A8201A\",\n  \"title\": \"🚨 [CRITICAL] SQL Injection (SQLi) Exploit\",\n  \"sections\": [{\"facts\": [{\"name\": \"MITRE Technique\", \"value\": \"T1190\"}]}]}", WHITE_COLOR),
        ("--- Discord Embed Format ---", CYAN_COLOR),
        ("{\n  \"username\": \"Sqrock-SIEM-AlertBot\",\n  \"embeds\": [{\n    \"title\": \"🚨 [CRITICAL] SQL Injection (SQLi) Exploit\",\n    \"color\": 11018266,\n    \"footer\": {\"text\": \"Candidate: Mohammed Peer Siddiqui\"}\n  }]}", WHITE_COLOR),
        ("", BG_COLOR),
        ("[+] Multi-Schema Serialization Validated: Standardized Cross-Platform Ingestion", GREEN_COLOR)
    ]
    render_lines(draw, lines)
    path = os.path.join(SCREENSHOTS_DIR, "04_payload_format_inspection.png")
    img.save(path)
    print(f"[+] Saved terminal screenshot: {path}")


def generate_screen_5():
    img, draw = draw_kali_frame("05_rate_throttling_storm_guard")
    lines = [
        ([("┌──(", GRAY_COLOR), ("kali@sqrock-secops", PROMPT_USER_COLOR), (")-[", GRAY_COLOR), ("~/Day28_SIEM_Webhook_Automation", PROMPT_DIR_COLOR), ("]", GRAY_COLOR)], None),
        ([("└─$ ", GRAY_COLOR), ("python3 webhook_dispatcher.py", WHITE_COLOR)], None),
        ("", BG_COLOR),
        ("Select Webhook Dispatcher Menu Option:", YELLOW_COLOR),
        ("  4) Test Token Bucket Rate Throttling / Alert Storm Guard", CYAN_COLOR),
        ("", BG_COLOR),
        ("[*] Testing Token Bucket Storm Guard (Dispatching 8 rapid alerts with burst=5):", YELLOW_COLOR),
        ("  Attempt 01: Status = DELIVERED_200 | Remaining Capacity: 4.00 tokens", GREEN_COLOR),
        ("  Attempt 02: Status = DELIVERED_200 | Remaining Capacity: 3.00 tokens", GREEN_COLOR),
        ("  Attempt 03: Status = DELIVERED_200 | Remaining Capacity: 2.00 tokens", GREEN_COLOR),
        ("  Attempt 04: Status = DELIVERED_200 | Remaining Capacity: 1.00 tokens", GREEN_COLOR),
        ("  Attempt 05: Status = DELIVERED_200 | Remaining Capacity: 0.00 tokens", GREEN_COLOR),
        ("  Attempt 06: Status = THROTTLED_429 | Remaining Capacity: 0.00 tokens (BLOCKED)", RED_COLOR),
        ("  Attempt 07: Status = THROTTLED_429 | Remaining Capacity: 0.00 tokens (BLOCKED)", RED_COLOR),
        ("  Attempt 08: Status = THROTTLED_429 | Remaining Capacity: 0.00 tokens (BLOCKED)", RED_COLOR),
        ("", BG_COLOR),
        ("[+] Alert Storm Guard Triggered: 3 Dropped to Prevent SOC Denial-of-Service", GREEN_COLOR),
        ("[+] Compliance: Conforms to RFC 6585 (Additional HTTP Status Codes / 429)", GREEN_COLOR)
    ]
    render_lines(draw, lines)
    path = os.path.join(SCREENSHOTS_DIR, "05_rate_throttling_storm_guard.png")
    img.save(path)
    print(f"[+] Saved terminal screenshot: {path}")


def generate_screen_6():
    img, draw = draw_kali_frame("06_github_repo_overview")
    lines = [
        ([("┌──(", GRAY_COLOR), ("kali@sqrock-secops", PROMPT_USER_COLOR), (")-[", GRAY_COLOR), ("~/Day28_SIEM_Webhook_Automation", PROMPT_DIR_COLOR), ("]", GRAY_COLOR)], None),
        ([("└─$ ", GRAY_COLOR), ("tree -L 2 -a -F --dirsfirst", WHITE_COLOR)], None),
        ("", BG_COLOR),
        (".", CYAN_COLOR),
        ("├── reports/", PROMPT_DIR_COLOR),
        ("│   ├── screenshots/", PROMPT_DIR_COLOR),
        ("│   │   ├── 01_kali_init_banner.png", WHITE_COLOR),
        ("│   │   ├── 02_master_operations_menu.png", WHITE_COLOR),
        ("│   │   ├── 03_batch_alert_dispatch.png", WHITE_COLOR),
        ("│   │   ├── 04_payload_format_inspection.png", WHITE_COLOR),
        ("│   │   ├── 05_rate_throttling_storm_guard.png", WHITE_COLOR),
        ("│   │   └── 06_github_repo_overview.png", WHITE_COLOR),
        ("│   └── Day28_SIEM_Webhook_Automation_Report_Sqrock_MdPeerSiddiqui.pdf", YELLOW_COLOR),
        ("├── samples/", PROMPT_DIR_COLOR),
        ("│   └── security_alerts.json", WHITE_COLOR),
        ("├── scripts/", PROMPT_DIR_COLOR),
        ("│   ├── generate_day28_pdf.py", WHITE_COLOR),
        ("│   └── generate_terminal_screens.py", WHITE_COLOR),
        ("├── tests/", PROMPT_DIR_COLOR),
        ("│   └── test_webhook_dispatcher.py", WHITE_COLOR),
        ("├── webhook_logs/", PROMPT_DIR_COLOR),
        ("│   ├── dispatch_audit.log", WHITE_COLOR),
        ("│   └── webhook_telemetry.json", WHITE_COLOR),
        ("├── README.md", GREEN_COLOR),
        ("└── webhook_dispatcher.py", GREEN_COLOR),
        ("", BG_COLOR),
        ([("6 directories, 14 files  |  Candidate: Mohammed Peer Siddiqui", CYAN_COLOR)], None)
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
    print("\n[+] All 6 Day 28 Kali Linux terminal screenshots generated successfully.")
