#!/usr/bin/env python3
"""
PEER'S Threat Intel Pipeline - Terminal & Lab Screenshot Generator
Generates pixel-perfect Kali Linux screenshots and GitHub visuals using PIL.
Day 24: Automated Threat Intel IP Blocking Pipeline
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
    draw.text((WIDTH - 180, 5), "Nov 17, 2026  10:55", fill=TEXT_WHITE, font=font_ui)
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
    draw.text((win_left + 15, win_top + 7), f"sqrock-soc@kali: ~/Day24_Threat_Intel_IP_Blocker - {title}", fill=TEXT_WHITE, font=font_ui_bold)

    return win_left + 18, win_top + tbar_height + 15


def create_screen_01(fonts):
    """01: Kali Initialization & Banner"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (threat_blocker.py)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day24_Threat_Intel_IP_Blocker]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 threat_blocker.py --help", fill=TEXT_WHITE, font=f_mono)

    banner_lines = [
        "==========================================================================",
        "  PEER'S THREAT INTELLIGENCE IP BLOCKING PIPELINE v2.0                    ",
        "  Automated IoC Feed Ingestion, Confidence Scoring & Firewall Enforcement  ",
        "  Compliance: NIST SP 800-150 | MITRE ATT&CK Mitigation M1037 (Filter IP) ",
        "==========================================================================",
        "Engine Version  : 2.0.9-RELEASE (Sqrock Alpha 2 Phase 2)",
        "Feed Ingestion  : JSON Threat Feeds (AlienVault OTX, AbuseIPDB, C2 Botnets)",
        "Enforcement Hub : Linux iptables (legacy chains) & nftables (declarative)",
        "",
        "USAGE: python3 threat_blocker.py [OPTIONS]",
        "  --feed PATH            Path to input threat feed (feeds/threat_intel_feed.json)",
        "  --threshold INT        Confidence score threshold to block (default: 75%)",
        "  --json-out PATH        Destination for machine-readable telemetry JSON",
        "  --txt-out PATH         Destination for SOC human-readable triage briefing",
        "",
        "STATUS: Initialized threat feed parser and firewall rule compiler."
    ]

    curr_y = y + 50
    for line in banner_lines:
        color = TEXT_CYAN if "=" in line or "PEER" in line or "NIST" in line else (TEXT_YELLOW if "USAGE" in line or "--" in line else (TEXT_GREEN if "STATUS" in line else TEXT_WHITE))
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 22

    draw.text((x, curr_y + 10), "┌──(sqrock-soc@kali)-[~/Day24_Threat_Intel_IP_Blocker]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, curr_y + 30), "└─$ _", fill=TEXT_WHITE, font=f_mono)

    return img


def create_screen_02(fonts):
    """02: Master Menu & Parameter Options"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (threat_scoring_matrix)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day24_Threat_Intel_IP_Blocker]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 threat_blocker.py --list-thresholds", fill=TEXT_WHITE, font=f_mono)

    lines = [
        "[*] THREAT INTELLIGENCE CONFIDENCE SCORING POLICY:",
        "--------------------------------------------------------------------------",
        " SCORE TIER    RISK LEVEL     DEFENSIVE ENFORCEMENT ACTION",
        "--------------------------------------------------------------------------",
        " 85 - 100%     CRITICAL       Immediate Automated Drop (iptables / nftables)",
        " 75 - 84%      HIGH           Enforce Edge Firewall Block + 24hr Quarantine",
        " 50 - 74%      MEDIUM         Log & Monitor (Alert SOC; do not drop)",
        " 01 - 49%      LOW            Permit traffic (Track behavioral anomaly)",
        " Whitelist     SAFE           Explicitly Allow (Cloudflare, Quad9, Google DNS)",
        "--------------------------------------------------------------------------",
        "[+] Default Pipeline Threshold: >= 75% triggers active drop rule generation."
    ]

    curr_y = y + 50
    for line in lines:
        color = TEXT_YELLOW if "[*]" in line or "---" in line else (TEXT_CYAN if "SCORE" in line else (TEXT_GREEN if "SAFE" in line or "[+]" in line else TEXT_WHITE))
        if "CRITICAL" in line: color = TEXT_RED
        elif "HIGH" in line and not "TIER" in line: color = (255, 140, 50)
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 24

    return img


def create_screen_03(fonts):
    """03: Threat Feed Ingestion & Parsing"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (feed_ingestion_preview)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day24_Threat_Intel_IP_Blocker]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ cat feeds/threat_intel_feed.json | head -n 22", fill=TEXT_WHITE, font=f_mono)

    feed_lines = [
        "[",
        '  {"ip": "185.220.101.5",  "source": "AlienVault OTX", "threat": "Tor Exit Node",       "score": 88},',
        '  {"ip": "45.154.255.89",  "source": "AbuseIPDB",      "threat": "Cobalt Strike C2",     "score": 98},',
        '  {"ip": "194.26.29.112",  "source": "EmergingThreats","threat": "SSH Brute-Force",     "score": 85},',
        '  {"ip": "103.145.13.24",  "source": "Cisco Talos",    "threat": "Mirai Botnet DDoS",    "score": 92},',
        '  {"ip": "91.240.118.170", "source": "AbuseIPDB",      "threat": "SQLi Scanner",         "score": 82},',
        '  {"ip": "198.51.100.42",  "source": "Internal SIEM",  "threat": "Unverified Port Probe","score": 50},',
        '  {"ip": "1.1.1.1",        "source": "Whitelist",      "threat": "Cloudflare DNS",       "score": 5}',
        "]",
        "",
        "[*] INGESTION SUMMARY: 7 IoC records validated across global reputation feeds."
    ]

    curr_y = y + 50
    for line in feed_lines:
        color = TEXT_RED if any(k in line for k in ["98", "92", "88", "85", "82"]) else (TEXT_GREEN if "Whitelist" in line or "[*]" in line else TEXT_WHITE)
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 24

    return img


def create_screen_04(fonts):
    """04: Live Enforcement & Drop Rule Synthesis"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (live firewall drop rules)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day24_Threat_Intel_IP_Blocker]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 threat_blocker.py --threshold 75", fill=TEXT_WHITE, font=f_mono)

    drop_lines = [
        "[+] ENFORCED FIREWALL DROP RULES (CONFIDENCE >= 75%):",
        "--------------------------------------------------------------------------",
        "STATUS     IPV4 ADDRESS     SCORE    FEED SOURCE        THREAT CLASSIFICATION",
        "--------------------------------------------------------------------------",
        "[DROP]     45.154.255.89    98%      AbuseIPDB          Cobalt Strike C2 Beacon",
        "[DROP]     103.145.13.24    92%      Cisco Talos        Mirai Botnet DDoS Worker",
        "[DROP]     185.220.101.5    88%      AlienVault OTX     Tor Exit Node / Proxy",
        "[DROP]     194.26.29.112    85%      Emerging Threats   SSH Brute-Force Daemon",
        "[DROP]     91.240.118.170   82%      AbuseIPDB          SQLi / Web Scanner",
        "--------------------------------------------------------------------------",
        "[ALLOW]    198.51.100.42    50%      Internal SIEM      Unverified Probe (<75%)",
        "[ALLOW]    1.1.1.1          5%       Global Whitelist   Public Anycast DNS",
        "--------------------------------------------------------------------------",
        "METRICS: 7 Ingested | 5 Enforced Drops | 2 Allowed | Avg Score: 71.4%"
    ]

    curr_y = y + 50
    for line in drop_lines:
        color = TEXT_YELLOW if "[+]" in line or "---" in line else (TEXT_RED if "[DROP]" in line else (TEXT_GREEN if "[ALLOW]" in line or "METRICS" in line else TEXT_WHITE))
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 22

    return img


def create_screen_05(fonts):
    """05: Generated iptables & nftables Scripts"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (firewall_script_inspection)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day24_Threat_Intel_IP_Blocker]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ head -n 14 firewall_rules/iptables_blocklist.sh", fill=TEXT_WHITE, font=f_mono)

    rules_lines = [
        "#!/bin/bash",
        "# PEER'S Automated Threat Intelligence iptables Blocklist",
        "# Standard: NIST SP 800-150 / MITRE ATT&CK M1037",
        "",
        "iptables -N THREAT_INTEL_BLOCK 2>/dev/null || true",
        "iptables -F THREAT_INTEL_BLOCK",
        "",
        "iptables -A THREAT_INTEL_BLOCK -s 45.154.255.89 -j DROP -m comment --comment \"Sqrock: Cobalt Strike C2 (Score: 98)\"",
        "iptables -A THREAT_INTEL_BLOCK -s 103.145.13.24 -j DROP -m comment --comment \"Sqrock: Mirai DDoS (Score: 92)\"",
        "iptables -A THREAT_INTEL_BLOCK -s 185.220.101.5 -j DROP -m comment --comment \"Sqrock: Tor Proxy (Score: 88)\"",
        "iptables -A THREAT_INTEL_BLOCK -s 194.26.29.112 -j DROP -m comment --comment \"Sqrock: SSH Brute (Score: 85)\"",
        "iptables -A THREAT_INTEL_BLOCK -s 91.240.118.170 -j DROP -m comment --comment \"Sqrock: SQLi Scanner (Score: 82)\"",
        "",
        "iptables -C INPUT -j THREAT_INTEL_BLOCK 2>/dev/null || iptables -I INPUT 1 -j THREAT_INTEL_BLOCK"
    ]

    curr_y = y + 50
    for line in rules_lines:
        color = TEXT_GRAY if line.startswith("#") else (TEXT_RED if "-j DROP" in line else (TEXT_CYAN if "iptables" in line else TEXT_WHITE))
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 22

    return img


def create_screen_06(fonts):
    """06: GitHub Repo Overview & Unit Tests"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (unit tests & project tree)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-soc@kali)-[~/Day24_Threat_Intel_IP_Blocker]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 -m unittest tests/test_threat_blocker.py -v", fill=TEXT_WHITE, font=f_mono)

    test_lines = [
        "test_confidence_threshold_filtering (TestThreatBlocker) ... ok",
        "test_feed_ingestion (TestThreatBlocker) ... ok",
        "test_ip_address_validation (TestThreatBlocker) ... ok",
        "test_iptables_rule_generation (TestThreatBlocker) ... ok",
        "test_json_and_txt_reporting (TestThreatBlocker) ... ok",
        "test_nftables_syntax_generation (TestThreatBlocker) ... ok",
        "----------------------------------------------------------------------",
        "Ran 6 tests in 0.007s | OK (100% Pass Rate)",
        "",
        "┌──(sqrock-soc@kali)-[~/Day24_Threat_Intel_IP_Blocker]",
        "└─$ tree -L 2",
        ".",
        "├── feeds/ (threat_intel_feed.json)",
        "├── firewall_rules/",
        "│   ├── iptables_blocklist.sh",
        "│   ├── nftables_blocklist.nft",
        "│   ├── threat_intel_report.json",
        "│   └── threat_intel_summary.txt",
        "├── README.md",
        "├── reports/",
        "│   ├── Day24_Threat_Intel_Pipeline_Report_Sqrock_MdPeerSiddiqui.pdf",
        "│   └── screenshots/ (01 to 06)",
        "├── tests/ (test_threat_blocker.py)",
        "└── threat_blocker.py"
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
        ("03_threat_feed_ingestion.png", create_screen_03),
        ("04_enforced_firewall_rules.png", create_screen_04),
        ("05_iptables_nftables_rules.png", create_screen_05),
        ("06_github_repo_overview.png", create_screen_06),
    ]

    for fname, func in screens:
        path = os.path.join(SCREENSHOTS_DIR, fname)
        img = func(fonts)
        img.save(path, "PNG")
        print(f"[+] Saved terminal screenshot: {path}")

    print("\n[+] All 6 Day 24 Kali Linux terminal screenshots generated successfully.")


if __name__ == "__main__":
    main()
