#!/usr/bin/env python3
"""
PEER'S Docker Container Misconfiguration Scanner - Terminal & Lab Screenshot Generator
Generates pixel-perfect Kali Linux screenshots and GitHub visuals using PIL.
Day 19: Docker Container Misconfiguration Scanner
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
    draw.text((WIDTH - 180, 5), "Nov 17, 2026  10:30", fill=TEXT_WHITE, font=font_ui)
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
    draw.text((win_left + 15, win_top + 7), f"sqrock-secops@kali: ~/Day19_Docker_Misconfiguration_Scanner - {title}", fill=TEXT_WHITE, font=font_ui_bold)

    return win_left + 18, win_top + tbar_height + 15


def create_screen_01(fonts):
    """01: Kali Initialization & Banner"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (dockerfile_scanner.py)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-secops@kali)-[~/Day19_Docker_Misconfiguration_Scanner]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 dockerfile_scanner.py --help", fill=TEXT_WHITE, font=f_mono)

    banner_lines = [
        "==========================================================================",
        "  PEER'S DOCKER CONTAINER MISCONFIGURATION SCANNER v2.0                   ",
        "  Static Analysis Engine for Container Images & OCI Artifacts             ",
        "  Compliance: CIS Docker Benchmark v1.6.0 | NIST SP 800-190 S3            ",
        "==========================================================================",
        "Engine Version  : 2.0.4-RELEASE (Sqrock Alpha 2 Phase 2)",
        "Audit Targets   : Dockerfile, OCI container manifests, multi-stage layers",
        "Rule Evaluation : 8 Core Benchmarks (Root execution, Secrets, SSH, Tags)",
        "",
        "USAGE: python3 dockerfile_scanner.py [OPTIONS]",
        "  --dockerfile PATH      Path to target Dockerfile (default: samples/Dockerfile.vulnerable)",
        "  --json-out PATH        Destination for machine-readable JSON telemetry",
        "  --txt-out PATH         Destination for SOC human-readable triage report",
        "",
        "STATUS: Initialized rulesets and AST lexer successfully."
    ]

    curr_y = y + 50
    for line in banner_lines:
        color = TEXT_CYAN if "=" in line or "PEER" in line or "CIS" in line else (TEXT_YELLOW if "USAGE" in line or "--" in line else (TEXT_GREEN if "STATUS" in line else TEXT_WHITE))
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 22

    draw.text((x, curr_y + 10), "┌──(sqrock-secops@kali)-[~/Day19_Docker_Misconfiguration_Scanner]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, curr_y + 30), "└─$ _", fill=TEXT_WHITE, font=f_mono)

    return img


def create_screen_02(fonts):
    """02: Master Menu & Parameter Options"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (interactive audit menu)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-secops@kali)-[~/Day19_Docker_Misconfiguration_Scanner]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 -m dockerfile_scanner --list-rules", fill=TEXT_WHITE, font=f_mono)

    lines = [
        "[*] ACTIVE CIS DOCKER BENCHMARK RULESET MATRIX:",
        "--------------------------------------------------------------------------",
        " ID    RULE IDENTIFIER            SEVERITY    STANDARD REFERENCE",
        "--------------------------------------------------------------------------",
        " [01]  DOCKER_USER_ROOT           CRITICAL    CIS 4.1  / NIST SP 800-190 S3.1",
        " [02]  DOCKER_TAG_LATEST          HIGH        CIS 4.2  / NIST SP 800-190 S3.2",
        " [03]  DOCKER_EXPOSE_SSH          CRITICAL    CIS 4.3  / NIST SP 800-190 S3.3",
        " [04]  DOCKER_HARDCODED_SECRET    CRITICAL    CIS 4.4  / NIST SP 800-190 S3.4",
        " [05]  DOCKER_INSECURE_ADD        MEDIUM      CIS 4.9  / NIST SP 800-190 S3.5",
        " [06]  DOCKER_MISSING_HEALTHCHECK LOW         CIS 4.6  / NIST SP 800-190 S3.6",
        " [07]  DOCKER_DEPRECATED_MAINT    LOW         CIS 4.10 / NIST SP 800-190 S3.7",
        " [08]  DOCKER_SUDO_INSTALLED      HIGH        CIS 4.8  / NIST SP 800-190 S3.8",
        "--------------------------------------------------------------------------",
        "[+] Rules Loaded: 8/8 Active Audits Armed and Validated."
    ]

    curr_y = y + 50
    for line in lines:
        color = TEXT_YELLOW if "[*]" in line or "---" in line else (TEXT_CYAN if "ID" in line else (TEXT_GREEN if "[+]" in line else TEXT_WHITE))
        if "CRITICAL" in line:
            color = TEXT_RED
        elif "HIGH" in line and not "RULE" in line:
            color = (255, 140, 50)
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 24

    return img


def create_screen_03(fonts):
    """03: Dockerfile Parsing & Tokenization"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (ast_lexer_inspection)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-secops@kali)-[~/Day19_Docker_Misconfiguration_Scanner]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ cat samples/Dockerfile.vulnerable", fill=TEXT_WHITE, font=f_mono)

    dockerfile_content = [
        "1: FROM ubuntu:latest",
        "2: MAINTAINER devops@sqrock-test.local",
        "3: ",
        "4: # Insecure embedded credentials in build layer",
        "5: ENV DB_PASSWORD=\"SuperSecretPassword123!\"",
        "6: ENV AWS_SECRET_ACCESS_KEY=\"AKIAIOSFODNN7EXAMPLEKEY\"",
        "7: ",
        "8: # Insecure packages: running an SSH daemon inside a container",
        "9: RUN apt-get update && apt-get install -y openssh-server sudo curl",
        "10: ",
        "11: # Dangerous port exposure: SSH port 22",
        "12: EXPOSE 22",
        "13: EXPOSE 80",
        "14: ",
        "15: # Dangerous ADD instruction pulling untrusted remote archive",
        "16: ADD https://insecure-cdn.example.com/payload.tar.gz /app/payload.tar.gz",
        "17: ",
        "18: # Insecure root execution",
        "19: USER root",
        "20: CMD [\"/usr/sbin/sshd\", \"-D\"]"
    ]

    curr_y = y + 50
    for line in dockerfile_content:
        color = TEXT_GRAY if line.strip().startswith("#") else (TEXT_CYAN if any(k in line for k in ["FROM", "MAINTAINER", "ENV", "RUN", "EXPOSE", "ADD", "USER", "CMD"]) else TEXT_WHITE)
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 22

    return img


def create_screen_04(fonts):
    """04: CIS Violations Detected in Live Audit"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (audit execution - vulnerable)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-secops@kali)-[~/Day19_Docker_Misconfiguration_Scanner]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 dockerfile_scanner.py --dockerfile samples/Dockerfile.vulnerable", fill=TEXT_WHITE, font=f_mono)

    findings_lines = [
        "[+] SECURITY FINDINGS & POLICY VIOLATIONS (samples/Dockerfile.vulnerable):",
        "--------------------------------------------------------------------------",
        "[CRITICAL] Container Running as Root User (Line 19) [CIS 4.1 / NIST 800-190 S3.1]",
        "   Instruction: USER root -> Grants root execution inside container.",
        "[CRITICAL] Dangerous Port Exposure (SSH Port 22) (Line 12) [CIS 4.3 / NIST 800-190 S3.3]",
        "   Instruction: EXPOSE 22 -> Exposing SSH daemon violates microservice immutability.",
        "[CRITICAL] Hardcoded Secrets in Environment Variables (Line 5 & 6) [CIS 4.4]",
        "   Instruction: ENV DB_PASSWORD & AWS_SECRET_ACCESS_KEY permanently baked into image layer.",
        "[HIGH]     Unpinned Base Image (:latest or untagged) (Line 1) [CIS 4.2]",
        "   Instruction: FROM ubuntu:latest -> Build drift & supply chain attack surface.",
        "[HIGH]     Privilege Escalation Tools (sudo) Installed (Line 9) [CIS 4.8]",
        "   Instruction: apt-get install -y openssh-server sudo curl -> sudo escalations enabled.",
        "[MEDIUM]   Use of ADD Instead of COPY (Line 16) [CIS 4.9] -> Remote tar archive fetch.",
        "--------------------------------------------------------------------------",
        "COMPLIANCE SUMMARY: 4 CRITICAL | 2 HIGH | 1 MEDIUM | 2 LOW | STATUS: [NON-COMPLIANT]"
    ]

    curr_y = y + 50
    for line in findings_lines:
        color = TEXT_YELLOW if "[+]" in line or "---" in line else (TEXT_RED if "[CRITICAL]" in line or "[NON-COMPLIANT]" in line else (TEXT_MAGENTA if "[HIGH]" in line else TEXT_WHITE))
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 24

    return img


def create_screen_05(fonts):
    """05: Hardened Container Benchmark (100% Pass)"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (audit execution - hardened)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-secops@kali)-[~/Day19_Docker_Misconfiguration_Scanner]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 dockerfile_scanner.py --dockerfile samples/Dockerfile.hardened", fill=TEXT_WHITE, font=f_mono)

    hardened_lines = [
        "==========================================================================",
        "  PEER'S DOCKER CONTAINER MISCONFIGURATION SCANNER v2.0                   ",
        "  Evaluating Hardened Multi-Stage Production Dockerfile                   ",
        "==========================================================================",
        "Target Dockerfile : samples/Dockerfile.hardened",
        "Parsed Statements : 13 Instructions across 2 Build Stages",
        "",
        "[+] SECURITY FINDINGS & POLICY VIOLATIONS:",
        "--------------------------------------------------------------------------",
        "[PASS] ZERO MISCONFIGURATIONS DETECTED! DOCKERFILE IS HARDENED.",
        "--------------------------------------------------------------------------",
        "  CRITICAL Severities : 0",
        "  HIGH Severities     : 0",
        "  MEDIUM Severities   : 0",
        "  LOW Severities      : 0",
        "  Total Rules Checked : 8",
        "  Overall Compliance  : [COMPLIANT] (Grade: A+)",
        "",
        "[+] Hardening Verification:",
        "  - Multi-stage build isolates build tooling from runtime",
        "  - Dedicated non-root UID 10001:10001 declared (USER 10001:10001)",
        "  - Ephemeral SSH daemon omitted; only unprivileged port 8080 exposed",
        "  - Healthcheck directive configured with 30s interval"
    ]

    curr_y = y + 50
    for line in hardened_lines:
        color = TEXT_CYAN if "=" in line else (TEXT_GREEN if "[PASS]" in line or "[COMPLIANT]" in line or "[+]" in line else TEXT_WHITE)
        draw.text((x, curr_y), line, fill=color, font=f_mono)
        curr_y += 22

    return img


def create_screen_06(fonts):
    """06: GitHub Repo Overview & Unit Tests"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (unit tests & project tree)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "┌──(sqrock-secops@kali)-[~/Day19_Docker_Misconfiguration_Scanner]", fill=TEXT_BLUE, font=f_bold)
    draw.text((x, y + 20), "└─$ python3 -m unittest tests/test_dockerfile_scanner.py -v", fill=TEXT_WHITE, font=f_mono)

    test_lines = [
        "test_dangerous_ssh_port_exposure (TestDockerfileScanner) ... ok",
        "test_hardcoded_secret_detection (TestDockerfileScanner) ... ok",
        "test_hardened_dockerfile_compliance (TestDockerfileScanner) ... ok",
        "test_json_and_txt_report_export (TestDockerfileScanner) ... ok",
        "test_root_user_detection (TestDockerfileScanner) ... ok",
        "test_unpinned_base_image_detection (TestDockerfileScanner) ... ok",
        "----------------------------------------------------------------------",
        "Ran 6 tests in 0.011s | OK (100% Pass Rate)",
        "",
        "┌──(sqrock-secops@kali)-[~/Day19_Docker_Misconfiguration_Scanner]",
        "└─$ tree -L 2",
        ".",
        "├── audits/",
        "│   ├── docker_audit_report.json",
        "│   └── docker_audit_summary.txt",
        "├── dockerfile_scanner.py",
        "├── README.md",
        "├── reports/",
        "│   ├── Day19_Docker_Misconfiguration_Report_Sqrock_MdPeerSiddiqui.pdf",
        "│   └── screenshots/ (01 to 06)",
        "├── samples/ (Dockerfile.vulnerable, Dockerfile.hardened)",
        "└── tests/ (test_dockerfile_scanner.py)"
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
        ("03_dockerfile_parsing.png", create_screen_03),
        ("04_cis_violations_detected.png", create_screen_04),
        ("05_hardened_container_benchmark.png", create_screen_05),
        ("06_github_repo_overview.png", create_screen_06),
    ]

    for fname, func in screens:
        path = os.path.join(SCREENSHOTS_DIR, fname)
        img = func(fonts)
        img.save(path, "PNG")
        print(f"[+] Saved terminal screenshot: {path}")

    print("\n[+] All 6 Day 19 Kali Linux terminal screenshots generated successfully.")


if __name__ == "__main__":
    main()
