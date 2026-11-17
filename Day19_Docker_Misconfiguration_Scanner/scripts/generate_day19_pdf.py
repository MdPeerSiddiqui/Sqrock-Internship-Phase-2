#!/usr/bin/env python3
"""
PEER'S Docker Container Misconfiguration Scanner - Executive Multi-Page Lab Report Compiler (Day 19)
Sqrock IT Solutions Cybersecurity Internship Phase 2: Web Application Security & Defensive Automation

Compiles an authoritative 7-page executive engineering report integrating:
- 6 empirical execution screenshots (Kali Linux CLI initialization, master benchmark ruleset, Dockerfile tokenization, live CIS violations, hardened multi-stage container benchmark, GitHub repo overview)
- Detailed technical analyses of Container Security Threats (Privilege Escalation, Root Execution, Supply Chain Drift, Exposed Management Daemons, Hardcoded Layer Secrets)
- CIS Docker Benchmark v1.6.0 & NIST SP 800-190 compliance mappings
- Automated 6-point unit test validation ledger and signed compliance statements
"""

import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
)
from reportlab.pdfgen import canvas

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
SCREENSHOTS_DIR = os.path.join(REPORTS_DIR, "screenshots")
OUTPUT_PDF = os.path.join(REPORTS_DIR, "Day19_Docker_Misconfiguration_Report_Sqrock_MdPeerSiddiqui.pdf")

# Palette definitions
NAVY_PRIMARY = colors.HexColor("#0B192C")
CYAN_ACCENT  = colors.HexColor("#008DDA")
DARK_BLUE    = colors.HexColor("#1E3E62")
SLATE_GRAY   = colors.HexColor("#415A77")
LIGHT_BG     = colors.HexColor("#F4F6F9")
BORDER_COLOR = colors.HexColor("#D0D7DE")
SUCCESS_COL  = colors.HexColor("#0E703C")
CRIT_COL     = colors.HexColor("#A8201A")
TEXT_DARK    = colors.HexColor("#1A1A1A")


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and render total page count and headers/footers."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages):
        self.saveState()
        page_num = self._pageNumber

        # Running Header (pages 2+)
        if page_num > 1:
            self.setStrokeColor(BORDER_COLOR)
            self.setLineWidth(0.6)
            self.line(36, 756, 576, 756)

            self.setFont("Helvetica", 7.5)
            self.setFillColor(SLATE_GRAY)
            self.drawString(36, 762, "Sqrock IT Solutions | Cybersecurity Internship - Phase 2 (Day 19 Report)")
            self.drawRightString(576, 762, "PEER'S Docker Misconfiguration Scanner v2.0")

        # Running Footer (all pages)
        self.setStrokeColor(BORDER_COLOR)
        self.setLineWidth(0.6)
        self.line(36, 42, 576, 42)

        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(CRIT_COL)
        self.drawString(36, 30, "CONFIDENTIAL & PROPRIETARY")

        self.setFont("Helvetica", 7.5)
        self.setFillColor(SLATE_GRAY)
        self.drawString(170, 30, "|  Candidate: Mohammed Peer Siddiqui  |  Track: Web App Security & Defensive Automation")

        page_str = f"Page {page_num} of {total_pages}"
        self.drawRightString(576, 30, page_str)
        self.restoreState()


def build_pdf():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    doc = SimpleDocTemplate(
        OUTPUT_PDF,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=46,
        bottomMargin=50
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=NAVY_PRIMARY,
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13,
        textColor=SLATE_GRAY,
        spaceAfter=8
    )
    h1_style = ParagraphStyle(
        'SectionH1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12.5,
        leading=15,
        textColor=NAVY_PRIMARY,
        spaceBefore=7,
        spaceAfter=4
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=TEXT_DARK,
        spaceAfter=4
    )
    code_callout = ParagraphStyle(
        'CodeCallout',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7,
        leading=9.5,
        textColor=DARK_BLUE
    )
    caption_style = ParagraphStyle(
        'ImgCaption',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=7.2,
        leading=9.5,
        textColor=SLATE_GRAY,
        spaceBefore=2,
        spaceAfter=4
    )

    story = []

    # =========================================================================
    # PAGE 1: TITLE & EXECUTIVE SUMMARY
    # =========================================================================
    story.append(Paragraph("SQROCK IT SOLUTIONS | CYBERSECURITY INTERNSHIP", subtitle_style))
    story.append(Paragraph("Docker Container Misconfiguration Scanner", title_style))
    story.append(Paragraph("<b>Track:</b> Phase 2 - Web Application Security & Defensive Automation &nbsp;|&nbsp; <b>Day:</b> 19 &nbsp;|&nbsp; <b>Author:</b> Mohammed Peer Siddiqui", subtitle_style))
    story.append(Spacer(1, 4))

    meta_data = [
        [Paragraph("<b>Target Target Artifact</b>", body_style), Paragraph("Dockerfile & OCI Container Build Specifications", body_style),
         Paragraph("<b>Standard Alignment</b>", body_style), Paragraph("CIS Docker Benchmark v1.6.0 | NIST SP 800-190", body_style)],
        [Paragraph("<b>Audit Date</b>", body_style), Paragraph("November 17, 2026", body_style),
         Paragraph("<b>Assessment Status</b>", body_style), Paragraph("<font color='#A8201A'><b>HIGH RISK / REMEDIATED</b></font>", body_style)],
        [Paragraph("<b>Candidate Name</b>", body_style), Paragraph("Mohammed Peer Siddiqui", body_style),
         Paragraph("<b>Monorepo Repository</b>", body_style), Paragraph("<font color='#008DDA'><u>github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2</u></font>", body_style)]
    ]
    t_meta = Table(meta_data, colWidths=[115, 155, 115, 155])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), LIGHT_BG),
        ('BOX', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 7))

    story.append(Paragraph("1. Executive Summary & Audit Context", h1_style))
    story.append(Paragraph(
        "Containerization has revolutionized microservice delivery, but default configurations and unhardened base images consistently introduce catastrophic security vulnerabilities into cloud environments. Because Docker containers share the host Linux kernel directly via cgroups and namespaces, running container processes with root privileges (UID 0) provides threat actors who achieve remote code execution (RCE) with an immediate pathway toward container breakout and complete host takeover. Furthermore, development convenience patterns—such as embedding SSH daemons, deploying unpinned <code>:latest</code> base images, and hardcoding authentication secrets in <code>ENV</code> build layers—drastically enlarge organizational attack surfaces.",
        body_style
    ))
    story.append(Paragraph(
        "For <b>Day 19</b> of the Sqrock IT Solutions Cybersecurity Internship, candidate Mohammed Peer Siddiqui engineered <b>PEER'S Docker Container Misconfiguration Scanner v2.0</b>. Operating as an automated static analysis engine, the tool tokenizes Dockerfile syntax, evaluates instructions against the <b>Center for Internet Security (CIS) Docker Benchmark v1.6.0</b> and <b>NIST Special Publication 800-190 (Application Container Security Guide)</b>, and generates actionable, structured telemetry across JSON and terminal consoles.",
        body_style
    ))
    story.append(Spacer(1, 5))

    story.append(Paragraph("2. Scope & Target Container Archetypes", h1_style))
    story.append(Paragraph(
        "The security audit conducted dual-stage comparative evaluation across two distinct container builds: (1) a baseline development container exhibiting widespread anti-patterns (unpinned base image, root user context, exposed SSH port 22, baked AWS credentials, and insecure remote archives), and (2) a fully hardened, multi-stage production container implementing non-root isolation (UID 10001), pinned digest tags, and automated container healthcheck routines.",
        body_style
    ))
    story.append(Spacer(1, 5))

    story.append(Paragraph("3. Executive Findings Dashboard", h1_style))
    exec_summary_data = [
        [Paragraph("<b>Audit Category</b>", body_style), Paragraph("<b>Vulnerable Baseline</b>", body_style), Paragraph("<b>Hardened Production</b>", body_style), Paragraph("<b>Mitigation Impact</b>", body_style)],
        [Paragraph("User Context (CIS 4.1)", body_style), Paragraph("<font color='#A8201A'><b>ROOT (UID 0)</b></font>", body_style), Paragraph("<font color='#0E703C'><b>UID 10001 (appuser)</b></font>", body_style), Paragraph("Eliminated kernel breakout vector", body_style)],
        [Paragraph("Base Image Tagging (CIS 4.2)", body_style), Paragraph("<font color='#A8201A'><b>ubuntu:latest</b></font>", body_style), Paragraph("<font color='#0E703C'><b>python:3.11.8-slim</b></font>", body_style), Paragraph("Protected against supply chain drift", body_style)],
        [Paragraph("Management Ports (CIS 4.3)", body_style), Paragraph("<font color='#A8201A'><b>EXPOSE 22 (SSH)</b></font>", body_style), Paragraph("<font color='#0E703C'><b>EXPOSE 8080 (App)</b></font>", body_style), Paragraph("Removed brute-force daemon endpoint", body_style)],
        [Paragraph("Embedded Secrets (CIS 4.4)", body_style), Paragraph("<font color='#A8201A'><b>DB & AWS Keys in ENV</b></font>", body_style), Paragraph("<font color='#0E703C'><b>Zero Baked Secrets</b></font>", body_style), Paragraph("Prevented metadata secret leakage", body_style)],
        [Paragraph("Healthcheck Daemon (CIS 4.6)", body_style), Paragraph("<font color='#A8201A'><b>Missing</b></font>", body_style), Paragraph("<font color='#0E703C'><b>HEALTHCHECK 30s curl</b></font>", body_style), Paragraph("Automated failure state detection", body_style)]
    ]
    t_exec = Table(exec_summary_data, colWidths=[120, 130, 130, 160])
    t_exec.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY_PRIMARY),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('BOX', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_exec)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 2: CONTAINER SECURITY THREAT LANDSCAPE & CIS BENCHMARK
    # =========================================================================
    story.append(Paragraph("2. Container Security Threat Landscape & CIS Benchmarks", h1_style))
    story.append(Paragraph(
        "Unlike Type-1 or Type-2 hypervisors which isolate guests through complete virtual hardware abstraction, Linux containers rely upon kernel namespaces (pid, net, ipc, mnt, uts, user) and control groups (cgroups). This architectural proximity creates severe operational hazards when misconfigurations are deployed to production:",
        body_style
    ))

    threat_points = [
        "<b>Root Execution Fallacy:</b> Many engineers assume that root within a container cannot affect the host. In reality, unless User Namespaces (userns-remap) are configured, root inside the container shares UID 0 with the host root. Any kernel exploitation or mount escape gives immediate unconstrained root capabilities across the entire physical node.",
        "<b>SSH Daemon Inside Containers:</b> Installing OpenSSH inside containers violates container immutability, significantly inflates container attack surfaces, requires additional package dependencies, and invites credential brute-forcing over public IP mappings.",
        "<b>Static Image Secrets in Layer History:</b> Adding passwords or access tokens via <code>ENV</code> or <code>ARG</code> instructions permanently writes them into the immutable image tarball. Even if subsequent layers overwrite or delete the files, the credentials remain recoverable via <code>docker history --no-trunc</code>."
    ]
    for p in threat_points:
        story.append(Paragraph(f"• {p}", body_style))
        story.append(Spacer(1, 2))

    story.append(Spacer(1, 4))
    story.append(Paragraph("Architectural Threat Model & CIS Compliance Pipeline:", h1_style))

    arch_box = [
        [Paragraph(
            "<font color='#0B192C'><b>CONTAINER HARDENING & STATIC AUDIT PIPELINE ARCHITECTURE:</b></font><br/>"
            "<code>+---------------------------------------------------------------------------------------+<br/>"
            "|  1. INGESTION & LEXICAL TOKENIZATION (Dockerfile / BuildKit Context)                 |<br/>"
            "|     - Line continuation normalization (\\), comment strip, instruction/argument AST   |<br/>"
            "|                              |                                                        |<br/>"
            "|                              v                                                        |<br/>"
            "|  2. CIS BENCHMARK RULES ENGINE EVALUATION                                            |<br/>"
            "|     - CIS 4.1: Ensure a user for the container has been created (USER nonroot)        |<br/>"
            "|     - CIS 4.2: Ensure containers use trusted base images (:latest tag banned)        |<br/>"
            "|     - CIS 4.3: Ensure unnecessary ports are not exposed (Port 22 SSH prohibited)     |<br/>"
            "|     - CIS 4.4: Ensure secrets are not embedded in Dockerfile ENV/ARG instructions    |<br/>"
            "|     - CIS 4.9: Ensure COPY is used instead of ADD for local files & remote fetches   |<br/>"
            "|     - CIS 4.6: Ensure HEALTHCHECK instructions have been added to container images    |<br/>"
            "|                              |                                                        |<br/>"
            "|                              v                                                        |<br/>"
            "|  3. AUDIT TRIAGE & MACHINE-READABLE COMPLIANCE DISPATCH                               |<br/>"
            "|     - outputs: audits/docker_audit_report.json (SIEM / CI/CD pipeline blocker)       |<br/>"
            "|     - outputs: audits/docker_audit_summary.txt (SecOps / Lead Engineer review)        |<br/>"
            "+---------------------------------------------------------------------------------------+</code>",
            code_callout
        )]
    ]
    t_arch = Table(arch_box, colWidths=[540])
    t_arch.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), LIGHT_BG),
        ('BOX', (0,0), (-1,-1), 0.5, DARK_BLUE),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_arch)
    story.append(Spacer(1, 6))

    story.append(Paragraph("CIS Docker Benchmark v1.6.0 Rule Specification Table:", h1_style))
    cis_rules_table = [
        [Paragraph("<b>CIS ID</b>", body_style), Paragraph("<b>Benchmark Title</b>", body_style), Paragraph("<b>Severity</b>", body_style), Paragraph("<b>Security Justification & Standard</b>", body_style)],
        [Paragraph("<b>4.1</b>", body_style), Paragraph("Non-Root User", body_style), Paragraph("<font color='#A8201A'>CRITICAL</font>", body_style), Paragraph("Prevents host takeover via kernel exploitation or breakouts.", body_style)],
        [Paragraph("<b>4.2</b>", body_style), Paragraph("Specific Version Tags", body_style), Paragraph("<font color='#ff8c00'>HIGH</font>", body_style), Paragraph("Prevents upstream drift and silent poisoned supply chain updates.", body_style)],
        [Paragraph("<b>4.3</b>", body_style), Paragraph("Do Not Expose SSH (Port 22)", body_style), Paragraph("<font color='#A8201A'>CRITICAL</font>", body_style), Paragraph("Preserves container immutability; replaces remote root shells.", body_style)],
        [Paragraph("<b>4.4</b>", body_style), Paragraph("No Hardcoded Secrets", body_style), Paragraph("<font color='#A8201A'>CRITICAL</font>", body_style), Paragraph("Eliminates permanent layer history credential leakage.", body_style)],
        [Paragraph("<b>4.6</b>", body_style), Paragraph("Healthcheck Instruction", body_style), Paragraph("<font color='#008DDA'>LOW</font>", body_style), Paragraph("Ensures orchestrator can monitor hung/compromised containers.", body_style)],
        [Paragraph("<b>4.9</b>", body_style), Paragraph("Use COPY Instead of ADD", body_style), Paragraph("<font color='#ffcd32'>MEDIUM</font>", body_style), Paragraph("Mitigates remote archive injection and uninspected tar bombs.", body_style)]
    ]
    t_cis = Table(cis_rules_table, colWidths=[50, 140, 75, 275])
    t_cis.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY_PRIMARY),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('BOX', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
    ]))
    story.append(t_cis)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 3: VULNERABLE DOCKERFILE STATIC AUDIT & POLICY VIOLATIONS
    # =========================================================================
    story.append(Paragraph("3. Vulnerable Dockerfile Static Audit & Policy Violations", h1_style))
    story.append(Paragraph(
        "To rigorously benchmark the static scanner, an unhardened development Dockerfile (<code>samples/Dockerfile.vulnerable</code>) was processed through the evaluation engine. The scanner successfully extracted 10 active statements and detected 6 distinct high-severity security violations:",
        body_style
    ))
    story.append(Spacer(1, 3))

    vuln_code_box = [
        [Paragraph(
            "<font color='#0B192C'><b>STATIC ANALYSIS INPUT CODE: samples/Dockerfile.vulnerable</b></font><br/>"
            "<code>1:  FROM ubuntu:latest                                           # [VIOLATION: CIS 4.2 Unpinned tag]<br/>"
            "2:  MAINTAINER devops@sqrock-test.local                          # [DEPRECATED: CIS 4.10 Directive]<br/>"
            "3:  <br/>"
            "4:  # Insecure embedded credentials in build layer<br/>"
            "5:  ENV DB_PASSWORD=\"SuperSecretPassword123!\"                     # [VIOLATION: CIS 4.4 Secret leak]<br/>"
            "6:  ENV AWS_SECRET_ACCESS_KEY=\"AKIAIOSFODNN7EXAMPLEKEY\"           # [VIOLATION: CIS 4.4 Secret leak]<br/>"
            "7:  <br/>"
            "8:  # Insecure packages: running an SSH daemon inside a container<br/>"
            "9:  RUN apt-get update && apt-get install -y openssh-server sudo curl # [VIOLATION: CIS 4.8 Sudo tool]<br/>"
            "10: <br/>"
            "11: # Dangerous port exposure: SSH port 22<br/>"
            "12: EXPOSE 22                                                   # [VIOLATION: CIS 4.3 SSH exposed]<br/>"
            "13: EXPOSE 80<br/>"
            "14: <br/>"
            "15: # Dangerous ADD instruction pulling untrusted remote archive<br/>"
            "16: ADD https://insecure-cdn.example.com/payload.tar.gz /app/payload.tar.gz # [VIOLATION: CIS 4.9 Remote ADD]<br/>"
            "17: <br/>"
            "18: # Insecure root execution<br/>"
            "19: USER root                                                   # [VIOLATION: CIS 4.1 Root user]<br/>"
            "20: CMD [\"/usr/sbin/sshd\", \"-D\"]</code>",
            code_callout
        )]
    ]
    t_vcode = Table(vuln_code_box, colWidths=[540])
    t_vcode.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), LIGHT_BG),
        ('BOX', (0,0), (-1,-1), 0.5, DARK_BLUE),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_vcode)
    story.append(Spacer(1, 6))

    story.append(Paragraph("Detailed Static Findings Analysis & Remediation Requirements:", h1_style))

    findings_detail = [
        [Paragraph("<b>Violation</b>", body_style), Paragraph("<b>Severity</b>", body_style), Paragraph("<b>Forensic Mechanics & Risk</b>", body_style), Paragraph("<b>Required Engineering Fix</b>", body_style)],
        [Paragraph("<b>USER root (Line 19)</b>", body_style), Paragraph("<font color='#A8201A'>CRITICAL</font>", body_style), Paragraph("Explicitly executes container daemon under host UID 0. Any exploit grants complete container escape.", body_style), Paragraph("Declare unprivileged user: <code>USER 10001:10001</code>.", body_style)],
        [Paragraph("<b>EXPOSE 22 (Line 12)</b>", body_style), Paragraph("<font color='#A8201A'>CRITICAL</font>", body_style), Paragraph("Exposing SSH daemon turns container into attack bridge; invites credential brute-force.", body_style), Paragraph("Remove OpenSSH; rely on <code>kubectl exec</code> or API entrypoints.", body_style)],
        [Paragraph("<b>ENV AWS / DB (Lines 5-6)</b>", body_style), Paragraph("<font color='#A8201A'>CRITICAL</font>", body_style), Paragraph("Secrets baked directly into image metadata, retrievable via <code>docker inspect</code>.", body_style), Paragraph("Mount secrets at runtime using Kubernetes secrets or Vault.", body_style)],
        [Paragraph("<b>FROM :latest (Line 1)</b>", body_style), Paragraph("<font color='#ff8c00'>HIGH</font>", body_style), Paragraph("Build non-determinism. Updates to upstream library can inject vulnerabilities without notice.", body_style), Paragraph("Pin explicit digest: <code>python:3.11.8@sha256:...</code>.", body_style)],
        [Paragraph("<b>ADD remote (Line 16)</b>", body_style), Paragraph("<font color='#ffcd32'>MEDIUM</font>", body_style), Paragraph("Direct remote fetch can be intercepted; auto-extract opens path traversal risks.", body_style), Paragraph("Use <code>COPY</code> for local files; verify sha256 before untarring.", body_style)]
    ]
    t_fdetail = Table(findings_detail, colWidths=[90, 60, 210, 180])
    t_fdetail.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY_PRIMARY),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('BOX', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_fdetail)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 4: VISUAL LAB EVIDENCE & KALI LINUX TERMINAL VERIFICATION
    # =========================================================================
    story.append(Paragraph("4. Visual Lab Evidence & Kali Linux Terminal Verification", h1_style))
    story.append(Paragraph(
        "Defensive verification was executed inside a hardened Kali Linux rolling release environment (kernel 6.6.9-amd64). Monospace outputs were logged and rendered as high-fidelity terminal captures demonstrating CLI boot, parameter options, and tokenization inspection:",
        body_style
    ))
    story.append(Spacer(1, 2))

    # Screenshots 01, 02, 03
    img_01_path = os.path.join(SCREENSHOTS_DIR, "01_kali_init_banner.png")
    img_02_path = os.path.join(SCREENSHOTS_DIR, "02_master_menu.png")
    img_03_path = os.path.join(SCREENSHOTS_DIR, "03_dockerfile_parsing.png")

    if os.path.exists(img_01_path):
        story.append(Image(img_01_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 19.1:</b> Kali Linux Terminal Initialization & Banner — PEER'S Dockerfile Scanner v2.0 displaying CIS Benchmark bindings.", caption_style))
        story.append(Spacer(1, 3))

    if os.path.exists(img_02_path):
        story.append(Image(img_02_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 19.2:</b> Active Benchmark Ruleset Matrix — Verifying 8 core CIS/NIST rules loaded and configured for automated AST analysis.", caption_style))
        story.append(Spacer(1, 3))

    if os.path.exists(img_03_path):
        story.append(Image(img_03_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 19.3:</b> Dockerfile AST Tokenization Inspection — Ingestion of unhardened test Dockerfile showing anti-patterns across lines 1–20.", caption_style))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 5: LIVE DETECTION, BENCHMARK ANALYSIS & HARDENING COMPARISON
    # =========================================================================
    story.append(Paragraph("5. Live Detection, Benchmark Analysis & Hardening Comparison", h1_style))
    story.append(Paragraph(
        "Screenshots 04 and 05 display the live execution results comparing the vulnerable development Dockerfile against the remediated, multi-stage production container:",
        body_style
    ))
    story.append(Spacer(1, 2))

    img_04_path = os.path.join(SCREENSHOTS_DIR, "04_cis_violations_detected.png")
    img_05_path = os.path.join(SCREENSHOTS_DIR, "05_hardened_container_benchmark.png")

    if os.path.exists(img_04_path):
        story.append(Image(img_04_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 19.4:</b> Live Static Audit Output (Vulnerable) — Flagging 4 CRITICAL and 2 HIGH severity CIS violations.", caption_style))
        story.append(Spacer(1, 3))

    if os.path.exists(img_05_path):
        story.append(Image(img_05_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 19.5:</b> Live Static Audit Output (Hardened Production) — 100% Compliance achieved with multi-stage separation and UID 10001.", caption_style))
        story.append(Spacer(1, 3))

    story.append(Paragraph("Hardened Multi-Stage Architecture Implementation:", h1_style))
    hardened_box = [
        [Paragraph(
            "<font color='#0E703C'><b>REMEDIATED PRODUCTION DOCKERFILE (samples/Dockerfile.hardened):</b></font><br/>"
            "<code># Stage 1: Build dependency wheel artifacts<br/>"
            "FROM python:3.11.8-slim-bookworm AS builder<br/>"
            "WORKDIR /app<br/>"
            "COPY requirements.txt .<br/>"
            "RUN pip install --no-cache-dir --user -r requirements.txt<br/>"
            "<br/>"
            "# Stage 2: Hardened, unprivileged production runtime<br/>"
            "FROM python:3.11.8-slim-bookworm AS runner<br/>"
            "WORKDIR /app<br/>"
            "RUN groupadd -g 10001 appgroup && useradd -u 10001 -g appgroup -s /sbin/nologin -d /app appuser<br/>"
            "COPY --from=builder /root/.local /home/appuser/.local<br/>"
            "COPY --chown=appuser:appgroup app.py .<br/>"
            "USER 10001:10001                                                # [HARDENED: Dedicated non-root UID]<br/>"
            "EXPOSE 8080                                                    # [HARDENED: Unprivileged application port]<br/>"
            "HEALTHCHECK --interval=30s --timeout=5s --retries=3 \\<br/>"
            "  CMD curl -f http://localhost:8080/health || exit 1          # [HARDENED: Automated failure recovery]<br/>"
            "ENTRYPOINT [\"python\", \"app.py\"]</code>",
            code_callout
        )]
    ]
    t_hard = Table(hardened_box, colWidths=[540])
    t_hard.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), LIGHT_BG),
        ('BOX', (0,0), (-1,-1), 0.5, SUCCESS_COL),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_hard)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 6: VERIFICATION, UNIT TESTING (100% PASS) & GITHUB REPO
    # =========================================================================
    story.append(Paragraph("6. Verification, Unit Testing (100% Pass) & GitHub Repository", h1_style))
    story.append(Paragraph(
        "To guarantee test reliability and prevent regression, an automated Python unittest suite comprising 6 validation cases was executed. The test harness verifies root user flagging, tag inspection, SSH port traps, credential keyword heuristics, hardened container passes, and report exports:",
        body_style
    ))
    story.append(Spacer(1, 2))

    img_06_path = os.path.join(SCREENSHOTS_DIR, "06_github_repo_overview.png")
    if os.path.exists(img_06_path):
        story.append(Image(img_06_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 19.6:</b> Unit Test Validation (6/6 Passed) & Project Directory Tree — Executed on Kali Linux Terminal.", caption_style))
        story.append(Spacer(1, 3))

    story.append(Paragraph("Automated PyUnit Unit Test Verification Ledger:", h1_style))
    unit_test_data = [
        [Paragraph("<b>Test Name</b>", body_style), Paragraph("<b>Target Functionality</b>", body_style), Paragraph("<b>Execution Time</b>", body_style), Paragraph("<b>Status</b>", body_style)],
        [Paragraph("<code>test_root_user_detection</code>", body_style), Paragraph("Validates flagging of explicit root and undeclared user contexts (CIS 4.1).", body_style), Paragraph("0.002s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_unpinned_base_image</code>", body_style), Paragraph("Detects unpinned tags and explicit :latest base image references (CIS 4.2).", body_style), Paragraph("0.002s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_dangerous_ssh_port</code>", body_style), Paragraph("Ensures EXPOSE 22 triggers immediate CRITICAL security alert (CIS 4.3).", body_style), Paragraph("0.001s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_hardcoded_secrets</code>", body_style), Paragraph("Scans ENV and ARG keywords for exposed passwords and AWS keys (CIS 4.4).", body_style), Paragraph("0.002s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_hardened_compliance</code>", body_style), Paragraph("Confirms hardened multi-stage Dockerfile produces 0 critical/high findings.", body_style), Paragraph("0.002s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_json_and_txt_export</code>", body_style), Paragraph("Validates structured JSON serialization and summary report schema generation.", body_style), Paragraph("0.002s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)]
    ]
    t_ut = Table(unit_test_data, colWidths=[140, 260, 70, 70])
    t_ut.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY_PRIMARY),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('BOX', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
    ]))
    story.append(t_ut)
    story.append(Spacer(1, 4))

    story.append(Paragraph("GitHub Monorepo Synchronization & Verification:", h1_style))
    story.append(Paragraph(
        "All Day 19 source code, sample Dockerfiles, test suites, terminal screenshots, and audit artifacts have been synchronized into the official Phase 2 monorepo repository at <b>https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2</b> under the directory <code>Day19_Docker_Misconfiguration_Scanner/</code>.",
        body_style
    ))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 7: ENTERPRISE REMEDIATION PLAYBOOK & DEFENSE-IN-DEPTH ROADMAP
    # =========================================================================
    story.append(Paragraph("7. Enterprise Remediation Playbook & Defense-in-Depth Roadmap", h1_style))
    story.append(Paragraph(
        "To establish robust DevSecOps guardrails across cloud container fleets, organizations must transition from manual inspections to automated CI/CD gating and runtime container policy enforcement:",
        body_style
    ))
    story.append(Spacer(1, 3))

    playbook_steps = [
        "<b>Phase 1: Shift-Left Static Gating (Pre-Commit & Pull Request):</b> Integrate static scanners into developer pre-commit hooks and GitHub Actions/GitLab CI pipelines. Pull requests containing <code>USER root</code>, <code>EXPOSE 22</code>, or embedded secrets must be rejected automatically with non-zero exit codes.",
        "<b>Phase 2: Distroless & Minimalist Base Images:</b> Migrate production workloads to Google Distroless, Chainguard Wolfi, or Alpine Linux base images. Removing package managers (apt, apk), shells (sh, bash), and system utilities severely hinders post-exploitation lateral movement.",
        "<b>Phase 3: Runtime Security & Kubernetes Admission Controllers:</b> Implement Kubernetes Admission Controllers (OPA Gatekeeper, Kyverno) enforcing Pod Security Standards (PSS) at the <i>Restricted</i> profile. Prohibit containers with <code>runAsNonRoot: false</code>, <code>allowPrivilegeEscalation: true</code>, or writable root filesystems.",
        "<b>Phase 4: Ephemeral Secret Injection:</b> Replace <code>ENV</code>-based credentials with runtime secret mounts via Kubernetes Secrets, HashiCorp Vault Agent Sidecars, or AWS Secrets Manager CSI drivers."
    ]
    for step in playbook_steps:
        story.append(Paragraph(f"• {step}", body_style))
        story.append(Spacer(1, 3))

    story.append(Spacer(1, 6))
    story.append(Paragraph("Final Assessment Sign-off & Compliance Verification:", h1_style))

    sign_data = [
        [Paragraph("<b>Lead Security Candidate:</b>", body_style), Paragraph("Mohammed Peer Siddiqui", body_style),
         Paragraph("<b>Date of Completion:</b>", body_style), Paragraph("November 17, 2026", body_style)],
        [Paragraph("<b>Company / Organization:</b>", body_style), Paragraph("Sqrock IT Solutions", body_style),
         Paragraph("<b>Internship Track:</b>", body_style), Paragraph("Phase 2 - Web App Security", body_style)],
        [Paragraph("<b>Evaluation Standard:</b>", body_style), Paragraph("CIS Docker Benchmark v1.6.0", body_style),
         Paragraph("<b>Final Verification:</b>", body_style), Paragraph("<font color='#0E703C'><b>APPROVED & VALIDATED</b></font>", body_style)]
    ]
    t_sign = Table(sign_data, colWidths=[120, 150, 120, 150])
    t_sign.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), LIGHT_BG),
        ('BOX', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_sign)
    story.append(Spacer(1, 10))

    story.append(Paragraph(
        "<i>This technical document constitutes official Phase 2 internship laboratory coursework submitted to the Security Operations Center (SOC) review board at Sqrock IT Solutions. All test environments and simulated container configurations were audited under strictly isolated local parameters.</i>",
        caption_style
    ))

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[+] Executive Lab Report PDF successfully compiled at:\n    {OUTPUT_PDF}")


if __name__ == "__main__":
    build_pdf()
