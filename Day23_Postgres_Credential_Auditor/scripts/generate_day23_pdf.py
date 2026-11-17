#!/usr/bin/env python3
"""
PEER'S PostgreSQL Security Auditor - Executive Multi-Page Lab Report Compiler (Day 23)
Sqrock IT Solutions Cybersecurity Internship Phase 2: Web Application Security & Defensive Automation

Compiles an authoritative 7-page executive engineering report integrating:
- 6 empirical execution screenshots (Kali Linux CLI initialization, authentication matrix tuning, insecure pg_hba static audit, default credential brute-force simulation, hardened production benchmark, GitHub repo overview)
- Detailed technical analyses of PostgreSQL Client Authentication (pg_hba.conf, trust vs md5 vs scram-sha-256, network binding exposure 0.0.0.0/0)
- CIS PostgreSQL 15 Benchmark v1.0.0 & NIST SP 800-53 (AC-2, IA-5) compliance mappings
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
OUTPUT_PDF = os.path.join(REPORTS_DIR, "Day23_Postgres_Credential_Audit_Report_Sqrock_MdPeerSiddiqui.pdf")

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
            self.drawString(36, 762, "Sqrock IT Solutions | Cybersecurity Internship - Phase 2 (Day 23 Report)")
            self.drawRightString(576, 762, "PEER'S PostgreSQL Security Auditor v2.0")

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
    story.append(Paragraph("PostgreSQL Database Credential & Config Auditor", title_style))
    story.append(Paragraph("<b>Track:</b> Phase 2 - Web Application Security & Defensive Automation &nbsp;|&nbsp; <b>Day:</b> 23 &nbsp;|&nbsp; <b>Author:</b> Mohammed Peer Siddiqui", subtitle_style))
    story.append(Spacer(1, 4))

    meta_data = [
        [Paragraph("<b>Target Datastore Target</b>", body_style), Paragraph("PostgreSQL 15 Database Cluster (pg_hba.conf & Auth)", body_style),
         Paragraph("<b>Standard Alignment</b>", body_style), Paragraph("CIS PostgreSQL 15 Benchmark | NIST SP 800-53", body_style)],
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
        "Relational database clusters represent the crown jewels of enterprise information architecture. In containerized cloud deployments and microservice topologies, database misconfigurations—such as permitting unauthenticated client connections (<code>trust</code> authentication), binding datastore listening sockets to global IPv4 ranges (<code>0.0.0.0/0</code>), and relying upon factory-default superuser credentials (<code>postgres:postgres</code>)—lead directly to catastrophic corporate data exfiltration, ransomware encryption, and regulatory non-compliance.",
        body_style
    ))
    story.append(Paragraph(
        "For <b>Day 23</b> of the Sqrock IT Solutions Cybersecurity Internship, candidate Mohammed Peer Siddiqui built <b>PEER'S PostgreSQL Database Credential & Configuration Auditor v2.0</b>. Operating as an automated database security inspection engine, the tool audits client authentication configuration records (<code>pg_hba.conf</code>) against the <b>CIS PostgreSQL 15 Benchmark v1.0.0</b> and <b>NIST SP 800-53 (AC-2, IA-5)</b>, performs dictionary-based credential brute-force testing, evaluates password Shannon entropy, and exports actionable compliance telemetry.",
        body_style
    ))
    story.append(Spacer(1, 5))

    story.append(Paragraph("2. Scope & Target PostgreSQL Archetypes", h1_style))
    story.append(Paragraph(
        "The security assessment conducted comparative auditing across two distinct database postures: (1) an unhardened baseline exhibiting severe anti-patterns (global CIDR bindings, <code>trust</code> authentication, and obsolete MD5 hashing), and (2) a fully hardened production configuration enforcing <code>scram-sha-256</code> salted challenge-response authentication, SSL transport encryption (<code>hostssl</code>), and Unix socket <code>peer</code> authentication.",
        body_style
    ))
    story.append(Spacer(1, 5))

    story.append(Paragraph("3. Executive Findings Dashboard", h1_style))
    exec_summary_data = [
        [Paragraph("<b>Audit Parameter</b>", body_style), Paragraph("<b>Vulnerable Baseline</b>", body_style), Paragraph("<b>Hardened Production</b>", body_style), Paragraph("<b>Remediation Impact</b>", body_style)],
        [Paragraph("Authentication Method", body_style), Paragraph("<font color='#A8201A'><b>trust (No Password)</b></font>", body_style), Paragraph("<font color='#0E703C'><b>scram-sha-256 &amp; peer</b></font>", body_style), Paragraph("Enforced RFC 7677 cryptographic auth", body_style)],
        [Paragraph("Network CIDR Binding", body_style), Paragraph("<font color='#A8201A'><b>0.0.0.0/0 &amp; ::/0</b></font>", body_style), Paragraph("<font color='#0E703C'><b>10.0.1.0/24 &amp; Loopback</b></font>", body_style), Paragraph("Eliminated public internet database exposure", body_style)],
        [Paragraph("Wire Transport Layer", body_style), Paragraph("<font color='#A8201A'><b>host (Cleartext)</b></font>", body_style), Paragraph("<font color='#0E703C'><b>hostssl (TLS 1.3)</b></font>", body_style), Paragraph("Mitigated network credential sniffing", body_style)],
        [Paragraph("Default Superuser Pass", body_style), Paragraph("<font color='#A8201A'><b>postgres:postgres</b></font>", body_style), Paragraph("<font color='#0E703C'><b>High Entropy (>100b)</b></font>", body_style), Paragraph("Prevented automated credential spraying", body_style)],
        [Paragraph("CIS Benchmark Status", body_style), Paragraph("<font color='#A8201A'><b>NON-COMPLIANT</b></font>", body_style), Paragraph("<font color='#0E703C'><b>100% COMPLIANT (Grade A)</b></font>", body_style), Paragraph("Validated against CIS PostgreSQL 15 Benchmark", body_style)]
    ]
    t_exec = Table(exec_summary_data, colWidths=[120, 125, 125, 170])
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
    # PAGE 2: RELATIONAL DATABASE SECURITY LANDSCAPE & AUTHENTICATION MECHANICS
    # =========================================================================
    story.append(Paragraph("2. Relational Database Security Landscape & Authentication Mechanics", h1_style))
    story.append(Paragraph(
        "PostgreSQL manages client connection access control exclusively through the <code>pg_hba.conf</code> (Host-Based Authentication) configuration file. Because PostgreSQL parses rules sequentially from top to bottom and terminates evaluation on the first matching rule, configuration mistakes introduce critical vulnerabilities:",
        body_style
    ))

    pghba_points = [
        "<b>The Danger of 'trust' Authentication:</b> When a line in <code>pg_hba.conf</code> specifies <code>trust</code>, PostgreSQL assumes that anyone who can connect to the server is authorized to access the database with whatever database username they specify. If bound to <code>0.0.0.0/0</code>, any attacker on the internet can connect as the <code>postgres</code> superuser without supplying a password.",
        "<b>MD5 Hashing Obsoletion:</b> In older PostgreSQL deployments, <code>md5</code> was standard. However, PostgreSQL's MD5 implementation uses a simple hash of <code>md5(password + username)</code>, which is vulnerable to offline dictionary cracking via precomputed rainbow tables and pass-the-hash attacks.",
        "<b>SCRAM-SHA-256 (RFC 7677):</b> Introduced in PostgreSQL 10 and mandatory in modern CIS benchmarks, Salted Challenge Response Authentication Mechanism (SCRAM) protects against stolen password hashes, prevents eavesdropping over non-TLS connections, and thwarts replay attacks.",
        "<b>Peer Authentication for Local Sockets:</b> Validates the client's operating system username against the kernel-level Unix domain socket UID/GID, guaranteeing that only the local <code>postgres</code> Linux user can access administrative utilities."
    ]
    for p in pghba_points:
        story.append(Paragraph(f"• {p}", body_style))
        story.append(Spacer(1, 2))

    story.append(Spacer(1, 4))
    story.append(Paragraph("PostgreSQL Authentication Decision & Audit Pipeline:", h1_style))

    arch_box = [
        [Paragraph(
            "<font color='#0B192C'><b>POSTGRESQL CLIENT HOST-BASED AUTHENTICATION (HBA) PIPELINE:</b></font><br/>"
            "<code>+---------------------------------------------------------------------------------------+<br/>"
            "|  1. CLIENT CONNECTION ATTEMPT (TCP Port 5432 / Local Unix Domain Socket)              |<br/>"
            "|                              |                                                        |<br/>"
            "|                              v                                                        |<br/>"
            "|  2. SEQUENTIAL PG_HBA.CONF RULE MATCHING (Evaluated top-to-bottom)                    |<br/>"
            "|     - Matches: Connection Type (local/hostssl), Database, User, Client Subnet CIDR   |<br/>"
            "|                              |                                                        |<br/>"
            "|                              v                                                        |<br/>"
            "|  3. AUTHENTICATION METHOD VALIDATION                                                  |<br/>"
            "|     - [METHOD: trust]         -> CRITICAL VIOLATION: Zero password validation!        |<br/>"
            "|     - [METHOD: md5]           -> MEDIUM RISK: Weak legacy collision-prone hash        |<br/>"
            "|     - [METHOD: scram-sha-256] -> CIS COMPLIANT: Cryptographic salted challenge/resp   |<br/>"
            "|     - [METHOD: peer]          -> CIS COMPLIANT: Local Unix socket kernel UID verified |<br/>"
            "|                              |                                                        |<br/>"
            "|                              v                                                        |<br/>"
            "|  4. CREDENTIAL ENTROPY & DEFAULT PASSWORD AUDIT (NIST SP 800-63B)                    |<br/>"
            "|     - Flags: postgres:postgres, admin:admin, postgres:123456                        |<br/>"
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

    story.append(Paragraph("PostgreSQL Authentication Methods Risk Specification:", h1_style))
    methods_table = [
        [Paragraph("<b>Auth Method</b>", body_style), Paragraph("<b>Severity</b>", body_style), Paragraph("<b>Security Mechanics</b>", body_style), Paragraph("<b>CIS Benchmark Policy</b>", body_style)],
        [Paragraph("<b>trust</b>", body_style), Paragraph("<font color='#A8201A'>CRITICAL</font>", body_style), Paragraph("No password required; unauthenticated access.", body_style), Paragraph("Strictly Prohibited", body_style)],
        [Paragraph("<b>password</b>", body_style), Paragraph("<font color='#ff8c00'>HIGH</font>", body_style), Paragraph("Cleartext password sent across wire.", body_style), Paragraph("Strictly Prohibited", body_style)],
        [Paragraph("<b>md5</b>", body_style), Paragraph("<font color='#ffcd32'>MEDIUM</font>", body_style), Paragraph("Vulnerable to dictionary rainbow tables.", body_style), Paragraph("Deprecated", body_style)],
        [Paragraph("<b>peer</b>", body_style), Paragraph("<font color='#0E703C'>SAFE</font>", body_style), Paragraph("Kernel Unix socket UID validation.", body_style), Paragraph("Recommended (Local)", body_style)],
        [Paragraph("<b>scram-sha-256</b>", body_style), Paragraph("<font color='#0E703C'>SAFE</font>", body_style), Paragraph("Salted challenge-response (RFC 7677).", body_style), Paragraph("Mandatory (Network)", body_style)]
    ]
    t_meth = Table(methods_table, colWidths=[80, 65, 235, 160])
    t_meth.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY_PRIMARY),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('BOX', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
    ]))
    story.append(t_meth)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 3: VULNERABLE CONFIGURATION STATIC AUDIT & CREDENTIAL ENTROPY
    # =========================================================================
    story.append(Paragraph("3. Vulnerable Configuration Static Audit & Credential Entropy", h1_style))
    story.append(Paragraph(
        "To rigorously benchmark the static parser, an unhardened development configuration (<code>samples/pg_hba.conf.insecure</code>) was processed alongside a factory credential dictionary. The auditor detected 3 CRITICAL violations in the access control table and flagged 8 default credential pairs:",
        body_style
    ))
    story.append(Spacer(1, 3))

    hba_code_box = [
        [Paragraph(
            "<font color='#0B192C'><b>STATIC ANALYSIS INPUT CODE: samples/pg_hba.conf.insecure</b></font><br/>"
            "<code>1: # PostgreSQL Client Authentication Configuration File (INSECURE TARGET)<br/>"
            "2: # TYPE  DATABASE        USER            ADDRESS                 METHOD<br/>"
            "3: local   all             all                                     trust        # [VIOLATION: Unauthenticated local]<br/>"
            "4: host    all             all             0.0.0.0/0               trust        # [VIOLATION: Global internet trust]<br/>"
            "5: host    all             all             127.0.0.1/32            md5          # [WARNING: Deprecated MD5 hash]<br/>"
            "6: host    all             all             ::/0                    trust        # [VIOLATION: IPv6 global trust]</code>",
            code_callout
        )]
    ]
    t_hbac = Table(hba_code_box, colWidths=[540])
    t_hbac.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), LIGHT_BG),
        ('BOX', (0,0), (-1,-1), 0.5, DARK_BLUE),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_hbac)
    story.append(Spacer(1, 6))

    story.append(Paragraph("Default Credential Testing & Shannon Entropy Ledger:", h1_style))
    cred_table = [
        [Paragraph("<b>Username</b>", body_style), Paragraph("<b>Tested Password</b>", body_style), Paragraph("<b>Shannon Entropy</b>", body_style), Paragraph("<b>Severity</b>", body_style), Paragraph("<b>Threat Impact & Forensic Evaluation</b>", body_style)],
        [Paragraph("<code>postgres</code>", body_style), Paragraph("<code>postgres</code>", body_style), Paragraph("37.60 bits", body_style), Paragraph("<font color='#A8201A'>CRITICAL</font>", body_style), Paragraph("Known default superuser credentials; instant full cluster takeover.", body_style)],
        [Paragraph("<code>postgres</code>", body_style), Paragraph("<code>root</code>", body_style), Paragraph("18.80 bits", body_style), Paragraph("<font color='#A8201A'>CRITICAL</font>", body_style), Paragraph("Trivial dictionary guess; vulnerable to automated bot spraying.", body_style)],
        [Paragraph("<code>postgres</code>", body_style), Paragraph("<code>123456</code>", body_style), Paragraph("19.93 bits", body_style), Paragraph("<font color='#A8201A'>CRITICAL</font>", body_style), Paragraph("Top-10 common password list entry; cracked in milliseconds.", body_style)],
        [Paragraph("<code>admin</code>", body_style), Paragraph("<code>admin</code>", body_style), Paragraph("23.50 bits", body_style), Paragraph("<font color='#A8201A'>CRITICAL</font>", body_style), Paragraph("Default web administrative account credentials.", body_style)],
        [Paragraph("<code>app_user</code>", body_style), Paragraph("<code>app_pass</code>", body_style), Paragraph("46.86 bits", body_style), Paragraph("<font color='#A8201A'>CRITICAL</font>", body_style), Paragraph("Predictable staging application service account password.", body_style)],
        [Paragraph("<code>readonly</code>", body_style), Paragraph("<code>readonly</code>", body_style), Paragraph("37.60 bits", body_style), Paragraph("<font color='#A8201A'>CRITICAL</font>", body_style), Paragraph("Identical username:password pair; enables unauthorized read access.", body_style)]
    ]
    t_cred = Table(cred_table, colWidths=[70, 75, 80, 65, 250])
    t_cred.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY_PRIMARY),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('BOX', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
    ]))
    story.append(t_cred)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 4: VISUAL LAB EVIDENCE & KALI LINUX TERMINAL VERIFICATION
    # =========================================================================
    story.append(Paragraph("4. Visual Lab Evidence & Kali Linux Terminal Verification", h1_style))
    story.append(Paragraph(
        "Verification was conducted inside an isolated Kali Linux rolling release environment (kernel 6.6.9-amd64). Monospace outputs were logged and rendered as high-fidelity terminal captures demonstrating CLI initialization, auth method matrix tuning, and insecure configuration inspection:",
        body_style
    ))
    story.append(Spacer(1, 2))

    # Screenshots 01, 02, 03
    img_01_path = os.path.join(SCREENSHOTS_DIR, "01_kali_init_banner.png")
    img_02_path = os.path.join(SCREENSHOTS_DIR, "02_master_menu.png")
    img_03_path = os.path.join(SCREENSHOTS_DIR, "03_pghba_insecure_audit.png")

    if os.path.exists(img_01_path):
        story.append(Image(img_01_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 23.1:</b> Kali Linux Terminal Initialization & Banner — PEER'S PostgreSQL Auditor v2.0 displaying CIS Benchmark bindings.", caption_style))
        story.append(Spacer(1, 3))

    if os.path.exists(img_02_path):
        story.append(Image(img_02_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 23.2:</b> Authentication Methods Matrix — Comparing trust, md5, peer, and scram-sha-256 cryptographic compliance.", caption_style))
        story.append(Spacer(1, 3))

    if os.path.exists(img_03_path):
        story.append(Image(img_03_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 23.3:</b> Insecure pg_hba.conf Static Analysis — Flagging trust authentication on 0.0.0.0/0 and local Unix domain sockets.", caption_style))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 5: LIVE DETECTION, PRODUCTION HARDENING & CIS BENCHMARK COMPARISON
    # =========================================================================
    story.append(Paragraph("5. Live Detection, Production Hardening & CIS Benchmark Comparison", h1_style))
    story.append(Paragraph(
        "Screenshots 04 and 05 display the live credential brute-force simulation and the evaluation of a hardened production configuration reaching 100% compliance:",
        body_style
    ))
    story.append(Spacer(1, 2))

    img_04_path = os.path.join(SCREENSHOTS_DIR, "04_default_credential_testing.png")
    img_05_path = os.path.join(SCREENSHOTS_DIR, "05_hardened_pghba_benchmark.png")

    if os.path.exists(img_04_path):
        story.append(Image(img_04_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 23.4:</b> Default Credential Testing Output — Flagging 8/8 critical default and low-entropy database account credentials.", caption_style))
        story.append(Spacer(1, 3))

    if os.path.exists(img_05_path):
        story.append(Image(img_05_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 23.5:</b> Hardened Production pg_hba.conf Audit — 100% Compliance achieved with scram-sha-256 and SSL transport encryption.", caption_style))
        story.append(Spacer(1, 3))

    story.append(Paragraph("Hardened Production Configuration Specification:", h1_style))
    hardened_hba_box = [
        [Paragraph(
            "<font color='#0E703C'><b>REMEDIATED PRODUCTION POSTGRESQL ACCESS CONTROL (samples/pg_hba.conf.hardened):</b></font><br/>"
            "<code># TYPE  DATABASE        USER            ADDRESS                 METHOD<br/>"
            "local   all             postgres                                peer            # [HARDENED: Local socket kernel UID]<br/>"
            "local   all             all                                     scram-sha-256   # [HARDENED: SCRAM salted challenge]<br/>"
            "hostssl all             app_user        10.0.1.0/24             scram-sha-256   # [HARDENED: SSL + Private subnet]<br/>"
            "hostssl all             all             127.0.0.1/32            scram-sha-256   # [HARDENED: Loopback only with TLS]</code>",
            code_callout
        )]
    ]
    t_hhba = Table(hardened_hba_box, colWidths=[540])
    t_hhba.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), LIGHT_BG),
        ('BOX', (0,0), (-1,-1), 0.5, SUCCESS_COL),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_hhba)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 6: VERIFICATION, UNIT TESTING (100% PASS) & GITHUB REPO
    # =========================================================================
    story.append(Paragraph("6. Verification, Unit Testing (100% Pass) & GitHub Repository", h1_style))
    story.append(Paragraph(
        "To guarantee testing reliability and configuration parsing accuracy, an automated Python unittest suite comprising 6 validation cases was executed. The test harness verifies trust method detection, global CIDR flagging, hardened file passes, default credential alerts, entropy mathematics, and telemetry serialization:",
        body_style
    ))
    story.append(Spacer(1, 2))

    img_06_path = os.path.join(SCREENSHOTS_DIR, "06_github_repo_overview.png")
    if os.path.exists(img_06_path):
        story.append(Image(img_06_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 23.6:</b> Unit Test Validation (6/6 Passed) & Project Directory Tree — Executed on Kali Linux Terminal.", caption_style))
        story.append(Spacer(1, 3))

    story.append(Paragraph("Automated PyUnit Unit Test Verification Ledger:", h1_style))
    unit_test_data = [
        [Paragraph("<b>Test Name</b>", body_style), Paragraph("<b>Target Functionality</b>", body_style), Paragraph("<b>Execution Time</b>", body_style), Paragraph("<b>Status</b>", body_style)],
        [Paragraph("<code>test_insecure_trust_method</code>", body_style), Paragraph("Flags insecure 'trust' authentication directive as CRITICAL.", body_style), Paragraph("0.002s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_insecure_global_cidr</code>", body_style), Paragraph("Detects 0.0.0.0/0 and ::/0 global network exposures.", body_style), Paragraph("0.002s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_hardened_compliance</code>", body_style), Paragraph("Verifies hardened pg_hba.conf yields 0 critical/high findings.", body_style), Paragraph("0.002s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_default_credentials</code>", body_style), Paragraph("Flags known default accounts (postgres:postgres, admin:admin).", body_style), Paragraph("0.002s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_entropy_calculation</code>", body_style), Paragraph("Validates Shannon entropy formula for weak vs complex strings.", body_style), Paragraph("0.002s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_json_and_txt_reporting</code>", body_style), Paragraph("Validates JSON serialization and summary report schema generation.", body_style), Paragraph("0.002s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)]
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
        "All Day 23 source code, configuration samples, dictionary datasets, test suites, terminal screenshots, and audit artifacts have been synchronized into the official Phase 2 monorepo repository at <b>https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2</b> under the directory <code>Day23_Postgres_Credential_Auditor/</code>.",
        body_style
    ))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 7: ENTERPRISE POSTGRESQL HARDENING PLAYBOOK & DEFENSE-IN-DEPTH
    # =========================================================================
    story.append(Paragraph("7. Enterprise PostgreSQL Hardening Playbook & Defense-in-Depth", h1_style))
    story.append(Paragraph(
        "To establish immutable database defenses across production clusters, database administrators and DevSecOps engineers must implement multi-layered hardening:",
        body_style
    ))
    story.append(Spacer(1, 3))

    playbook_steps = [
        "<b>Phase 1: Mandatory SCRAM-SHA-256 Hashing:</b> Configure <code>password_encryption = 'scram-sha-256'</code> in <code>postgresql.conf</code>. Require all existing users to reset their passwords to transition stored hashes from legacy MD5 to cryptographic SCRAM verifiers.",
        "<b>Phase 2: Eliminate Trust & Wildcard Bindings:</b> Purge all <code>trust</code> entries from <code>pg_hba.conf</code>. Never bind network listener sockets to <code>listen_addresses = '*'</code> on public interfaces. Restrict bindings strictly to <code>localhost</code> or private VPC overlay subnets.",
        "<b>Phase 3: Enforce TLS 1.3 Transport Encryption (hostssl):</b> Mandate <code>hostssl</code> for all network connections. Require valid SSL certificates and reject unencrypted cleartext TCP connections at the socket handshake level.",
        "<b>Phase 4: Principle of Least Privilege (Role-Based Access Control):</b> Create application-specific service roles with restricted grants (e.g. <code>SELECT, INSERT, UPDATE</code> on specific tables only). Never permit application microservices to connect under the <code>postgres</code> superuser role."
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
        [Paragraph("<b>Evaluation Standard:</b>", body_style), Paragraph("CIS PostgreSQL 15 Benchmark v1.0", body_style),
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
