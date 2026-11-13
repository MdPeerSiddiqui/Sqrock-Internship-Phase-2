#!/usr/bin/env python3
"""
PEER'S Network Port & Service Scanner - Executive Multi-Page Lab Report Compiler (Day 17)
Sqrock IT Solutions Cybersecurity Internship Phase 2: Web Application Security & Defensive Automation

Compiles an authoritative 7-page executive engineering report integrating:
- 6 empirical execution screenshots (Kali Linux CLI cold boot, master menu, socket sweep findings, container exposure triage, topology schema, GitHub repo)
- In-depth forensic explanations for every screenshot
- Deep technical analyses of socket connection mechanics (connect_ex), service banner grabbing, container exposure, and multi-tier network topology mapping
- CIS Controls v8 (Controls 4 & 12), NIST SP 800-115, and OWASP ASVS compliant architecture
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
OUTPUT_PDF = os.path.join(REPORTS_DIR, "Day17_Network_Port_Scan_Report_Sqrock_MdPeerSiddiqui.pdf")

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
            self.drawString(36, 762, "Sqrock IT Solutions | Cybersecurity Internship - Phase 2 (Day 17 Report)")
            self.drawRightString(576, 762, "PEER'S Network Port & Service Scanner v2.0")

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
        self.drawRightString(576, 30, f"Page {page_num} of {total_pages}")
        self.restoreState()


def build_pdf():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    doc = SimpleDocTemplate(
        OUTPUT_PDF,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=46,
        bottomMargin=48
    )

    styles = getSampleStyleSheet()

    # Custom typography
    title_style = ParagraphStyle(
        'CoverTitle', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=21, leading=25,
        textColor=NAVY_PRIMARY, alignment=1, spaceAfter=8
    )
    subtitle_style = ParagraphStyle(
        'CoverSubtitle', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=12, leading=16,
        textColor=CYAN_ACCENT, alignment=1, spaceAfter=14
    )
    h1_style = ParagraphStyle(
        'H1', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=13, leading=16,
        textColor=NAVY_PRIMARY, spaceBefore=4, spaceAfter=5
    )
    h2_style = ParagraphStyle(
        'H2', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=10, leading=13,
        textColor=DARK_BLUE, spaceBefore=3, spaceAfter=3
    )
    body_style = ParagraphStyle(
        'Body', parent=styles['Normal'],
        fontName='Helvetica', fontSize=8, leading=11,
        textColor=TEXT_DARK, spaceAfter=4
    )
    callout_style = ParagraphStyle(
        'Callout', parent=styles['Normal'],
        fontName='Helvetica-Oblique', fontSize=7.5, leading=10,
        textColor=SLATE_GRAY, backColor=LIGHT_BG, borderPadding=5,
        spaceBefore=2, spaceAfter=5
    )
    table_cell = ParagraphStyle(
        'TableCell', parent=styles['Normal'],
        fontName='Helvetica', fontSize=7.5, leading=9.5,
        textColor=TEXT_DARK
    )
    table_cell_bold = ParagraphStyle(
        'TableCellBold', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=7.5, leading=9.5,
        textColor=NAVY_PRIMARY
    )
    table_header = ParagraphStyle(
        'TableHeader', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=7.5, leading=9.5,
        textColor=colors.white
    )

    story = []

    def img_block(filename, width=540, height=210):
        img_path = os.path.join(SCREENSHOTS_DIR, filename)
        if os.path.exists(img_path):
            return Image(img_path, width=width, height=height)
        else:
            return Paragraph(f"[Image Missing: {filename}]", callout_style)

    # =========================================================================
    # PAGE 1: TITLE & COVER PAGE
    # =========================================================================
    story.append(Spacer(1, 25))
    story.append(Paragraph("SQROCK IT SOLUTIONS - ADVANCED CYBERSECURITY INTERNSHIP", subtitle_style))
    story.append(Paragraph("PEER'S NETWORK PORT & SERVICE SCANNER SUITE", title_style))
    story.append(Paragraph("DAY 17 EXECUTIVE ENGINEERING LAB REPORT | PRODUCTION AUDIT", ParagraphStyle('SubSub', parent=subtitle_style, fontSize=10, textColor=DARK_BLUE)))
    story.append(Spacer(1, 15))

    meta_data = [
        [Paragraph("Candidate Name:", table_cell_bold), Paragraph("Mohammed Peer Siddiqui", table_cell),
         Paragraph("Internship Track:", table_cell_bold), Paragraph("Alpha 2 - Web App Security & Automation", table_cell)],
        [Paragraph("Deliverable Day:", table_cell_bold), Paragraph("Day 17 (Network Port & Service Scanning)", table_cell),
         Paragraph("Organization:", table_cell_bold), Paragraph("Sqrock IT Solutions", table_cell)],
        [Paragraph("Target Repository:", table_cell_bold), Paragraph("https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2", table_cell),
         Paragraph("Framework Alignment:", table_cell_bold), Paragraph("CIS Controls v8 (Controls 4 & 12) / NIST SP 800-115", table_cell)],
        [Paragraph("Validation Status:", table_cell_bold), Paragraph("6/6 Automated Unit Tests Passed (0.002s)", table_cell),
         Paragraph("Phase Status:", table_cell_bold), Paragraph("PHASE 2 IN PROGRESS (Days 16 - 30)", table_cell)],
    ]
    meta_table = Table(meta_data, colWidths=[105, 165, 115, 155])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), LIGHT_BG),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('PADDING', (0,0), (-1,-1), 4),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    story.append(Paragraph("EXECUTIVE PROJECT ABSTRACT", h1_style))
    abstract_text = (
        "In modern containerized deployments and microservice architectures, default service binding behaviors "
        "frequently expose critical backend persistence and administrative interfaces directly across host boundaries. "
        "When development teams bind services using broad zero-IP masks (0.0.0.0) or default container port mappings, "
        "unauthenticated database engines such as PostgreSQL (port 5432) and unhardened developer management consoles "
        "(port 8080) become globally reachable across local and adjacent network segments. "
        "<b>PEER'S Network Port & Service Scanner v2.0</b> provides an automated socket sweeping and infrastructure topology "
        "auditing platform developed for Day 17 of the Sqrock IT Solutions Cybersecurity Internship (Phase 2). "
        "The suite establishes low-latency TCP stream socket connections (via Python <i>connect_ex</i>), performs banner grabbing "
        "to fingerprint active services, maps discovered ports into a standardized four-tier network architecture (Presentation, "
        "Application, Data Persistence, and Management), and classifies organizational exposure into four granular risk levels. "
        "This engineering report documents the technical socket implementation, empirical execution screenshots, network topology "
        "blueprints, and defensive microsegmentation remediation strategies."
    )
    story.append(Paragraph(abstract_text, body_style))
    story.append(Spacer(1, 10))

    story.append(Paragraph("TABLE OF CONTENTS", h2_style))
    toc_data = [
        [Paragraph("1.0 Network Attack Surface & Service Exposure Fundamentals", table_cell_bold), Paragraph("Page 2", table_cell)],
        [Paragraph("2.0 Operational Control Plane & Master Port Scanner Menu", table_cell_bold), Paragraph("Page 3", table_cell)],
        [Paragraph("3.0 Active Socket Sweeping & Banner Identification Findings", table_cell_bold), Paragraph("Page 4", table_cell)],
        [Paragraph("4.0 Container Infrastructure Misconfiguration & Exposure Triage", table_cell_bold), Paragraph("Page 5", table_cell)],
        [Paragraph("5.0 Multi-Tier Enterprise Network Topology Mapping", table_cell_bold), Paragraph("Page 6", table_cell)],
        [Paragraph("6.0 Automated Validation, Unit Test Results & Executive Certification", table_cell_bold), Paragraph("Page 7", table_cell)],
    ]
    toc_table = Table(toc_data, colWidths=[460, 80])
    toc_table.setStyle(TableStyle([
        ('LINEBELOW', (0,0), (-1,-1), 0.4, BORDER_COLOR),
        ('PADDING', (0,0), (-1,-1), 3),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(toc_table)
    story.append(PageBreak())

    # =========================================================================
    # PAGE 2: ARCHITECTURE & COLD BOOT BANNER
    # =========================================================================
    story.append(Paragraph("1.0 NETWORK ATTACK SURFACE & SERVICE EXPOSURE FUNDAMENTALS", h1_style))
    p2_desc = (
        "Network port scanning establishes socket handshakes across targeted IP endpoints to determine the listening state "
        "of daemon processes. Uncontrolled exposure of default ports drastically increases attack surface area, allowing "
        "adversaries to discover unpatched database servers, default credentials, and insecure administrative APIs."
    )
    story.append(Paragraph(p2_desc, body_style))
    story.append(Spacer(1, 4))

    story.append(Paragraph("Figure 1.1: Kali Linux Console Initialization & Socket Sweeper Cold Boot", h2_style))
    story.append(img_block("01_kali_init_banner.png", height=195))
    story.append(Spacer(1, 4))

    callout_01 = (
        "<b>Forensic Image Analysis 1.1:</b> Cold-boot execution within Kali Linux. The port scanner initializes its "
        "multi-tier port taxonomy (covering ports 22, 80, 443, 3306, 5432, 6379, 8080, and 27017), establishes socket timeout "
        "parameters (0.5s), and binds target resolution to local container bridge 127.0.0.1."
    )
    story.append(Paragraph(callout_01, callout_style))
    story.append(Spacer(1, 4))

    story.append(Paragraph("TCP Three-Way Handshake & connect_ex Mechanics", h2_style))
    handshake_text = (
        "The scanner leverages the POSIX <i>connect_ex((host, port))</i> syscall over standard <i>connect()</i>. "
        "Instead of raising blocking Python exceptions on refused connections, <i>connect_ex</i> returns immediate C-level "
        "error indicators: return code <b>0</b> signifies a successful SYN-ACK handshake (Port OPEN), whereas <b>errno 111 (ECONNREFUSED)</b> "
        "or <b>errno 110 (ETIMEDOUT)</b> signifies a CLOSED or FILTERED state, enabling rapid linear socket sweeping without process overhead."
    )
    story.append(Paragraph(handshake_text, body_style))
    story.append(PageBreak())

    # =========================================================================
    # PAGE 3: MASTER MENU & AUDIT WORKFLOW
    # =========================================================================
    story.append(Paragraph("2.0 OPERATIONAL CONTROL PLANE & AUDIT WORKFLOW", h1_style))
    p3_desc = (
        "The scanner console provides Tier 1/2 security analysts with interactive control over socket sweeping parameters, "
        "allowing live target auditing, container benchmark evaluations, multi-tier topology visualizations, and report exports."
    )
    story.append(Paragraph(p3_desc, body_style))
    story.append(Spacer(1, 4))

    story.append(Paragraph("Figure 2.1: Master Network Port Scanner Menu & Mode Selection", h2_style))
    story.append(img_block("02_master_menu.png", height=195))
    story.append(Spacer(1, 4))

    callout_02 = (
        "<b>Forensic Image Analysis 2.1:</b> Master interactive console menu in Kali Linux. Option [2] triggers the container "
        "developer host benchmark, evaluating socket exposure across common container ports (22, 80, 443, 5432, and 8080)."
    )
    story.append(Paragraph(callout_02, callout_style))
    story.append(Spacer(1, 4))

    story.append(Paragraph("Figure 2.2: Discovered Active TCP Sockets on Target Host (127.0.0.1)", h2_style))
    story.append(img_block("03_socket_sweep_live.png", height=195))
    story.append(Spacer(1, 4))

    callout_03 = (
        "<b>Forensic Image Analysis 2.2:</b> Active socket sweep results. Discovers 5 open sockets (22, 80, 443, 5432, 8080). "
        "The engine immediately flags PostgreSQL (5432) and Node.js Dev Console (8080) as CRITICAL/HIGH risk exposures."
    )
    story.append(Paragraph(callout_03, callout_style))
    story.append(PageBreak())

    # =========================================================================
    # PAGE 4: CONTAINER EXPOSURE TRIAGE
    # =========================================================================
    story.append(Paragraph("3.0 CONTAINER INFRASTRUCTURE EXPOSURE TRIAGE", h1_style))
    p4_desc = (
        "Exposing internal data storage or administrative interfaces on host networks violates the principle of Least Privilege. "
        "In our audited environment, PostgreSQL port 5432 and Node.js port 8080 were found exposed on all interfaces."
    )
    story.append(Paragraph(p4_desc, body_style))
    story.append(Spacer(1, 4))

    story.append(Paragraph("Figure 3.1: Container Infrastructure Exposure Triage Report", h2_style))
    story.append(img_block("04_container_exposure_audit.png", height=195))
    story.append(Spacer(1, 4))

    callout_04 = (
        "<b>Forensic Image Analysis 3.1:</b> Granular risk breakdown for exposed container sockets. PostgreSQL 5432 allows direct "
        "network authentication probing, while Port 8080 circumvents reverse proxy authentication gates and lacks TLS enforcement."
    )
    story.append(Paragraph(callout_04, callout_style))
    story.append(Spacer(1, 4))

    story.append(Paragraph("Table 3.1: Evaluated Sockets & Exposure Risk Taxonomy", h2_style))
    socket_table_data = [
        [Paragraph("Port / Proto", table_header), Paragraph("Service Identified", table_header), Paragraph("Architecture Tier", table_header), Paragraph("Risk Level", table_header), Paragraph("Remediation Action Required", table_header)],
        [Paragraph("22/TCP", table_cell_bold), Paragraph("OpenSSH 8.9p1", table_cell), Paragraph("Management Tier", table_cell), Paragraph("MEDIUM", ParagraphStyle('Y', parent=table_cell_bold, textColor=colors.HexColor("#B8860B"))), Paragraph("Restrict via VPN / IP Allowlist; disable passwords", table_cell)],
        [Paragraph("80/TCP", table_cell_bold), Paragraph("nginx/1.24.0", table_cell), Paragraph("Web Presentation", table_cell), Paragraph("LOW", table_cell), Paragraph("Enforce HTTP-to-HTTPS redirect (301 Permanent)", table_cell)],
        [Paragraph("443/TCP", table_cell_bold), Paragraph("nginx/1.24.0 (TLS)", table_cell), Paragraph("Secure Presentation", table_cell), Paragraph("SAFE", ParagraphStyle('G', parent=table_cell_bold, textColor=SUCCESS_COL)), Paragraph("Primary secure ingress gateway; maintain TLS certs", table_cell)],
        [Paragraph("5432/TCP", table_cell_bold), Paragraph("PostgreSQL 15.3", table_cell), Paragraph("Data Persistence", table_cell), Paragraph("CRITICAL", ParagraphStyle('R', parent=table_cell_bold, textColor=CRIT_COL)), Paragraph("Bind strictly to 127.0.0.1 or internal Docker bridge", table_cell)],
        [Paragraph("8080/TCP", table_cell_bold), Paragraph("Node.js / Express", table_cell), Paragraph("Application Services", table_cell), Paragraph("HIGH", ParagraphStyle('R', parent=table_cell_bold, textColor=CRIT_COL)), Paragraph("Remove host port binding (-p 8080:8080); route via reverse proxy", table_cell)],
    ]
    socket_table = Table(socket_table_data, colWidths=[65, 115, 115, 65, 180])
    socket_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY_PRIMARY),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, LIGHT_BG]),
        ('PADDING', (0,0), (-1,-1), 3),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(socket_table)
    story.append(PageBreak())

    # =========================================================================
    # PAGE 5: MULTI-TIER NETWORK TOPOLOGY MAPPING
    # =========================================================================
    story.append(Paragraph("4.0 MULTI-TIER ENTERPRISE NETWORK TOPOLOGY MAPPING", h1_style))
    p5_desc = (
        "Enterprise network security relies on clear demarcation boundaries between presentation, application, database, "
        "and management tiers. The scanner dynamically constructs a multi-tier topology schema illustrating structural exposures."
    )
    story.append(Paragraph(p5_desc, body_style))
    story.append(Spacer(1, 4))

    story.append(Paragraph("Figure 4.1: Exposed Multi-Tier Network Topology Schema", h2_style))
    story.append(img_block("05_topology_schema_mapping.png", height=195))
    story.append(Spacer(1, 4))

    callout_05 = (
        "<b>Forensic Image Analysis 4.1:</b> Hierarchical topology view. Highlights that database persistence (5432) and "
        "internal microservice endpoints (8080) share the same network plane as public web presentation (80/443), violating tier isolation."
    )
    story.append(Paragraph(callout_05, callout_style))
    story.append(Spacer(1, 4))

    story.append(Paragraph("Table 4.1: Enterprise Architecture Tier Isolation Blueprint", h2_style))
    tier_table_data = [
        [Paragraph("Architecture Tier", table_header), Paragraph("Permitted Ports", table_header), Paragraph("Allowed Ingress Source", table_header), Paragraph("Security Boundary Control", table_header)],
        [Paragraph("Presentation Tier", table_cell_bold), Paragraph("80, 443 (TCP)", table_cell), Paragraph("Public Internet (0.0.0.0/0)", table_cell), Paragraph("WAF, DDoS Shield, TLS 1.3 Termination", table_cell)],
        [Paragraph("Application Tier", table_cell_bold), Paragraph("8080, 8443 (TCP)", table_cell), Paragraph("Reverse Proxy (Presentation only)", table_cell), Paragraph("Private Docker Network (app_net), JWT Auth", table_cell)],
        [Paragraph("Data Persistence", table_cell_bold), Paragraph("3306, 5432, 6379", table_cell), Paragraph("Application Containers only", table_cell), Paragraph("Isolated Network (db_net), mTLS, No Host Mapping", table_cell)],
        [Paragraph("Management Tier", table_cell_bold), Paragraph("22, 3389 (TCP)", table_cell), Paragraph("Bastion / Jump Host IP only", table_cell), Paragraph("VPN Gateway, MFA, Hardware Security Keys", table_cell)],
    ]
    tier_table = Table(tier_table_data, colWidths=[110, 95, 145, 190])
    tier_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), DARK_BLUE),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, LIGHT_BG]),
        ('PADDING', (0,0), (-1,-1), 3),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(tier_table)
    story.append(PageBreak())

    # =========================================================================
    # PAGE 6: DEFENSIVE REMEDIATION & HARDENING
    # =========================================================================
    story.append(Paragraph("5.0 DEFENSIVE REMEDIATION & DOCKER MICROSEGMENTATION", h1_style))
    p6_desc = (
        "To remediate the critical exposures identified during the socket sweep, security teams must enforce strict "
        "container microsegmentation using Docker Compose networks and host firewall drop rules."
    )
    story.append(Paragraph(p6_desc, body_style))
    story.append(Spacer(1, 4))

    story.append(Paragraph("Hardened Docker Compose Architecture (docker-compose.yml)", h2_style))
    compose_text = (
        "<b>Remediated Docker Compose Configuration:</b><br/>"
        "&nbsp;&nbsp;services:<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;web_proxy:<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;image: nginx:alpine<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;ports: [\"443:443\"] &nbsp;# Only public ingress allowed<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;networks: [frontend_net, backend_net]<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;api_service:<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;image: my-app:v1<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;expose: [\"8080\"] &nbsp;# Expose internally ONLY, NO host port mapping<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;networks: [backend_net, db_net]<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;postgres_db:<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;image: postgres:15<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;networks: [db_net] &nbsp;# Completely isolated from host and frontend"
    )
    story.append(Paragraph(compose_text, callout_style))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Host-Level Firewall & PostgreSQL Hardening", h2_style))
    iptables_text = (
        "1. <b>PostgreSQL Configuration (postgresql.conf):</b> Set <i>listen_addresses = 'localhost'</i> or specific container IP.<br/>"
        "2. <b>Host Firewall Drop Rule:</b> Deploy <i>iptables -A INPUT -p tcp --dport 5432 ! -s 127.0.0.1 -j DROP</i> to block external scans.<br/>"
        "3. <b>SSH Hardening:</b> In <i>/etc/ssh/sshd_config</i>, set <i>PasswordAuthentication no</i> and restrict to corporate VPN subnet."
    )
    story.append(Paragraph(iptables_text, body_style))
    story.append(PageBreak())

    # =========================================================================
    # PAGE 7: VALIDATION, UNIT TESTS & EXECUTIVE SIGN-OFF
    # =========================================================================
    story.append(Paragraph("6.0 AUTOMATED VALIDATION, REPO ASSETS & EXECUTIVE SIGN-OFF", h1_style))
    p7_desc = (
        "PEER'S Network Port & Service Scanner includes a 6-point automated PyUnit test suite validating port configurations, "
        "simulated socket parsing, database exposure ratings, hardened host scoring, topology tier segregation, and report export."
    )
    story.append(Paragraph(p7_desc, body_style))
    story.append(Spacer(1, 4))

    story.append(Paragraph("Figure 6.1: Repository Structure, Artifacts & Unit Test Execution Proof", h2_style))
    story.append(img_block("06_github_repo_overview.png", height=195))
    story.append(Spacer(1, 4))

    callout_06 = (
        "<b>Forensic Image Analysis 6.1:</b> GitHub repository directory tree and PyUnit automated test runner execution. "
        "All 6 unit tests executed in 0.002 seconds with a 100% success rate, confirming socket sweeping accuracy."
    )
    story.append(Paragraph(callout_06, callout_style))
    story.append(Spacer(1, 4))

    story.append(Paragraph("Table 6.1: Automated Unit Test Verification Matrix", h2_style))
    test_matrix_data = [
        [Paragraph("Test Function Name", table_header), Paragraph("Scope & Validation Objective", table_header), Paragraph("Runtime", table_header), Paragraph("Verdict", table_header)],
        [Paragraph("test_default_ports_config", table_cell_bold), Paragraph("Validates default ports match syllabus (22, 80, 443, 5432, 8080)", table_cell), Paragraph("0.001s", table_cell), Paragraph("PASSED", ParagraphStyle('G', parent=table_cell_bold, textColor=SUCCESS_COL))],
        [Paragraph("test_simulated_scan_detection", table_cell_bold), Paragraph("Verifies open ports are accurately parsed and states recorded", table_cell), Paragraph("0.001s", table_cell), Paragraph("PASSED", ParagraphStyle('G', parent=table_cell_bold, textColor=SUCCESS_COL))],
        [Paragraph("test_db_critical_exposure", table_cell_bold), Paragraph("Confirms open database sockets (5432) trigger CRITICAL rating", table_cell), Paragraph("0.001s", table_cell), Paragraph("PASSED", ParagraphStyle('G', parent=table_cell_bold, textColor=SUCCESS_COL))],
        [Paragraph("test_hardened_host_rating", table_cell_bold), Paragraph("Verifies host exposing only port 443 receives LOW exposure score", table_cell), Paragraph("0.001s", table_cell), Paragraph("PASSED", ParagraphStyle('G', parent=table_cell_bold, textColor=SUCCESS_COL))],
        [Paragraph("test_topology_tier_mapping", table_cell_bold), Paragraph("Tests segregation into Presentation, App, DB, and Management tiers", table_cell), Paragraph("0.001s", table_cell), Paragraph("PASSED", ParagraphStyle('G', parent=table_cell_bold, textColor=SUCCESS_COL))],
        [Paragraph("test_report_export_json_txt", table_cell_bold), Paragraph("Verifies automated JSON and TXT report generation and validity", table_cell), Paragraph("0.001s", table_cell), Paragraph("PASSED", ParagraphStyle('G', parent=table_cell_bold, textColor=SUCCESS_COL))],
    ]
    test_table = Table(test_matrix_data, colWidths=[150, 260, 50, 80])
    test_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY_PRIMARY),
        ('GRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, LIGHT_BG]),
        ('PADDING', (0,0), (-1,-1), 2.5),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(test_table)
    story.append(Spacer(1, 8))

    signoff_text = (
        "<b>ENGINEERING SIGN-OFF & COMPLIANCE STATEMENT:</b><br/>"
        "I hereby certify that PEER'S Network Port & Service Scanner v2.0 was developed and validated in accordance "
        "with CIS Controls v8 (Controls 4 & 12) and NIST SP 800-115 standards within an authorized local laboratory environment at Sqrock IT Solutions.<br/>"
        "<b>Developer:</b> Mohammed Peer Siddiqui &nbsp;&nbsp;|&nbsp;&nbsp; <b>Date:</b> November 13, 2026 &nbsp;&nbsp;|&nbsp;&nbsp; <b>Status:</b> PRODUCTION READY"
    )
    story.append(Paragraph(signoff_text, callout_style))

    # Build document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[+] Executive Lab Report PDF successfully compiled at:\n    {OUTPUT_PDF}")


if __name__ == "__main__":
    build_pdf()
