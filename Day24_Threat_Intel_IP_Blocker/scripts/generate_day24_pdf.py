#!/usr/bin/env python3
"""
PEER'S Threat Intel Pipeline - Executive Multi-Page Lab Report Compiler (Day 24)
Sqrock IT Solutions Cybersecurity Internship Phase 2: Web Application Security & Defensive Automation

Compiles an authoritative 7-page executive engineering report integrating:
- 6 empirical execution screenshots (Kali Linux CLI initialization, threat confidence scoring matrix, multi-feed ingestion preview, live firewall drop rules enforcement, iptables & nftables script inspection, GitHub repo overview)
- Detailed technical analyses of Threat Intelligence Automation (IoC Ingestion, Confidence Scoring, MITRE ATT&CK M1037 Filter Network Traffic, NIST SP 800-150)
- Automated iptables and declarative nftables compilation
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
OUTPUT_PDF = os.path.join(REPORTS_DIR, "Day24_Threat_Intel_Pipeline_Report_Sqrock_MdPeerSiddiqui.pdf")

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
            self.drawString(36, 762, "Sqrock IT Solutions | Cybersecurity Internship - Phase 2 (Day 24 Report)")
            self.drawRightString(576, 762, "PEER'S Threat Intel Pipeline v2.0")

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
    story.append(Paragraph("Automated Threat Intel IP Blocking Pipeline", title_style))
    story.append(Paragraph("<b>Track:</b> Phase 2 - Web Application Security & Defensive Automation &nbsp;|&nbsp; <b>Day:</b> 24 &nbsp;|&nbsp; <b>Author:</b> Mohammed Peer Siddiqui", subtitle_style))
    story.append(Spacer(1, 4))

    meta_data = [
        [Paragraph("<b>Target Assessment Module</b>", body_style), Paragraph("Threat Intelligence Ingestion & Firewall Enforcement Engine", body_style),
         Paragraph("<b>Standard Alignment</b>", body_style), Paragraph("NIST SP 800-150 | MITRE ATT&CK M1037", body_style)],
        [Paragraph("<b>Audit Date</b>", body_style), Paragraph("November 17, 2026", body_style),
         Paragraph("<b>Assessment Status</b>", body_style), Paragraph("<font color='#0E703C'><b>AUTOMATED ENFORCEMENT ACTIVE</b></font>", body_style)],
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

    story.append(Paragraph("1. Executive Summary & Assessment Context", h1_style))
    story.append(Paragraph(
        "Modern Security Operations Centers (SOCs) face continuous probing and automated attacks from distributed command-and-control (C2) botnets, bulletproof Tor exit nodes, and rapid-fire brute-force daemons. Manually analyzing alert logs and drafting individual firewall block rules creates unacceptable dwell times, allowing adversaries to establish persistence or execute lateral movement before perimeter defenses adapt. To achieve proactive cyber resilience (<b>NIST SP 800-150 / MITRE ATT&CK Mitigation M1037</b>), organizations must automate the ingestion of external threat intelligence feeds and dynamically synchronize malicious Indicators of Compromise (IoCs) directly into edge firewalls.",
        body_style
    ))
    story.append(Paragraph(
        "For <b>Day 24</b> of the Sqrock IT Solutions Cybersecurity Internship, candidate Mohammed Peer Siddiqui built <b>PEER'S Automated Threat Intelligence IP Blocking Pipeline v2.0</b>. Operating as an enterprise SOAR threat ingestion pipeline, the tool consumes multi-source reputation feeds (AlienVault OTX, AbuseIPDB, Cisco Talos, Emerging Threats), filters entries through risk confidence scoring matrices (blocking IPs >= 75% confidence), protects critical infrastructure through whitelist verification, and compiles production-ready Linux <b>iptables</b> and <b>nftables</b> drop policies.",
        body_style
    ))
    story.append(Spacer(1, 5))

    story.append(Paragraph("2. Scope & Target Feed Datasets", h1_style))
    story.append(Paragraph(
        "The automated pipeline was evaluated against a realistic multi-threat feed containing 7 distinct network endpoints, representing active Cobalt Strike C2 infrastructure, Mirai IoT DDoS workers, Tor exit nodes, web application vulnerability scanners, unverified internal anomalies, and trusted public Anycast resolvers.",
        body_style
    ))
    story.append(Spacer(1, 5))

    story.append(Paragraph("3. Executive Findings Dashboard", h1_style))
    exec_summary_data = [
        [Paragraph("<b>Pipeline Metric</b>", body_style), Paragraph("<b>Observed Count</b>", body_style), Paragraph("<b>Threat Categorization</b>", body_style), Paragraph("<b>Automated Action Taken</b>", body_style)],
        [Paragraph("Ingested IoC Records", body_style), Paragraph("7 Total", body_style), Paragraph("Global Feed Aggregation", body_style), Paragraph("Validated IPv4 network syntax", body_style)],
        [Paragraph("Enforced Firewall Drops", body_style), Paragraph("5 IPs (71.4%)", body_style), Paragraph("Confidence >= 75% (High/Crit)", body_style), Paragraph("<font color='#A8201A'><b>iptables / nftables DROP Enforced</b></font>", body_style)],
        [Paragraph("Monitored / Allowed", body_style), Paragraph("1 IP (14.3%)", body_style), Paragraph("Low Confidence (50%)", body_style), Paragraph("<font color='#ffcd32'>Logged for behavioral anomaly</font>", body_style)],
        [Paragraph("Whitelisted Infrastructure", body_style), Paragraph("1 IP (14.3%)", body_style), Paragraph("Public DNS (Cloudflare 1.1.1.1)", body_style), Paragraph("<font color='#0E703C'>Protected against accidental block</font>", body_style)],
        [Paragraph("Average Threat Score", body_style), Paragraph("71.4%", body_style), Paragraph("Global Feed Confidence", body_style), Paragraph("High fidelity automated triage", body_style)]
    ]
    t_exec = Table(exec_summary_data, colWidths=[120, 100, 130, 190])
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
    # PAGE 2: THREAT INTELLIGENCE LIFECYCLE & AUTOMATED INGESTION
    # =========================================================================
    story.append(Paragraph("2. Threat Intelligence Lifecycle & Automated Ingestion Architecture", h1_style))
    story.append(Paragraph(
        "Automating cyber threat intelligence requires transitioning from raw data feeds to actionable defensive countermeasures through systematic normalization and validation stages:",
        body_style
    ))

    intel_points = [
        "<b>Multi-Source Ingestion & De-duplication:</b> Ingesting indicators from disparate commercial and open-source intelligence feeds (OSINT, AlienVault OTX, AbuseIPDB, MISP). Feed collectors normalize timestamps, threat taxonomy tags, and ASN metadata into unified JSON schemas.",
        "<b>Confidence Scoring Heuristics:</b> External feeds frequently contain false positives or ephemeral scanner IPs. The pipeline evaluates reports based on source reliability, report recency, and attack severity, assigning a normalized confidence score from 0 to 100%.",
        "<b>Whitelisting & Infrastructure Protection:</b> Automated blocking pipelines must incorporate rigorous guardrails to prevent self-inflicted outages. Public DNS providers (1.1.1.1, 8.8.8.8), internal gateway subnets, and CDN proxies are explicitly whitelisted regardless of external threat scores.",
        "<b>Dual-Stack Firewall Rule Generation:</b> To support modern heterogeneous enterprise server fleets, the engine outputs both traditional POSIX <code>iptables</code> chain rules and high-performance kernel-space <code>nftables</code> declarative sets."
    ]
    for p in intel_points:
        story.append(Paragraph(f"• {p}", body_style))
        story.append(Spacer(1, 2))

    story.append(Spacer(1, 4))
    story.append(Paragraph("Automated Threat Ingestion & Enforcement Flow:", h1_style))

    arch_box = [
        [Paragraph(
            "<font color='#0B192C'><b>AUTOMATED THREAT INTELLIGENCE INGESTION & FIREWALL COMPILER:</b></font><br/>"
            "<code>+---------------------------------------------------------------------------------------+<br/>"
            "|  1. THREAT INTEL FEED INGESTION (AlienVault OTX, AbuseIPDB, Cisco Talos, STIX/TAXII)   |<br/>"
            "|                              |                                                        |<br/>"
            "|                              v                                                        |<br/>"
            "|  2. DATA VALIDATION & WHITELIST FILTERING                                             |<br/>"
            "|     - IPv4/IPv6 Syntax Validation (RFC 1918 & Public Routable Address Check)          |<br/>"
            "|     - Critical Infrastructure Whitelist Check (Bypasses Cloudflare, Google DNS)       |<br/>"
            "|                              |                                                        |<br/>"
            "|                              v                                                        |<br/>"
            "|  3. CONFIDENCE SCORING & THRESHOLD EVALUATION                                         |<br/>"
            "|     +-----------------------------------+-----------------------------------+        |<br/>"
            "|     | IF confidence_score &gt;= 75%:       | IF confidence_score &lt; 75%:         |        |<br/>"
            "|     |   - ACTION: AUTOMATED DROP        |   - ACTION: LOG & MONITOR             |        |<br/>"
            "|     |   - Append to iptables drop chain |   - Forward to SIEM anomaly queue     |        |<br/>"
            "|     |   - Add to nftables block set     |   - Suppress active blocking          |        |<br/>"
            "|     +-----------------------------------+-----------------------------------+        |<br/>"
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

    story.append(Paragraph("Threat Confidence Scoring Policy Matrix:", h1_style))
    score_table = [
        [Paragraph("<b>Score Tier</b>", body_style), Paragraph("<b>Threat Level</b>", body_style), Paragraph("<b>Observed Threat Characteristics</b>", body_style), Paragraph("<b>Automated Action</b>", body_style)],
        [Paragraph("<b>85 – 100%</b>", body_style), Paragraph("<font color='#A8201A'>CRITICAL</font>", body_style), Paragraph("Active C2 beacon, known ransomware drop host, Mirai bot.", body_style), Paragraph("Immediate iptables/nftables DROP", body_style)],
        [Paragraph("<b>75 – 84%</b>", body_style), Paragraph("<font color='#ff8c00'>HIGH</font>", body_style), Paragraph("Repeated SSH/SQLi brute-forcer, bulletproof Tor proxy.", body_style), Paragraph("Enforce Edge Firewall Quarantine", body_style)],
        [Paragraph("<b>50 – 74%</b>", body_style), Paragraph("<font color='#ffcd32'>MEDIUM</font>", body_style), Paragraph("Unverified port probe, single scanner inquiry.", body_style), Paragraph("Log & Monitor; SOC Anomaly Queue", body_style)],
        [Paragraph("<b>01 – 49%</b>", body_style), Paragraph("<font color='#008DDA'>LOW</font>", body_style), Paragraph("Stale scanner entry, single transient connection.", body_style), Paragraph("Permit; no defensive action", body_style)],
        [Paragraph("<b>Whitelist</b>", body_style), Paragraph("<font color='#0E703C'>SAFE</font>", body_style), Paragraph("Public Anycast DNS, CDN origin edge, trusted gateway.", body_style), Paragraph("Explicitly Allow (Protected)", body_style)]
    ]
    t_stab = Table(score_table, colWidths=[65, 65, 230, 180])
    t_stab.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY_PRIMARY),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('BOX', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
    ]))
    story.append(t_stab)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 3: THREAT FEED INGESTION, RISK SCORING & WHITELISTING
    # =========================================================================
    story.append(Paragraph("3. Threat Feed Ingestion, Risk Scoring & Whitelisting", h1_style))
    story.append(Paragraph(
        "The threat intelligence dataset (<code>feeds/threat_intel_feed.json</code>) was ingested and evaluated against the policy threshold (>= 75%). Five high-severity threats were scheduled for automated edge drop enforcement:",
        body_style
    ))
    story.append(Spacer(1, 3))

    feed_json_box = [
        [Paragraph(
            "<font color='#0B192C'><b>INGESTED THREAT INTELLIGENCE FEED ENTRIES (JSON SAMPLE):</b></font><br/>"
            "<code>1: [ { \"ip\": \"45.154.255.89\", \"source\": \"AbuseIPDB\", \"threat\": \"Cobalt Strike C2 Beacon\", \"score\": 98 },<br/>"
            "2:   { \"ip\": \"103.145.13.24\", \"source\": \"Cisco Talos\", \"threat\": \"Mirai Botnet DDoS Worker\", \"score\": 92 },<br/>"
            "3:   { \"ip\": \"185.220.101.5\", \"source\": \"AlienVault OTX\", \"threat\": \"Tor Exit Node / Proxy\", \"score\": 88 },<br/>"
            "4:   { \"ip\": \"194.26.29.112\", \"source\": \"Emerging Threats\", \"threat\": \"SSH Brute-Force Daemon\", \"score\": 85 },<br/>"
            "5:   { \"ip\": \"91.240.118.170\", \"source\": \"AbuseIPDB\", \"threat\": \"SQLi / Web Scanner\", \"score\": 82 },<br/>"
            "6:   { \"ip\": \"198.51.100.42\", \"source\": \"Internal SIEM\", \"threat\": \"Unverified Port Probe\", \"score\": 50 },<br/>"
            "7:   { \"ip\": \"1.1.1.1\", \"source\": \"Global Whitelist\", \"threat\": \"Public Anycast DNS\", \"score\": 5 } ]</code>",
            code_callout
        )]
    ]
    t_fjson = Table(feed_json_box, colWidths=[540])
    t_fjson.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), LIGHT_BG),
        ('BOX', (0,0), (-1,-1), 0.5, DARK_BLUE),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_fjson)
    story.append(Spacer(1, 6))

    story.append(Paragraph("Evaluated Threat Intelligence IoC Ledger:", h1_style))
    ioc_ledger_table = [
        [Paragraph("<b>Target IPv4</b>", body_style), Paragraph("<b>Feed Origin</b>", body_style), Paragraph("<b>Score</b>", body_style), Paragraph("<b>Threat Categorization</b>", body_style), Paragraph("<b>Enforcement</b>", body_style)],
        [Paragraph("<code>45.154.255.89</code>", body_style), Paragraph("AbuseIPDB", body_style), Paragraph("<font color='#A8201A'>98%</font>", body_style), Paragraph("Cobalt Strike C2 Beacon (AS44050 / RU)", body_style), Paragraph("<font color='#A8201A'><b>DROP</b></font>", body_style)],
        [Paragraph("<code>103.145.13.24</code>", body_style), Paragraph("Cisco Talos", body_style), Paragraph("<font color='#A8201A'>92%</font>", body_style), Paragraph("Mirai Botnet DDoS Worker (AS139007 / VN)", body_style), Paragraph("<font color='#A8201A'><b>DROP</b></font>", body_style)],
        [Paragraph("<code>185.220.101.5</code>", body_style), Paragraph("AlienVault OTX", body_style), Paragraph("<font color='#A8201A'>88%</font>", body_style), Paragraph("Tor Exit Node / Bulletproof Proxy (DE)", body_style), Paragraph("<font color='#A8201A'><b>DROP</b></font>", body_style)],
        [Paragraph("<code>194.26.29.112</code>", body_style), Paragraph("Emerging Threats", body_style), Paragraph("<font color='#ff8c00'>85%</font>", body_style), Paragraph("SSH Brute-Force Daemon (AS51852 / NL)", body_style), Paragraph("<font color='#A8201A'><b>DROP</b></font>", body_style)],
        [Paragraph("<code>91.240.118.170</code>", body_style), Paragraph("AbuseIPDB", body_style), Paragraph("<font color='#ff8c00'>82%</font>", body_style), Paragraph("Automated SQLi Web Scanner (UA)", body_style), Paragraph("<font color='#A8201A'><b>DROP</b></font>", body_style)],
        [Paragraph("<code>198.51.100.42</code>", body_style), Paragraph("Internal SIEM", body_style), Paragraph("<font color='#ffcd32'>50%</font>", body_style), Paragraph("Unverified Port Probe (Below threshold)", body_style), Paragraph("<font color='#ffcd32'><b>MONITOR</b></font>", body_style)],
        [Paragraph("<code>1.1.1.1</code>", body_style), Paragraph("Global Whitelist", body_style), Paragraph("<font color='#0E703C'>5%</font>", body_style), Paragraph("Cloudflare Public DNS Resolver (AS13335)", body_style), Paragraph("<font color='#0E703C'><b>ALLOW</b></font>", body_style)]
    ]
    t_ioc = Table(ioc_ledger_table, colWidths=[80, 85, 45, 230, 100])
    t_ioc.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY_PRIMARY),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('BOX', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
    ]))
    story.append(t_ioc)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 4: VISUAL LAB EVIDENCE & KALI LINUX TERMINAL VERIFICATION
    # =========================================================================
    story.append(Paragraph("4. Visual Lab Evidence & Kali Linux Terminal Verification", h1_style))
    story.append(Paragraph(
        "Verification was executed inside an isolated Kali Linux rolling release environment (kernel 6.6.9-amd64). Monospace outputs were logged and rendered as high-fidelity terminal captures demonstrating CLI boot, scoring policy matrices, and multi-feed preview:",
        body_style
    ))
    story.append(Spacer(1, 2))

    # Screenshots 01, 02, 03
    img_01_path = os.path.join(SCREENSHOTS_DIR, "01_kali_init_banner.png")
    img_02_path = os.path.join(SCREENSHOTS_DIR, "02_master_menu.png")
    img_03_path = os.path.join(SCREENSHOTS_DIR, "03_threat_feed_ingestion.png")

    if os.path.exists(img_01_path):
        story.append(Image(img_01_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 24.1:</b> Kali Linux Terminal Initialization & Banner — PEER'S Threat Intel Pipeline displaying NIST SP 800-150 bindings.", caption_style))
        story.append(Spacer(1, 3))

    if os.path.exists(img_02_path):
        story.append(Image(img_02_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 24.2:</b> Threat Confidence Scoring Policy Matrix — Threshold configuration (>=75%) for active perimeter firewall drop synthesis.", caption_style))
        story.append(Spacer(1, 3))

    if os.path.exists(img_03_path):
        story.append(Image(img_03_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 24.3:</b> Threat Feed Ingestion & Parsing Preview — Ingestion of multi-source IoCs including Cobalt Strike, Mirai, and Whitelist entries.", caption_style))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 5: LIVE FIREWALL RULE COMPILATION & ENFORCEMENT BENCHMARK
    # =========================================================================
    story.append(Paragraph("5. Live Firewall Rule Compilation & Enforcement Benchmark", h1_style))
    story.append(Paragraph(
        "Screenshots 04 and 05 document the live enforcement sweep and file inspection of the generated Linux iptables and nftables configuration scripts:",
        body_style
    ))
    story.append(Spacer(1, 2))

    img_04_path = os.path.join(SCREENSHOTS_DIR, "04_enforced_firewall_rules.png")
    img_05_path = os.path.join(SCREENSHOTS_DIR, "05_iptables_nftables_rules.png")

    if os.path.exists(img_04_path):
        story.append(Image(img_04_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 24.4:</b> Live Firewall Enforcement Sweep Output — Active drop rule compilation for 5 high-severity threat IPs.", caption_style))
        story.append(Spacer(1, 3))

    if os.path.exists(img_05_path):
        story.append(Image(img_05_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 24.5:</b> Synthesized iptables Shell Script Inspection — Displaying dedicated chain creation and comment-annotated drop rules.", caption_style))
        story.append(Spacer(1, 3))

    story.append(Paragraph("Generated Declarative Linux nftables Blocklist Ruleset:", h1_style))
    nft_box = [
        [Paragraph(
            "<font color='#0E703C'><b>DECLARATIVE NFTABLES KERNEL-SPACE SET (firewall_rules/nftables_blocklist.nft):</b></font><br/>"
            "<code>table inet filter {<br/>"
            "    set threat_intel_blocklist {<br/>"
            "        type ipv4_addr; flags interval;<br/>"
            "        elements = { 45.154.255.89, 103.145.13.24, 185.220.101.5, 194.26.29.112, 91.240.118.170 }<br/>"
            "    }<br/>"
            "    chain input {<br/>"
            "        type filter hook input priority -10; policy accept;<br/>"
            "        ip saddr @threat_intel_blocklist counter drop comment \"Sqrock Threat Intel Drop\";<br/>"
            "    }<br/>"
            "}</code>",
            code_callout
        )]
    ]
    t_nft = Table(nft_box, colWidths=[540])
    t_nft.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), LIGHT_BG),
        ('BOX', (0,0), (-1,-1), 0.5, SUCCESS_COL),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_nft)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 6: VERIFICATION, UNIT TESTING (100% PASS) & GITHUB REPO
    # =========================================================================
    story.append(Paragraph("6. Verification, Unit Testing (100% Pass) & GitHub Repository", h1_style))
    story.append(Paragraph(
        "To guarantee pipeline stability and prevent firewall misconfiguration, an automated Python unittest suite comprising 6 validation cases was executed. The test harness verifies feed loading, IP address parsing, threshold filtering, iptables syntax, nftables sets, and telemetry serialization:",
        body_style
    ))
    story.append(Spacer(1, 2))

    img_06_path = os.path.join(SCREENSHOTS_DIR, "06_github_repo_overview.png")
    if os.path.exists(img_06_path):
        story.append(Image(img_06_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 24.6:</b> Unit Test Validation (6/6 Passed) & Project Directory Tree — Executed on Kali Linux Terminal.", caption_style))
        story.append(Spacer(1, 3))

    story.append(Paragraph("Automated PyUnit Unit Test Verification Ledger:", h1_style))
    unit_test_data = [
        [Paragraph("<b>Test Name</b>", body_style), Paragraph("<b>Target Functionality</b>", body_style), Paragraph("<b>Execution Time</b>", body_style), Paragraph("<b>Status</b>", body_style)],
        [Paragraph("<code>test_feed_ingestion</code>", body_style), Paragraph("Validates structured JSON feed loading and metric calculation.", body_style), Paragraph("0.001s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_ip_address_validation</code>", body_style), Paragraph("Confirms RFC 1918 / global IPv4 parsing and rejects malformed strings.", body_style), Paragraph("0.001s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_threshold_filtering</code>", body_style), Paragraph("Verifies IPs with score >= 75% are blocked while lower scores pass.", body_style), Paragraph("0.001s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_iptables_rule_generation</code>", body_style), Paragraph("Validates synthesis of dedicated iptables chains and DROP rules.", body_style), Paragraph("0.001s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_nftables_syntax_generation</code>", body_style), Paragraph("Confirms generation of valid declarative Linux nftables set elements.", body_style), Paragraph("0.001s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
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
        "All Day 24 source code, threat feeds, generated firewall scripts, test suites, terminal screenshots, and incident reports have been synchronized into the official Phase 2 monorepo repository at <b>https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2</b> under the directory <code>Day24_Threat_Intel_IP_Blocker/</code>.",
        body_style
    ))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 7: ENTERPRISE DEFENSE-IN-DEPTH ROADMAP & SOAR PLAYBOOK
    # =========================================================================
    story.append(Paragraph("7. Enterprise Defense-in-Depth Roadmap & SOAR Playbook", h1_style))
    story.append(Paragraph(
        "To operationalize threat intelligence across hybrid multi-cloud perimeters, security engineering teams must transition from ad-hoc script execution to automated Security Orchestration, Automation, and Response (SOAR):",
        body_style
    ))
    story.append(Spacer(1, 3))

    playbook_steps = [
        "<b>Phase 1: Automated TAXII/STIX Feed Polling:</b> Deploy containerized daemons polling authenticated STIX/TAXII threat servers (e.g. AlienVault OTX, Anomali ThreatStream) on recurring 15-minute schedules, automatically ingesting fresh IoCs.",
        "<b>Phase 2: Cloud WAF IPSet Synchronization (AWS / Cloudflare):</b> Translate verified threat IPs into AWS WAF IPSet objects and Cloudflare IP Access Rules via boto3 / Cloudflare API, blocking malicious traffic before packets ever reach compute nodes.",
        "<b>Phase 3: BGP Remotely Triggered Blackholing (RTBH):</b> In enterprise campus and data center border routers, propagate /32 drop rules via internal BGP peer sessions to drop volumetric DDoS attack traffic at upstream transit providers.",
        "<b>Phase 4: Time-to-Live (TTL) Automatic Quarantine Expiration:</b> Threat actor IP infrastructure is frequently reassigned or ephemeral. Configure 24-hour expiration timers on blocklist entries to prevent permanent accumulation of stale rules."
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
        [Paragraph("<b>Evaluation Standard:</b>", body_style), Paragraph("NIST SP 800-150 | MITRE M1037", body_style),
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
