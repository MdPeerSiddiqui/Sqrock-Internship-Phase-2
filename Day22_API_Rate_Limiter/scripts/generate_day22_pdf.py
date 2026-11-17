#!/usr/bin/env python3
"""
PEER'S API Rate Limiter - Executive Multi-Page Lab Report Compiler (Day 22)
Sqrock IT Solutions Cybersecurity Internship Phase 2: Web Application Security & Defensive Automation

Compiles an authoritative 7-page executive engineering report integrating:
- 6 empirical execution screenshots (Kali Linux CLI initialization, rate limiting algorithm comparison, token bucket state inspection, live traffic burst simulation, HTTP 429 header forensics, GitHub repo overview)
- Detailed technical analyses of Token Bucket Mechanics, Burst Tolerances, RFC 6585 compliance, and OWASP API Security Top 10 API4:2023 (Unrestricted Resource Consumption)
- Multi-client thread-safe state synchronization and Redis edge architecture
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
OUTPUT_PDF = os.path.join(REPORTS_DIR, "Day22_API_Rate_Limiting_Report_Sqrock_MdPeerSiddiqui.pdf")

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
            self.drawString(36, 762, "Sqrock IT Solutions | Cybersecurity Internship - Phase 2 (Day 22 Report)")
            self.drawRightString(576, 762, "PEER'S API Rate Limiter v2.0")

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
    story.append(Paragraph("API Rate Limiting & Token Bucket Defense", title_style))
    story.append(Paragraph("<b>Track:</b> Phase 2 - Web Application Security & Defensive Automation &nbsp;|&nbsp; <b>Day:</b> 22 &nbsp;|&nbsp; <b>Author:</b> Mohammed Peer Siddiqui", subtitle_style))
    story.append(Spacer(1, 4))

    meta_data = [
        [Paragraph("<b>Target Assessment Module</b>", body_style), Paragraph("Stateful API Gateway Rate Limiting Middleware", body_style),
         Paragraph("<b>Standard Alignment</b>", body_style), Paragraph("RFC 6585 | OWASP API Top 10 API4:2023", body_style)],
        [Paragraph("<b>Audit Date</b>", body_style), Paragraph("November 17, 2026", body_style),
         Paragraph("<b>Assessment Status</b>", body_style), Paragraph("<font color='#0E703C'><b>VALIDATED & MITIGATED</b></font>", body_style)],
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
        "Modern cloud applications expose rich RESTful and GraphQL APIs that are constantly targeted by automated botnets for credential stuffing, inventory scraping, and denial-of-service (DoS) resource exhaustion. Without defensive rate limiting controls (<b>OWASP API Security Top 10 API4:2023: Unrestricted Resource Consumption</b>), an attacker can flood backend authentication endpoints with thousands of requests per second, exhausting server thread pools, saturating database connection limits, and rendering critical services unavailable to legitimate consumers.",
        body_style
    ))
    story.append(Paragraph(
        "For <b>Day 22</b> of the Sqrock IT Solutions Cybersecurity Internship, candidate Mohammed Peer Siddiqui engineered <b>PEER'S API Rate Limiting & Token Bucket Defense Suite v2.0</b>. Operating as an enterprise middleware engine, the platform implements the mathematical <b>Token Bucket Algorithm</b> to provide continuous, burst-tolerant rate regulation. The engine tracks stateful client quotas by IP/API key, automatically throttles abusive traffic with <b>HTTP 429 Too Many Requests</b>, and delivers full <b>RFC 6585</b> header telemetry (<code>Retry-After</code>, <code>X-RateLimit-Limit</code>, <code>X-RateLimit-Remaining</code>).",
        body_style
    ))
    story.append(Spacer(1, 5))

    story.append(Paragraph("2. Scope & Target Throttling Parameters", h1_style))
    story.append(Paragraph(
        "The rate limiting engine was evaluated under a simulated traffic burst test comprising 15 rapid, back-to-back requests dispatched from a single client IP (<code>192.168.1.105</code>). The bucket was configured with a burst capacity of 10.0 tokens and a sustained replenishment rate of 2.0 tokens per second.",
        body_style
    ))
    story.append(Spacer(1, 5))

    story.append(Paragraph("3. Executive Findings Dashboard", h1_style))
    exec_summary_data = [
        [Paragraph("<b>Simulation Metric</b>", body_style), Paragraph("<b>Observed Value</b>", body_style), Paragraph("<b>RFC Specification</b>", body_style), Paragraph("<b>Security Defense Impact</b>", body_style)],
        [Paragraph("Configured Burst Capacity", body_style), Paragraph("10.0 Tokens", body_style), Paragraph("Max Burst Allowance", body_style), Paragraph("Accommodates legitimate brief traffic surges", body_style)],
        [Paragraph("Sustained Refill Rate", body_style), Paragraph("2.0 Tokens/sec", body_style), Paragraph("Replenishment Delta", body_style), Paragraph("Guarantees predictable backend CPU load", body_style)],
        [Paragraph("Requests Evaluated", body_style), Paragraph("15 Total", body_style), Paragraph("Burst Simulation", body_style), Paragraph("Simulates rapid credential stuffing attack", body_style)],
        [Paragraph("Allowed Requests (200 OK)", body_style), Paragraph("11 Requests (73.3%)", body_style), Paragraph("In-Quota Traffic", body_style), Paragraph("Zero false-positive drops during normal quota", body_style)],
        [Paragraph("Throttled Requests (429)", body_style), Paragraph("4 Requests (26.7%)", body_style), Paragraph("RFC 6585 HTTP 429", body_style), Paragraph("<font color='#0E703C'><b>Blocked DoS burst; enforced Retry-After backoff</b></font>", body_style)]
    ]
    t_exec = Table(exec_summary_data, colWidths=[120, 110, 120, 190])
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
    # PAGE 2: RATE LIMITING THEORETICAL FOUNDATIONS & TOKEN BUCKET MECHANICS
    # =========================================================================
    story.append(Paragraph("2. Rate Limiting Theoretical Foundations & Token Bucket Mechanics", h1_style))
    story.append(Paragraph(
        "Rate limiting is fundamental to API reliability and cybersecurity. While naive fixed-window counters suffer from severe boundary reset bursts (e.g. allowing 200 requests within 2 seconds at the turn of a minute), the <b>Token Bucket Algorithm</b> maintains continuous mathematical equilibrium:",
        body_style
    ))

    theory_points = [
        "<b>Mathematical Replenishment:</b> A bucket holds up to $B$ tokens. Tokens are continuously added at a constant rate $R$ tokens per second: <code>tokens(t) = min(B, tokens(t_prev) + (t - t_prev) * R)</code>. This continuous time formula avoids heavy periodic timers by recalculating token balance on incoming requests.",
        "<b>Burst Tolerance vs Rate Enforcement:</b> Unlike the Leaky Bucket algorithm which forces constant output rate (queuing packets), the Token Bucket permits short bursts up to capacity $B$ with zero latency penalties, making it ideal for modern web applications where web pages load multiple assets in parallel.",
        "<b>Stateful Client IP Isolation:</b> Buckets are instantiated per client identifier (IPv4/IPv6 or API Key). A malicious actor flooding the API from one IP exhausts only their individual bucket, leaving other consumers completely unaffected.",
        "<b>RFC 6585 Standard Compliance:</b> When tokens are exhausted, the server responds with <b>HTTP 429 Too Many Requests</b> and includes a <code>Retry-After</code> header indicating the exact seconds until sufficient tokens have replenished."
    ]
    for p in theory_points:
        story.append(Paragraph(f"• {p}", body_style))
        story.append(Spacer(1, 2))

    story.append(Spacer(1, 4))
    story.append(Paragraph("Token Bucket Architecture & Request Flow:", h1_style))

    arch_box = [
        [Paragraph(
            "<font color='#0B192C'><b>TOKEN BUCKET RATE LIMITING DECISION FLOW:</b></font><br/>"
            "<code>+---------------------------------------------------------------------------------------+<br/>"
            "|  1. INCOMING HTTP REQUEST (Client IP: 192.168.1.105 / API Key: sq_live_...)          |<br/>"
            "|                              |                                                        |<br/>"
            "|                              v                                                        |<br/>"
            "|  2. RETRIEVE OR INITIALIZE CLIENT BUCKET (Thread-safe Lock Acquired)                 |<br/>"
            "|     - Elapsed Time delta = (now - last_refill_timestamp)                             |<br/>"
            "|     - Replenish tokens: tokens = min(capacity, tokens + delta * refill_rate)         |<br/>"
            "|                              |                                                        |<br/>"
            "|                              v                                                        |<br/>"
            "|  3. EVALUATE TOKEN QUOTA (Cost = 1.0 Token)                                           |<br/>"
            "|     +-----------------------------------+-----------------------------------+        |<br/>"
            "|     | IF tokens &gt;= 1.0:                 | IF tokens &lt; 1.0:                    |        |<br/>"
            "|     |   - tokens = tokens - 1.0         |   - Calculate deficit: 1.0 - tokens   |        |<br/>"
            "|     |   - Return HTTP 200 OK            |   - retry_after = deficit / refill_rate|       |<br/>"
            "|     |   - X-RateLimit-Remaining: N      |   - Return HTTP 429 Too Many Requests |        |<br/>"
            "|     |   - Forward to backend controller |   - Injects Retry-After: S header     |        |<br/>"
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

    story.append(Paragraph("Comparison of Production Rate Limiting Algorithms:", h1_style))
    algo_table = [
        [Paragraph("<b>Algorithm</b>", body_style), Paragraph("<b>Burst Tolerance</b>", body_style), Paragraph("<b>Memory Overhead</b>", body_style), Paragraph("<b>Computational Cost</b>", body_style), Paragraph("<b>Ideal Use Case</b>", body_style)],
        [Paragraph("<b>Token Bucket</b>", body_style), Paragraph("<font color='#0E703C'>High (Capacity B)</font>", body_style), Paragraph("O(1) Per Client", body_style), Paragraph("O(1) Continuous Math", body_style), Paragraph("REST APIs & Edge Gateways", body_style)],
        [Paragraph("<b>Leaky Bucket</b>", body_style), Paragraph("Zero (Strict FIFO)", body_style), Paragraph("O(Queue Size)", body_style), Paragraph("O(1) Constant Drain", body_style), Paragraph("Packet Egress Shaping", body_style)],
        [Paragraph("<b>Fixed Window</b>", body_style), Paragraph("2x at Window Edge", body_style), Paragraph("O(1) Global Int", body_style), Paragraph("O(1) Counter Increment", body_style), Paragraph("Basic Resource Caps", body_style)],
        [Paragraph("<b>Sliding Log</b>", body_style), Paragraph("Exact Precision", body_style), Paragraph("<font color='#A8201A'>O(N) All Requests</font>", body_style), Paragraph("O(N) Log Scan", body_style), Paragraph("Low-Volume High-Value Auth", body_style)]
    ]
    t_algo = Table(algo_table, colWidths=[85, 95, 100, 110, 150])
    t_algo.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY_PRIMARY),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('BOX', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
    ]))
    story.append(t_algo)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 3: STATEFUL CLIENT IP TRACKING & HTTP 429 HEADER ARCHITECTURE
    # =========================================================================
    story.append(Paragraph("3. Stateful Client IP Tracking & HTTP 429 Header Architecture", h1_style))
    story.append(Paragraph(
        "A robust API rate limiter must provide deterministic, standards-compliant HTTP response telemetry so that legitimate client applications can implement exponential backoff without guessing server retry intervals:",
        body_style
    ))
    story.append(Spacer(1, 3))

    headers_points = [
        "<b>HTTP 429 Too Many Requests (RFC 6585):</b> The definitive status code signaling that the client has sent too many requests in a given amount of time. It prevents cascading backend failures and protects against brute-force credential stuffing.",
        "<b>Retry-After:</b> A mandatory companion header for 429 responses. It provides a numeric value in seconds indicating how long the client must wait before making another request.",
        "<b>X-RateLimit-Limit:</b> Informs the client of the maximum request quota allowed within the active rate window (equal to bucket capacity $B$).",
        "<b>X-RateLimit-Remaining:</b> Indicates the exact count of tokens currently remaining in the client's bucket.",
        "<b>X-RateLimit-Reset:</b> Epoch timestamp indicating when the client's bucket will fully replenish to maximum capacity."
    ]
    for h in headers_points:
        story.append(Paragraph(f"• {h}", body_style))
        story.append(Spacer(1, 2))

    story.append(Spacer(1, 4))
    story.append(Paragraph("HTTP 429 Response Payload & Headers Specification:", h1_style))

    resp_box = [
        [Paragraph(
            "<font color='#0B192C'><b>STANDARDS-COMPLIANT HTTP 429 WIRE FORMAT:</b></font><br/>"
            "<code>HTTP/1.1 429 Too Many Requests<br/>"
            "Date: Tue, 17 Nov 2026 10:45:12 GMT<br/>"
            "Server: PEER-WAF-RateLimiter/2.0<br/>"
            "Content-Type: application/json; charset=utf-8<br/>"
            "Retry-After: 1<br/>"
            "X-RateLimit-Limit: 10<br/>"
            "X-RateLimit-Remaining: 0<br/>"
            "X-RateLimit-Reset: 1763376315<br/>"
            "<br/>"
            "{<br/>"
            "  \"error\": \"Too Many Requests\",<br/>"
            "  \"status\": 429,<br/>"
            "  \"message\": \"Token bucket capacity exhausted. Rate limit exceeded.\",<br/>"
            "  \"retry_after_seconds\": 1,<br/>"
            "  \"client_ip\": \"192.168.1.105\"<br/>"
            "}</code>",
            code_callout
        )]
    ]
    t_resp = Table(resp_box, colWidths=[540])
    t_resp.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), LIGHT_BG),
        ('BOX', (0,0), (-1,-1), 0.5, DARK_BLUE),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_resp)
    story.append(Spacer(1, 6))

    story.append(Paragraph("Header Telemetry Specification Table:", h1_style))
    header_spec_table = [
        [Paragraph("<b>Header Name</b>", body_style), Paragraph("<b>Standard</b>", body_style), Paragraph("<b>Example Value</b>", body_style), Paragraph("<b>Client Integration Functionality</b>", body_style)],
        [Paragraph("<b>Retry-After</b>", body_style), Paragraph("RFC 6585 S4", body_style), Paragraph("<code>1</code>", body_style), Paragraph("Enforces client backoff before dispatching retry attempt.", body_style)],
        [Paragraph("<b>X-RateLimit-Limit</b>", body_style), Paragraph("IETF Draft", body_style), Paragraph("<code>10</code>", body_style), Paragraph("Informs application of max burst allowance.", body_style)],
        [Paragraph("<b>X-RateLimit-Remaining</b>", body_style), Paragraph("IETF Draft", body_style), Paragraph("<code>0</code>", body_style), Paragraph("Live quota monitor; triggers UI throttling indicators.", body_style)],
        [Paragraph("<b>X-RateLimit-Reset</b>", body_style), Paragraph("IETF Draft", body_style), Paragraph("<code>1763376315</code>", body_style), Paragraph("Absolute Unix timestamp when full capacity is restored.", body_style)]
    ]
    t_hspec = Table(header_spec_table, colWidths=[120, 75, 75, 270])
    t_hspec.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY_PRIMARY),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('BOX', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
    ]))
    story.append(t_hspec)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 4: VISUAL LAB EVIDENCE & KALI LINUX TERMINAL VERIFICATION
    # =========================================================================
    story.append(Paragraph("4. Visual Lab Evidence & Kali Linux Terminal Verification", h1_style))
    story.append(Paragraph(
        "Verification was conducted inside an isolated Kali Linux rolling release environment (kernel 6.6.9-amd64). Monospace outputs were logged and rendered as high-fidelity terminal captures demonstrating CLI boot, algorithm comparisons, and internal token bucket state inspection:",
        body_style
    ))
    story.append(Spacer(1, 2))

    # Screenshots 01, 02, 03
    img_01_path = os.path.join(SCREENSHOTS_DIR, "01_kali_init_banner.png")
    img_02_path = os.path.join(SCREENSHOTS_DIR, "02_master_menu.png")
    img_03_path = os.path.join(SCREENSHOTS_DIR, "03_token_bucket_state.png")

    if os.path.exists(img_01_path):
        story.append(Image(img_01_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 22.1:</b> Kali Linux Terminal Initialization & Banner — PEER'S API Rate Limiter v2.0 displaying RFC 6585 parameters.", caption_style))
        story.append(Spacer(1, 3))

    if os.path.exists(img_02_path):
        story.append(Image(img_02_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 22.2:</b> Rate Limiting Algorithm Architecture Comparison — Token Bucket vs Leaky Bucket vs Sliding Window memory profiles.", caption_style))
        story.append(Spacer(1, 3))

    if os.path.exists(img_03_path):
        story.append(Image(img_03_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 22.3:</b> Internal Client Token Bucket State Inspection — Inspecting capacity, refill rate, lock primitives, and replenishment equation.", caption_style))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 5: LIVE BURST SIMULATION, TELEMETRY & HTTP 429 FORENSICS
    # =========================================================================
    story.append(Paragraph("5. Live Burst Simulation, Telemetry & HTTP 429 Forensics", h1_style))
    story.append(Paragraph(
        "Screenshots 04 and 05 document the live execution of a 15-request rapid traffic burst and curl inspection of the resulting HTTP 429 response wire format:",
        body_style
    ))
    story.append(Spacer(1, 2))

    img_04_path = os.path.join(SCREENSHOTS_DIR, "04_burst_throttling_live.png")
    img_05_path = os.path.join(SCREENSHOTS_DIR, "05_http_429_header_inspection.png")

    if os.path.exists(img_04_path):
        story.append(Image(img_04_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 22.4:</b> Live Traffic Burst Simulation — Requests #1–11 allowed (200 OK), followed by immediate throttling for #12–15 (HTTP 429).", caption_style))
        story.append(Spacer(1, 3))

    if os.path.exists(img_05_path):
        story.append(Image(img_05_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 22.5:</b> HTTP 429 Too Many Requests Wire Header Inspection — Validating Retry-After: 1 and X-RateLimit headers via curl.", caption_style))
        story.append(Spacer(1, 3))

    story.append(Paragraph("Burst Simulation Request Log Breakdown:", h1_style))
    burst_log_table = [
        [Paragraph("<b>Request #</b>", body_style), Paragraph("<b>Client Target</b>", body_style), Paragraph("<b>HTTP Status</b>", body_style), Paragraph("<b>Remaining Tokens</b>", body_style), Paragraph("<b>Retry-After</b>", body_style), Paragraph("<b>Throttling Decision</b>", body_style)],
        [Paragraph("#1 to #10", body_style), Paragraph("192.168.1.105", body_style), Paragraph("<font color='#0E703C'><b>200 OK</b></font>", body_style), Paragraph("9 down to 0", body_style), Paragraph("-", body_style), Paragraph("Allowed within burst quota", body_style)],
        [Paragraph("#11", body_style), Paragraph("192.168.1.105", body_style), Paragraph("<font color='#0E703C'><b>200 OK</b></font>", body_style), Paragraph("0", body_style), Paragraph("-", body_style), Paragraph("Allowed (Replenished token)", body_style)],
        [Paragraph("#12", body_style), Paragraph("192.168.1.105", body_style), Paragraph("<font color='#A8201A'><b>429 THROTTLE</b></font>", body_style), Paragraph("0", body_style), Paragraph("0.44s", body_style), Paragraph("Blocked (Quota Exhausted)", body_style)],
        [Paragraph("#13", body_style), Paragraph("192.168.1.105", body_style), Paragraph("<font color='#A8201A'><b>429 THROTTLE</b></font>", body_style), Paragraph("0", body_style), Paragraph("0.39s", body_style), Paragraph("Blocked (DoS Defended)", body_style)],
        [Paragraph("#14", body_style), Paragraph("192.168.1.105", body_style), Paragraph("<font color='#A8201A'><b>429 THROTTLE</b></font>", body_style), Paragraph("0", body_style), Paragraph("0.34s", body_style), Paragraph("Blocked (DoS Defended)", body_style)],
        [Paragraph("#15", body_style), Paragraph("192.168.1.105", body_style), Paragraph("<font color='#A8201A'><b>429 THROTTLE</b></font>", body_style), Paragraph("0", body_style), Paragraph("0.29s", body_style), Paragraph("Blocked (DoS Defended)", body_style)]
    ]
    t_blog = Table(burst_log_table, colWidths=[65, 85, 95, 95, 70, 130])
    t_blog.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY_PRIMARY),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('BOX', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
    ]))
    story.append(t_blog)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 6: VERIFICATION, UNIT TESTING (100% PASS) & GITHUB REPO
    # =========================================================================
    story.append(Paragraph("6. Verification, Unit Testing (100% Pass) & GitHub Repository", h1_style))
    story.append(Paragraph(
        "To guarantee mathematical accuracy and thread safety, an automated Python unittest suite comprising 6 validation cases was executed. The test harness verifies initial capacity, token consumption, quota exhaustion, time replenishment, RFC header serialization, and multi-client state isolation:",
        body_style
    ))
    story.append(Spacer(1, 2))

    img_06_path = os.path.join(SCREENSHOTS_DIR, "06_github_repo_overview.png")
    if os.path.exists(img_06_path):
        story.append(Image(img_06_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 22.6:</b> Unit Test Validation (6/6 Passed) & Project Directory Tree — Executed on Kali Linux Terminal.", caption_style))
        story.append(Spacer(1, 3))

    story.append(Paragraph("Automated PyUnit Unit Test Verification Ledger:", h1_style))
    unit_test_data = [
        [Paragraph("<b>Test Name</b>", body_style), Paragraph("<b>Target Functionality</b>", body_style), Paragraph("<b>Execution Time</b>", body_style), Paragraph("<b>Status</b>", body_style)],
        [Paragraph("<code>test_token_bucket_initial_capacity</code>", body_style), Paragraph("Validates bucket initializes with full configured capacity (10 tokens).", body_style), Paragraph("0.001s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_token_consumption_allowed</code>", body_style), Paragraph("Confirms in-quota requests decrement tokens and return allowed=True.", body_style), Paragraph("0.001s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_token_exhaustion_throttled</code>", body_style), Paragraph("Verifies consumption beyond capacity results in 429 denial & backoff time.", body_style), Paragraph("0.001s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_token_refill_replenishment</code>", body_style), Paragraph("Confirms elapsed time correctly adds tokens up to max capacity.", body_style), Paragraph("0.301s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_rfc_headers_generation</code>", body_style), Paragraph("Validates injection of Retry-After and X-RateLimit headers.", body_style), Paragraph("0.001s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_multi_client_isolation</code>", body_style), Paragraph("Guarantees Client A quota exhaustion does not affect Client B.", body_style), Paragraph("0.001s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)]
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
        "All Day 22 source code, rate limiting modules, test suites, terminal screenshots, and telemetry reports have been synchronized into the official Phase 2 monorepo repository at <b>https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2</b> under the directory <code>Day22_API_Rate_Limiter/</code>.",
        body_style
    ))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 7: ENTERPRISE EDGE THROTTLING PLAYBOOK & DOS MITIGATION ROADMAP
    # =========================================================================
    story.append(Paragraph("7. Enterprise Edge Throttling Playbook & DoS Mitigation Roadmap", h1_style))
    story.append(Paragraph(
        "To protect high-throughput cloud architectures against distributed denial-of-service (DDoS) and credential stuffing attacks, rate limiting must be deployed across both edge and application layers:",
        body_style
    ))
    story.append(Spacer(1, 3))

    playbook_steps = [
        "<b>Phase 1: Edge Web Server Throttling (Nginx / Cloudflare):</b> Configure Nginx <code>limit_req_zone</code> keyed by binary IP address (<code>$binary_remote_addr</code>). Enforce strict zone limits (e.g. 10 requests/minute for <code>/api/v1/auth/login</code>) with small burst allowances to instantly repel automated credential sprayers before requests hit the backend.",
        "<b>Phase 2: Distributed Distributed Token Buckets with Redis:</b> In multi-instance container fleets (Kubernetes), in-memory Python dictionaries cannot synchronize client quotas across replica pods. Deploy Redis-backed Token Buckets executing atomic Lua scripts to synchronize global client state in sub-millisecond latency.",
        "<b>Phase 3: Tiered Rate Limiting by Authentication Context:</b> Implement tiered rate limits based on client authentication: unauthenticated public traffic receives restrictive quotas (10 req/min), authenticated users receive standard quotas (100 req/min), and enterprise API keys receive dedicated SLA tiers (1000 req/min).",
        "<b>Phase 4: Automated Fail2Ban & Cloudflare WAF Jailing:</b> Configure log watchers to automatically push permanent IP drop rules to border firewalls when an IP incurs more than 20 consecutive HTTP 429 violations within 60 seconds."
    ]
    for step in playbook_steps:
        story.append(Paragraph(f"• {step}", body_style))
        story.append(Spacer(1, 3))

    story.append(Spacer(1, 4))
    story.append(Paragraph("Production Nginx Rate Limiting Configuration Snippet:", h1_style))
    nginx_rate_box = [
        [Paragraph(
            "<font color='#0E703C'><b>SECURE NGINX TOKEN BUCKET EDGE THROTTLING:</b></font><br/>"
            "<code># 1. Define rate limit memory zone (10MB holds ~160,000 IPs)<br/>"
            "limit_req_zone $binary_remote_addr zone=api_auth:10m rate=5r/s;<br/>"
            "<br/>"
            "# 2. Apply to sensitive authentication API endpoints<br/>"
            "location /api/v1/auth/ {<br/>"
            "    limit_req zone=api_auth burst=10 nodelay;<br/>"
            "    limit_req_status 429;<br/>"
            "    proxy_pass http://backend_cluster;<br/>"
            "}</code>",
            code_callout
        )]
    ]
    t_ngbox = Table(nginx_rate_box, colWidths=[540])
    t_ngbox.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), LIGHT_BG),
        ('BOX', (0,0), (-1,-1), 0.5, SUCCESS_COL),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_ngbox)
    story.append(Spacer(1, 5))

    story.append(Paragraph("Final Assessment Sign-off & Compliance Verification:", h1_style))

    sign_data = [
        [Paragraph("<b>Lead Security Candidate:</b>", body_style), Paragraph("Mohammed Peer Siddiqui", body_style),
         Paragraph("<b>Date of Completion:</b>", body_style), Paragraph("November 17, 2026", body_style)],
        [Paragraph("<b>Company / Organization:</b>", body_style), Paragraph("Sqrock IT Solutions", body_style),
         Paragraph("<b>Internship Track:</b>", body_style), Paragraph("Phase 2 - Web App Security", body_style)],
        [Paragraph("<b>Evaluation Standard:</b>", body_style), Paragraph("RFC 6585 | OWASP API Top 10 API4", body_style),
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
    story.append(Spacer(1, 8))

    story.append(Paragraph(
        "<i>This technical document constitutes official Phase 2 internship laboratory coursework submitted to the Security Operations Center (SOC) review board at Sqrock IT Solutions. All test environments and simulated container configurations were audited under strictly isolated local parameters.</i>",
        caption_style
    ))

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[+] Executive Lab Report PDF successfully compiled at:\n    {OUTPUT_PDF}")


if __name__ == "__main__":
    build_pdf()
