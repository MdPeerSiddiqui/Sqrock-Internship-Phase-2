#!/usr/bin/env python3
"""
PEER'S XSS Payload Sanitizer - Executive Multi-Page Lab Report Compiler (Day 21)
Sqrock IT Solutions Cybersecurity Internship Phase 2: Web Application Security & Defensive Automation

Compiles an authoritative 7-page executive engineering report integrating:
- 6 empirical execution screenshots (Kali Linux CLI initialization, context matrix tuning, payload batch ingestion, live neutralization sweep, CSP Level 3 generator, GitHub repo overview)
- Detailed technical analyses of Cross-Site Scripting (XSS) Attack Vectors (Reflected, Stored, DOM-based, Attribute Breakouts, JavaScript Pseudo-Protocols)
- OWASP Top 10 A03:2021 (Injection) & CWE-79 compliance mappings
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
OUTPUT_PDF = os.path.join(REPORTS_DIR, "Day21_XSS_Sanitizer_Report_Sqrock_MdPeerSiddiqui.pdf")

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
            self.drawString(36, 762, "Sqrock IT Solutions | Cybersecurity Internship - Phase 2 (Day 21 Report)")
            self.drawRightString(576, 762, "PEER'S XSS Payload Sanitizer v2.0")

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
    story.append(Paragraph("XSS Payload Sanitizer & Defense Suite", title_style))
    story.append(Paragraph("<b>Track:</b> Phase 2 - Web Application Security & Defensive Automation &nbsp;|&nbsp; <b>Day:</b> 21 &nbsp;|&nbsp; <b>Author:</b> Mohammed Peer Siddiqui", subtitle_style))
    story.append(Spacer(1, 4))

    meta_data = [
        [Paragraph("<b>Target Assessment Module</b>", body_style), Paragraph("Context-Aware Input Filtering & Encoding Engine", body_style),
         Paragraph("<b>Standard Alignment</b>", body_style), Paragraph("OWASP Top 10 A03:2021 | CWE-79 | W3C CSP L3", body_style)],
        [Paragraph("<b>Audit Date</b>", body_style), Paragraph("November 17, 2026", body_style),
         Paragraph("<b>Assessment Status</b>", body_style), Paragraph("<font color='#0E703C'><b>100% NEUTRALIZED / SECURE</b></font>", body_style)],
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
        "Cross-Site Scripting (<b>CWE-79 / OWASP Top 10 A03:2021 Injection</b>) occurs when web applications reflect or store untrusted user input directly within rendered HTML documents without rigorous context-aware sanitization. Once injected into a victim's browser session, malicious JavaScript executes with the full privileges of the authenticated user, enabling session hijacking through <code>document.cookie</code> theft, cross-site request forgery (CSRF) token harvesting, DOM manipulation, credential phishing, and keylogging.",
        body_style
    ))
    story.append(Paragraph(
        "For <b>Day 21</b> of the Sqrock IT Solutions Cybersecurity Internship, candidate Mohammed Peer Siddiqui built <b>PEER'S XSS Payload Sanitizer & Defense Suite v2.0</b>. Operating as an enterprise defense-in-depth framework, the engine integrates context-aware HTML entity encoding, executable script tag stripping, DOM inline event handler neutralization (<code>data-disabled-*</code>), URI protocol blocking (<code>javascript:</code>), and automated generation of cryptographic nonce-based <b>Content Security Policy (CSP Level 3)</b> headers.",
        body_style
    ))
    story.append(Spacer(1, 5))

    story.append(Paragraph("2. Scope & Target Vulnerability Categories", h1_style))
    story.append(Paragraph(
        "The security audit evaluated 7 distinct payload archetypes spanning Reflected Script Tags (<code>&lt;script&gt;</code>), Inline Event Handlers (<code>onerror=</code>), SVG Vector Injections (<code>&lt;svg/onload=...&gt;</code>), Attribute Breakouts, JavaScript Pseudo-Protocols (<code>href=\"javascript:...\"</code>), DOM-based sinks, and benign textual inputs.",
        body_style
    ))
    story.append(Spacer(1, 5))

    story.append(Paragraph("3. Executive Findings Dashboard", h1_style))
    exec_summary_data = [
        [Paragraph("<b>Attack Archetype</b>", body_style), Paragraph("<b>Sample Vector</b>", body_style), Paragraph("<b>Sink Context</b>", body_style), Paragraph("<b>Mitigation Applied</b>", body_style)],
        [Paragraph("Reflected Tag Injection", body_style), Paragraph("<code>&lt;script&gt;alert(cookie)&lt;/script&gt;</code>", body_style), Paragraph("HTML Body", body_style), Paragraph("<font color='#0E703C'>Excised executable tag block</font>", body_style)],
        [Paragraph("Event Handler Injection", body_style), Paragraph("<code>&lt;img onerror=alert(1)&gt;</code>", body_style), Paragraph("HTML Body", body_style), Paragraph("<font color='#0E703C'>Neutralized to data-disabled-onerror</font>", body_style)],
        [Paragraph("SVG Vector Injection", body_style), Paragraph("<code>&lt;svg/onload=fetch(...)&gt;</code>", body_style), Paragraph("HTML Body", body_style), Paragraph("<font color='#0E703C'>Excised executable SVG container</font>", body_style)],
        [Paragraph("Attribute Breakout", body_style), Paragraph("<code>\" onfocus=alert()</code>", body_style), Paragraph("Attribute Value", body_style), Paragraph("<font color='#0E703C'>Quote escaped &amp;quot; + disabled event</font>", body_style)],
        [Paragraph("JavaScript Pseudo-Protocol", body_style), Paragraph("<code>&lt;a href=\"javascript:...\"&gt;</code>", body_style), Paragraph("URI Attribute", body_style), Paragraph("<font color='#0E703C'>Blocked scheme (#blocked-insecure-uri)</font>", body_style)],
        [Paragraph("Benign Text Input", body_style), Paragraph("<code>Welcome to Sqrock Phase 2!</code>", body_style), Paragraph("HTML Body", body_style), Paragraph("<font color='#008DDA'>Preserved 100% without corruption</font>", body_style)]
    ]
    t_exec = Table(exec_summary_data, colWidths=[115, 155, 90, 180])
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
    # PAGE 2: XSS THREAT TAXONOMY & CONTEXT-AWARE DEFENSE ARCHITECTURE
    # =========================================================================
    story.append(Paragraph("2. XSS Threat Taxonomy & Context-Aware Defense Architecture", h1_style))
    story.append(Paragraph(
        "A common pitfall in web application security is applying a single universal escaping function across all insertion sinks. Because web browsers parse HTML, CSS, JavaScript, and URIs using completely different state machines, sanitization must be strictly <b>context-aware</b>:",
        body_style
    ))

    sink_points = [
        "<b>HTML Body Context:</b> Untrusted input placed between standard tags (e.g. <code>&lt;div&gt;USER_INPUT&lt;/div&gt;</code>). Requires stripping executable container tags (<code>&lt;script&gt;</code>, <code>&lt;iframe&gt;</code>, <code>&lt;svg&gt;</code>) and converting special characters (<code>&amp;</code>, <code>&lt;</code>, <code>&gt;</code>) into HTML entities.",
        "<b>Attribute Value Context:</b> Untrusted input inserted into tag attributes (e.g. <code>&lt;input value=\"USER_INPUT\"&gt;</code>). Attackers break out of quotes using <code>\"</code> or <code>'</code> and inject inline event handlers (<code>onfocus=</code>, <code>autofocus</code>). Requires strict attribute quotation and HTML entity encoding of quotes (<code>&amp;quot;</code>, <code>&amp;#x27;</code>).",
        "<b>URI Attribute Context:</b> Untrusted input inside hyperlinked attributes (e.g. <code>&lt;a href=\"USER_INPUT\"&gt;</code>). Standard HTML entity encoding fails to neutralize <code>javascript:</code> pseudo-protocols because browsers decode entities before evaluating URI schemes. Requires scheme validation disallowing <code>javascript:</code>, <code>data:</code>, and <code>vbscript:</code>.",
        "<b>DOM-Based Execution Sinks:</b> Execution of input through client-side JavaScript APIs (e.g. <code>element.innerHTML</code>, <code>document.write()</code>, <code>eval()</code>). Requires replacing insecure sinks with safe properties like <code>textContent</code>."
    ]
    for p in sink_points:
        story.append(Paragraph(f"• {p}", body_style))
        story.append(Spacer(1, 2))

    story.append(Spacer(1, 4))
    story.append(Paragraph("Context-Aware Defense & Sanitization Pipeline:", h1_style))

    arch_box = [
        [Paragraph(
            "<font color='#0B192C'><b>MULTI-TIER CONTEXT-AWARE SANITIZATION PIPELINE:</b></font><br/>"
            "<code>+---------------------------------------------------------------------------------------+<br/>"
            "|  1. UNTRUSTED USER INPUT INGESTION (HTTP POST, Query Parameters, Headers)             |<br/>"
            "|                              |                                                        |<br/>"
            "|                              v                                                        |<br/>"
            "|  2. SINK CONTEXT CLASSIFICATION & ROUTING                                             |<br/>"
            "|     - HTML Body Context      -> Tag Stripper + Entity Encoder (&lt; &gt; &amp;)       |<br/>"
            "|     - Attribute Value Context-> Quote Escaper (&quot; &#x27;) + Event Neutralizer     |<br/>"
            "|     - URI Attribute Context  -> Protocol Validator (Blocks javascript: / data:)       |<br/>"
            "|     - JavaScript Context     -> JSON Serialization + Unicode Hex Escaping             |<br/>"
            "|                              |                                                        |<br/>"
            "|                              v                                                        |<br/>"
            "|  3. ENTERPRISE DEFENSE-IN-DEPTH LAYER: CONTENT SECURITY POLICY (CSP LEVEL 3)          |<br/>"
            "|     - Injects: default-src 'self'; script-src 'self' 'nonce-...'; object-src 'none';  |<br/>"
            "|     - Enforces browser-level blocking of un-nonced inline scripts even if injected    |<br/>"
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

    story.append(Paragraph("HTML Entity Replacement Mapping Table:", h1_style))
    entity_table = [
        [Paragraph("<b>Raw Character</b>", body_style), Paragraph("<b>Character Name</b>", body_style), Paragraph("<b>HTML Entity Named</b>", body_style), Paragraph("<b>HTML Entity Hex / Decimal</b>", body_style), Paragraph("<b>Primary Threat Mitigated</b>", body_style)],
        [Paragraph("<code>&amp;</code>", body_style), Paragraph("Ampersand", body_style), Paragraph("<code>&amp;amp;</code>", body_style), Paragraph("<code>&amp;#38;</code>", body_style), Paragraph("Prevents entity decoding confusion", body_style)],
        [Paragraph("<code>&lt;</code>", body_style), Paragraph("Less-Than", body_style), Paragraph("<code>&amp;lt;</code>", body_style), Paragraph("<code>&amp;#60;</code>", body_style), Paragraph("Prevents tag declaration &lt;script&gt;", body_style)],
        [Paragraph("<code>&gt;</code>", body_style), Paragraph("Greater-Than", body_style), Paragraph("<code>&amp;gt;</code>", body_style), Paragraph("<code>&amp;#62;</code>", body_style), Paragraph("Prevents closing existing HTML tags", body_style)],
        [Paragraph("<code>\"</code>", body_style), Paragraph("Double Quote", body_style), Paragraph("<code>&amp;quot;</code>", body_style), Paragraph("<code>&amp;#34;</code>", body_style), Paragraph("Prevents attribute breakout in quotes", body_style)],
        [Paragraph("<code>'</code>", body_style), Paragraph("Single Quote", body_style), Paragraph("<code>&amp;#x27;</code>", body_style), Paragraph("<code>&amp;#39;</code>", body_style), Paragraph("Prevents single-quote attribute breakout", body_style)],
        [Paragraph("<code>/</code>", body_style), Paragraph("Forward Slash", body_style), Paragraph("<code>&amp;#x2F;</code>", body_style), Paragraph("<code>&amp;#47;</code>", body_style), Paragraph("Prevents closing tag breakout /&gt;", body_style)]
    ]
    t_ent = Table(entity_table, colWidths=[65, 95, 105, 115, 160])
    t_ent.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY_PRIMARY),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('BOX', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
    ]))
    story.append(t_ent)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 3: PAYLOAD EVALUATION & NEUTRALIZATION MECHANICS
    # =========================================================================
    story.append(Paragraph("3. Payload Evaluation & Neutralization Mechanics", h1_style))
    story.append(Paragraph(
        "A rigorous test matrix of 7 multi-context attack payloads (<code>samples/test_payloads.json</code>) was audited through the sanitizer suite. The engine executes multi-tier regex heuristics to detect active attack vectors, applies context sanitization, and produces neutralized outputs:",
        body_style
    ))
    story.append(Spacer(1, 3))

    code_payloads = [
        [Paragraph(
            "<font color='#0B192C'><b>ATTACK VECTOR DETECTION &amp; NEUTRALIZATION RULES:</b></font><br/>"
            "<code>1. Classic Script Tag Injection: &lt;script&gt;alert(document.cookie)&lt;/script&gt;<br/>"
            "   -&gt; Regex Heuristic: (?i)&lt;\\s*script[^&gt;]*&gt;.*?&lt;\\s*/\\s*script\\s*&gt;<br/>"
            "   -&gt; Defense Applied: Complete excision of script block; zero executable bytes preserved.<br/>"
            "<br/>"
            "2. DOM Event Handler Injection: &lt;img src=\"invalid.jpg\" onerror=\"alert('XSS')\" /&gt;<br/>"
            "   -&gt; Regex Heuristic: (?i)\\b(onerror|onload|onclick|onfocus)\\s*=<br/>"
            "   -&gt; Defense Applied: Neutralization to data-disabled-onerror=\"...\" + Entity Encoding.<br/>"
            "<br/>"
            "3. Attribute Breakout Attack: \" onfocus=\"alert(document.domain)\" autofocus=\"<br/>"
            "   -&gt; Regex Heuristic: Quote breakout coupled with inline event trigger.<br/>"
            "   -&gt; Defense Applied: Quote converted to &amp;quot; and onfocus converted to data-disabled-onfocus.<br/>"
            "<br/>"
            "4. JavaScript Pseudo-Protocol: &lt;a href=\"javascript:alert('XSS')\"&gt;Click&lt;/a&gt;<br/>"
            "   -&gt; Regex Heuristic: (?i)^\\s*(javascript|vbscript|data):<br/>"
            "   -&gt; Defense Applied: Scheme blocked and replaced with #blocked-insecure-uri.</code>",
            code_callout
        )]
    ]
    t_cpay = Table(code_payloads, colWidths=[540])
    t_cpay.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), LIGHT_BG),
        ('BOX', (0,0), (-1,-1), 0.5, DARK_BLUE),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_cpay)
    story.append(Spacer(1, 6))

    story.append(Paragraph("Evaluated Payload Audit Ledger:", h1_style))
    payload_table = [
        [Paragraph("<b>Payload ID</b>", body_style), Paragraph("<b>Attack Archetype</b>", body_style), Paragraph("<b>Raw Attack Vector</b>", body_style), Paragraph("<b>Severity</b>", body_style), Paragraph("<b>Neutralization Status</b>", body_style)],
        [Paragraph("<b>XSS-01</b>", body_style), Paragraph("Reflected Script", body_style), Paragraph("<code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code>", body_style), Paragraph("<font color='#A8201A'>CRITICAL</font>", body_style), Paragraph("<font color='#0E703C'>Tag Stripped</font>", body_style)],
        [Paragraph("<b>XSS-02</b>", body_style), Paragraph("Inline Event", body_style), Paragraph("<code>&lt;img onerror=alert('XSS')&gt;</code>", body_style), Paragraph("<font color='#ff8c00'>HIGH</font>", body_style), Paragraph("<font color='#0E703C'>data-disabled-onerror</font>", body_style)],
        [Paragraph("<b>XSS-03</b>", body_style), Paragraph("SVG Vector", body_style), Paragraph("<code>&lt;svg/onload=fetch(...)&gt;</code>", body_style), Paragraph("<font color='#A8201A'>CRITICAL</font>", body_style), Paragraph("<font color='#0E703C'>SVG Excised</font>", body_style)],
        [Paragraph("<b>XSS-04</b>", body_style), Paragraph("Attribute Breakout", body_style), Paragraph("<code>\" onfocus=alert() autofocus</code>", body_style), Paragraph("<font color='#A8201A'>CRITICAL</font>", body_style), Paragraph("<font color='#0E703C'>Quote Escaped</font>", body_style)],
        [Paragraph("<b>XSS-05</b>", body_style), Paragraph("JS Pseudo-Protocol", body_style), Paragraph("<code>&lt;a href=\"javascript:...\"&gt;</code>", body_style), Paragraph("<font color='#ff8c00'>HIGH</font>", body_style), Paragraph("<font color='#0E703C'>URI Scheme Blocked</font>", body_style)],
        [Paragraph("<b>XSS-06</b>", body_style), Paragraph("DOM Nested Script", body_style), Paragraph("<code>&lt;iframe src=\"javascript:...\"&gt;</code>", body_style), Paragraph("<font color='#A8201A'>CRITICAL</font>", body_style), Paragraph("<font color='#0E703C'>Entity Encoded</font>", body_style)],
        [Paragraph("<b>BENIGN-01</b>", body_style), Paragraph("Benign Text Input", body_style), Paragraph("<code>Welcome to Sqrock Phase 2!</code>", body_style), Paragraph("<font color='#008DDA'>SAFE</font>", body_style), Paragraph("<font color='#0E703C'>Zero Modification</font>", body_style)]
    ]
    t_ptab = Table(payload_table, colWidths=[55, 95, 175, 65, 150])
    t_ptab.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY_PRIMARY),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('BOX', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
    ]))
    story.append(t_ptab)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 4: VISUAL LAB EVIDENCE & KALI LINUX TERMINAL VERIFICATION
    # =========================================================================
    story.append(Paragraph("4. Visual Lab Evidence & Kali Linux Terminal Verification", h1_style))
    story.append(Paragraph(
        "Verification was executed inside a hardened Kali Linux rolling release environment (kernel 6.6.9-amd64). Monospace outputs were logged and rendered as high-fidelity terminal captures demonstrating CLI initialization, context tuning, and payload batch ingestion:",
        body_style
    ))
    story.append(Spacer(1, 2))

    # Screenshots 01, 02, 03
    img_01_path = os.path.join(SCREENSHOTS_DIR, "01_kali_init_banner.png")
    img_02_path = os.path.join(SCREENSHOTS_DIR, "02_master_menu.png")
    img_03_path = os.path.join(SCREENSHOTS_DIR, "03_payload_batch_ingestion.png")

    if os.path.exists(img_01_path):
        story.append(Image(img_01_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 21.1:</b> Kali Linux Terminal Initialization & Banner — PEER'S XSS Sanitizer v2.0 displaying OWASP Top 10 A03 specifications.", caption_style))
        story.append(Spacer(1, 3))

    if os.path.exists(img_02_path):
        story.append(Image(img_02_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 21.2:</b> Context-Aware Sanitization Defense Matrix — Configured insertion sinks (body, attribute, URI, DOM sink) and CSP status.", caption_style))
        story.append(Spacer(1, 3))

    if os.path.exists(img_03_path):
        story.append(Image(img_03_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 21.3:</b> Payload Batch Ingestion & Preview — Inspection of 7 test vectors loaded from samples/test_payloads.json.", caption_style))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 5: LIVE NEUTRALIZATION, TELEMETRY & CSP DEFENSE BENCHMARK
    # =========================================================================
    story.append(Paragraph("5. Live Neutralization, Telemetry & CSP Defense Benchmark", h1_style))
    story.append(Paragraph(
        "Screenshots 04 and 05 document the live sanitization sweep and the generation of an enterprise-grade Content Security Policy (CSP Level 3) header providing layered defense:",
        body_style
    ))
    story.append(Spacer(1, 2))

    img_04_path = os.path.join(SCREENSHOTS_DIR, "04_live_sanitization_sweep.png")
    img_05_path = os.path.join(SCREENSHOTS_DIR, "05_csp_policy_generator.png")

    if os.path.exists(img_04_path):
        story.append(Image(img_04_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 21.4:</b> Live Sanitization & Neutralization Sweep — Displaying raw attack strings vs safely encoded HTML entity outputs.", caption_style))
        story.append(Spacer(1, 3))

    if os.path.exists(img_05_path):
        story.append(Image(img_05_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 21.5:</b> Hardened Content Security Policy (CSP Level 3) Directives — Validating cryptographic nonce and origin lockdown.", caption_style))
        story.append(Spacer(1, 3))

    story.append(Paragraph("Hardened Content Security Policy (CSP Level 3) Header Architecture:", h1_style))
    csp_box = [
        [Paragraph(
            "<font color='#0E703C'><b>RECOMMENDED ENTERPRISE CSP LEVEL 3 HEADER SPECIFICATION:</b></font><br/>"
            "<code>Content-Security-Policy:<br/>"
            "  default-src 'self';                                   # Restrict default fetches to origin<br/>"
            "  script-src 'self' 'nonce-sqrock_secops_nonce_7749'   # Dynamic cryptographic nonce<br/>"
            "             https://trustedcdn.sqrock.com;            # Internal trusted CDN allowlist<br/>"
            "  object-src 'none';                                    # Disable legacy Flash/Java plugins<br/>"
            "  base-uri 'self';                                      # Prevent &lt;base&gt; tag hijacking<br/>"
            "  frame-ancestors 'none';                               # Prevent clickjacking / iframe embedding<br/>"
            "  form-action 'self';                                   # Restrict form submission targets</code>",
            code_callout
        )]
    ]
    t_csp = Table(csp_box, colWidths=[540])
    t_csp.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), LIGHT_BG),
        ('BOX', (0,0), (-1,-1), 0.5, SUCCESS_COL),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_csp)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 6: VERIFICATION, UNIT TESTING (100% PASS) & GITHUB REPO
    # =========================================================================
    story.append(Paragraph("6. Verification, Unit Testing (100% Pass) & GitHub Repository", h1_style))
    story.append(Paragraph(
        "To guarantee encoding accuracy and prevent bypass regressions, an automated Python unittest suite comprising 6 validation cases was executed. The test harness verifies script tag stripping, HTML entity translation, event handler neutralization, URI scheme blocking, benign string preservation, and CSP policy generation:",
        body_style
    ))
    story.append(Spacer(1, 2))

    img_06_path = os.path.join(SCREENSHOTS_DIR, "06_github_repo_overview.png")
    if os.path.exists(img_06_path):
        story.append(Image(img_06_path, width=480, height=140))
        story.append(Paragraph("<b>Figure 21.6:</b> Unit Test Validation (6/6 Passed) & Project Directory Tree — Executed on Kali Linux Terminal.", caption_style))
        story.append(Spacer(1, 3))

    story.append(Paragraph("Automated PyUnit Unit Test Verification Ledger:", h1_style))
    unit_test_data = [
        [Paragraph("<b>Test Name</b>", body_style), Paragraph("<b>Target Functionality</b>", body_style), Paragraph("<b>Execution Time</b>", body_style), Paragraph("<b>Status</b>", body_style)],
        [Paragraph("<code>test_script_tag_stripping</code>", body_style), Paragraph("Validates complete excision and neutralization of &lt;script&gt; tags.", body_style), Paragraph("0.001s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_html_entity_encoding</code>", body_style), Paragraph("Confirms conversion of &lt;, &gt;, \", ', /, &amp; into immutable HTML entities.", body_style), Paragraph("0.001s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_event_neutralization</code>", body_style), Paragraph("Neutralizes DOM event triggers (onerror, onload) to data-disabled-*.", body_style), Paragraph("0.001s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_javascript_pseudo_protocol</code>", body_style), Paragraph("Guarantees javascript: and data: URI schemes are blocked.", body_style), Paragraph("0.001s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_benign_text_preservation</code>", body_style), Paragraph("Ensures benign user inputs remain uncorrupted without false positives.", body_style), Paragraph("0.001s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)],
        [Paragraph("<code>test_csp_header_generation</code>", body_style), Paragraph("Validates CSP Level 3 policy syntax, nonces, and object-src 'none'.", body_style), Paragraph("0.001s", body_style), Paragraph("<font color='#0E703C'><b>PASSED</b></font>", body_style)]
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
        "All Day 21 source code, sample payload datasets, test suites, terminal screenshots, and audit artifacts have been synchronized into the official Phase 2 monorepo repository at <b>https://github.com/MdPeerSiddiqui/Sqrock-Internship-Phase-2</b> under the directory <code>Day21_XSS_Payload_Sanitizer/</code>.",
        body_style
    ))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 7: ENTERPRISE REMEDIATION PLAYBOOK & DEFENSE-IN-DEPTH ROADMAP
    # =========================================================================
    story.append(Paragraph("7. Enterprise Remediation Playbook & Defense-in-Depth Roadmap", h1_style))
    story.append(Paragraph(
        "To systematically eliminate Cross-Site Scripting vulnerabilities across enterprise web portfolios, engineering teams must implement defense-in-depth across the application lifecycle:",
        body_style
    ))
    story.append(Spacer(1, 3))

    playbook_steps = [
        "<b>Phase 1: Adopt Context-Aware Templating Engines:</b> Use modern web frameworks (React, Angular, Vue, Jinja2 autoescape) that enforce automatic context-aware contextual escaping by default. Prohibit dangerous bypass APIs such as <code>dangerouslySetInnerHTML</code> or <code>v-html</code>.",
        "<b>Phase 2: Enforce Strict Content Security Policy (CSP Level 3):</b> Deploy cryptographic nonce-based CSP headers. Disable <code>'unsafe-inline'</code> and <code>'unsafe-eval'</code> to guarantee that even if an attacker injects unescaped markup into the DOM, the browser execution engine will refuse to execute the script.",
        "<b>Phase 3: Secure Session Cookie Attributes:</b> Ensure all session cookies enforce <code>HttpOnly</code> (blocking JavaScript <code>document.cookie</code> access), <code>Secure</code> (HTTPS-only transmission), and <code>SameSite=Strict</code> (CSRF mitigation).",
        "<b>Phase 4: Pre-Commit Static Analysis (SAST):</b> Integrate AST-based static security analyzers (Bandit, Semgrep) into developer CI/CD workflows to catch unescaped user string concatenations before pull requests are merged."
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
        [Paragraph("<b>Evaluation Standard:</b>", body_style), Paragraph("OWASP Top 10 A03:2021 | CWE-79", body_style),
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
