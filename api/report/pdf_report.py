import io
from datetime import datetime
from typing import Dict, Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT


SEVERITY_COLORS = {
    "critical": colors.HexColor("#DC2626"),
    "high": colors.HexColor("#EA580C"),
    "medium": colors.HexColor("#D97706"),
    "low": colors.HexColor("#2563EB"),
    "info": colors.HexColor("#6B7280"),
}


def generate_pdf(report: Dict[str, Any]) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    styles.add(ParagraphStyle(
        "CoverTitle", parent=styles["Title"],
        fontSize=28, spaceAfter=10, textColor=colors.HexColor("#0F172A"),
        alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        "CoverSubtitle", parent=styles["Normal"],
        fontSize=14, spaceAfter=6, textColor=colors.HexColor("#64748B"),
        alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        "SectionTitle", parent=styles["Heading1"],
        fontSize=18, spaceBefore=20, spaceAfter=10,
        textColor=colors.HexColor("#0F172A"),
    ))
    styles.add(ParagraphStyle(
        "SubSection", parent=styles["Heading2"],
        fontSize=13, spaceBefore=12, spaceAfter=6,
        textColor=colors.HexColor("#334155"),
    ))
    styles.add(ParagraphStyle(
        "FindingTitle", parent=styles["Heading3"],
        fontSize=11, spaceBefore=10, spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        "BodyText2", parent=styles["Normal"],
        fontSize=9, spaceAfter=4, leading=13,
    ))

    elements = []

    # === COVER PAGE ===
    elements.append(Spacer(1, 60 * mm))
    elements.append(Paragraph("DEVSPIRE", styles["CoverTitle"]))
    elements.append(Paragraph("Security Assessment Report", styles["CoverSubtitle"]))
    elements.append(Spacer(1, 20 * mm))
    elements.append(Paragraph(f"Target: {report['target']}", styles["CoverSubtitle"]))
    elements.append(Paragraph(f"Date: {report.get('completed_at', '')[:10]}", styles["CoverSubtitle"]))
    elements.append(Paragraph(f"Scan ID: {report['scan_id']}", styles["CoverSubtitle"]))
    elements.append(Spacer(1, 20 * mm))

    grade = report.get("grade", "?")
    score = report.get("score", 0)
    grade_color = (
        colors.HexColor("#16A34A") if score >= 75
        else colors.HexColor("#D97706") if score >= 50
        else colors.HexColor("#DC2626")
    )
    elements.append(Paragraph(
        f'<font size="48" color="{grade_color}"><b>{grade}</b></font>',
        ParagraphStyle("Grade", alignment=TA_CENTER, parent=styles["Normal"]),
    ))
    elements.append(Paragraph(
        f'Security Score: {score}/100',
        ParagraphStyle("Score", alignment=TA_CENTER, fontSize=14, parent=styles["Normal"]),
    ))
    elements.append(PageBreak())

    # === EXECUTIVE SUMMARY ===
    elements.append(Paragraph("Executive Summary", styles["SectionTitle"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E2E8F0")))
    elements.append(Spacer(1, 5 * mm))

    summary = report.get("summary", {})
    summary_text = (
        f"A comprehensive security assessment was conducted on <b>{report['target']}</b>. "
        f"The analysis identified <b>{report['total_findings']}</b> findings across 10 security modules. "
        f"The overall security score is <b>{score}/100 (Grade {grade})</b>."
    )
    elements.append(Paragraph(summary_text, styles["BodyText2"]))
    elements.append(Spacer(1, 5 * mm))

    # Summary table
    summary_data = [
        ["Severity", "Count"],
        ["Critical", str(summary.get("critical", 0))],
        ["High", str(summary.get("high", 0))],
        ["Medium", str(summary.get("medium", 0))],
        ["Low", str(summary.get("low", 0))],
        ["Info", str(summary.get("info", 0))],
    ]
    summary_table = Table(summary_data, colWidths=[80 * mm, 40 * mm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 10 * mm))

    # === FINDINGS TABLE ===
    elements.append(Paragraph("Findings Overview", styles["SectionTitle"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E2E8F0")))
    elements.append(Spacer(1, 5 * mm))

    findings = report.get("findings", [])
    if findings:
        findings_header = [["#", "Severity", "Finding", "Module"]]
        findings_rows = []
        for i, f in enumerate(findings, 1):
            findings_rows.append([
                str(i),
                f.get("severity", "info").upper(),
                Paragraph(f.get("title", "")[:80], styles["BodyText2"]),
                f.get("module", ""),
            ])

        findings_table = Table(
            findings_header + findings_rows,
            colWidths=[10 * mm, 20 * mm, 100 * mm, 30 * mm],
        )
        findings_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ALIGN", (0, 0), (1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(findings_table)
    else:
        elements.append(Paragraph("No findings detected.", styles["BodyText2"]))

    elements.append(PageBreak())

    # === DETAILED FINDINGS ===
    elements.append(Paragraph("Detailed Findings", styles["SectionTitle"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E2E8F0")))

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "info")
        sev_color = SEVERITY_COLORS.get(sev, colors.gray)
        elements.append(Paragraph(
            f'<font color="{sev_color}"><b>[{sev.upper()}]</b></font> #{i} — {_escape(f.get("title", ""))}',
            styles["FindingTitle"],
        ))
        if f.get("description"):
            elements.append(Paragraph(f"<b>Description:</b> {_escape(f['description'])}", styles["BodyText2"]))
        if f.get("module"):
            elements.append(Paragraph(f"<b>Module:</b> {f['module']}", styles["BodyText2"]))
        if f.get("evidence"):
            evidence = f["evidence"] if isinstance(f["evidence"], list) else [f["evidence"]]
            elements.append(Paragraph(f"<b>Evidence:</b> {_escape(', '.join(str(e) for e in evidence[:3]))}", styles["BodyText2"]))
        if f.get("remediation"):
            elements.append(Paragraph(f"<b>Remediation:</b> {_escape(f['remediation'])}", styles["BodyText2"]))
        elements.append(Spacer(1, 3 * mm))

    elements.append(PageBreak())

    # === TECHNOLOGY STACK ===
    elements.append(Paragraph("Technology Stack", styles["SectionTitle"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E2E8F0")))
    elements.append(Spacer(1, 5 * mm))

    tech = report.get("technologies", {})
    if tech:
        for category, items in tech.items():
            elements.append(Paragraph(f"<b>{category.replace('_', ' ').title()}:</b> {', '.join(items)}", styles["BodyText2"]))
    else:
        elements.append(Paragraph("No technologies detected.", styles["BodyText2"]))

    elements.append(Spacer(1, 10 * mm))

    # === SUBDOMAINS ===
    subs = report.get("subdomains", [])
    if subs:
        elements.append(Paragraph("Discovered Subdomains", styles["SectionTitle"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E2E8F0")))
        elements.append(Spacer(1, 5 * mm))
        for s in subs:
            status = ""
            if s.get("https"):
                status = f"HTTPS {s['https'].get('status_code', '?')}"
            elif s.get("http"):
                status = f"HTTP {s['http'].get('status_code', '?')}"
            elements.append(Paragraph(f"• {s['subdomain']} — {status}", styles["BodyText2"]))

    elements.append(Spacer(1, 10 * mm))

    # === RECOMMENDATIONS ===
    recommendations = report.get("recommendations", [])
    if recommendations:
        elements.append(Paragraph("Top Recommendations", styles["SectionTitle"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E2E8F0")))
        elements.append(Spacer(1, 5 * mm))
        for rec in recommendations:
            elements.append(Paragraph(
                f"<b>{rec['priority']}.</b> [{rec['severity'].upper()}] {_escape(rec['action'])}",
                styles["BodyText2"],
            ))

    elements.append(PageBreak())

    # === DISCLAIMER ===
    elements.append(Paragraph("Disclaimer", styles["SectionTitle"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E2E8F0")))
    elements.append(Spacer(1, 5 * mm))
    elements.append(Paragraph(
        "This security assessment was performed using automated scanning tools provided by DevSpire. "
        "The findings represent the state of the target at the time of scanning and may not reflect subsequent changes. "
        "This report should be used for authorized security testing purposes only. "
        "DevSpire does not assume liability for any actions taken based on this report. "
        "Always obtain proper authorization before conducting security assessments.",
        styles["BodyText2"],
    ))
    elements.append(Spacer(1, 5 * mm))
    elements.append(Paragraph(
        f"Report generated by DevSpire on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        ParagraphStyle("Footer", alignment=TA_CENTER, fontSize=8, textColor=colors.gray, parent=styles["Normal"]),
    ))

    doc.build(elements)
    return buffer.getvalue()


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
