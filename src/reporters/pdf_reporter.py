"""CloudGuard PDF report generator.

Renders a CloudGuard findings list as a styled PDF audit report. Uses
ReportLab for layout. Designed to produce a downloadable artifact suitable
for cover letter attachment, internal audit prep, and external auditor
review. Output structure mirrors the conventions of a SOC 2 / PCI audit
deliverable: executive summary, control-by-control findings, framework
mapping, and remediation guidance.
"""
from collections import Counter
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


# --- styling constants ---------------------------------------------------

BRAND_COLOR = colors.HexColor("#0B3D91")
ACCENT_COLOR = colors.HexColor("#0563C1")
PASS_COLOR = colors.HexColor("#1B7A3E")
FAIL_COLOR = colors.HexColor("#B0202F")
TABLE_HEADER_BG = colors.HexColor("#0B3D91")
TABLE_ALT_BG = colors.HexColor("#F2F4F8")
SUMMARY_BG = colors.HexColor("#EAF2FB")


# Human-readable framework names for the legend
FRAMEWORK_LABELS = {
    "soc2": "SOC 2 TSC 2017",
    "pci_dss_4": "PCI DSS 4.0.1",
    "hipaa": "HIPAA Security Rule",
    "nist_800_53": "NIST SP 800-53 Rev. 5",
    "iso_27001": "ISO 27001:2022",
    "cis_aws": "CIS AWS Foundations",
}


def _build_styles() -> dict:
    """Build a paragraph style dictionary for the report."""
    base = getSampleStyleSheet()

    return {
        "title": ParagraphStyle(
            "title", parent=base["Title"],
            fontSize=20, leading=24, spaceAfter=4,
            textColor=BRAND_COLOR, alignment=0,
        ),
        "subtitle": ParagraphStyle(
            "subtitle", parent=base["Normal"],
            fontSize=10, leading=12, textColor=colors.grey, spaceAfter=12,
        ),
        "h2": ParagraphStyle(
            "h2", parent=base["Heading2"],
            fontSize=13, leading=16, spaceBefore=12, spaceAfter=6,
            textColor=BRAND_COLOR,
        ),
        "body": ParagraphStyle(
            "body", parent=base["Normal"],
            fontSize=9, leading=12, spaceAfter=4,
        ),
        "cell": ParagraphStyle(
            "cell", parent=base["Normal"],
            fontSize=8, leading=10,
        ),
        "cell_bold": ParagraphStyle(
            "cell_bold", parent=base["Normal"],
            fontSize=8, leading=10, fontName="Helvetica-Bold",
        ),
        "small": ParagraphStyle(
            "small", parent=base["Normal"],
            fontSize=8, leading=10, textColor=colors.grey,
        ),
    }


# --- internal helpers ----------------------------------------------------

def _format_framework_refs(refs: dict) -> str:
    """Compact one-line framework citation string for table cells.

    Renders as e.g. 'SOC 2: CC6.1 · PCI: 8.4.2/8.4.3 · CIS: 1.5'
    """
    parts = []
    short_labels = {
        "soc2": "SOC 2", "pci_dss_4": "PCI",
        "hipaa": "HIPAA", "nist_800_53": "NIST",
        "iso_27001": "ISO", "cis_aws": "CIS",
    }
    for key in ["soc2", "pci_dss_4", "hipaa", "nist_800_53", "iso_27001", "cis_aws"]:
        values = refs.get(key)
        if values:
            label = short_labels.get(key, key)
            parts.append(f"<b>{label}:</b> {'/'.join(values)}")
    return " · ".join(parts) if parts else "—"


def _summary_block(findings: list[dict], styles: dict) -> Table:
    """Build the executive summary box at the top of the report."""
    total = len(findings)
    passed = sum(1 for f in findings if f.get("passed"))
    failed = total - passed

    severity_counter = Counter(
        f.get("severity", "unknown").lower()
        for f in findings if not f.get("passed")
    )

    framework_counter = Counter()
    for f in findings:
        for key in f.get("framework_refs", {}):
            framework_counter[key] += 1

    summary_html = (
        f"<b>Controls evaluated:</b> {total} &nbsp;&nbsp; "
        f"<b>Passed:</b> <font color='#1B7A3E'>{passed}</font> &nbsp;&nbsp; "
        f"<b>Failed:</b> <font color='#B0202F'>{failed}</font><br/><br/>"
        f"<b>Failed by severity:</b> "
        f"Critical {severity_counter.get('critical', 0)} · "
        f"High {severity_counter.get('high', 0)} · "
        f"Medium {severity_counter.get('medium', 0)} · "
        f"Low {severity_counter.get('low', 0)}<br/><br/>"
        f"<b>Frameworks covered across all checks:</b> "
        + ", ".join(
            FRAMEWORK_LABELS.get(k, k)
            for k in sorted(framework_counter.keys())
        )
    )

    cell = Paragraph(summary_html, styles["body"])
    table = Table([[cell]], colWidths=[7.1 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SUMMARY_BG),
        ("BOX", (0, 0), (-1, -1), 0.75, BRAND_COLOR),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    return table


def _findings_table(findings: list[dict], styles: dict) -> Table:
    """Build the main control findings table."""
    headers = ["Control ID", "Severity", "Status", "Frameworks Cited", "Remediation"]

    data = [headers]
    for f in findings:
        passed = f.get("passed", False)
        status_text = "PASS" if passed else "FAIL"
        status_para = Paragraph(
            f"<b><font color='{'#1B7A3E' if passed else '#B0202F'}'>{status_text}</font></b>",
            styles["cell"],
        )
        remediation = f.get("remediation") or "—"
        framework_text = _format_framework_refs(f.get("framework_refs", {}))

        row = [
            Paragraph(f.get("control_id", "—"), styles["cell_bold"]),
            Paragraph(f.get("severity", "—").upper(), styles["cell"]),
            status_para,
            Paragraph(framework_text, styles["cell"]),
            Paragraph(remediation, styles["cell"]),
        ]
        data.append(row)

    table = Table(
        data,
        colWidths=[1.4 * inch, 0.7 * inch, 0.55 * inch, 2.1 * inch, 2.35 * inch],
        repeatRows=1,
    )

    table_style = [
        # Header row
        ("BACKGROUND", (0, 0), (-1, 0), TABLE_HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("ALIGN", (0, 0), (-1, 0), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        # Body rows
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CCCCCC")),
    ]
    # Alternating row shading
    for i in range(1, len(data)):
        if i % 2 == 0:
            table_style.append(("BACKGROUND", (0, i), (-1, i), TABLE_ALT_BG))

    table.setStyle(TableStyle(table_style))
    return table


def _framework_legend(styles: dict) -> Paragraph:
    """A small footer-style block decoding the framework abbreviations."""
    items = [f"<b>{short}</b> → {full}" for short, full in [
        ("SOC 2", "SOC 2 Trust Services Criteria 2017"),
        ("PCI", "PCI DSS 4.0.1"),
        ("HIPAA", "HIPAA Security Rule (45 CFR 164.312)"),
        ("NIST", "NIST SP 800-53 Rev. 5"),
        ("ISO", "ISO 27001:2022 Annex A"),
        ("CIS", "CIS AWS Foundations Benchmark"),
    ]]
    body = "&nbsp;&nbsp;|&nbsp;&nbsp;".join(items)
    return Paragraph(f"<b>Framework legend:</b><br/>{body}", styles["small"])


# --- public API ----------------------------------------------------------

def generate_pdf_report(
    findings: list[dict],
    output_path: Path,
    account_id: str = None,
) -> Path:
    """Render a CloudGuard findings list as a PDF report.

    Args:
        findings: list of finding dicts produced by CloudGuard checks.
        output_path: where to write the PDF.
        account_id: optional AWS account ID to include in the header.

    Returns:
        The path the PDF was written to.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    styles = _build_styles()
    story = []

    # Title block
    story.append(Paragraph("CloudGuard — AWS Control Findings Report", styles["title"]))
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    subtitle_parts = [f"Generated {timestamp}"]
    if account_id:
        subtitle_parts.append(f"Account {account_id}")
    story.append(Paragraph(" · ".join(subtitle_parts), styles["subtitle"]))

    story.append(Paragraph(
        "This report is generated by CloudGuard's continuous control "
        "monitoring engine via direct AWS API queries. Findings include "
        "multi-framework citations spanning SOC 2, PCI DSS 4.0.1, HIPAA, "
        "NIST 800-53, ISO 27001, and CIS AWS Foundations Benchmark.",
        styles["body"],
    ))

    # Executive summary
    story.append(Spacer(1, 8))
    story.append(Paragraph("Executive Summary", styles["h2"]))
    story.append(_summary_block(findings, styles))

    # Findings table
    story.append(Spacer(1, 12))
    story.append(Paragraph("Control Findings", styles["h2"]))
    story.append(_findings_table(findings, styles))

    # Framework legend at the bottom
    story.append(Spacer(1, 18))
    story.append(_framework_legend(styles))

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        leftMargin=0.7 * inch,
        rightMargin=0.7 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.7 * inch,
        title="CloudGuard Findings Report",
        author="CloudGuard CCM",
    )
    doc.build(story)

    return output_path