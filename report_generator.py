from datetime import datetime
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib import colors


class PDFReportGenerator:
    def build_pdf(self, results: dict) -> bytes:
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Title"],
            alignment=TA_CENTER,
            fontSize=22,
            leading=28,
        )
        body = ParagraphStyle(
            "Body",
            parent=styles["BodyText"],
            fontSize=10,
            leading=16,
            wordWrap="CJK",
        )

        def p(text):
            return Paragraph(str(text), body)

        story = []

        volume = results.get("volume", {})
        cluster = results.get("cluster_analysis", {})
        region = results.get("region_analysis", {})
        ff_pattern = results.get("ff_pattern", {})

        # Cover
        story.append(Paragraph("Firmware Threat Intelligence Report", title_style))
        story.append(Spacer(1, 0.2 * inch))
        story.append(p(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
        story.append(Spacer(1, 0.25 * inch))

        # Summary
        story.append(Paragraph("Executive Summary", styles["Heading1"]))
        summary = (
            f"The firmware produced <b>{results.get('total_changes', 0)}</b> byte-level changes with "
            f"<b>{results.get('mass_erase_regions', 0)}</b> suspected erase regions. "
            f"Volume status: <b>{volume.get('status', 'UNKNOWN')}</b>. "
            f"Cluster status: <b>{cluster.get('status', 'UNKNOWN')}</b>. "
            f"Region status: <b>{region.get('status', 'UNKNOWN')}</b>."
        )
        story.append(p(summary))
        story.append(Spacer(1, 0.2 * inch))

        # Heuristic table with wrapped paragraphs
        story.append(Paragraph("Heuristic Summary", styles["Heading1"]))
        heuristic_rows = [
            [p("<b>Metric</b>"), p("<b>Value</b>")],
            [p("Total Changes"), p(results.get("total_changes", 0))],
            [p("Mass Erase Regions"), p(results.get("mass_erase_regions", 0))],
            [p("Volume"), p(volume.get("description", "N/A"))],
            [p("FF Pattern"), p(ff_pattern.get("description", "N/A"))],
            [p("Cluster Analysis"), p(cluster.get("description", "N/A"))],
            [p("Region Analysis"), p(region.get("description", "N/A"))],
        ]

        heuristic_table = Table(heuristic_rows, colWidths=[2.0 * inch, 4.8 * inch])
        heuristic_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(heuristic_table)
        story.append(Spacer(1, 0.25 * inch))

        detector_keys = [
            ("Rollback Hardening", "rollback"),
            ("Covert Channel", "covert"),
            ("Stealth Region Drift", "stealth"),
            ("Syscall Hook Surface", "hook"),
            ("Rootkit Persistence", "rootkit"),
            ("Fragmentation", "fragmentation"),
            ("Masquerade", "masquerade"),
            ("Secure Boot Bypass", "secure_boot"),
            ("Integrity Bypass", "integrity"),
        ]

        story.append(Paragraph("Detailed Detector Findings", styles["Heading1"]))

        for title, key in detector_keys:
            result = results.get(key, {})
            if not result:
                continue

            rows = [[p("<b>Field</b>"), p("<b>Value</b>")]]
            for field, value in result.items():
                rows.append([p(field), p(value)])

            table = Table(rows, colWidths=[2.0 * inch, 4.8 * inch])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A8A")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]))

            story.append(KeepTogether([
                Paragraph(title, styles["Heading2"]),
                table,
                Spacer(1, 0.18 * inch),
            ]))

        story.append(PageBreak())
        story.append(Paragraph("Analyst Verdict", styles["Heading1"]))
        story.append(p(
            "The report now uses wrapped table cells, improved spacing, and stable widths so long text no longer gets cut off."
        ))

        doc.build(story)
        pdf = buffer.getvalue()
        buffer.close()
        return pdf
