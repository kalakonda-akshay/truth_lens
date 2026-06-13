from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.models import AnalysisReport


def build_pdf(report: AnalysisReport) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, title=f"TruthLens Report {report.id}")
    styles = getSampleStyleSheet()
    story = [
        Paragraph("TruthLens Synthetic Media Verification Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"File: {report.filename}", styles["Normal"]),
        Paragraph(f"Awareness: {report.awareness_message}", styles["Normal"]),
        Spacer(1, 12),
    ]

    score_table = Table(
        [
            ["Authenticity", "Deepfake Probability", "Risk Level", "Confidence"],
            [
                f"{report.scores.authenticity_score}%",
                f"{report.scores.deepfake_probability}%",
                report.scores.risk_level,
                f"{report.scores.confidence_score}%",
            ],
        ]
    )
    score_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("PADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.extend([score_table, Spacer(1, 14), Paragraph("Evidence", styles["Heading2"])])

    for item in report.evidence:
        story.append(Paragraph(f"<b>{item.label}</b> [{item.severity}]: {item.detail}", styles["BodyText"]))
        story.append(Spacer(1, 6))

    story.extend([Spacer(1, 8), Paragraph("Metadata", styles["Heading2"])])
    story.append(Paragraph(f"Codec: {report.metadata.codec}", styles["BodyText"]))
    story.append(Paragraph(f"File size: {report.metadata.file_size_mb} MB", styles["BodyText"]))
    story.append(Paragraph(f"Duration: {report.metadata.duration_seconds or 'N/A'} seconds", styles["BodyText"]))
    story.append(Paragraph("This report is a prototype forensic aid and should be reviewed by a qualified analyst for high-impact decisions.", styles["Italic"]))
    doc.build(story)
    return buffer.getvalue()
