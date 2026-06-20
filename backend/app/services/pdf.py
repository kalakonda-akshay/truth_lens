from io import BytesIO
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Image as ReportImage
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.config import get_settings
from app.models import AnalysisReport


DISCLAIMER = (
    "This report has been generated using automated forensic analysis techniques. "
    "Results are probabilistic assessments and should be considered advisory in nature. "
    "TruthLens AI does not guarantee absolute authenticity or inauthenticity. "
    "Additional human verification is recommended for critical decisions."
)


def _section(title: str, rows: list[list[str]], header_color: str = "#0f172a") -> Table:
    table = Table([[title, ""]] + rows, colWidths=[2.25 * inch, 4.65 * inch])
    table.setStyle(
        TableStyle(
            [
                ("SPAN", (0, 0), (-1, 0)),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(header_color)),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 1), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    return table


def _score_cards(report: AnalysisReport) -> Table:
    if report.media_type in {"url", "email"}:
        threat_score = int(report.url_analysis.get("threat_score", report.scores.threat_score))
        phishing_probability = int(report.url_analysis.get("phishing_probability", report.scores.threat_score))
        domain_risk_score = int(report.url_analysis.get("domain_risk_score", report.scores.threat_score))
        classification = str(report.url_analysis.get("threat_classification", report.threat_classification)).upper()
        risk_color = "#dc2626" if threat_score >= 65 else "#f59e0b" if threat_score >= 35 else "#059669"
        table = Table(
            [
                ["THREAT SCORE", "PHISHING PROBABILITY", "DOMAIN RISK SCORE", "THREAT CLASSIFICATION"],
                [f"{threat_score}%", f"{phishing_probability}%", f"{domain_risk_score}%", classification],
            ],
            colWidths=[1.72 * inch] * 4,
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eaf8fb")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 8),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 1), (-1, 1), 16),
                    ("TEXTCOLOR", (0, 1), (-1, 1), colors.HexColor(risk_color)),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#cbd5e1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
                    ("PADDING", (0, 0), (-1, -1), 10),
                ]
            )
        )
        return table
    risk_color = "#dc2626" if report.scores.risk_level in {"High", "Critical"} else "#f59e0b" if report.scores.risk_level == "Medium" else "#059669"
    table = Table(
        [
            ["AUTHENTICITY SCORE", "AI / SYNTHETIC PROBABILITY", "RISK LEVEL", "THREAT SCORE"],
            [
                f"{report.scores.authenticity_score}%",
                f"{report.scores.deepfake_probability}%",
                report.scores.risk_level.upper(),
                f"{report.scores.threat_score}%",
            ],
        ],
        colWidths=[1.72 * inch] * 4,
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eaf8fb")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 8),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 1), (-1, 1), 18),
                ("TEXTCOLOR", (0, 1), (0, 1), colors.HexColor("#059669")),
                ("TEXTCOLOR", (1, 1), (1, 1), colors.HexColor("#dc2626" if report.scores.deepfake_probability >= 65 else "#f59e0b")),
                ("TEXTCOLOR", (2, 1), (2, 1), colors.HexColor(risk_color)),
                ("TEXTCOLOR", (3, 1), (3, 1), colors.HexColor(risk_color)),
                ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
                ("PADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    return table


def _classification_color(classification: str) -> str:
    if classification == "ANALYSIS FAILED":
        return "#991b1b"
    if classification in {"AI GENERATED", "AI Generated"}:
        return "#dc2626"
    if classification in {"LIKELY AI GENERATED", "Likely AI Generated"}:
        return "#f97316"
    if classification == "SUSPICIOUS":
        return "#facc15"
    if classification in {"AUTHENTIC", "LIKELY AUTHENTIC"}:
        return "#059669"
    if classification == "AI Generated":
        return "#dc2626"
    if classification == "Likely AI Generated":
        return "#f97316"
    if classification == "Manipulated":
        return "#facc15"
    if classification == "Authentic":
        return "#059669"
    return "#94a3b8"


def _draw_shell(canvas, doc, report: AnalysisReport):
    canvas.saveState()
    width, height = letter
    canvas.setFillColor(colors.HexColor("#031225"))
    canvas.rect(0, height - 94, width, 94, fill=1, stroke=0)
    canvas.setFillColor(colors.HexColor("#22d3ee"))
    canvas.circle(44, height - 48, 26, fill=0, stroke=1)
    canvas.setFont("Helvetica-Bold", 24)
    canvas.setFillColor(colors.white)
    canvas.drawString(82, height - 44, "Truth")
    canvas.setFillColor(colors.HexColor("#22d3ee"))
    canvas.drawString(146, height - 44, "Lens")
    canvas.setFont("Helvetica-Bold", 11)
    canvas.setFillColor(colors.white)
    canvas.drawString(84, height - 64, "AI")
    canvas.setFont("Helvetica", 8)
    canvas.drawString(82, height - 78, "See Truth. Stop Deception.")

    canvas.setFont("Helvetica-Bold", 22)
    canvas.drawCentredString(width / 2, height - 42, "FORENSIC ANALYSIS REPORT")
    canvas.setFont("Helvetica-Bold", 11)
    canvas.setFillColor(colors.HexColor("#bae6fd"))
    canvas.drawCentredString(width / 2, height - 63, "Synthetic Media & Cybersecurity Verification")

    canvas.setFont("Helvetica-Bold", 7.5)
    canvas.setFillColor(colors.white)
    right_x = width - 186
    lines = [
        ("REPORT ID", report.id[:18]),
        ("ANALYSIS DATE", report.uploaded_at[:19].replace("T", " ")),
        ("VERSION", "2.0.0"),
        ("ANALYZED BY", "TruthLens AI Engine"),
    ]
    for idx, (label, value) in enumerate(lines):
        y = height - 28 - idx * 14
        canvas.drawString(right_x, y, label)
        canvas.drawString(right_x + 68, y, ":")
        canvas.drawString(right_x + 78, y, value)

    canvas.setFillColor(colors.HexColor("#031225"))
    canvas.rect(0, 0, width, 36, fill=1, stroke=0)
    canvas.setFillColor(colors.HexColor("#22d3ee"))
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawCentredString(width / 2, 22, "Generated by TruthLens AI Engine")
    canvas.drawCentredString(width / 2, 12, "TEAM TRUTHLENS  |  See Truth. Stop Deception.")
    canvas.restoreState()


def build_pdf(report: AnalysisReport) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        title=f"TruthLens Report {report.id}",
        topMargin=1.18 * inch,
        bottomMargin=0.6 * inch,
        leftMargin=0.42 * inch,
        rightMargin=0.42 * inch,
    )
    styles = getSampleStyleSheet()
    body = ParagraphStyle("TruthLensBody", parent=styles["BodyText"], fontSize=8.5, leading=11)
    heading = ParagraphStyle("TruthLensHeading", parent=styles["Heading2"], fontSize=11, textColor=colors.HexColor("#0f172a"))

    story = [
        _section(
            "SUBMITTED FILE DETAILS",
            [
                ["File Name", report.filename],
                ["File Type", report.media_type.title()],
                ["File Size", f"{report.metadata.file_size_mb} MB"],
                ["Source", "Direct Upload" if report.media_type not in {"url", "email"} else "User Submitted Text"],
            ],
        ),
        Spacer(1, 8),
        _section(
            "ANALYSIS SUMMARY",
            [
                ["Media Type Detected", report.media_type.title()],
                ["Analysis Performed", report.analysis_summary],
                ["Authenticity Verdict", report.authenticity_verdict],
                ["Analysis Status", report.analysis_status.upper()],
                ["Model Used", report.model_used],
                *([["Error Details", report.error_details]] if report.error_details else []),
                *(
                    [
                        ["Threat Score", f"{report.url_analysis.get('threat_score', report.scores.threat_score)}%"],
                        ["Phishing Probability", f"{report.url_analysis.get('phishing_probability', report.scores.deepfake_probability)}%"],
                        ["Domain Risk Score", f"{report.url_analysis.get('domain_risk_score', report.scores.threat_score)}%"],
                    ]
                    if report.media_type in {"url", "email"}
                    else [
                        ["Overall Authenticity", f"{report.scores.authenticity_score}%"],
                        ["AI Generated Probability", f"{report.scores.deepfake_probability}%"],
                        ["AI Generated Classification", report.ai_classification.upper()],
                    ]
                ),
                ["Risk Level", report.scores.risk_level.upper()],
                ["Threat Classification", report.threat_classification.upper()],
                ["Model Confidence", f"{report.model_confidence}%"],
                ["Voice Clone Detected", report.voice_clone_detected],
                ["Deepfake Detection", report.deepfake_detected],
            ],
            "#083344",
        ),
        Spacer(1, 8),
        _score_cards(report),
        Spacer(1, 8),
        Table(
            [[
                "AUTHENTICITY VERDICT",
                report.authenticity_verdict.upper(),
            ]],
            colWidths=[2.25 * inch, 4.65 * inch],
            style=TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#031225")),
                    ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
                    ("BACKGROUND", (1, 0), (1, 0), colors.HexColor(_classification_color(report.authenticity_verdict))),
                    ("TEXTCOLOR", (1, 0), (1, 0), colors.white if report.authenticity_verdict != "SUSPICIOUS" else colors.HexColor("#0f172a")),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 14),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#cbd5e1")),
                    ("PADDING", (0, 0), (-1, -1), 12),
                ]
            ),
        ),
        Spacer(1, 8),
        _section(
            "MODEL-BACKED DECISION",
            [
                ["Threat Classification", report.threat_classification],
                ["Authenticity Verdict", report.authenticity_verdict],
                ["Analysis Status", report.analysis_status.upper()],
                ["Model Used", report.model_used],
                *([["Error Details", report.error_details]] if report.error_details else []),
                ["Model Confidence", f"{report.model_confidence}%"],
                ["Voice Clone Detected", report.voice_clone_detected],
                ["Deepfake Detection", report.deepfake_detected],
                ["Evidence Summary", report.evidence_summary],
            ],
            "#164e63",
        ),
        Spacer(1, 8),
        _section(
            "1. METADATA ANALYSIS",
            [
                ["Camera Information", report.metadata.camera_information],
                ["Creation Date", report.metadata.creation_date],
                ["Editing Software", report.metadata.editing_software],
                ["EXIF Data", "Present" if report.metadata.exif_data else "Not found"],
                ["Metadata Indicators", "; ".join(report.metadata.tampering_indicators)],
            ],
        ),
        Spacer(1, 8),
    ]

    visual_rows: list[list[str]] = []
    if report.image_forensics:
        for key, value in report.image_forensics.items():
            if key not in {"summary", "heatmap_generated", "resolution"}:
                visual_rows.append([key.replace("_", " ").title(), str(value)])
    elif report.audio_clone_detection:
        for key, value in report.audio_clone_detection.items():
            visual_rows.append([key.replace("_", " ").title(), str(value)])
    else:
        visual_rows.append(["Visual Analysis", "No visual module evidence available for this media type."])
    story.extend([
        _section("2. VISUAL / SIGNAL ANALYSIS", visual_rows or [["Indicators", "No measured indicators crossed reporting threshold."]], "#0f766e"),
        Spacer(1, 8),
        _section("3. AI ARTIFACT / THREAT DETECTION", [[item.label, item.detail] for item in report.evidence] or [["Findings", "No high-risk evidence items were generated."]], "#7f1d1d"),
        Spacer(1, 8),
    ])

    local_images: list[str] = []
    storage_dir = get_settings().storage_dir
    for frame in report.suspicious_frames[:2]:
        if frame.frame_url.startswith("/frames/"):
            candidate = storage_dir / "frames" / Path(frame.frame_url).name
            if candidate.exists():
                local_images.append(str(candidate))
    if local_images:
        image_row = [ReportImage(path, width=2.75 * inch, height=1.55 * inch) for path in local_images]
        story.extend([Paragraph("4. EVIDENCE VISUALIZATION", heading), Table([image_row]), Spacer(1, 8)])

    story.extend(
        [
            _section("5. KEY FINDINGS", [["Finding", finding] for finding in report.key_findings] or [["Finding", "No high-risk findings generated."]], "#0f172a"),
            Spacer(1, 8),
            _section("6. CONCLUSION", [["Conclusion", report.conclusion]], "#7f1d1d" if report.scores.threat_score >= 35 else "#065f46"),
            Spacer(1, 8),
            _section("7. RECOMMENDATION", [["Recommendation", item] for item in report.recommendations], "#0f766e"),
            Spacer(1, 8),
            Paragraph("DISCLAIMER", heading),
            Paragraph(DISCLAIMER, body),
        ]
    )
    doc.build(story, onFirstPage=lambda c, d: _draw_shell(c, d, report), onLaterPages=lambda c, d: _draw_shell(c, d, report))
    return buffer.getvalue()
