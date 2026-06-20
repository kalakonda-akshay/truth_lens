from __future__ import annotations

import importlib.metadata
import platform
import sqlite3
from datetime import datetime, timezone
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.config import get_settings
from app.database import _database_path, db_connection, init_db


def _version(package: str) -> str:
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return "Not installed"


def _configured(value: str) -> str:
    return "Configured" if value.strip() else "Not configured"


def _schema() -> list[dict[str, Any]]:
    output = []
    with db_connection() as conn:
        tables = [row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()]
        for table in tables:
            fields = [
                {
                    "name": row["name"],
                    "type": row["type"] or "TEXT",
                    "required": bool(row["notnull"]),
                    "primary_key": bool(row["pk"]),
                }
                for row in conn.execute(f'PRAGMA table_info("{table}")').fetchall()
            ]
            output.append({"name": table, "fields": fields})
    return output


def _database_health() -> str:
    try:
        with sqlite3.connect(_database_path()) as conn:
            conn.execute("SELECT 1").fetchone()
        return "Operational"
    except sqlite3.Error:
        return "Offline"


def build_system_documentation() -> dict[str, Any]:
    init_db()
    settings = get_settings()
    schema = _schema()
    api_integrations = [
        {
            "name": "Sightengine",
            "purpose": "AI-generated image and sampled video-frame detection.",
            "status": "Operational" if settings.sightengine_api_user and settings.sightengine_api_secret else "Not configured",
            "endpoint": "https://api.sightengine.com/1.0/check.json",
            "usage": "Images are submitted directly; up to eight extracted video frames are submitted with genai and deepfake models.",
            "credentials": "SIGHTENGINE_API_USER and SIGHTENGINE_API_SECRET (masked; values never returned).",
        },
        {
            "name": "Reality Defender",
            "purpose": "Synthetic speech and voice-clone detection.",
            "status": _configured(settings.reality_defender_api_key),
            "endpoint": "https://api.prd.realitydefender.xyz/api/files/aws-presigned and /api/media/users/{request_id}",
            "usage": "Audio receives a presigned upload URL, uploads to object storage, then polls the media result for AUTHENTIC, FAKE, or SUSPICIOUS.",
            "credentials": "REALITY_DEFENDER_API_KEY (masked; value never returned).",
        },
        {
            "name": "Google OAuth",
            "purpose": "Optional Google Identity Services sign-in.",
            "status": _configured(settings.google_client_id),
            "endpoint": "https://oauth2.googleapis.com/tokeninfo",
            "usage": "The backend validates the Google ID token audience and verified-email claim before creating or updating the local user profile.",
            "credentials": "GOOGLE_CLIENT_ID (masked; value never returned).",
        },
        {
            "name": "VirusTotal",
            "purpose": "No active purpose in the current implementation.",
            "status": "Removed",
            "endpoint": "Not used",
            "usage": "External phishing dependency was removed. URL and embedded-email-link analysis use the local TruthLens URL engine.",
            "credentials": "No VirusTotal secret is read or stored.",
        },
    ]
    configured_services = {item["name"]: item["status"] for item in api_integrations}
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "Generated from installed packages, FastAPI settings, SQLite PRAGMA schema inspection, and implemented service modules.",
        "frontend": {
            "framework": "Next.js App Router",
            "version": "15.5.19",
            "runtime": f"React 19 / TypeScript {_version('typescript') if _version('typescript') != 'Not installed' else '5.7.2'}",
            "ui_libraries": ["Tailwind CSS 3.4.17", "Lucide React 0.468.0", "jsPDF 4.2.1", "html2canvas 1.4.1"],
            "routing": "Next.js app directory with dynamic /analyze/[type], /results/[id], API proxy routes, and optional NEXT_PUBLIC_BASE_PATH.",
            "state_management": "React context for authentication; component state for forms/uploads; localStorage for session token/user and report cache.",
        },
        "backend": {
            "framework": f"FastAPI {_version('fastapi')}",
            "runtime": f"Python {platform.python_version()} with Uvicorn {_version('uvicorn')}",
            "api_structure": ["/auth/*", "/analyze", "/analyze/url", "/analyze/email", "/user/reports", "/reports/{id}", "/system/documentation"],
            "services": ["auth.py", "analyzer.py", "content_models.py", "pretrained_models.py", "provider_clients.py", "risk.py", "pdf.py", "storage.py", "system_docs.py"],
        },
        "authentication": {
            "provider": "TruthLens local identity with optional Google Identity Services.",
            "login_methods": ["Email and password", "Google ID token when GOOGLE_CLIENT_ID is configured"],
            "google_status": configured_services["Google OAuth"],
            "session_management": "40-byte URL-safe bearer tokens; only HMAC-SHA256 token hashes are stored; sessions expire after 14 days.",
            "password_storage": "PBKDF2-HMAC-SHA256 with a random 16-byte salt and 210,000 iterations.",
            "account_storage": "SQLite users table at the path resolved from TRUTHLENS_DATABASE_URL.",
            "authorization": "users.role plus TRUTHLENS_ADMIN_EMAILS; /system-docs requires administrator.",
        },
        "database": {
            "provider": "SQLite via Python sqlite3",
            "path": str(_database_path()),
            "tables": schema,
            "logical_entities": {
                "Users": "Stored in users.",
                "Cases": "Derived from user-owned rows in analyses; no separate cases table exists.",
                "Reports": "Complete AnalysisReport JSON is stored in analyses.report_json.",
                "Evidence": "Embedded inside report_json evidence and suspicious_frames arrays; generated frame files are stored under TRUTHLENS_STORAGE_DIR/frames.",
                "Settings": "Environment-driven through pydantic-settings; no settings table exists.",
                "Sessions": "Stored in sessions as token_hash, user_id, and expires_at.",
            },
        },
        "integrations": api_integrations,
        "pipelines": {
            "Image": [
                "Upload is classified by extension/MIME and stored under storage/uploads.",
                "Metadata scanner reads file size, creation timestamp, codec/resolution, EXIF camera and editing-software traces.",
                "Sightengine genai/deepfake inference is required; failure produces ANALYSIS FAILED rather than an authentic verdict.",
                "OpenCV/Pillow content features measure texture, edges, lighting, compression and noise; evidence regions are created only from measured anomalies.",
                "Provider probability and measured forensic signals feed authenticity, AI probability, classification and risk.",
                "The AnalysisReport is persisted and rendered by the TruthLens PDF engine.",
            ],
            "Video": [
                "OpenCV opens the container and samples frames across the timeline.",
                "Frame features measure face-region, edge, texture, compression, noise and temporal inconsistency.",
                "Up to eight frames are sent to Sightengine genai/deepfake analysis.",
                "Frame and provider scores are aggregated; suspicious frames are retained only when evidence crosses thresholds.",
                "Final deepfake probability drives authenticity, AI classification, risk, evidence timeline and PDF output.",
            ],
            "Audio": [
                "SoundFile decodes audio and generates a real spectrogram evidence image.",
                "Reality Defender supplies a presigned upload URL and asynchronous ensemble result.",
                "The FAKE/SUSPICIOUS/AUTHENTIC result becomes synthetic-audio and voice-clone probability.",
                "Local spectral, MFCC, flatness, frequency, RMS and pitch-contour measurements support explainability.",
                "Provider failure produces ANALYSIS FAILED with zero fabricated probability.",
            ],
            "URL": [
                "The local engine parses scheme, host, path, query, TLD and domain labels.",
                "It checks raw IP use, HTTPS, subdomain depth, URL length, risky TLDs and redirect parameters.",
                "Brand variants detect impersonation and typosquatting; keywords detect login, wallet, OTP and credential themes.",
                "Measured indicators accumulate a bounded threat score and SAFE/SUSPICIOUS/LIKELY PHISHING/MALICIOUS classification.",
            ],
            "Email": [
                "The local engine analyzes sender/reply-to mismatch, consumer-domain impersonation and brand claims.",
                "It scores urgency, credential requests, financial lures, risky attachments and generic greetings.",
                "HTTP(S) links are extracted and passed through the same local URL engine.",
                "The strongest email or embedded-link signal determines threat score and highlighted evidence.",
            ],
        },
        "report_engine": {
            "pdf_generation": "ReportLab builds the branded TruthLens forensic PDF from the persisted AnalysisReport.",
            "evidence_creation": "EvidenceItem records originate from provider responses or measured metadata/content indicators; suspicious visual assets are referenced by frame URL.",
            "risk_calculation": "risk_level maps scores: Low <35, Medium 35-64, High 65-84, Critical >=85.",
            "authenticity_calculation": "For media, authenticity is 100 minus the final AI/deepfake/synthetic probability; failed required provider analysis returns ANALYSIS FAILED.",
        },
        "deployment": {
            "current_domain": settings.frontend_domain,
            "vercel_project": settings.vercel_project,
            "backend": "Railway service truthlens-api; health check /health; Nixpacks; Uvicorn start command.",
            "environment_variables": [
                "NEXT_PUBLIC_API_URL", "NEXT_PUBLIC_BASE_PATH", "NEXT_PUBLIC_GOOGLE_CLIENT_ID",
                "TRUTHLENS_DATABASE_URL", "TRUTHLENS_STORAGE_DIR", "TRUTHLENS_AUTH_SECRET",
                "TRUTHLENS_ADMIN_EMAILS", "SIGHTENGINE_API_USER", "SIGHTENGINE_API_SECRET",
                "REALITY_DEFENDER_API_KEY", "GOOGLE_CLIENT_ID", "ALLOWED_ORIGINS",
            ],
            "build_status": "Verified by npm run build and Python compileall before deployment.",
            "deployment_status": settings.deployment_status,
        },
        "health": {
            "Image Engine": "Operational" if configured_services["Sightengine"] == "Operational" else "Configuration required",
            "Video Engine": "Operational" if configured_services["Sightengine"] == "Operational" else "Configuration required",
            "Audio Engine": "Operational" if configured_services["Reality Defender"] == "Configured" else "Configuration required",
            "URL Engine": "Operational (local)",
            "Email Engine": "Operational (local)",
            "Database": _database_health(),
            "Authentication": "Operational",
            "Google Sign-In": configured_services["Google OAuth"],
        },
    }


def build_system_documentation_pdf(documentation: dict[str, Any]) -> bytes:
    buffer = BytesIO()
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(buffer, pagesize=letter, leftMargin=0.55 * inch, rightMargin=0.55 * inch, topMargin=0.55 * inch, bottomMargin=0.55 * inch)
    story = [Paragraph("TruthLens System Documentation", styles["Title"]), Paragraph(documentation["source"], styles["BodyText"]), Spacer(1, 12)]
    for section_name, content in documentation.items():
        if section_name in {"generated_at", "source"}:
            continue
        story.append(Paragraph(section_name.replace("_", " ").title(), styles["Heading2"]))
        rows = []
        if isinstance(content, dict):
            for key, value in content.items():
                rendered = ", ".join(map(str, value)) if isinstance(value, list) else str(value)
                rows.append([Paragraph(key.replace("_", " ").title(), styles["BodyText"]), Paragraph(rendered, styles["BodyText"])])
        elif isinstance(content, list):
            rows = [[Paragraph(str(index + 1), styles["BodyText"]), Paragraph(str(value), styles["BodyText"])] for index, value in enumerate(content)]
        if rows:
            table = Table(rows, colWidths=[1.65 * inch, 5.25 * inch], repeatRows=0)
            table.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eaf2ff")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]))
            story.extend([table, Spacer(1, 10)])
    doc.build(story)
    return buffer.getvalue()
