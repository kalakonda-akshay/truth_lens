import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

from app.config import get_settings
from app.database import db_connection
from app.models import AnalysisReport


def _canonical_report_payload(report: AnalysisReport) -> str:
    data = report.model_dump(mode="json")
    for field in ("report_hash", "report_signature", "verification_url"):
        data.pop(field, None)
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def report_hash(report: AnalysisReport) -> str:
    return hashlib.sha256(_canonical_report_payload(report).encode("utf-8")).hexdigest()


def report_signature(hash_value: str) -> str:
    secret = get_settings().auth_secret.encode("utf-8")
    return hmac.new(secret, hash_value.encode("utf-8"), hashlib.sha256).hexdigest()


def verification_url(report_id: str) -> str:
    base = get_settings().public_app_url.rstrip("/")
    return f"{base}/verify/{report_id}" if base else f"/verify/{report_id}"


def attach_integrity(report: AnalysisReport) -> AnalysisReport:
    hash_value = report_hash(report)
    return report.model_copy(
        update={
            "report_hash": hash_value,
            "report_signature": report_signature(hash_value),
            "verification_url": verification_url(report.id),
        }
    )


def save_integrity(report: AnalysisReport) -> None:
    secured = attach_integrity(report)
    with db_connection() as conn:
        values = (
            secured.id,
            secured.report_hash,
            secured.report_signature,
            secured.verification_url,
            datetime.now(timezone.utc).isoformat(),
        )
        if conn.dialect == "postgres":
            conn.execute(
                """
                INSERT INTO report_integrity (report_id, report_hash, signature, verification_url, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT (report_id) DO UPDATE SET
                    report_hash = EXCLUDED.report_hash,
                    signature = EXCLUDED.signature,
                    verification_url = EXCLUDED.verification_url,
                    created_at = EXCLUDED.created_at
                """,
                values,
            )
        else:
            conn.execute(
                """
                INSERT OR REPLACE INTO report_integrity
                (report_id, report_hash, signature, verification_url, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                values,
            )


def verification_record(report: AnalysisReport | None) -> dict[str, Any]:
    if report is None:
        return {"status": "not_found", "valid": False}
    secured = attach_integrity(report)
    with db_connection() as conn:
        row = conn.execute(
            "SELECT * FROM report_integrity WHERE report_id = ?",
            (secured.id,),
        ).fetchone()
    stored_hash = row["report_hash"] if row else secured.report_hash
    stored_signature = row["signature"] if row else secured.report_signature
    expected_signature = report_signature(stored_hash)
    valid = hmac.compare_digest(stored_hash, secured.report_hash) and hmac.compare_digest(stored_signature, expected_signature)
    return {
        "status": "verified" if valid else "mismatch",
        "valid": valid,
        "report_id": secured.id,
        "report_hash": secured.report_hash,
        "signature": secured.report_signature,
        "verification_url": secured.verification_url,
        "media_type": secured.media_type,
        "filename": secured.filename,
        "uploaded_at": secured.uploaded_at,
        "risk_level": secured.scores.risk_level,
        "threat_classification": secured.threat_classification,
        "authenticity_verdict": secured.authenticity_verdict,
    }
