import json

from app.database import db_connection
from app.models import AnalysisReport


def save_report(report: AnalysisReport, user_id: str | None = None) -> None:
    with db_connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO analyses
            (id, filename, media_type, uploaded_at, report_json, user_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                report.id,
                report.filename,
                report.media_type,
                report.uploaded_at,
                report.model_dump_json(),
                user_id,
            ),
        )


def get_report(report_id: str) -> AnalysisReport | None:
    with db_connection() as conn:
        row = conn.execute(
            "SELECT report_json FROM analyses WHERE id = ?",
            (report_id,),
        ).fetchone()
    if row is None:
        return None
    return AnalysisReport.model_validate(json.loads(row["report_json"]))


def list_reports(user_id: str) -> list[AnalysisReport]:
    with db_connection() as conn:
        rows = conn.execute(
            "SELECT report_json FROM analyses WHERE user_id = ? ORDER BY uploaded_at DESC",
            (user_id,),
        ).fetchall()
    return [AnalysisReport.model_validate(json.loads(row["report_json"])) for row in rows]


def list_admin_users() -> list[dict]:
    with db_connection() as conn:
        rows = conn.execute(
            """
            SELECT users.id, users.email, users.name, users.provider, users.role, users.created_at,
                   COUNT(analyses.id) AS total_analyses,
                   SUM(CASE WHEN analyses.media_type = 'image' THEN 1 ELSE 0 END) AS image_analyses,
                   MAX(analyses.uploaded_at) AS last_activity
            FROM users
            LEFT JOIN analyses ON analyses.user_id = users.id
            GROUP BY users.id
            ORDER BY users.created_at DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def list_admin_analyses() -> list[dict]:
    with db_connection() as conn:
        rows = conn.execute(
            """
            SELECT analyses.id, analyses.filename, analyses.media_type, analyses.uploaded_at,
                   analyses.report_json, users.id AS user_id, users.email AS user_email,
                   users.name AS user_name
            FROM analyses
            LEFT JOIN users ON users.id = analyses.user_id
            ORDER BY analyses.uploaded_at DESC
            LIMIT 500
            """
        ).fetchall()
    records = []
    for row in rows:
        report = json.loads(row["report_json"])
        scores = report.get("scores", {})
        records.append(
            {
                "id": row["id"],
                "filename": row["filename"],
                "media_type": row["media_type"],
                "uploaded_at": row["uploaded_at"],
                "user_id": row["user_id"],
                "user_email": row["user_email"] or "Anonymous upload",
                "user_name": row["user_name"] or "Unknown",
                "risk_level": scores.get("risk_level", "Unknown"),
                "authenticity_score": scores.get("authenticity_score", 0),
                "ai_probability": scores.get("deepfake_probability", 0),
                "threat_score": scores.get("threat_score", 0),
                "analysis_status": report.get("analysis_status", "unknown"),
                "ai_classification": report.get("ai_classification", "Unable To Determine"),
                "authenticity_verdict": report.get("authenticity_verdict", report.get("verdict", "Unknown")),
                "evidence_count": len(report.get("evidence", [])),
                "report": report,
            }
        )
    return records
