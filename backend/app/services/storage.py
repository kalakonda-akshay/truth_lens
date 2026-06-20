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
