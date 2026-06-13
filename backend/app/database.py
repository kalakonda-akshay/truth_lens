import sqlite3
from contextlib import contextmanager
from pathlib import Path

from app.config import get_settings


def _database_path() -> Path:
    url = get_settings().database_url
    if not url.startswith("sqlite:///"):
        raise ValueError("TruthLens prototype currently supports SQLite URLs only.")
    return Path(url.replace("sqlite:///", "", 1)).resolve()


@contextmanager
def db_connection():
    path = _database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with db_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                media_type TEXT NOT NULL,
                uploaded_at TEXT NOT NULL,
                report_json TEXT NOT NULL
            )
            """
        )
