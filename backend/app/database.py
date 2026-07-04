import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from app.config import get_settings


def _database_url() -> str:
    return get_settings().database_url


def _is_postgres(url: str) -> bool:
    return url.startswith("postgres://") or url.startswith("postgresql://")


def _database_path(url: str) -> Path:
    if not url.startswith("sqlite:///"):
        raise ValueError("TruthLens supports SQLite and PostgreSQL database URLs.")
    return Path(url.replace("sqlite:///", "", 1)).resolve()


class Database:
    def __init__(self, conn: Any, dialect: str):
        self.conn = conn
        self.dialect = dialect

    def execute(self, query: str, params: tuple[Any, ...] = ()):
        if self.dialect == "postgres":
            query = query.replace("?", "%s")
            cursor = self.conn.cursor()
            cursor.execute(query, params)
            return cursor
        return self.conn.execute(query, params)

    def commit(self) -> None:
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


@contextmanager
def db_connection():
    url = _database_url()
    if _is_postgres(url):
        import psycopg
        from psycopg.rows import dict_row

        raw_conn = psycopg.connect(url, row_factory=dict_row)
        conn = Database(raw_conn, "postgres")
    else:
        path = _database_path(url)
        path.parent.mkdir(parents=True, exist_ok=True)
        raw_conn = sqlite3.connect(path)
        raw_conn.row_factory = sqlite3.Row
        conn = Database(raw_conn, "sqlite")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with db_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                password_hash TEXT,
                avatar_url TEXT NOT NULL DEFAULT '',
                provider TEXT NOT NULL DEFAULT 'email',
                role TEXT NOT NULL DEFAULT 'member',
                password_reset_required INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS otp_challenges (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS report_integrity (
                report_id TEXT PRIMARY KEY,
                report_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                verification_url TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        if conn.dialect == "sqlite":
            user_columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
            if "role" not in user_columns:
                conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'member'")
            if "password_reset_required" not in user_columns:
                conn.execute("ALTER TABLE users ADD COLUMN password_reset_required INTEGER NOT NULL DEFAULT 0")
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(analyses)").fetchall()}
            if "user_id" not in columns:
                conn.execute("ALTER TABLE analyses ADD COLUMN user_id TEXT")
        else:
            conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'member'")
            conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_required INTEGER NOT NULL DEFAULT 0")
            conn.execute("ALTER TABLE analyses ADD COLUMN IF NOT EXISTS user_id TEXT")
