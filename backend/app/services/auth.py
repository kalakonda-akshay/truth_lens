import base64
import hashlib
import hmac
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from app.config import get_settings
from app.database import db_connection


SESSION_DAYS = 14


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 210_000)
    return f"pbkdf2_sha256${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(derived).decode()}"


def _password_matches(password: str, stored: str) -> bool:
    try:
        _, salt_text, digest_text = stored.split("$", 2)
        salt = base64.urlsafe_b64decode(salt_text.encode())
        expected = base64.urlsafe_b64decode(digest_text.encode())
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 210_000)
        return hmac.compare_digest(candidate, expected)
    except (ValueError, TypeError):
        return False


def _token_hash(token: str) -> str:
    secret = get_settings().auth_secret.encode("utf-8")
    return hmac.new(secret, token.encode("utf-8"), hashlib.sha256).hexdigest()


def _public_user(row: Any) -> dict[str, str]:
    return {
        "id": row["id"],
        "email": row["email"],
        "name": row["name"],
        "avatar_url": row["avatar_url"],
        "provider": row["provider"],
        "role": "administrator" if row["email"].lower() in get_settings().administrators else row["role"],
    }


def _create_session(user_id: str) -> str:
    token = secrets.token_urlsafe(40)
    expires_at = (_now() + timedelta(days=SESSION_DAYS)).isoformat()
    with db_connection() as conn:
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (_token_hash(token), user_id, expires_at),
        )
    return token


def register_user(name: str, email: str, password: str) -> tuple[dict[str, str], str]:
    normalized_email = email.strip().lower()
    if len(password) < 8:
        raise ValueError("Password must contain at least 8 characters.")
    user_id = str(uuid.uuid4())
    with db_connection() as conn:
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (normalized_email,)).fetchone()
        if existing:
            raise ValueError("An account with this email already exists.")
        configured_admin = normalized_email in get_settings().administrators
        existing_admin = conn.execute("SELECT id FROM users WHERE role = 'administrator' LIMIT 1").fetchone()
        initial_admin = existing_admin is None and not get_settings().administrators
        role = "administrator" if configured_admin or initial_admin else "analyst"
        conn.execute(
            """
            INSERT INTO users (id, email, name, password_hash, avatar_url, provider, role, created_at)
            VALUES (?, ?, ?, ?, '', 'email', ?, ?)
            """,
            (
                user_id,
                normalized_email,
                name.strip() or "TruthLens Analyst",
                _password_hash(password),
                role,
                _now().isoformat(),
            ),
        )
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _public_user(row), _create_session(user_id)


def login_user(email: str, password: str) -> tuple[dict[str, str], str]:
    with db_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()
    if row is None or not row["password_hash"] or not _password_matches(password, row["password_hash"]):
        raise ValueError("Invalid email or password.")
    return _public_user(row), _create_session(row["id"])


def authenticate_token(token: str) -> dict[str, str] | None:
    if not token:
        return None
    with db_connection() as conn:
        row = conn.execute(
            """
            SELECT users.* FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token_hash = ? AND sessions.expires_at > ?
            """,
            (_token_hash(token), _now().isoformat()),
        ).fetchone()
    return _public_user(row) if row else None


def logout_user(token: str) -> None:
    with db_connection() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))


def google_login(credential: str) -> tuple[dict[str, str], str]:
    settings = get_settings()
    if not settings.google_client_id:
        raise ValueError("Google Sign-In is not configured.")
    response = requests.get(
        "https://oauth2.googleapis.com/tokeninfo",
        params={"id_token": credential},
        timeout=20,
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("aud") != settings.google_client_id or payload.get("email_verified") not in {"true", True}:
        raise ValueError("Google credential validation failed.")
    email = str(payload["email"]).lower()
    with db_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if row is None:
            user_id = str(uuid.uuid4())
            existing_admin = conn.execute("SELECT id FROM users WHERE role = 'administrator' LIMIT 1").fetchone()
            initial_admin = existing_admin is None and not settings.administrators
            role = "administrator" if email in settings.administrators or initial_admin else "analyst"
            conn.execute(
                """
                INSERT INTO users (id, email, name, password_hash, avatar_url, provider, role, created_at)
                VALUES (?, ?, ?, NULL, ?, 'google', ?, ?)
                """,
                (
                    user_id,
                    email,
                    payload.get("name") or "TruthLens Analyst",
                    payload.get("picture") or "",
                    role,
                    _now().isoformat(),
                ),
            )
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        else:
            conn.execute(
                "UPDATE users SET name = ?, avatar_url = ?, provider = 'google' WHERE id = ?",
                (payload.get("name") or row["name"], payload.get("picture") or row["avatar_url"], row["id"]),
            )
            row = conn.execute("SELECT * FROM users WHERE id = ?", (row["id"],)).fetchone()
    return _public_user(row), _create_session(row["id"])
