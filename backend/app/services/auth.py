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
OTP_MINUTES = 10


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
        "role": row["role"] if "role" in row.keys() else "member",
        "password_reset_required": bool(row["password_reset_required"]) if "password_reset_required" in row.keys() else False,
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


def _role_for_email(email: str) -> str:
    return "founder_admin" if email.strip().lower() in get_settings().admin_email_set else "member"


def _hash_otp(challenge_id: str, code: str) -> str:
    secret = get_settings().auth_secret.encode("utf-8")
    payload = f"{challenge_id}:{code}".encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def ensure_founder_admin() -> None:
    settings = get_settings()
    if not settings.admin_email_set:
        return
    with db_connection() as conn:
        for email in settings.admin_email_set:
            row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if row:
                conn.execute("UPDATE users SET role = 'founder_admin' WHERE id = ?", (row["id"],))
            elif settings.founder_admin_bootstrap_password:
                conn.execute(
                    """
                    INSERT INTO users (id, email, name, password_hash, avatar_url, provider, role, password_reset_required, created_at)
                    VALUES (?, ?, ?, ?, '', 'email', 'founder_admin', 0, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        email,
                        "Akshay Kalakonda",
                        _password_hash(settings.founder_admin_bootstrap_password),
                        _now().isoformat(),
                    ),
                )


def register_user(name: str, email: str, password: str) -> tuple[dict[str, str], str]:
    normalized_email = email.strip().lower()
    if len(password) < 8:
        raise ValueError("Password must contain at least 8 characters.")
    user_id = str(uuid.uuid4())
    with db_connection() as conn:
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (normalized_email,)).fetchone()
        if existing:
            raise ValueError("An account with this email already exists.")
        conn.execute(
            """
            INSERT INTO users (id, email, name, password_hash, avatar_url, provider, role, password_reset_required, created_at)
            VALUES (?, ?, ?, ?, '', 'email', ?, 0, ?)
            """,
            (user_id, normalized_email, name.strip() or "TruthLens Analyst", _password_hash(password), _role_for_email(normalized_email), _now().isoformat()),
        )
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _public_user(row), _create_session(user_id)


def login_user(email: str, password: str) -> tuple[dict[str, str], str]:
    with db_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()
    if row is None or not row["password_hash"] or not _password_matches(password, row["password_hash"]):
        raise ValueError("Invalid email or password.")
    return _public_user(row), _create_session(row["id"])


def request_login_otp(email: str, password: str) -> dict[str, str]:
    normalized_email = email.strip().lower()
    with db_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (normalized_email,)).fetchone()
    if row is None:
        raise ValueError("Please register first, then login.")
    if not row["password_hash"] or not _password_matches(password, row["password_hash"]):
        raise ValueError("Invalid email or password.")

    challenge_id = str(uuid.uuid4())
    code = f"{secrets.randbelow(1_000_000):06d}"
    with db_connection() as conn:
        conn.execute(
            """
            INSERT INTO otp_challenges (id, user_id, code_hash, expires_at, consumed_at, created_at)
            VALUES (?, ?, ?, ?, NULL, ?)
            """,
            (
                challenge_id,
                row["id"],
                _hash_otp(challenge_id, code),
                (_now() + timedelta(minutes=OTP_MINUTES)).isoformat(),
                _now().isoformat(),
            ),
        )
    response = {
        "status": "otp_required",
        "challenge_id": challenge_id,
        "message": "Enter the 6-digit OTP to complete secure login.",
    }
    # Prototype-safe fallback: without SMTP, show the OTP in the login flow instead of silently failing.
    if os.getenv("TRUTHLENS_SHOW_DEV_OTP", "true").lower() in {"1", "true", "yes"}:
        response["dev_otp"] = code
    return response


def verify_login_otp(challenge_id: str, code: str) -> tuple[dict[str, str], str]:
    with db_connection() as conn:
        row = conn.execute(
            """
            SELECT otp_challenges.*, users.email FROM otp_challenges
            JOIN users ON users.id = otp_challenges.user_id
            WHERE otp_challenges.id = ?
            """,
            (challenge_id,),
        ).fetchone()
        if (
            row is None
            or row["consumed_at"]
            or row["expires_at"] <= _now().isoformat()
            or not hmac.compare_digest(row["code_hash"], _hash_otp(challenge_id, code.strip()))
        ):
            raise ValueError("Invalid or expired OTP.")
        conn.execute("UPDATE otp_challenges SET consumed_at = ? WHERE id = ?", (_now().isoformat(), challenge_id))
        user_row = conn.execute("SELECT * FROM users WHERE id = ?", (row["user_id"],)).fetchone()
    return _public_user(user_row), _create_session(row["user_id"])


def change_password(user_id: str, current_password: str, new_password: str) -> dict[str, str]:
    if len(new_password) < 8:
        raise ValueError("New password must contain at least 8 characters.")
    with db_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None or not row["password_hash"] or not _password_matches(current_password, row["password_hash"]):
            raise ValueError("Current password is incorrect.")
        conn.execute(
            "UPDATE users SET password_hash = ?, password_reset_required = 0 WHERE id = ?",
            (_password_hash(new_password), user_id),
        )
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        updated = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _public_user(updated)


def admin_reset_user_password(user_id: str) -> dict[str, str]:
    temp_password = f"TL-{secrets.token_urlsafe(9)}"
    with db_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            raise ValueError("User not found.")
        conn.execute(
            "UPDATE users SET password_hash = ?, provider = 'email', password_reset_required = 1 WHERE id = ?",
            (_password_hash(temp_password), user_id),
        )
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    return {
        "user_id": user_id,
        "email": row["email"],
        "temporary_password": temp_password,
        "message": "Temporary password generated. The user must change it after login.",
    }


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
            conn.execute(
                """
                INSERT INTO users (id, email, name, password_hash, avatar_url, provider, role, password_reset_required, created_at)
                VALUES (?, ?, ?, NULL, ?, 'google', ?, 0, ?)
                """,
                (user_id, email, payload.get("name") or "TruthLens Analyst", payload.get("picture") or "", _role_for_email(email), _now().isoformat()),
            )
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        else:
            conn.execute(
                "UPDATE users SET name = ?, avatar_url = ?, provider = 'google' WHERE id = ?",
                (payload.get("name") or row["name"], payload.get("picture") or row["avatar_url"], row["id"]),
            )
            row = conn.execute("SELECT * FROM users WHERE id = ?", (row["id"],)).fetchone()
    return _public_user(row), _create_session(row["id"])
