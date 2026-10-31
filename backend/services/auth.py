"""Accounts: password hashing, sign-in sessions, rate limits and request authentication.

Passwords are hashed with scrypt from the standard library (no extra dependency); the
stored string records its parameters so the cost can be raised later.  A sign-in session
is a random token in an HttpOnly cookie.  The database keeps only the SHA-256 hash of the
token, so a copy of the database cannot be used to sign in.

Configuration (environment variables):
    CORS_ORIGINS        comma-separated frontend origins allowed to call the API with the
                        session cookie (default: localhost and 127.0.0.1 on ports 3000/3001)
    COOKIE_SECURE       "true" to send the cookie over HTTPS only (required in production)
    COOKIE_SAMESITE     lax (default), strict, or none (none implies COOKIE_SECURE)
    AUTH_SESSION_DAYS   how long a sign-in lasts (default 30)
    AUTH_REGISTER_LIMIT sign-ups allowed per client IP per hour (default 30)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
import unicodedata
from collections import deque
from typing import Deque, Dict, List, Optional

from fastapi import HTTPException, Request, Response

from db.database import get_db

logger = logging.getLogger(__name__)

COOKIE_NAME = "instantnodes_session"
_DEFAULT_ORIGINS = (
    "http://localhost:3000,http://127.0.0.1:3000,"
    "http://localhost:3001,http://127.0.0.1:3001"
)


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        logger.warning("%s is not a number; using %d", name, default)
        return default


def _allowed_origins() -> List[str]:
    origins = []
    for raw in os.getenv("CORS_ORIGINS", _DEFAULT_ORIGINS).split(","):
        origin = raw.strip().rstrip("/")
        if not origin:
            continue
        if origin == "*":
            # A wildcard with credentials would let any website act as the signed-in user.
            logger.warning("CORS_ORIGINS: '*' is ignored; list the frontend origins instead")
            continue
        origins.append(origin)
    return origins


SESSION_DAYS = _env_int("AUTH_SESSION_DAYS", 30)
COOKIE_SECURE = _env_flag("COOKIE_SECURE")
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax").strip().lower()
if COOKIE_SAMESITE not in ("lax", "strict", "none"):
    logger.warning("COOKIE_SAMESITE=%r is not lax, strict or none; using lax", COOKIE_SAMESITE)
    COOKIE_SAMESITE = "lax"
if COOKIE_SAMESITE == "none" and not COOKIE_SECURE:
    logger.warning("COOKIE_SAMESITE=none requires a secure cookie; setting COOKIE_SECURE")
    COOKIE_SECURE = True
ALLOWED_ORIGINS = _allowed_origins()


def browser_origin_allowed(origin: Optional[str]) -> bool:
    """True for requests without an Origin (non-browser clients) or from a listed origin."""
    return not origin or origin.rstrip("/") in ALLOWED_ORIGINS


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


# --------------------------------------------------------------------------- #
# Passwords                                                                   #
# --------------------------------------------------------------------------- #
# scrypt N=2^14, r=8, p=5 (16 MiB, about 0.2 s): one of the OWASP-recommended settings.
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2 ** 14, 8, 5
_SCRYPT_DKLEN = 32
_SCRYPT_MAXMEM = 128 * 1024 * 1024
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128

# Passwords that are guessed first; the policy is length plus this list (NIST SP 800-63B).
_COMMON_PASSWORDS = frozenset({
    "password", "password1", "password12", "password123", "passw0rd", "p@ssw0rd",
    "12345678", "123456789", "1234567890", "11111111", "00000000", "87654321",
    "qwertyui", "qwerty12", "qwerty123", "qwertyuiop", "1q2w3e4r", "1qaz2wsx",
    "abcd1234", "abc12345", "iloveyou", "letmein1", "welcome1", "welcome123",
    "admin123", "administrator", "changeme", "sunshine", "princess", "football",
    "baseball", "superman", "trustno1", "computer", "internet", "monkey123",
    "cisco123", "instantnodes",
})


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _password_bytes(password: str) -> bytes:
    return unicodedata.normalize("NFKC", password).encode("utf-8")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        _password_bytes(password), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN, maxmem=_SCRYPT_MAXMEM,
    )
    return "$".join(
        ["scrypt", str(_SCRYPT_N), str(_SCRYPT_R), str(_SCRYPT_P), _b64(salt), _b64(digest)]
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_text, digest_text = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest_text)
        candidate = hashlib.scrypt(
            _password_bytes(password), salt=base64.b64decode(salt_text),
            n=int(n), r=int(r), p=int(p), dklen=len(expected), maxmem=_SCRYPT_MAXMEM,
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, expected)


# Verified against when the email is unknown, so both cases take the same time.  It is the
# hash of a random password nobody knows, fixed here so the first request is not slower.
_DUMMY_HASH = "scrypt$16384$8$5$EAZZXyzhMfylbFTbfWJA/w==$CwBc+rgzG3EhjqNiITRK0ZN+Ea+4G6XsYzf1w6pwBbA="


# --------------------------------------------------------------------------- #
# Validation                                                                  #
# --------------------------------------------------------------------------- #
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalise_email(value: str) -> str:
    return (value or "").strip().lower()


def name_problem(name: str) -> Optional[str]:
    if not name:
        return "Enter your name."
    if len(name) > 60:
        return "Use at most 60 characters for your name."
    if any(unicodedata.category(char) == "Cc" for char in name):
        return "Your name contains characters that are not allowed."
    return None


def email_problem(email: str) -> Optional[str]:
    if not email:
        return "Enter your email address."
    if len(email) > 254 or not _EMAIL_RE.match(email):
        return "Enter a valid email address, such as name@example.com."
    return None


def password_problem(password: str, email: str = "") -> Optional[str]:
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Use at least {MIN_PASSWORD_LENGTH} characters for your password."
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"Use at most {MAX_PASSWORD_LENGTH} characters for your password."
    lowered = password.lower()
    if lowered in _COMMON_PASSWORDS or len(set(lowered)) == 1:
        return "This password is too easy to guess. Choose a longer or less common one."
    if email and lowered == email.lower():
        return "Your password cannot be your email address."
    return None


# --------------------------------------------------------------------------- #
# Rate limits                                                                 #
# --------------------------------------------------------------------------- #
class RateLimiter:
    """At most ``limit`` events per ``window`` seconds per key, counted in this process."""

    def __init__(self, limit: int, window: float) -> None:
        self.limit = limit
        self.window = window
        self._events: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()
        self._records = 0

    def _trim(self, events: Deque[float], now: float) -> None:
        while events and events[0] <= now - self.window:
            events.popleft()

    def retry_after(self, key: str) -> int:
        """Seconds until ``key`` may try again; 0 when it may try now."""
        with self._lock:
            events = self._events.get(key)
            if not events:
                return 0
            now = time.monotonic()
            self._trim(events, now)
            if len(events) < self.limit:
                return 0
            return max(1, int(events[0] + self.window - now) + 1)

    def record(self, key: str) -> None:
        with self._lock:
            now = time.monotonic()
            events = self._events.setdefault(key, deque())
            events.append(now)
            self._trim(events, now)
            self._records += 1
            if self._records % 500 == 0:  # forget keys with no recent events
                for stale in [k for k, v in self._events.items() if not v or v[-1] <= now - self.window]:
                    del self._events[stale]

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)


LOGIN_FAILURES = RateLimiter(limit=10, window=15 * 60)  # per client IP and email
LOGIN_FAILURES_BY_IP = RateLimiter(limit=100, window=15 * 60)
REGISTRATIONS = RateLimiter(limit=_env_int("AUTH_REGISTER_LIMIT", 30), window=60 * 60)
PASSWORD_FAILURES = RateLimiter(limit=10, window=15 * 60)  # per account


def too_many(retry_after: int, message: str) -> HTTPException:
    minutes = max(1, (retry_after + 59) // 60)
    return HTTPException(
        status_code=429,
        detail=f"{message} Try again in {minutes} minute{'s' if minutes != 1 else ''}.",
        headers={"Retry-After": str(retry_after)},
    )


# --------------------------------------------------------------------------- #
# Users                                                                       #
# --------------------------------------------------------------------------- #
class EmailTaken(Exception):
    pass


def iso_utc(value: Optional[str]) -> Optional[str]:
    """SQLite CURRENT_TIMESTAMP text (UTC) as ISO 8601 with a Z suffix."""
    if not value:
        return None
    return str(value).replace(" ", "T") + ("" if str(value).endswith("Z") else "Z")


def public_user(user: dict) -> dict:
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "created_at": iso_utc(user.get("created_at")),
    }


def create_user(email: str, name: str, password: str) -> dict:
    password_hash = hash_password(password)
    conn = get_db()
    try:
        cursor = conn.execute(
            "INSERT INTO users (email, name, password_hash) VALUES (?, ?, ?)",
            (email, name, password_hash),
        )
        conn.commit()
        row = conn.execute(
            "SELECT id, email, name, created_at FROM users WHERE id = ?", (cursor.lastrowid,)
        ).fetchone()
    except sqlite3.IntegrityError as exc:
        raise EmailTaken(email) from exc
    finally:
        conn.close()
    return dict(row)


def authenticate(email: str, password: str) -> Optional[dict]:
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, email, name, created_at, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        verify_password(password, _DUMMY_HASH)
        return None
    if not verify_password(password, row["password_hash"]):
        return None
    user = dict(row)
    user.pop("password_hash")
    return user


def password_matches(user_id: int, password: str) -> bool:
    conn = get_db()
    try:
        row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
    finally:
        conn.close()
    return row is not None and verify_password(password, row["password_hash"])


def set_password(user_id: int, password: str, keep_session_id: Optional[int]) -> None:
    """Store a new password and sign out every other session of the account."""
    password_hash = hash_password(password)
    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP "
            "WHERE id = ?",
            (password_hash, user_id),
        )
        conn.execute(
            "DELETE FROM auth_sessions WHERE user_id = ? AND id IS NOT ?",
            (user_id, keep_session_id),
        )
        conn.commit()
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Sign-in sessions                                                            #
# --------------------------------------------------------------------------- #
def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(user_id: int, user_agent: str = "") -> str:
    token = secrets.token_urlsafe(32)
    conn = get_db()
    try:
        conn.execute("DELETE FROM auth_sessions WHERE expires_at <= datetime('now')")
        conn.execute(
            "INSERT INTO auth_sessions (user_id, token_hash, expires_at, user_agent) "
            "VALUES (?, ?, datetime('now', ?), ?)",
            (user_id, _token_hash(token), f"+{SESSION_DAYS} days", (user_agent or "")[:200]),
        )
        conn.execute(
            "UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?", (user_id,)
        )
        conn.commit()
    finally:
        conn.close()
    return token


def user_for_token(token: Optional[str]) -> Optional[dict]:
    """The signed-in user for a session token, or None if it is unknown or expired."""
    if not token or len(token) > 256:
        return None
    conn = get_db()
    try:
        row = conn.execute(
            """
            SELECT u.id, u.email, u.name, u.created_at, s.id AS auth_session_id
            FROM auth_sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ? AND s.expires_at > datetime('now')
            """,
            (_token_hash(token),),
        ).fetchone()
        if row is None:
            return None
        # Record activity at most every five minutes instead of on every request.
        conn.execute(
            "UPDATE auth_sessions SET last_seen_at = CURRENT_TIMESTAMP WHERE id = ? "
            "AND (last_seen_at IS NULL OR last_seen_at <= datetime('now', '-5 minutes'))",
            (row["auth_session_id"],),
        )
        conn.commit()
        return dict(row)
    finally:
        conn.close()


def delete_session(token: Optional[str]) -> None:
    if not token:
        return
    conn = get_db()
    try:
        conn.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (_token_hash(token),))
        conn.commit()
    finally:
        conn.close()


def delete_user_sessions(user_id: int) -> None:
    conn = get_db()
    try:
        conn.execute("DELETE FROM auth_sessions WHERE user_id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        COOKIE_NAME, token, max_age=SESSION_DAYS * 24 * 60 * 60, path="/",
        httponly=True, secure=COOKIE_SECURE, samesite=COOKIE_SAMESITE,
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        COOKIE_NAME, path="/", httponly=True, secure=COOKIE_SECURE, samesite=COOKIE_SAMESITE
    )


# --------------------------------------------------------------------------- #
# Request dependencies                                                        #
# --------------------------------------------------------------------------- #
def current_user(request: Request) -> dict:
    """FastAPI dependency: the signed-in user, or 401."""
    user = user_for_token(request.cookies.get(COOKIE_NAME))
    if user is None:
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    return user
