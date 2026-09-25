"""Password hashing, access tokens and login throttling."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from threading import Lock
from uuid import UUID

import jwt

from app.config import settings

# scrypt parameters (RFC 7914); ~16 MiB memory per hash.
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P, _KEY_LEN = 2**14, 8, 1, 32
_ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_KEY_LEN)
    encode = lambda raw: base64.b64encode(raw).decode()
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${encode(salt)}${encode(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest)
        actual = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def validate_password_strength(password: str) -> str | None:
    if len(password) < 12:
        return "Password must be at least 12 characters."
    classes = sum(any(check(c) for c in password) for check in (str.islower, str.isupper, str.isdigit, lambda c: not c.isalnum()))
    if classes < 3:
        return "Password must mix at least three of: lowercase, uppercase, digits, symbols."
    return None


def create_access_token(user_id: UUID, role: str) -> tuple[str, datetime]:
    expires = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expiry_minutes)
    payload = {"sub": str(user_id), "role": role, "exp": expires, "iat": datetime.now(timezone.utc), "jti": secrets.token_hex(8)}
    return jwt.encode(payload, settings.effective_jwt_secret, algorithm=_ALGORITHM), expires


def decode_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, settings.effective_jwt_secret, algorithms=[_ALGORITHM], options={"require": ["exp", "sub"]})
    except jwt.PyJWTError:
        return None


class LoginThrottle:
    """Locks an (account, client) pair after repeated failures. In-memory, per process."""

    def __init__(self) -> None:
        self._failures: dict[str, list[datetime]] = defaultdict(list)
        self._lock = Lock()

    def _recent(self, key: str) -> list[datetime]:
        window = datetime.now(timezone.utc) - timedelta(minutes=settings.login_lockout_minutes)
        self._failures[key] = [moment for moment in self._failures[key] if moment > window]
        return self._failures[key]

    def is_locked(self, key: str) -> bool:
        with self._lock:
            return len(self._recent(key)) >= settings.login_max_failures

    def record_failure(self, key: str) -> None:
        with self._lock:
            self._recent(key).append(datetime.now(timezone.utc))

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


login_throttle = LoginThrottle()
