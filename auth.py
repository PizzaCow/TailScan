"""Simple password auth + session handling."""

import os
import hashlib
import hmac
from itsdangerous import TimestampSigner, BadSignature, SignatureExpired

SECRET_KEY = os.getenv("SECRET_KEY", "changeme")
PASSWORD_HASH = os.getenv("PASSWORD_HASH", "")  # sha256 hex of password
SESSION_MAX_AGE = 60 * 60 * 24 * 7  # 7 days

signer = TimestampSigner(SECRET_KEY)


def check_password(password: str) -> bool:
    """Check password against stored hash."""
    if not PASSWORD_HASH:
        return False
    h = hashlib.sha256(password.encode()).hexdigest()
    return hmac.compare_digest(h, PASSWORD_HASH)


def make_session_cookie() -> str:
    """Create a signed session cookie."""
    return signer.sign("authenticated").decode()


def validate_session_cookie(cookie: str) -> bool:
    """Validate session cookie. Returns True if valid."""
    try:
        signer.unsign(cookie, max_age=SESSION_MAX_AGE)
        return True
    except (BadSignature, SignatureExpired, Exception):
        return False
