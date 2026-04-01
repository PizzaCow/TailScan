"""Tailscale OAuth flow + session handling."""

import os
import secrets
import time
import httpx
from itsdangerous import TimestampSigner, BadSignature, SignatureExpired

SECRET_KEY = os.getenv("SECRET_KEY", "changeme")
SESSION_MAX_AGE = 60 * 60 * 24 * 7  # 7 days

signer = TimestampSigner(SECRET_KEY)

# In-memory CSRF state store (fine for single-instance)
_csrf_states: dict[str, float] = {}


def generate_oauth_url(client_id: str, redirect_uri: str) -> tuple[str, str]:
    """Generate Tailscale OAuth URL + CSRF state."""
    state = secrets.token_urlsafe(32)
    _csrf_states[state] = time.time()
    # Clean old states
    cutoff = time.time() - 600
    for k in list(_csrf_states.keys()):
        if _csrf_states[k] < cutoff:
            del _csrf_states[k]

    url = (
        f"https://login.tailscale.com/oauth/authorize"
        f"?client_id={client_id}"
        f"&response_type=code"
        f"&redirect_uri={redirect_uri}"
        f"&scope=openid+profile+email"
        f"&state={state}"
    )
    return url, state


def validate_csrf_state(state: str) -> bool:
    """Validate and consume CSRF state."""
    if state not in _csrf_states:
        return False
    age = time.time() - _csrf_states.pop(state)
    return age < 600  # 10 min expiry


def exchange_code(client_id: str, client_secret: str, code: str, redirect_uri: str) -> dict:
    """Exchange OAuth code for tokens."""
    resp = httpx.post(
        "https://api.tailscale.com/api/v2/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
        },
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def get_userinfo(access_token: str) -> dict:
    """Get user info from Tailscale."""
    resp = httpx.get(
        "https://api.tailscale.com/api/v2/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def make_session_cookie(user_info: dict, access_token: str) -> str:
    """Create a signed session cookie value."""
    import json, base64
    payload = json.dumps({
        "sub": user_info.get("sub", ""),
        "name": user_info.get("name", ""),
        "email": user_info.get("email", ""),
        "token": access_token,
    })
    encoded = base64.urlsafe_b64encode(payload.encode()).decode()
    return signer.sign(encoded).decode()


def decode_session_cookie(cookie: str) -> dict | None:
    """Decode and validate session cookie. Returns user dict or None."""
    try:
        unsigned = signer.unsign(cookie, max_age=SESSION_MAX_AGE)
        import json, base64
        payload = json.loads(base64.urlsafe_b64decode(unsigned).decode())
        return payload
    except (BadSignature, SignatureExpired, Exception):
        return None
