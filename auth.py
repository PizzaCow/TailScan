"""
auth.py — Tailscale OAuth 2.0 SSO flow + session handling
"""
import os
import secrets
import httpx
from fastapi import APIRouter, Request, Response, HTTPException
from fastapi.responses import RedirectResponse

router = APIRouter()

TAILSCALE_AUTH_URL = "https://login.tailscale.com/oauth/authorize"
TAILSCALE_TOKEN_URL = "https://login.tailscale.com/oauth/token"
TAILSCALE_USERINFO_URL = "https://api.tailscale.com/api/v2/oauth/userinfo"

CLIENT_ID = os.getenv("TS_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("TS_CLIENT_SECRET", "")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8080")
REDIRECT_URI = f"{BASE_URL}/auth/callback"

# In-memory session store: session_token -> user_info dict
_sessions: dict[str, dict] = {}
# PKCE / state store
_pending_states: dict[str, str] = {}


def create_session(user_info: dict) -> str:
    token = secrets.token_urlsafe(32)
    _sessions[token] = user_info
    return token


def get_session(request: Request) -> dict | None:
    token = request.cookies.get("session")
    if not token:
        return None
    return _sessions.get(token)


def require_session(request: Request) -> dict:
    user = get_session(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


@router.get("/auth/login")
async def login(request: Request):
    """Redirect to Tailscale OAuth authorization page."""
    state = secrets.token_urlsafe(16)
    _pending_states[state] = state
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid profile email",
        "state": state,
    }
    from urllib.parse import urlencode
    url = f"{TAILSCALE_AUTH_URL}?{urlencode(params)}"
    return RedirectResponse(url)


@router.get("/auth/callback")
async def callback(request: Request, code: str = "", state: str = "", error: str = ""):
    """Handle OAuth callback from Tailscale."""
    if error:
        raise HTTPException(status_code=400, detail=f"OAuth error: {error}")
    if not code:
        raise HTTPException(status_code=400, detail="Missing code")
    if state not in _pending_states:
        raise HTTPException(status_code=400, detail="Invalid state")
    del _pending_states[state]

    # Exchange code for token
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            TAILSCALE_TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
            },
            headers={"Accept": "application/json"},
        )
        if token_resp.status_code != 200:
            raise HTTPException(status_code=400, detail=f"Token exchange failed: {token_resp.text}")
        token_data = token_resp.json()
        access_token = token_data.get("access_token", "")

        # Fetch user info
        userinfo_resp = await client.get(
            TAILSCALE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if userinfo_resp.status_code != 200:
            # Fallback: store minimal info
            user_info = {"sub": "unknown", "access_token": access_token}
        else:
            user_info = userinfo_resp.json()
            user_info["access_token"] = access_token

    session_token = create_session(user_info)
    response = RedirectResponse(url="/")
    response.set_cookie(
        "session",
        session_token,
        httponly=True,
        samesite="lax",
        max_age=86400 * 7,  # 7 days
    )
    return response


@router.get("/auth/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get("session")
    if token and token in _sessions:
        del _sessions[token]
    r = RedirectResponse(url="/")
    r.delete_cookie("session")
    return r
