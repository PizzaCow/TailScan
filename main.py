"""TailScan — FastAPI app."""

import os
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import auth
import tailscale
import scanner

app = FastAPI(title="TailScan")
templates = Jinja2Templates(directory="templates")

CLIENT_ID = os.getenv("TAILSCALE_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("TAILSCALE_CLIENT_SECRET", "")
REDIRECT_URI = os.getenv("TAILSCALE_REDIRECT_URI", "http://localhost:8080/auth/callback")
TAILNET = os.getenv("TAILNET", "-")  # "-" = current tailnet


def get_session(request: Request) -> dict | None:
    cookie = request.cookies.get("ts_session")
    if not cookie:
        return None
    return auth.decode_session_cookie(cookie)


# ─── Auth routes ────────────────────────────────────────────────────────────

@app.get("/login")
def login():
    url, _ = auth.generate_oauth_url(CLIENT_ID, REDIRECT_URI)
    return RedirectResponse(url)


@app.get("/auth/callback")
def auth_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    if error:
        raise HTTPException(400, f"OAuth error: {error}")
    if not code:
        raise HTTPException(400, "Missing code")

    try:
        tokens = auth.exchange_code(CLIENT_ID, CLIENT_SECRET, code, REDIRECT_URI)
        access_token = tokens.get("access_token", "")
        user_info = auth.get_userinfo(access_token)
    except Exception as e:
        raise HTTPException(500, f"Auth failed: {e}")

    cookie_val = auth.make_session_cookie(user_info, access_token)
    response = RedirectResponse("/", status_code=302)
    response.set_cookie(
        "ts_session", cookie_val,
        httponly=True, samesite="lax",
        max_age=60 * 60 * 24 * 7
    )
    return response


@app.get("/logout")
def logout():
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie("ts_session")
    return response


# ─── Main UI ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    session = get_session(request)
    if not session:
        return RedirectResponse("/login")
    return templates.TemplateResponse("index.html", {
        "request": request,
        "user": session,
    })


# ─── API endpoints ──────────────────────────────────────────────────────────

@app.get("/api/peers")
def api_peers(request: Request):
    if not get_session(request):
        raise HTTPException(401)
    peers = tailscale.get_all_peers_local()
    current_exit = tailscale.get_current_exit_node()
    return {"peers": peers, "current_exit_node": current_exit}


@app.post("/api/exit-node/set")
async def api_set_exit_node(request: Request):
    if not get_session(request):
        raise HTTPException(401)
    body = await request.json()
    ip = body.get("ip", "")
    ok = tailscale.set_exit_node(ip)
    if not ok:
        raise HTTPException(500, "Failed to set exit node")
    return {"ok": True, "exit_node": ip or None}


@app.post("/api/exit-node/disconnect")
def api_disconnect(request: Request):
    if not get_session(request):
        raise HTTPException(401)
    tailscale.set_exit_node("")
    return {"ok": True}


@app.get("/api/scan")
def api_scan(request: Request):
    if not get_session(request):
        raise HTTPException(401)

    geo = scanner.get_wan_geo()
    current_exit = tailscale.get_current_exit_node()

    if not current_exit:
        return {
            "connected": False,
            "geo": geo,
            "devices": [],
            "subnet": None,
        }

    subnet = scanner.detect_lan_subnet()
    devices = []
    if subnet:
        devices = scanner.scan_lan(subnet)

    return {
        "connected": True,
        "exit_node_ip": current_exit,
        "geo": geo,
        "subnet": subnet,
        "devices": devices,
    }


@app.get("/api/geo")
def api_geo(request: Request):
    if not get_session(request):
        raise HTTPException(401)
    return scanner.get_wan_geo()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=False)
