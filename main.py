"""TailScan — FastAPI app."""

import os
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Request, Response, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import auth
import tailscale
import scanner

app = FastAPI(title="TailScan")
templates = Jinja2Templates(directory="templates")


def get_session(request: Request) -> bool:
    cookie = request.cookies.get("ts_session")
    if not cookie:
        return False
    return auth.validate_session_cookie(cookie)


# ─── Auth routes ────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str = ""):
    return templates.TemplateResponse("login.html", {"request": request, "error": error})


@app.post("/login")
async def login_submit(request: Request, password: str = Form(...)):
    if not auth.check_password(password):
        return RedirectResponse("/login?error=Invalid+password", status_code=302)
    cookie_val = auth.make_session_cookie()
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
    if not get_session(request):
        return RedirectResponse("/login")
    return templates.TemplateResponse("index.html", {"request": request})


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

    subnet = scanner.detect_lan_subnet(exit_node_ip=current_exit)
    devices = []
    if subnet:
        devices = scanner.scan_lan(subnet)
    else:
        devices = [{"error": "Could not detect LAN subnet. The exit node may not be advertising its local routes."}]

    return {
        "connected": True,
        "exit_node_ip": current_exit,
        "geo": geo,
        "subnet": subnet or "unknown",
        "devices": devices,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=False)
