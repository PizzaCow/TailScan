"""
main.py — TailScan FastAPI application
"""
import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import auth
import tailscale
import scanner

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("TailScan starting up...")
    yield
    # Shutdown
    print("TailScan shutting down.")


app = FastAPI(title="TailScan", lifespan=lifespan)
app.include_router(auth.router)


# ── Page Routes ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user = auth.get_session(request)
    if not user:
        return RedirectResponse(url="/auth/login")
    return templates.TemplateResponse("index.html", {"request": request, "user": user})


# ── API Routes ─────────────────────────────────────────────────────────────────

@app.get("/api/status")
async def api_status(request: Request):
    """Get tailnet status: peers + active exit node."""
    auth.require_session(request)
    try:
        status = await tailscale.get_tailnet_status()
        peers = tailscale.parse_peers(status)
        active = next((p for p in peers if p["is_active_exit_node"]), None)
        return {
            "peers": peers,
            "active_exit_node": active,
            "self": next((p for p in peers if p.get("is_self")), None),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/exit-node/connect")
async def connect_exit_node(request: Request):
    """Switch to a new exit node."""
    auth.require_session(request)
    body = await request.json()
    ip = body.get("ip", "").strip()
    if not ip:
        raise HTTPException(status_code=400, detail="ip is required")
    try:
        await tailscale.set_exit_node(ip)
        # Small delay so routing table settles
        await asyncio.sleep(2)
        return {"ok": True, "exit_node": ip}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/exit-node/disconnect")
async def disconnect_exit_node(request: Request):
    """Disconnect from current exit node."""
    auth.require_session(request)
    try:
        await tailscale.set_exit_node("")
        await asyncio.sleep(1)
        return {"ok": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scan")
async def api_scan(request: Request):
    """
    Run a full scan:
    1. Get WAN IP + geolocation
    2. Detect LAN subnet
    3. Run nmap sweep
    Returns combined results.
    """
    auth.require_session(request)
    try:
        # Run geo and subnet detection concurrently
        geo_task = asyncio.create_task(scanner.get_wan_geo())
        geo = await geo_task

        subnet = scanner.detect_lan_subnet()
        if not subnet:
            return {
                "geo": geo,
                "subnet": None,
                "hosts": [],
                "error": "Could not detect LAN subnet. Are you connected to an exit node?",
            }

        hosts = await scanner.scan_lan(subnet)
        return {
            "geo": geo,
            "subnet": subnet,
            "hosts": hosts,
            "error": None,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/geo")
async def api_geo(request: Request):
    """Quick WAN IP + geo lookup without scanning."""
    auth.require_session(request)
    try:
        geo = await scanner.get_wan_geo()
        return geo
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run("main:app", host=host, port=port, reload=False)
