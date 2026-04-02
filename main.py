"""TailScan — FastAPI app."""

import os
import logging
from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)

from fastapi import FastAPI, Request, Response, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
import auth
import tailscale
import scanner
import json
import httpx
import re

log = logging.getLogger("tailscan")

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


@app.get("/api/port-scan")
def api_port_scan(request: Request, ip: str):
    if not get_session(request):
        raise HTTPException(401)
    log.info(f"Port scanning {ip}")
    result = scanner.scan_ports(ip)
    log.info(f"Port scan {ip}: {len(result.get('open_ports', []))} ports, OS: {result.get('os_guess')}")
    return result


@app.post("/api/exit-node/set")
async def api_set_exit_node(request: Request):
    if not get_session(request):
        raise HTTPException(401)
    body = await request.json()
    ip = body.get("ip", "")
    log.info(f"Setting exit node to: {ip!r}")
    ok = tailscale.set_exit_node(ip)
    log.info(f"set_exit_node returned: {ok}")
    current = tailscale.get_current_exit_node()
    log.info(f"get_current_exit_node after set: {current!r}")
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
    """SSE stream: emits geo/meta first, then one device per event as discovered."""
    if not get_session(request):
        raise HTTPException(401)

    def generate():
        log.info("Starting scan (stream)...")
        geo = scanner.get_wan_geo()
        current_exit = tailscale.get_current_exit_node()
        subnets = scanner.detect_lan_subnets(exit_node_ip=current_exit) if current_exit else []
        log.info(f"Exit: {current_exit!r}, subnets: {subnets!r}")

        meta = {
            "type": "meta",
            "connected": bool(current_exit),
            "exit_node_ip": current_exit,
            "geo": geo,
            "subnet": ", ".join(subnets) if subnets else "unknown",
        }
        yield f"data: {json.dumps(meta)}\n\n"

        if not current_exit:
            return

        if not subnets:
            yield f"data: {json.dumps({'type': 'error', 'message': 'Could not detect LAN subnet. Enable subnet routes on the exit node.'})}\n\n"
            return

        count = 0
        for subnet in subnets:
            log.info(f"Scanning subnet {subnet}")
            for device in scanner.scan_lan_stream(subnet):
                if "error" in device:
                    yield f"data: {json.dumps({'type': 'error', 'message': device['error']})}\n\n"
                    return
                device["type"] = "device"
                count += 1
                log.info(f"Device: {device.get('ip')} ({device.get('hostname')})")
                yield f"data: {json.dumps(device)}\n\n"

        log.info(f"Scan complete: {count} devices")
        yield f"data: {json.dumps({'type': 'done', 'count': count})}\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ─── Proxy ──────────────────────────────────────────────────────────────────

@app.get("/browse", response_class=HTMLResponse)
def browse(request: Request, ip: str, port: int = 80):
    """Redirect straight into the full-page proxy (no iframe)."""
    if not get_session(request):
        return RedirectResponse("/login")
    scheme = "https" if port in (443, 8443, 8006) else "http"
    return RedirectResponse(f"/proxy/{scheme}/{ip}/{port}/")


@app.api_route("/proxy/{scheme}/{ip}/{port}/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy(request: Request, scheme: str, ip: str, port: int, path: str):
    """Transparent HTTP proxy — runs on the server, so it reaches the LAN via the exit node."""
    if not get_session(request):
        raise HTTPException(401)
    if scheme not in ("http", "https"):
        raise HTTPException(400, "Invalid scheme")

    target_url = f"{scheme}://{ip}:{port}/{path}"
    if request.url.query:
        target_url += f"?{request.url.query}"

    headers = {k: v for k, v in request.headers.items()
               if k.lower() not in ("host", "connection", "transfer-encoding")}
    headers["host"] = f"{ip}:{port}"

    body = await request.body()

    try:
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=True) as client:
            resp = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
            )
    except httpx.ConnectError:
        return HTMLResponse("<h3 style='font-family:sans-serif;padding:20px'>Could not connect to device</h3>", status_code=502)
    except httpx.TimeoutException:
        return HTMLResponse("<h3 style='font-family:sans-serif;padding:20px'>Connection timed out</h3>", status_code=504)

    resp_headers = {k: v for k, v in resp.headers.items()
                    if k.lower() not in ("content-encoding", "transfer-encoding",
                                         "content-security-policy", "x-frame-options")}

    content_type = resp.headers.get("content-type", "")
    content = resp.content

    # Rewrite HTML: fix links + inject JS interceptor for SPA navigation
    if "text/html" in content_type:
        proxy_base = f"/proxy/{scheme}/{ip}/{port}"
        origin = f"{scheme}://{ip}:{port}"
        text = content.decode("utf-8", errors="replace")

        # Rewrite root-relative href/src/action="/path" → proxied
        text = re.sub(
            r'(href|src|action)=(["\'])/(?!/)',
            lambda m: f'{m.group(1)}={m.group(2)}{proxy_base}/',
            text
        )
        # Rewrite absolute origin URLs → proxied
        text = re.sub(
            rf'{re.escape(origin)}(/[^"\'> ]*)?',
            lambda m: f"{proxy_base}{m.group(1) or '/'}",
            text
        )

        # Inject JS interceptor before </head> (or at top of body) to handle:
        # - fetch() / XHR with root-relative or absolute URLs
        # - window.location / history.pushState navigation
        # - dynamically inserted <a> / <form> elements
        interceptor = f"""<script>
(function() {{
  var _proxyBase = {repr(proxy_base)};
  var _origin = {repr(origin)};
  function _rw(url) {{
    if (!url) return url;
    if (url.startsWith(_origin)) return _proxyBase + url.slice(_origin.length) || _proxyBase + '/';
    if (url.startsWith('/') && !url.startsWith('//') && !url.startsWith(_proxyBase))
      return _proxyBase + url;
    return url;
  }}
  // Patch fetch
  var _fetch = window.fetch;
  window.fetch = function(input, init) {{
    if (typeof input === 'string') input = _rw(input);
    else if (input && input.url) input = new Request(_rw(input.url), input);
    return _fetch.call(this, input, init);
  }};
  // Patch XHR
  var _open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url) {{
    arguments[1] = _rw(url);
    return _open.apply(this, arguments);
  }};
  // Patch history
  var _push = history.pushState.bind(history);
  history.pushState = function(state, title, url) {{ return _push(state, title, url ? _rw(url) : url); }};
  var _replace = history.replaceState.bind(history);
  history.replaceState = function(state, title, url) {{ return _replace(state, title, url ? _rw(url) : url); }};
  // Patch link clicks (catch dynamic content too)
  document.addEventListener('click', function(e) {{
    var el = e.target.closest('a[href]');
    if (!el) return;
    var h = el.getAttribute('href');
    var rw = _rw(h);
    if (rw !== h) {{ e.preventDefault(); window.location.href = rw; }}
  }}, true);
}})();
</script>"""
        if "</head>" in text:
            text = text.replace("</head>", interceptor + "</head>", 1)
        else:
            text = interceptor + text

        content = text.encode("utf-8")
        resp_headers["content-type"] = "text/html; charset=utf-8"

    # Rewrite Location headers on redirects
    if "location" in resp_headers:
        loc = resp_headers["location"]
        proxy_base = f"/proxy/{scheme}/{ip}/{port}"
        origin = f"{scheme}://{ip}:{port}"
        if loc.startswith(origin):
            resp_headers["location"] = proxy_base + loc[len(origin):]
        elif loc.startswith("/") and not loc.startswith(proxy_base):
            resp_headers["location"] = proxy_base + loc

    resp_headers.pop("content-length", None)
    return Response(content=content, status_code=resp.status_code,
                    headers=resp_headers, media_type=content_type)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=False)
