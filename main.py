"""TailScan — FastAPI app."""

import os
import time
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
from pathlib import Path

CACHE_DIR = Path(os.getenv("CACHE_DIR", "/tmp/tailscan-cache"))
CACHE_DIR.mkdir(parents=True, exist_ok=True)

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


def _cache_key(exit_node_ip: str, subnets: list) -> str:
    """Stable filename for a network context."""
    tag = exit_node_ip.replace(".", "_") + "__" + "_".join(s.replace("/", "-") for s in subnets)
    return tag

def _load_cache(key: str) -> dict | None:
    f = CACHE_DIR / f"{key}.json"
    if f.exists():
        try:
            return json.loads(f.read_text())
        except Exception:
            pass
    return None

def _save_cache(key: str, data: dict):
    f = CACHE_DIR / f"{key}.json"
    try:
        f.write_text(json.dumps(data))
    except Exception as e:
        log.warning(f"Cache write failed: {e}")


@app.get("/api/scan")
def api_scan(request: Request):
    """SSE stream: emits cached devices immediately, then live scan results."""
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

        # Emit cached devices immediately so the page shows something right away
        cache_key = _cache_key(current_exit, subnets)
        cached = _load_cache(cache_key)
        if cached and cached.get("devices"):
            log.info(f"Serving {len(cached['devices'])} cached devices for {cache_key}")
            for dev in cached["devices"].values():
                ev = dict(dev, type="cached")
                yield f"data: {json.dumps(ev)}\n\n"
            yield f"data: {json.dumps({'type': 'cache_done', 'count': len(cached['devices']), 'scanned_at': cached.get('scanned_at', 0)})}\n\n"

        # Live scan — accumulate results so we can update cache at the end
        live_devices: dict[str, dict] = {}
        count = 0
        for subnet in subnets:
            log.info(f"Scanning subnet {subnet}")
            for device in scanner.scan_lan_stream(subnet):
                if "error" in device:
                    yield f"data: {json.dumps({'type': 'error', 'message': device['error']})}\n\n"
                    return
                device["type"] = "device"
                count += 1
                live_devices[device["ip"]] = device
                log.info(f"Device: {device.get('ip')} ({device.get('hostname')})")
                yield f"data: {json.dumps(device)}\n\n"

        log.info(f"Scan complete: {count} devices")
        yield f"data: {json.dumps({'type': 'done', 'count': count})}\n\n"

        # Persist results to cache (devices without port scan data yet — ports get merged by client)
        _save_cache(cache_key, {"devices": live_devices, "scanned_at": int(time.time())})

    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/cache/ports")
async def api_cache_ports(request: Request):
    """Save port scan results to cache for a given network key."""
    if not get_session(request):
        raise HTTPException(401)
    current_exit = tailscale.get_current_exit_node()
    subnets = scanner.detect_lan_subnets(exit_node_ip=current_exit) if current_exit else []
    if not current_exit or not subnets:
        return {"ok": False, "reason": "no exit node"}
    cache_key = _cache_key(current_exit, subnets)
    return {"ok": True, "key": cache_key}

@app.post("/api/cache/ports")
async def api_cache_ports_save(request: Request):
    """Merge client-side port scan results into the cache."""
    if not get_session(request):
        raise HTTPException(401)
    body = await request.json()  # {ip: {open_ports, os_guess}}
    current_exit = tailscale.get_current_exit_node()
    subnets = scanner.detect_lan_subnets(exit_node_ip=current_exit) if current_exit else []
    if not current_exit or not subnets:
        return {"ok": False}
    cache_key = _cache_key(current_exit, subnets)
    cached = _load_cache(cache_key) or {"devices": {}, "scanned_at": int(time.time())}
    for ip, ports_data in body.items():
        if ip in cached["devices"]:
            cached["devices"][ip].update(ports_data)
        else:
            cached["devices"][ip] = ports_data
    _save_cache(cache_key, cached)
    return {"ok": True}


# ─── Proxy ──────────────────────────────────────────────────────────────────
# URL format: /proxy?t=http://192.168.0.25:8989/path
# This keeps real-looking URLs in the browser address bar.

def _proxy_url(target_url: str) -> str:
    """Build the TailScan proxy URL for a given target."""
    from urllib.parse import quote
    return f"/proxy?t={quote(target_url, safe=':/?=&')}"

def _rw_url(url: str, origin: str, proxy_prefix: str) -> str:
    """Rewrite a URL to go through the proxy."""
    if not url:
        return url
    if url.startswith(origin):
        path = url[len(origin):]
        return proxy_prefix + (path or "/")
    if url.startswith("/") and not url.startswith("//"):
        return proxy_prefix + url
    return url


@app.get("/browse", response_class=HTMLResponse)
def browse(request: Request, ip: str, port: int = 80):
    """Redirect into the proxy with a clean ?t= URL."""
    if not get_session(request):
        return RedirectResponse("/login")
    scheme = "https" if port in (443, 8443, 8006) else "http"
    from urllib.parse import quote
    return RedirectResponse(f"/proxy?t={quote(f'{scheme}://{ip}:{port}/', safe=':/?=&')}")


@app.api_route("/proxy", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy(request: Request):
    """
    Transparent HTTP proxy via ?t=<target_url>.
    Browser address bar shows: /proxy?t=http://192.168.0.25:8989/settings
    """
    if not get_session(request):
        raise HTTPException(401)

    from urllib.parse import urlparse, urlencode, parse_qs, quote, unquote

    # Extract target from query string — everything after ?t= (including & params in target)
    raw_query = str(request.url.query)
    if not raw_query.startswith("t="):
        raise HTTPException(400, "Missing ?t= parameter")
    target_url = unquote(raw_query[2:])

    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(400, "Invalid scheme")

    origin = f"{parsed.scheme}://{parsed.netloc}"
    # proxy_prefix: /proxy?t=http://ip:port  (path will be appended)
    proxy_prefix = f"/proxy?t={quote(origin, safe=':/?=&')}"

    headers = {k: v for k, v in request.headers.items()
               if k.lower() not in ("host", "connection", "transfer-encoding", "referer")}
    headers["host"] = parsed.netloc

    body = await request.body()

    try:
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
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
                                         "content-security-policy", "x-frame-options",
                                         "content-length")}

    # Handle redirects — rewrite Location through proxy
    if resp.status_code in (301, 302, 303, 307, 308):
        loc = resp_headers.get("location", "")
        if loc:
            # Absolute redirect
            if loc.startswith("http://") or loc.startswith("https://"):
                resp_headers["location"] = f"/proxy?t={quote(loc, safe=':/?=&')}"
            else:
                # Root-relative redirect
                new_target = origin + (loc if loc.startswith("/") else "/" + loc)
                resp_headers["location"] = f"/proxy?t={quote(new_target, safe=':/?=&')}"
        return Response(content=b"", status_code=resp.status_code, headers=resp_headers)

    content_type = resp.headers.get("content-type", "")
    content = resp.content

    # Rewrite HTML: fix links + inject JS interceptor for SPA navigation
    if "text/html" in content_type:
        text = content.decode("utf-8", errors="replace")

        # Rewrite root-relative href/src/action="/path"
        text = re.sub(
            r'(href|src|action)=(["\'])/(?!/)',
            lambda m: f'{m.group(1)}={m.group(2)}{proxy_prefix}/',
            text
        )
        # Rewrite absolute origin URLs
        text = re.sub(
            rf'{re.escape(origin)}(/[^"\'> ]*)?',
            lambda m: f"{proxy_prefix}{m.group(1) or '/'}",
            text
        )

        # JS interceptor: patches fetch, XHR, history, and link clicks
        interceptor = f"""<script>
(function() {{
  var _pfx = {json.dumps(proxy_prefix)};
  var _orig = {json.dumps(origin)};
  function _rw(url) {{
    if (!url || typeof url !== 'string') return url;
    if (url.startsWith(_orig)) return _pfx + (url.slice(_orig.length) || '/');
    if (url.startsWith('/') && !url.startsWith('//') && !url.startsWith('/proxy'))
      return _pfx + url;
    return url;
  }}
  var _fetch = window.fetch;
  window.fetch = function(input, init) {{
    if (typeof input === 'string') input = _rw(input);
    else if (input instanceof Request) input = new Request(_rw(input.url), input);
    return _fetch.call(this, input, init);
  }};
  var _xhrOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(m, url) {{
    arguments[1] = _rw(url); return _xhrOpen.apply(this, arguments);
  }};
  var _push = history.pushState.bind(history);
  history.pushState = function(s,t,url) {{ return _push(s,t,url?_rw(url):url); }};
  var _repl = history.replaceState.bind(history);
  history.replaceState = function(s,t,url) {{ return _repl(s,t,url?_rw(url):url); }};
  document.addEventListener('click', function(e) {{
    var el = e.target.closest('a[href]');
    if (!el) return;
    var h = el.getAttribute('href');
    if (!h || h.startsWith('#') || h.startsWith('javascript:')) return;
    var rw = _rw(h);
    if (rw !== h) {{ e.preventDefault(); window.location.href = rw; }}
  }}, true);
}})();
</script>"""
        if "</head>" in text:
            text = text.replace("</head>", interceptor + "</head>", 1)
        elif "<body" in text:
            text = re.sub(r'(<body[^>]*>)', r'\1' + interceptor, text, count=1)
        else:
            text = interceptor + text

        content = text.encode("utf-8")
        resp_headers["content-type"] = "text/html; charset=utf-8"

    return Response(content=content, status_code=resp.status_code,
                    headers=resp_headers, media_type=content_type)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=False)
