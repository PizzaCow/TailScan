"""TailScan — FastAPI app."""

VERSION = "0.04"

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
from fastapi.staticfiles import StaticFiles
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

from contextlib import asynccontextmanager
import asyncio as _asyncio

@asynccontextmanager
async def lifespan(app):
    # Start SOCKS5 proxy in the background
    import socks5
    _asyncio.create_task(socks5.start_socks5_server())
    yield

app = FastAPI(title="TailScan", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
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
# Extra query params (e.g. ?t=http://ip/search&q=foo) are forwarded to target.

from urllib.parse import urlparse, quote, unquote, urljoin


def _make_proxy_url(target_url: str) -> str:
    return f"/proxy?t={quote(target_url, safe='')}"


def _rewrite_url(url: str, origin: str, base_path: str = "/") -> str | None:
    """
    Rewrite a URL to go through /proxy?t=...
    Returns None if the URL should not be rewritten (relative fragment, data:, blob:, etc.)
    base_path: the path of the current proxied page, for resolving relative URLs.
    """
    if not url or not isinstance(url, str):
        return None
    if url.startswith(("#", "javascript:", "data:", "blob:", "mailto:", "tel:")):
        return None
    # Already proxied
    if url.startswith("/proxy?t="):
        return None
    # Absolute URL — only rewrite same origin
    if url.startswith("http://") or url.startswith("https://"):
        if url.startswith(origin):
            return _make_proxy_url(url)
        return None  # external URL — leave it alone
    # Protocol-relative
    if url.startswith("//"):
        return None
    # Root-relative
    if url.startswith("/"):
        return _make_proxy_url(origin + url)
    # Relative URL — resolve against base_path
    resolved = urljoin(origin + base_path, url)
    if resolved.startswith(origin):
        return _make_proxy_url(resolved)
    return None


def _inject_interceptor(text: str, origin: str, base_path: str) -> str:
    """Inject JS interceptor that handles all navigation/fetch in proxied pages."""
    interceptor = f"""<script>
(function(){{
  var _O={json.dumps(origin)};
  var _B={json.dumps(base_path)};
  function _enc(u){{return encodeURIComponent(u);}}
  function _rw(url){{
    if(!url||typeof url!=='string')return url;
    if(url.startsWith('#')||url.startsWith('javascript:')||url.startsWith('data:')||
       url.startsWith('blob:')||url.startsWith('mailto:')||url.startsWith('tel:'))return url;
    if(url.startsWith('/proxy?t='))return url;
    if(url.startsWith(_O))return '/proxy?t='+_enc(url);
    if(url.startsWith('http://')||url.startsWith('https://'))return url; // external
    if(url.startsWith('//'))return url;
    if(url.startsWith('/'))return '/proxy?t='+_enc(_O+url);
    // Relative URL
    try{{
      var abs=new URL(url,_O+_B).href;
      if(abs.startsWith(_O))return '/proxy?t='+_enc(abs);
    }}catch(e){{}}
    return url;
  }}
  // Patch fetch
  var _ft=window.fetch;
  window.fetch=function(i,o){{
    if(typeof i==='string')i=_rw(i);
    else if(i instanceof Request)i=new Request(_rw(i.url),i);
    return _ft.call(this,i,o);
  }};
  // Patch XHR
  var _xo=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(m,u){{arguments[1]=_rw(u);return _xo.apply(this,arguments);}};
  // Patch history
  var _hp=history.pushState.bind(history);
  history.pushState=function(s,t,u){{return _hp(s,t,u?_rw(u):u);}};
  var _hr=history.replaceState.bind(history);
  history.replaceState=function(s,t,u){{return _hr(s,t,u?_rw(u):u);}};
  // Patch window.location setter (covers window.location = '...' and .href = '...')
  try{{
    var _locDesc=Object.getOwnPropertyDescriptor(window,'location');
    if(!_locDesc||_locDesc.configurable){{
      var _locProto=Object.getOwnPropertyDescriptor(Location.prototype,'href');
      if(_locProto&&_locProto.set){{
        var _origSet=_locProto.set;
        Object.defineProperty(Location.prototype,'href',{{
          get:_locProto.get,
          set:function(u){{return _origSet.call(this,_rw(u));}},
          configurable:true
        }});
      }}
    }}
  }}catch(e){{}}
  // Patch window.location.assign / replace
  var _la=window.location.assign.bind(window.location);
  try{{window.location.assign=function(u){{return _la(_rw(u));}};}}catch(e){{}}
  var _lr=window.location.replace.bind(window.location);
  try{{window.location.replace=function(u){{return _lr(_rw(u));}};}}catch(e){{}}
  // Click interceptor — catches dynamic links and forms
  document.addEventListener('click',function(e){{
    var el=e.target.closest('a[href]');
    if(!el)return;
    var h=el.getAttribute('href');
    var rw=_rw(h);
    if(rw&&rw!==h){{e.preventDefault();window.location.href=rw;}}
  }},true);
  // Form submit interceptor — catches GET forms (like Google search)
  document.addEventListener('submit',function(e){{
    var f=e.target;
    if(!f||f.method&&f.method.toLowerCase()==='post')return;
    var action=f.action||window.location.href;
    var rw=_rw(action);
    if(rw&&rw!==action){{
      e.preventDefault();
      var params=new URLSearchParams(new FormData(f));
      window.location.href=rw+(rw.includes('?')?'&':'?')+params.toString();
    }}
  }},true);
}})();
</script>"""
    if "</head>" in text:
        return text.replace("</head>", interceptor + "\n</head>", 1)
    if "<body" in text:
        return re.sub(r'(<body[^>]*>)', r'\1' + interceptor, text, count=1)
    return interceptor + text


@app.get("/guac-launch", response_class=HTMLResponse)
def guac_launch(request: Request, target: str, proto: str = "ssh"):
    """
    Intermediary page that pre-sets Guacamole's inputMethod preference to 'osk'
    in localStorage (on the Guacamole origin) then redirects to the connection.
    This ensures the on-screen keyboard is available on mobile without needing
    to swipe open the menu.
    """
    if not get_session(request):
        return RedirectResponse("/login")
    # Extract the Guacamole origin from the target URL
    from urllib.parse import urlparse
    parsed = urlparse(target)
    guac_origin = f"{parsed.scheme}://{parsed.netloc}"
    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Opening session...</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body {{ background:#191724; color:#e0def4; font-family:sans-serif;
         display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }}
  p {{ opacity:.7; }}
</style>
</head>
<body>
<p>Opening session...</p>
<script>
// Set Guacamole preferences in its localStorage before redirecting.
// We use an invisible iframe pointed at the Guacamole origin to run
// the localStorage write in the correct origin context.
(function() {{
  var prefs = null;
  try {{
    var raw = localStorage.getItem("GUAC_PREFERENCES");
    prefs = raw ? JSON.parse(raw) : {{}};
  }} catch(e) {{ prefs = {{}}; }}
  // Default to OSK for all sessions (user can change in Guac settings)
  if (!prefs.inputMethod) prefs.inputMethod = "osk";
  try {{ localStorage.setItem("GUAC_PREFERENCES", JSON.stringify(prefs)); }} catch(e) {{}}
  // Redirect to the actual Guacamole client URL
  window.location.replace({repr(target)});
}})();
</script>
</body>
</html>"""
    return HTMLResponse(html)


@app.get("/browse", response_class=HTMLResponse)
def browse(request: Request, ip: str, port: int = 80):
    """Redirect into the proxy."""
    if not get_session(request):
        return RedirectResponse("/login")
    scheme = "https" if port in (443, 8443, 8006) else "http"
    return RedirectResponse(f"/proxy?t={quote(f'{scheme}://{ip}:{port}/', safe='')}")


def _error_page(msg: str, target: str, code: int) -> HTMLResponse:
    return HTMLResponse(f"""<!DOCTYPE html>
<html><head><title>TailScan Proxy Error</title>
<style>body{{font-family:sans-serif;background:#191724;color:#e0def4;display:flex;
align-items:center;justify-content:center;height:100vh;margin:0;}}
.box{{text-align:center;}} h2{{color:#eb6f92;}} a{{color:#9ccfd8;}}
code{{background:#1f1d2e;padding:4px 8px;border-radius:4px;font-size:13px;}}
</style></head><body><div class="box">
<h2>{"⏱ Timed Out" if code==504 else "🔌 Connection Failed" if code==502 else "⚠ Proxy Error"}</h2>
<p>{msg}</p>
<p><code>{target}</code></p>
<p><a href="javascript:history.back()">← Go back</a></p>
</div></body></html>""", status_code=code)


@app.api_route("/proxy", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy(request: Request):
    """Transparent HTTP proxy. URL: /proxy?t=<full_target_url>"""
    if not get_session(request):
        raise HTTPException(401)

    t_param = request.query_params.get("t")
    if not t_param:
        raise HTTPException(400, "Missing ?t= parameter")

    # Forward any extra query params as part of the target URL
    extra = {k: v for k, v in request.query_params.multi_items() if k != "t"}
    target_url = t_param
    if extra:
        sep = "&" if "?" in target_url else "?"
        target_url += sep + "&".join(f"{quote(k)}={quote(v)}" for k, v in extra)

    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(400, "Invalid scheme")

    origin = f"{parsed.scheme}://{parsed.netloc}"
    # base_path for relative URL resolution (path portion of the proxied page)
    base_path = parsed.path or "/"

    # Strip hop-by-hop and problematic headers
    skip_req = {"host", "connection", "transfer-encoding", "referer",
                "accept-encoding"}  # let httpx handle compression
    headers = {k: v for k, v in request.headers.items() if k.lower() not in skip_req}
    headers["host"] = parsed.netloc

    body = await request.body()

    try:
        async with httpx.AsyncClient(
            verify=False, timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=False,
            limits=httpx.Limits(max_connections=10)
        ) as client:
            resp = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
            )
    except httpx.ConnectError as e:
        return _error_page(f"Could not connect: {e}", target_url, 502)
    except httpx.TimeoutException:
        return _error_page("The device took too long to respond.", target_url, 504)
    except Exception as e:
        return _error_page(str(e), target_url, 502)

    skip_resp = {"content-encoding", "transfer-encoding", "content-security-policy",
                 "x-frame-options", "content-length", "strict-transport-security"}
    resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in skip_resp}

    # Handle redirects — rewrite Location through proxy
    if resp.status_code in (301, 302, 303, 307, 308):
        loc = resp_headers.get("location", "")
        if loc:
            if loc.startswith("http://") or loc.startswith("https://"):
                resp_headers["location"] = _make_proxy_url(loc)
            else:
                resolved = urljoin(origin + base_path, loc)
                resp_headers["location"] = _make_proxy_url(resolved)
        return Response(content=b"", status_code=resp.status_code, headers=resp_headers)

    content_type = resp.headers.get("content-type", "")
    content = resp.content

    if "text/html" in content_type:
        text = content.decode(resp.charset_encoding or "utf-8", errors="replace")

        # Remove any <base href> — it breaks relative URL resolution
        text = re.sub(r'<base\s[^>]*>', '', text, flags=re.IGNORECASE)

        # Rewrite static HTML attributes: href, src, action, srcset
        def rewrite_attr(m):
            attr, q, url = m.group(1), m.group(2), m.group(3)
            rw = _rewrite_url(url, origin, base_path)
            return f'{attr}={q}{rw}{q}' if rw else m.group(0)

        text = re.sub(
            r'(href|src|action|data-src)=(["\'])([^"\']+)\2',
            rewrite_attr, text, flags=re.IGNORECASE
        )
        # srcset (comma-separated URL descriptors)
        def rewrite_srcset(m):
            parts = []
            for entry in m.group(1).split(","):
                entry = entry.strip()
                pieces = entry.split(None, 1)
                if pieces:
                    rw = _rewrite_url(pieces[0], origin, base_path)
                    if rw:
                        pieces[0] = rw
                parts.append(" ".join(pieces))
            return f'srcset="{", ".join(parts)}"'
        text = re.sub(r'srcset="([^"]+)"', rewrite_srcset, text, flags=re.IGNORECASE)

        # Rewrite absolute origin URLs left in inline JS/CSS strings
        text = re.sub(
            rf'(["\']){re.escape(origin)}(/[^"\']*)?(["\'])',
            lambda m: f'{m.group(1)}{_make_proxy_url(origin + (m.group(2) or "/"))}{m.group(3)}',
            text
        )

        # Inject JS interceptor (handles runtime navigation, fetch, XHR, forms)
        text = _inject_interceptor(text, origin, base_path)

        content = text.encode("utf-8")
        resp_headers["content-type"] = "text/html; charset=utf-8"

    return Response(content=content, status_code=resp.status_code,
                    headers=resp_headers, media_type=content_type)


@app.get("/api/version")
def api_version():
    return {"version": VERSION}


# ─── Guacamole integration ──────────────────────────────────────────────────

GUAC_BASE = os.getenv("GUAC_URL", "http://guacamole:8080/guacamole")
GUAC_ADMIN_USER = os.getenv("GUAC_ADMIN_USER", "guacadmin")
GUAC_ADMIN_PASS = os.getenv("GUAC_ADMIN_PASS", "guacadmin")

_guac_token_cache: dict = {}  # {"token": str, "expires": float}

# ─── Browser session management ─────────────────────────────────────────────
import subprocess, socket, secrets as _secrets
BROWSER_IMAGE = os.getenv("BROWSER_IMAGE", "tailscan-browser:latest")
BROWSER_VNC_PASSWORD = os.getenv("BROWSER_VNC_PASSWORD", "tailscan")
_browser_sessions: dict = {}  # target_url -> {container_id, vnc_port, conn_id}

def _find_free_port(start: int = 5910, end: int = 5990) -> int:
    for port in range(start, end):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError("No free VNC ports available")


async def _guac_token(client: httpx.AsyncClient) -> str:
    """Get a Guacamole API auth token, reusing if still valid."""
    now = time.time()
    if _guac_token_cache.get("token") and _guac_token_cache.get("expires", 0) > now:
        return _guac_token_cache["token"]
    resp = await client.post(
        f"{GUAC_BASE}/api/tokens",
        data={"username": GUAC_ADMIN_USER, "password": GUAC_ADMIN_PASS},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    resp.raise_for_status()
    token = resp.json()["authToken"]
    _guac_token_cache["token"] = token
    _guac_token_cache["expires"] = now + 1800  # tokens valid ~30 min
    return token


@app.get("/api/guac-connect")
async def api_guac_connect(request: Request, ip: str, port: int, proto: str):
    """
    Create (or reuse) a Guacamole connection for ip:port via proto (ssh/rdp/vnc),
    return the direct client URL.
    """
    if not get_session(request):
        raise HTTPException(401)
    if proto not in ("ssh", "rdp", "vnc"):
        raise HTTPException(400, "Invalid protocol")

    conn_name = f"tailscan-{proto}-{ip}-{port}"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            token = await _guac_token(client)

            # List existing connections
            r = await client.get(
                f"{GUAC_BASE}/api/session/data/postgresql/connections",
                params={"token": token},
            )
            r.raise_for_status()
            existing = r.json()

            # Find or create
            conn_id = None
            for cid, conn in existing.items():
                if conn.get("name") == conn_name:
                    conn_id = cid
                    break

            if not conn_id:
                # Build connection params per protocol
                params: dict = {"hostname": ip, "port": str(port)}
                if proto == "ssh":
                    params.update({
                        "username": "",
                        "private-key": "",
                        # Enable SFTP file transfer panel in Guacamole
                        "enable-sftp": "true",
                        "sftp-root-directory": "/",
                    })
                elif proto == "rdp":
                    params.update({
                        "username": "", "password": "",
                        "security": "nla", "ignore-cert": "true",
                        "resize-method": "reconnect",
                    })
                elif proto == "vnc":
                    params.update({"password": ""})

                payload = {
                    "name": conn_name,
                    "protocol": proto,
                    "parameters": params,
                    "attributes": {
                        "max-connections": "5",
                        "max-connections-per-user": "5",
                    },
                    "parentIdentifier": "ROOT",
                }
                r = await client.post(
                    f"{GUAC_BASE}/api/session/data/postgresql/connections",
                    params={"token": token},
                    json=payload,
                )
                r.raise_for_status()
                conn_id = r.json()["identifier"]
                log.info(f"Guacamole: created {proto} connection {conn_id} for {ip}:{port}")
            else:
                log.info(f"Guacamole: reusing connection {conn_id} for {ip}:{port}")

            # Build the client URL — Guacamole uses base64url of "id\0c\0default"
            import base64
            client_id = base64.b64encode(
                f"{conn_id}\0c\0postgresql".encode()
            ).decode().rstrip("=")
            # Build the client URL using the incoming request's host so it
            # works regardless of whether the user is on localhost, LAN IP,
            # or a domain name.  The internal GUAC_BASE is still used for
            # server-side API calls; only the browser-facing URL changes.
            request_host = request.headers.get("host", "localhost").split(":")[0]
            guac_public_base = f"http://{request_host}:8085/guacamole"
            client_url = f"{guac_public_base}/#/client/{client_id}"
            # Load Guacamole client URL directly (works in both iframe and new tab)
            url = client_url
            return {"url": url, "connection_id": conn_id}

    except httpx.HTTPStatusError as e:
        log.error(f"Guacamole API error: {e.response.status_code} {e.response.text}")
        raise HTTPException(502, f"Guacamole API error: {e.response.status_code}")
    except Exception as e:
        log.error(f"Guacamole connect error: {e}")
        raise HTTPException(502, str(e))


@app.get("/api/browse-session")
async def api_browse_session(request: Request, url: str, width: int = 1280, height: int = 800):
    """
    Spin up (or reuse) a LibreWolf VNC container pre-navigated to `url`,
    create a Guacamole VNC connection for it, and return the Guacamole client URL.
    """
    if not get_session(request):
        raise HTTPException(401)

    # Reuse existing session for the same URL if container is still running
    if url in _browser_sessions:
        s = _browser_sessions[url]
        try:
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", s["container_id"]],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout.strip() == "true":
                conn_id = s["conn_id"]
                import base64
                client_id = base64.b64encode(
                    f"{conn_id}\0c\0postgresql".encode()
                ).decode().rstrip("=")
                request_host = request.headers.get("host", "localhost").split(":")[0]
                guac_url = f"http://{request_host}:8085/guacamole/#/client/{client_id}"
                return {"url": guac_url}
        except Exception:
            pass
        # Container died — clean up
        _browser_sessions.pop(url, None)

    vnc_port = _find_free_port()
    conn_name = f"tailscan-browse-{vnc_port}"

    # Start the container
    try:
        result = subprocess.run([
            "docker", "run", "-d", "--rm",
            "--name", conn_name,
            "-p", f"127.0.0.1:{vnc_port}:5900",
            "-e", f"URL={url}",
            "-e", f"GEOMETRY={width}x{height}",
            "-e", f"VNC_PASSWORD={BROWSER_VNC_PASSWORD}",
            BROWSER_IMAGE,
        ], capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip())
        container_id = result.stdout.strip()
    except Exception as e:
        raise HTTPException(500, f"Failed to start browser container: {e}")

    # Give the container a moment to start VNC
    import asyncio
    await asyncio.sleep(3)

    # Register in Guacamole
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            token = await _guac_token(client)
            payload = {
                "name": conn_name,
                "protocol": "vnc",
                "parameters": {
                    "hostname": "127.0.0.1",
                    "port": str(vnc_port),
                    "password": BROWSER_VNC_PASSWORD,
                    "color-depth": "24",
                },
                "attributes": {
                    "max-connections": "2",
                    "max-connections-per-user": "2",
                },
                "parentIdentifier": "ROOT",
            }
            r = await client.post(
                f"{GUAC_BASE}/api/session/data/postgresql/connections",
                params={"token": token},
                json=payload,
            )
            r.raise_for_status()
            conn_id = r.json()["identifier"]
    except Exception as e:
        # Kill container if Guacamole registration fails
        subprocess.run(["docker", "stop", container_id], capture_output=True)
        raise HTTPException(502, f"Guacamole registration failed: {e}")

    _browser_sessions[url] = {
        "container_id": container_id,
        "vnc_port": vnc_port,
        "conn_id": conn_id,
        "conn_name": conn_name,
    }

    import base64
    client_id = base64.b64encode(
        f"{conn_id}\0c\0postgresql".encode()
    ).decode().rstrip("=")
    request_host = request.headers.get("host", "localhost").split(":")[0]
    guac_url = f"http://{request_host}:8085/guacamole/#/client/{client_id}"
    return {"url": guac_url}


@app.delete("/api/browse-session")
async def api_browse_session_delete(request: Request, url: str):
    """Kill the browser container for a given URL and clean up the Guacamole connection."""
    if not get_session(request):
        raise HTTPException(401)
    s = _browser_sessions.pop(url, None)
    if not s:
        return {"status": "not_found"}
    subprocess.run(["docker", "stop", s["container_id"]], capture_output=True)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            token = await _guac_token(client)
            await client.delete(
                f"{GUAC_BASE}/api/session/data/postgresql/connections/{s['conn_id']}",
                params={"token": token},
            )
    except Exception:
        pass
    return {"status": "stopped"}


# ─── elFinder connector ──────────────────────────────────────────────────────

import base64 as _b64
import mimetypes as _mimetypes

def _elf_id(proto: str, host: str, port: int, share: str, path: str) -> str:
    """Encode a volume+path into an elFinder hash."""
    vol = f"{proto}:{host}:{port}:{share}"
    raw = f"{vol}:{path}"
    return _b64.urlsafe_b64encode(raw.encode()).decode().rstrip("=") + "_"

def _elf_decode(hash_: str) -> tuple:
    """Decode an elFinder hash back to (proto, host, port, share, path)."""
    padded = hash_.rstrip("_") + "=="
    raw = _b64.urlsafe_b64decode(padded).decode()
    proto, host, port, share, path = raw.split(":", 4)
    return proto, host, int(port), share, path

def _elf_entry(proto, host, port, share, path, name, is_dir, size=0, mime=None):
    hash_ = _elf_id(proto, host, port, share, path)
    parent_path = "/".join(path.rstrip("/").split("/")[:-1]) or "/"
    phash = _elf_id(proto, host, port, share, parent_path) if path != "/" else None
    if mime is None:
        mime = "directory" if is_dir else (_mimetypes.guess_type(name)[0] or "application/octet-stream")
    entry = {
        "hash": hash_,
        "name": name,
        "mime": mime,
        "size": 0 if is_dir else size,
        "dirs": 1 if is_dir else 0,
        "read": 1, "write": 1, "locked": 0, "hidden": 0,
        "ts": 0,
        "tmb": False,   # disable thumbnail generation — avoids loading full-size files
        "volumeid": f"{proto}_{host}_{port}_{share}_",
    }
    if phash:
        entry["phash"] = phash
    return entry

def _elf_root_entry(proto, host, port, share):
    hash_ = _elf_id(proto, host, port, share, "/")
    label = f"{proto.upper()}:{host}" + (f"/{share}" if share else "")
    return {
        "hash": hash_,
        "name": label,
        "mime": "directory",
        "size": 0, "dirs": 1, "read": 1, "write": 1, "locked": 0, "hidden": 0, "ts": 0,
        "volumeid": f"{proto}_{host}_{port}_{share}_",
        "isroot": 1,
        "options": {
            "path": "/", "separator": "/", "disabled": [],
            "archivers": {"create": [], "extract": []},
            "copyOverwrite": 1, "uploadMaxSize": 0,
        },
    }

async def _elf_ls(proto, host, port, share, path, user, password):
    if proto == "ftp":
        return fb.ftp_list(host, port, user, password, path)
    else:
        return fb.smb_list(host, user, password, share, path, port)

async def _elf_open(proto, host, port, share, path, user, password):
    """Return (entries, cwd_entry) for a directory."""
    if path == "/":
        cwd_entry = _elf_root_entry(proto, host, port, share)
    else:
        name = path.rstrip("/").split("/")[-1] or "root"
        cwd_entry = _elf_entry(proto, host, port, share, path, name, True)
        # Non-root dirs also need options for elFinder to display contents
        cwd_entry["options"] = {
            "path": path,
            "url": "",
            "tmbUrl": "",
            "separator": "/",
            "copyOverwrite": 1,
            "uploadOverwrite": 1,
            "uploadMaxSize": 0,
            "disabled": [],
            "archivers": {"create": [], "extract": []},
        }

    entries = await _asyncio.get_event_loop().run_in_executor(
        None, lambda: _elf_ls_sync(proto, host, port, share, path, user, password)
    )
    files = []
    for e in entries:
        if e.get("type") == "share":
            # SMB share listing — each "entry" is a share, encode share name into hash
            files.append(_elf_entry(proto, host, port, e["name"], "/",
                                    e["name"], True))
        else:
            child_path = (path.rstrip("/") + "/" + e["name"])
            files.append(_elf_entry(proto, host, port, share, child_path,
                                    e["name"], e["type"] == "dir", e.get("size", 0)))
    return cwd_entry, files

def _elf_ls_sync(proto, host, port, share, path, user, password):
    if proto == "ftp":
        return fb.ftp_list(host, port, user, password, path)
    else:
        return fb.smb_list(host, user, password, share, path, port)


@app.get("/api/elfinder")
@app.post("/api/elfinder")
async def elfinder_connector(request: Request):
    if not get_session(request):
        raise HTTPException(401)

    # Parse params from GET or POST
    if request.method == "POST":
        form = await request.form()
        params = dict(form)
    else:
        params = dict(request.query_params)

    cmd = params.get("cmd", "")
    # Volume credentials passed as query params: proto, host, port, share, user, password
    proto  = params.get("proto", "ftp")
    host   = params.get("host", "")
    port   = int(params.get("port", 21 if proto == "ftp" else 445))
    share  = params.get("share", "")
    user   = params.get("user", "")
    password = params.get("password", "")

    def err(msg):
        return JSONResponse({"error": msg})

    # ── open ──────────────────────────────────────────────────────────────────
    if cmd == "open":
        init = params.get("init") == "1"
        target = params.get("target", "")
        if init or not target:
            path = "/"
            # use share/creds from URL params on init
        else:
            try:
                # Decode share AND path from the hash — don't rely on URL params
                _, _, _, share, path = _elf_decode(target)
            except Exception:
                path = "/"
        try:
            cwd, files = await _elf_open(proto, host, port, share, path, user, password)
        except Exception as e:
            return err(str(e))

        # Build ancestor entries so the tree sidebar stays populated.
        # elFinder removes tree nodes for any dir not present in the files array.
        ancestors = []
        if path != "/":
            parts = path.strip("/").split("/")
            for i in range(len(parts)):
                anc_path = "/" + "/".join(parts[:i+1])
                if anc_path == path:
                    continue  # already in files as cwd
                anc_name = parts[i]
                ancestors.append(_elf_entry(proto, host, port, share,
                                            anc_path, anc_name, True))

        # Always include options — elFinder needs them on every open to
        # correctly assign files to the right volume/pane
        vol_options = {
            "path": path,
            "url": "",
            "tmbUrl": "",
            "separator": "/",
            "copyOverwrite": 1,
            "uploadOverwrite": 1,
            "uploadMaxSize": 0,
            "disabled": [],
            "archivers": {"create": [], "extract": []},
        }
        resp = {
            "cwd": cwd,
            "files": ancestors + [cwd] + files,
            "api": "2.1",
            "uplMaxSize": "256M",
            "uplMaxFile": 20,
            "options": vol_options,
        }
        if init:
            resp["init"] = 1
        return JSONResponse(resp)

    # ── ls ────────────────────────────────────────────────────────────────────
    elif cmd == "ls":
        target = params.get("target", "")
        try:
            _, _, _, share, path = _elf_decode(target)
            entries = await _asyncio.get_event_loop().run_in_executor(
                None, lambda: _elf_ls_sync(proto, host, port, share, path, user, password)
            )
            return JSONResponse({"list": [e["name"] for e in entries]})
        except Exception as e:
            return err(str(e))

    # ── tree ──────────────────────────────────────────────────────────────────
    elif cmd == "tree":
        target = params.get("target", "")
        try:
            _, _, _, share, path = _elf_decode(target)
            entries = await _asyncio.get_event_loop().run_in_executor(
                None, lambda: _elf_ls_sync(proto, host, port, share, path, user, password)
            )
            dirs = [_elf_entry(proto, host, port, share,
                               path.rstrip("/") + "/" + e["name"],
                               e["name"], True)
                    for e in entries if e["type"] == "dir"]
            return JSONResponse({"tree": dirs})
        except Exception as e:
            return err(str(e))

    # ── get (file content for preview) ───────────────────────────────────────
    elif cmd == "get":
        target = params.get("target", "")
        try:
            _, h, p, sh, path = _elf_decode(target)
            if proto == "ftp":
                data = await _asyncio.get_event_loop().run_in_executor(
                    None, lambda: fb.ftp_download(h, p, user, password, path))
            else:
                data = await _asyncio.get_event_loop().run_in_executor(
                    None, lambda: fb.smb_download(h, user, password, sh, path, p))
            return JSONResponse({"content": data.decode(errors="replace")})
        except Exception as e:
            return err(str(e))

    # ── file (download) ───────────────────────────────────────────────────────
    elif cmd == "file":
        target = params.get("target", "")
        try:
            _, h, p, sh, path = _elf_decode(target)
            if proto == "ftp":
                data = await _asyncio.get_event_loop().run_in_executor(
                    None, lambda: fb.ftp_download(h, p, user, password, path))
            else:
                data = await _asyncio.get_event_loop().run_in_executor(
                    None, lambda: fb.smb_download(h, user, password, sh, path, p))
            name = path.split("/")[-1] or "file"
            mime = _mimetypes.guess_type(name)[0] or "application/octet-stream"
            return Response(data, media_type=mime,
                            headers={"Content-Disposition": f'attachment; filename="{name}"'})
        except Exception as e:
            return err(str(e))

    # ── upload ────────────────────────────────────────────────────────────────
    elif cmd == "upload":
        target = params.get("target", "")
        try:
            _, h, p, sh, dir_path = _elf_decode(target)
        except Exception:
            return err("Invalid target")
        uploaded = []
        form = await request.form()
        for key, f in form.multi_items():
            if key.startswith("upload") and hasattr(f, "filename"):
                data = await f.read()
                dest = dir_path.rstrip("/") + "/" + f.filename
                if proto == "ftp":
                    await _asyncio.get_event_loop().run_in_executor(
                        None, lambda: fb.ftp_upload(h, p, user, password, dest, data))
                else:
                    await _asyncio.get_event_loop().run_in_executor(
                        None, lambda: fb.smb_upload(h, user, password, sh, dest, data, p))
                uploaded.append(_elf_entry(proto, h, p, sh, dest, f.filename, False, len(data)))
        return JSONResponse({"added": uploaded})

    # ── mkdir ─────────────────────────────────────────────────────────────────
    elif cmd == "mkdir":
        target = params.get("target", "")
        name = params.get("name", "")
        try:
            _, h, p, sh, dir_path = _elf_decode(target)
            new_path = dir_path.rstrip("/") + "/" + name
            if proto == "ftp":
                await _asyncio.get_event_loop().run_in_executor(
                    None, lambda: fb.ftp_mkdir(h, p, user, password, new_path))
            else:
                await _asyncio.get_event_loop().run_in_executor(
                    None, lambda: fb.smb_mkdir(h, user, password, sh, new_path, p))
            entry = _elf_entry(proto, h, p, sh, new_path, name, True)
            return JSONResponse({"added": [entry]})
        except Exception as e:
            return err(str(e))

    # ── rm ────────────────────────────────────────────────────────────────────
    elif cmd == "rm":
        targets = params.getlist("targets[]") if hasattr(params, "getlist") else [v for k, v in params.items() if k == "targets[]"]
        # Also handle form multi-values
        if request.method == "POST":
            form = await request.form()
            targets = [v for k, v in form.multi_items() if k == "targets[]"]
        removed = []
        for t in targets:
            try:
                _, h, p, sh, path = _elf_decode(t)
                # Guess if dir by trying dir delete first
                try:
                    if proto == "ftp":
                        await _asyncio.get_event_loop().run_in_executor(
                            None, lambda: fb.ftp_delete(h, p, user, password, path, True))
                    else:
                        await _asyncio.get_event_loop().run_in_executor(
                            None, lambda: fb.smb_delete(h, user, password, sh, path, True, p))
                except Exception:
                    if proto == "ftp":
                        await _asyncio.get_event_loop().run_in_executor(
                            None, lambda: fb.ftp_delete(h, p, user, password, path, False))
                    else:
                        await _asyncio.get_event_loop().run_in_executor(
                            None, lambda: fb.smb_delete(h, user, password, sh, path, False, p))
                removed.append(t)
            except Exception:
                pass
        return JSONResponse({"removed": removed})

    # ── rename ────────────────────────────────────────────────────────────────
    elif cmd == "rename":
        # FTP/SMB rename not implemented yet — return error gracefully
        return err("Rename not supported yet")

    # ── info / size ───────────────────────────────────────────────────────────
    elif cmd in ("info", "size", "dim"):
        return JSONResponse({"dim": "", "size": 0})

    # ── unknown ───────────────────────────────────────────────────────────────
    else:
        return JSONResponse({"error": f"Unknown command: {cmd}"})


# ─── File browser API ────────────────────────────────────────────────────────
import filebrowser as fb
from fastapi.responses import StreamingResponse as _StreamingResponse
import io as _io

# ── FTP ──────────────────────────────────────────────────────────────────────

@app.get("/api/ftp/list")
def ftp_list(request: Request, host: str, port: int = 21,
             username: str = "", password: str = "", path: str = "/"):
    if not get_session(request):
        raise HTTPException(401)
    try:
        return fb.ftp_list(host, port, username, password, path)
    except Exception as e:
        raise HTTPException(502, str(e))


@app.get("/api/ftp/download")
def ftp_download(request: Request, host: str, port: int = 21,
                 username: str = "", password: str = "", path: str = ""):
    if not get_session(request):
        raise HTTPException(401)
    try:
        data = fb.ftp_download(host, port, username, password, path)
        filename = path.split("/")[-1] or "file"
        return _StreamingResponse(
            _io.BytesIO(data),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        raise HTTPException(502, str(e))


@app.post("/api/ftp/upload")
async def ftp_upload(request: Request, host: str, port: int = 21,
                     username: str = "", password: str = "", path: str = ""):
    if not get_session(request):
        raise HTTPException(401)
    try:
        data = await request.body()
        fb.ftp_upload(host, port, username, password, path, data)
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(502, str(e))


@app.post("/api/ftp/mkdir")
def ftp_mkdir(request: Request, host: str, port: int = 21,
              username: str = "", password: str = "", path: str = ""):
    if not get_session(request):
        raise HTTPException(401)
    try:
        fb.ftp_mkdir(host, port, username, password, path)
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(502, str(e))


@app.delete("/api/ftp/delete")
def ftp_delete(request: Request, host: str, port: int = 21,
               username: str = "", password: str = "",
               path: str = "", is_dir: bool = False):
    if not get_session(request):
        raise HTTPException(401)
    try:
        fb.ftp_delete(host, port, username, password, path, is_dir)
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(502, str(e))


# ── SMB ──────────────────────────────────────────────────────────────────────

@app.get("/api/smb/shares")
def smb_shares(request: Request, host: str, port: int = 445,
               username: str = "", password: str = ""):
    if not get_session(request):
        raise HTTPException(401)
    try:
        return fb.smb_list_shares(host, username, password, port)
    except Exception as e:
        raise HTTPException(502, str(e))


@app.get("/api/smb/list")
def smb_list(request: Request, host: str, share: str, path: str = "/",
             port: int = 445, username: str = "", password: str = ""):
    if not get_session(request):
        raise HTTPException(401)
    try:
        return fb.smb_list(host, username, password, share, path, port)
    except Exception as e:
        raise HTTPException(502, str(e))


@app.get("/api/smb/download")
def smb_download(request: Request, host: str, share: str, path: str,
                 port: int = 445, username: str = "", password: str = ""):
    if not get_session(request):
        raise HTTPException(401)
    try:
        data = fb.smb_download(host, username, password, share, path, port)
        filename = path.split("/")[-1].split("\\")[-1] or "file"
        return _StreamingResponse(
            _io.BytesIO(data),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        raise HTTPException(502, str(e))


@app.post("/api/smb/upload")
async def smb_upload(request: Request, host: str, share: str, path: str,
                     port: int = 445, username: str = "", password: str = ""):
    if not get_session(request):
        raise HTTPException(401)
    try:
        data = await request.body()
        fb.smb_upload(host, username, password, share, path, data, port)
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(502, str(e))


@app.post("/api/smb/mkdir")
def smb_mkdir(request: Request, host: str, share: str, path: str,
              port: int = 445, username: str = "", password: str = ""):
    if not get_session(request):
        raise HTTPException(401)
    try:
        fb.smb_mkdir(host, username, password, share, path, port)
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(502, str(e))


@app.delete("/api/smb/delete")
def smb_delete(request: Request, host: str, share: str, path: str,
               port: int = 445, username: str = "", password: str = "",
               is_dir: bool = False):
    if not get_session(request):
        raise HTTPException(401)
    try:
        fb.smb_delete(host, username, password, share, path, is_dir, port)
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(502, str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=False)
