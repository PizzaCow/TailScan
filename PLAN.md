# TailScan — Project Plan

## What It Is

A self-hosted web app that lets you manage Tailscale exit nodes and scan the LAN at each remote site — all from a browser, no agents required on remote machines.

---

## Architecture

```
[ Browser ] ──HTTPS──► [ TailScan Server (Linux, Tailscale installed) ]
                                │
                                ├── Tailscale CLI (exit node switching)
                                ├── nmap (LAN scanning)
                                └── ip-api.com (WAN geolocation)
```

- The TailScan server **is** the Tailscale client
- Switching exit nodes via the UI runs `tailscale set --exit-node=<node>` on the server itself
- All scans run from the server, so they see the remote site's LAN and WAN IP
- You always reach the web UI via the server's **Tailscale IP** (never WAN), so exit node changes can't lock you out

---

## Stack

| Component | Technology |
|---|---|
| Backend | Python — FastAPI |
| Frontend | Single-page app (HTML/JS, no framework) |
| Auth | Tailscale SSO (OAuth 2.0 via Tailscale API) |
| LAN scan | nmap (installed on server, called via subprocess) |
| WAN/Geo | ip-api.com (free, no key needed) |
| Sessions | Signed cookie (keeps you logged in) |
| TLS | Served on port 443 via self-signed or Let's Encrypt |

---

## Features

### Dashboard
- List all devices on your tailnet (via Tailscale API)
- Highlight which are exit nodes
- Show online/offline status, OS, last seen
- One-click to activate an exit node

### Site View (after connecting to exit node)
- WAN IP of the remote site
- Geolocation: city, region/province, country, lat/lon
- LAN device table:
  - Local IP
  - Hostname (reverse DNS / nmap)
  - Ping (ms)
  - MAC address (if available)
  - Vendor (from MAC OUI lookup)
- Auto-refresh every 30s
- Manual refresh button

### Auth
- Login via Tailscale SSO (OAuth — "Login with Tailscale")
- Only users on your tailnet can log in
- Session cookie keeps you signed in

---

## Setup (planned)

```bash
# 1. Install dependencies
sudo apt install nmap python3 python3-pip
pip install fastapi uvicorn requests python-multipart

# 2. Clone and configure
git clone https://github.com/PizzaCow/TailScan
cd TailScan
cp .env.example .env
# Fill in: TAILSCALE_CLIENT_ID, TAILSCALE_CLIENT_SECRET, SECRET_KEY

# 3. Run
python3 main.py
# Access via http://<tailscale-ip>:443
```

---

## Security Notes

- Web UI only accessible via Tailscale IP (not exposed to public internet)
- Auth via Tailscale SSO — no passwords to manage
- Switching exit nodes affects all server traffic — use with care
- nmap runs as root (required for ARP/ping sweep) — server should be dedicated to this

---

## Repo Structure (planned)

```
TailScan/
├── main.py              # FastAPI app entry point
├── tailscale.py         # Tailscale API + CLI wrapper
├── scanner.py           # nmap + geo lookup logic
├── auth.py              # Tailscale OAuth flow + session handling
├── templates/
│   └── index.html       # Frontend SPA
├── static/
│   └── app.js           # Frontend logic
├── .env.example         # Config template
├── requirements.txt
└── README.md
```

---

## Open Questions / Future

- [ ] Multi-user support (restrict to specific tailnet users/tags)
- [ ] Scan history / device change detection
- [ ] Port scan per device (optional, on demand)
- [ ] Docker container for easy deployment
- [ ] Auto-detect LAN subnet from routing table after exit node switch
