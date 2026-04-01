# TailScan

Self-hosted web app to manage Tailscale exit nodes and scan the LAN at each remote site — all from a browser.

## How it works

- The server running TailScan **is** the Tailscale client
- Selecting an exit node in the UI runs `tailscale set --exit-node=<ip>` on the server
- All scans (nmap, WAN IP, geolocation) run from the server through the exit node
- Access the UI via the server's **Tailscale IP** — so exit node switches can never lock you out

---

## Quick Start

### 1. Prerequisites

- Linux machine with [Tailscale](https://tailscale.com/download) installed and running
- Python 3.11+
- Git

### 2. Create Tailscale OAuth credentials

1. Go to [https://login.tailscale.com/admin/settings/oauth](https://login.tailscale.com/admin/settings/oauth)
2. Create a new OAuth client
3. Scopes needed: `openid`, `profile`, `email`
4. Set redirect URI to: `http://<your-tailscale-ip>:8080/auth/callback`
5. Save the **Client ID** and **Client Secret**

### 3. Install

```bash
git clone https://github.com/PizzaCow/TailScan /opt/tailscan
cd /opt/tailscan
chmod +x start.sh update.sh
./start.sh
# First run creates .env — edit it, then run ./start.sh again
```

### 4. Configure `.env`

```env
TAILSCALE_CLIENT_ID=your_client_id
TAILSCALE_CLIENT_SECRET=your_client_secret
TAILSCALE_REDIRECT_URI=http://100.x.x.x:8080/auth/callback
SECRET_KEY=<random 32-char string>
TAILNET=your-tailnet-name
```

Generate a secret key:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 5. Launch

```bash
./start.sh
```

Access at `http://<tailscale-ip>:8080`

---

## Run as a service (optional)

```bash
cp tailscan.service /etc/systemd/system/
# Edit WorkingDirectory in the service file if you installed somewhere other than /opt/tailscan
systemctl daemon-reload
systemctl enable tailscan
systemctl start tailscan
```

---

## Update

```bash
cd /opt/tailscan
./update.sh
```

---

## Features

- **Tailscale SSO** — login with your Tailscale account, no separate passwords
- **Exit node selector** — see all tailnet devices, click to connect
- **LAN scan** — nmap ping sweep auto-detects subnet, shows IP, hostname, ping, MAC, vendor
- **WAN + Geo** — WAN IP, city, region, country, lat/lon, ISP, timezone via ip-api.com
- **Auto-refresh** — scans every 30s while connected
- **Dark UI** — clean dark theme

---

## Security

- UI is only served on port 8080 — keep it on Tailscale, don't expose to public internet
- Auth via Tailscale SSO — only your tailnet members can log in
- Switching exit nodes affects **all** server traffic — use on a dedicated machine

---

## Stack

- Python + FastAPI
- nmap for LAN scanning
- ip-api.com for WAN geolocation (free, no key needed)
- Tailscale OAuth for auth
- Zero JS frameworks — plain HTML/CSS/JS frontend
