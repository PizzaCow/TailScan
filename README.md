# TailScan 🌐

A self-hosted web app that lets you browse your Tailscale network, switch exit nodes, and scan their LANs — all from a clean dark UI, accessible only to tailnet members.

![TailScan UI](https://img.shields.io/badge/TailScan-dark%20navy%20UI-4f79e0?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776ab?style=flat-square)
![FastAPI](https://img.shields.io/badge/FastAPI-latest-009688?style=flat-square)

## Features

- **Tailscale SSO** — login with your Tailscale account. Only tailnet members can access.
- **Device list** — all tailnet peers shown in the sidebar with exit nodes highlighted.
- **One-click exit node switching** — click a node, wait 2s, scan begins.
- **WAN + Geolocation** — shows WAN IP, city, region, country, ISP, timezone via ip-api.com.
- **LAN scan** — nmap ping sweep of the exit node's local subnet (IP, hostname, ping, MAC, vendor, status).
- **Auto-refresh** — scans every 30 seconds with a visible countdown.

---

## Quick Start

### 1. Clone the repo

```bash
git clone https://github.com/PizzaCow/TailScan.git
cd TailScan
```

### 2. Set up Tailscale OAuth

1. Go to [https://login.tailscale.com/admin/settings/oauth](https://login.tailscale.com/admin/settings/oauth)
2. Click **Create OAuth client**
3. Set **Scopes**: `openid`, `profile`, `email`, `devices:read`
4. Set **Redirect URI**: `http://<your-tailscale-ip>:8080/auth/callback`
   - Find your Tailscale IP: `tailscale ip -4`
5. Copy the **Client ID** and **Client Secret**

### 3. Configure .env

```bash
cp .env.example .env
nano .env   # or vim .env
```

Fill in these 3 values:
```
TS_CLIENT_ID=your_oauth_client_id
TS_CLIENT_SECRET=your_oauth_client_secret
BASE_URL=http://100.x.x.x:8080    # your Tailscale IP
```

### 4. Run

```bash
chmod +x start.sh
./start.sh
```

This will:
- Detect your Tailscale IP
- Install nmap if missing
- Create a Python virtualenv
- Install all Python dependencies
- Start TailScan on port 8080

Open your browser to: `http://<tailscale-ip>:8080`

---

## Update

```bash
./update.sh
```

Pulls latest code, updates dependencies, and restarts the service if installed.

---

## Run as a Service (systemd)

```bash
# Copy files to /opt/tailscan
sudo cp -r . /opt/tailscan
cd /opt/tailscan

# Set up venv + dependencies
./start.sh   # ctrl+c after it starts to confirm setup works

# Install systemd service
sudo cp tailscan.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable tailscan
sudo systemctl start tailscan

# Check status
sudo systemctl status tailscan
sudo journalctl -u tailscan -f
```

---

## How It Works

| Component | Technology |
|-----------|-----------|
| Web framework | FastAPI + Uvicorn |
| Auth | Tailscale OAuth 2.0 (OIDC) |
| Tailnet info | `tailscale status --json` |
| Exit node switch | `tailscale set --exit-node=<ip>` |
| LAN scan | `nmap -sn --send-ip <subnet>` |
| WAN IP + geo | [ip-api.com](http://ip-api.com/json) (free, no key) |
| Subnet detection | `ip route` + `ip addr` |
| Frontend | Vanilla JS SPA, dark navy theme |

### Architecture Notes

- The server running TailScan **is** the Tailscale client — switching exit nodes affects the whole machine's routing.
- nmap runs as root (or with `CAP_NET_RAW`) to perform ping sweeps.
- MAC addresses and vendor info are **only available on the local LAN** (ARP). Over a routed exit node, MAC shows as "N/A (routed)" — this is expected.
- Sessions are stored in memory (restart clears all logins). For persistence, replace the session store in `auth.py`.

---

## File Structure

```
TailScan/
├── main.py              # FastAPI app + API routes
├── tailscale.py         # Tailscale API + CLI wrapper
├── scanner.py           # nmap scanner + ip-api.com geo
├── auth.py              # Tailscale OAuth flow + sessions
├── templates/
│   └── index.html       # Frontend SPA (dark theme)
├── .env.example         # Config template
├── requirements.txt     # Python dependencies
├── start.sh             # First-time setup + launch
├── update.sh            # Pull + restart
├── tailscan.service     # systemd unit
└── README.md
```

---

## Requirements

- Python 3.10+
- Tailscale installed and connected on the server
- nmap (`start.sh` installs it automatically)
- Root or `CAP_NET_RAW` capability for nmap

---

## Security Notes

- TailScan should only be accessed over Tailscale (port 8080 over HTTP is fine — Tailscale encrypts the connection).
- Do **not** expose port 8080 to the public internet.
- The OAuth redirect URI must match exactly what you configured in the Tailscale admin panel.
- Exit node switching requires root/sudo for `tailscale set` — run the app as root or grant sudo permissions.

---

## Troubleshooting

**"tailscale set: permission denied"**
> Run TailScan as root, or grant the user `sudo` access to `tailscale`.

**MAC addresses show "N/A (routed)"**
> This is expected when using exit nodes — you're routing through them, not on the same LAN. ARP is not available over routed paths.

**Login loop / redirect mismatch**
> Make sure `BASE_URL` in `.env` exactly matches the **Redirect URI** you set in the Tailscale OAuth admin.

**Scan shows no hosts**
> - Check that you're connected to an exit node (`tailscale status`)
> - Verify nmap is installed: `which nmap`
> - Check the detected subnet is correct (shown in the LAN card)

---

## License

MIT — do whatever you want with it.
