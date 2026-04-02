# TailScan

Self-hosted web app to manage Tailscale exit nodes and scan remote LANs — all from a browser.

![Python](https://img.shields.io/badge/python-3.11+-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green) ![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## How it works

- The machine running TailScan **is** the Tailscale client
- Selecting an exit node runs `tailscale set --exit-node=<ip>` on the server
- LAN discovery, port scanning, and WAN geolocation all run through the active exit node
- Access the UI via the server's **Tailscale IP** — so exit node switches can never lock you out

---

## Features

- **Exit node selector** — lists all tailnet peers, one click to switch or disconnect
- **Live LAN discovery** — fping sweep streams devices as they respond (~9s for /24)
- **Auto port scan** — after discovery, scans common ports on every device automatically
- **Port chips** — open ports shown as compact inline chips; hover for service name
- **WAN + geo** — WAN IP, city, region, ISP, timezone via ip-api.com (no key needed)
- **Diff refresh** — auto-refreshes every 30s without wiping the device list; port results persist
- **Password auth** — SHA256 hashed password, 7-day session cookie
- **Dark UI** — zero JS frameworks, plain HTML/CSS/JS

---

## Requirements

- Linux machine with [Tailscale](https://tailscale.com/download) installed and connected
- Python 3.11+
- `fping` and `nmap` (installed automatically by `start.sh`)
- Git

---

## Quick Start

```bash
git clone https://github.com/PizzaCow/TailScan /opt/tailscan
cd /opt/tailscan
chmod +x start.sh update.sh
./start.sh
```

On first run, `start.sh` creates `.env` from `.env.example` and exits. Edit it:

```bash
nano /opt/tailscan/.env
```

Then run again:

```bash
./start.sh
```

Access at `http://<tailscale-ip>:8080`

---

## Configuration

`.env` file (copy from `.env.example`):

```env
PASSWORD_HASH=<sha256 hex of your password>
SECRET_KEY=<random 64-char hex string>
```

Generate values:

```bash
# Password hash
python3 -c "import hashlib; print(hashlib.sha256(b'yourpassword').hexdigest())"

# Secret key
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

## Run as a systemd service

```bash
sudo cp tailscan.service /etc/systemd/system/
# Edit WorkingDirectory if you installed somewhere other than /opt/tailscan
sudo systemctl daemon-reload
sudo systemctl enable --now tailscan
```

Check status:

```bash
sudo systemctl status tailscan
journalctl -u tailscan -f
```

---

## Update

```bash
cd /opt/tailscan
./update.sh
```

Pulls latest from GitHub and restarts the server (or restarts the systemd service if active).

---

## How exit node scanning works

TailScan detects the active exit node's advertised subnet from the Tailscale status JSON (`AllowedIPs`). The exit node must have **subnet routing enabled and approved** in the Tailscale admin console.

If no advertised subnet is found, TailScan falls back to the server's local routing table.

---

## Security notes

- Run on a **dedicated machine** — switching exit nodes affects all server traffic
- Keep port 8080 on Tailscale only; do **not** expose to the public internet
- `.env` contains your password hash and secret key — keep it out of git (already in `.gitignore`)

---

## Stack

| Component | Purpose |
|---|---|
| Python + FastAPI | Backend + SSE streaming |
| fping | Fast LAN host discovery |
| nmap | On-demand port scanning (TCP connect, no probes) |
| ip-api.com | WAN geolocation (free, no key required) |
| Plain HTML/CSS/JS | Frontend — no frameworks |
