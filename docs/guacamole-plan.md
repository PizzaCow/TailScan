# Guacamole Integration Plan

## What Is Guacamole?

Apache Guacamole is a clientless remote desktop gateway. It runs as a server and exposes all remote connections through a web browser — no plugins, no clients needed. Supports:

- **RDP** — Windows desktops/servers
- **VNC** — Linux, NAS, anything with a VNC server
- **SSH** — Terminal access + SFTP file browser
- **Browser via VNC** — Run LibreWolf in a VNC container, navigate to any web UI

---

## Architecture (for this deployment)

```
[Your browser]
     |
     | HTTPS (Tailscale)
     v
[TailScan host: tailscan node, port 8080]
     |
     ├── TailScan (port 8080)      — LAN scanner + port chips
     └── Guacamole (port 9090)     — Remote desktop gateway
              |
              | guacd (localhost:4822)
              v
     [LAN devices via exit node]
       - RDP  → Windows machines
       - VNC  → NAS, Linux, LibreWolf container
       - SSH  → Any SSH-enabled device
```

Everything runs on the same host as TailScan (the `tailscan` Tailscale node). guacd connects out to LAN devices through the active Tailscale exit node.

---

## Docker Compose

File: `guacamole/docker-compose.yml`

```yaml
version: "3.9"

services:
  guacd:
    image: guacamole/guacd:latest
    restart: unless-stopped
    networks: [guac-net]

  postgres:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: guacamole_db
      POSTGRES_USER: guacamole_user
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - guac-pgdata:/var/lib/postgresql/data
      - ./initdb.sql:/docker-entrypoint-initdb.d/initdb.sql:ro
    networks: [guac-net]

  guacamole:
    image: guacamole/guacamole:latest
    restart: unless-stopped
    depends_on: [guacd, postgres]
    environment:
      GUACD_HOSTNAME: guacd
      POSTGRESQL_HOSTNAME: postgres
      POSTGRESQL_DATABASE: guacamole_db
      POSTGRESQL_USERNAME: guacamole_user
      POSTGRESQL_PASSWORD: ${POSTGRES_PASSWORD}
    ports:
      - "9090:8080"
    networks: [guac-net]

  # LibreWolf VNC container — for browsing LAN web UIs with a real browser
  librewolf-vnc:
    image: lscr.io/linuxserver/librewolf:latest
    restart: unless-stopped
    environment:
      PUID: 1000
      PGID: 1000
      TZ: America/Edmonton
    ports:
      - "3390:3000"   # VNC port (mapped to 3390 to avoid conflict)
    volumes:
      - librewolf-data:/config
    networks: [guac-net]

volumes:
  guac-pgdata:
  librewolf-data:

networks:
  guac-net:
    driver: bridge
```

`.env` file (not in git):
```
POSTGRES_PASSWORD=<strong random password>
```

---

## Initial Setup

### 1. Generate the Postgres init SQL

```bash
docker run --rm guacamole/guacamole:latest /opt/guacamole/bin/initdb.sh --postgresql > guacamole/initdb.sql
```

### 2. Start the stack

```bash
cd guacamole
docker compose up -d
```

### 3. First login

URL: `http://<tailscan-ip>:9090/guacamole`  
Default creds: `guacadmin` / `guacadmin`  
**Change the password immediately.**

### 4. Add the LibreWolf VNC connection

In Guacamole admin:
- Protocol: VNC
- Hostname: `librewolf-vnc`
- Port: `3000`
- Name: "LibreWolf Browser"

---

## TailScan Integration

### Green Port Chips

Ports `22` (SSH), `3389` (RDP), `5900–5903` (VNC) show as **green chips** in TailScan.

Once Guacamole is deployed, set `GUAC_URL` in `templates/index.html`:

```javascript
const GUAC_URL = 'http://100.97.92.103:9090/guacamole';
```

Clicking a green chip will open a Guacamole connection to that IP/port.

### "Browse" Button (Web UIs)

For web UIs that the HTTP proxy can't handle (TrueNAS, complex SPAs), a "Browse" button will:
1. Hit `/api/browse-via-guac?ip=192.168.x.x&port=443&scheme=https`
2. TailScan tells the LibreWolf container to navigate to that URL
3. Guacamole VNC session to LibreWolf opens in a new tab

Implementation: TailScan sends the URL to LibreWolf via its `/config` endpoint or by launching `librewolf --new-tab <url>` inside the container.

---

## LibreWolf Container Notes

- Image: `lscr.io/linuxserver/librewolf` (linuxserver.io — well-maintained, built on their baseimage-kasmvnc)
- Exposes VNC on port `3000` internally
- Accessible via Guacamole as a VNC connection
- Can also be accessed directly at `http://<host>:3390` (KasmVNC web UI built in)
- Privacy-hardened Firefox fork — no telemetry, uBlock Origin pre-installed

---

## File Browse

Guacamole supports SFTP file transfer when connecting via SSH or RDP:
- SSH connections: enable "SFTP" in connection settings, get drag-and-drop file browser
- NAS devices with SSH: direct SFTP browse
- Windows: RDP + file transfer

---

## Roadmap

| Phase | Status | Notes |
|-------|--------|-------|
| Deploy Guacamole + guacd + postgres | ⬜ todo | Docker Compose above |
| Deploy LibreWolf VNC container | ⬜ todo | Alongside Guacamole |
| Green port chips in TailScan | ✅ done (v0.03) | No link until GUAC_URL set |
| Wire GUAC_URL → clickable green chips | ⬜ todo | Set after deployment |
| Browse-via-Guac for web UIs | ⬜ todo | Replaces HTTP proxy for hard SPAs |
| SFTP file browse via SSH chips | ⬜ todo | Auto-enable SFTP on SSH connections |

---

## Auth Notes

- Guacamole uses its own local user DB (PostgreSQL)
- Auth: local accounts only for now
- Future option: OIDC via MAS (account.rewr.ca) if desired

---

## Ports Summary

| Service | Port | Notes |
|---------|------|-------|
| Guacamole web UI | 9090 | → `/guacamole` path |
| guacd | 4822 | internal only, not exposed |
| Postgres | 5432 | internal only |
| LibreWolf KasmVNC | 3390 | direct access (bypass Guac) |
| LibreWolf (via Guac VNC) | 3000 | internal, accessed through Guac |
