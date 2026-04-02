# TailScan

A fast LAN scanner that runs on your Tailscale network. Connect to an exit node and scan what's on its local network — from anywhere.

> **Docker project.** The recommended way to run TailScan is via Docker Compose. Manual/bare-metal setup is possible but not the primary path.

## What it does

- Connects to any Tailscale exit node
- Discovers all live hosts using **fping** (~10s for a /24)
- Scans 118 common ports per host using **nmap** (~1s per host)
- Proxies web UIs directly through the exit node — SPA-aware
- Caches scan results per network for instant page loads
- **Guacamole integration** — SSH, RDP, and VNC sessions direct from the browser (green chips)
- Copyparty file server support (orange chips, browsable)
- File transfer protocol detection (SMB, FTP, NFS, rsync, AFP — orange chips)
- Theme switcher — Dark Slate and Rosé Pine (persists via localStorage)

## Stack

- **Python 3** / **FastAPI** / **uvicorn**
- **fping** — host discovery via ICMP
- **nmap** — TCP connect port scan, no root required (`-sT`)
- **httpx** — async HTTP for reverse proxy and WAN geo lookup
- **Apache Guacamole** — browser-based SSH/RDP/VNC client
- **Tailscale** — peer list and exit node control via `tailscale status --json`

## Port chip colors

| Color | Meaning |
|-------|---------|
| 🔵 Blue | Web UI — click to open via proxy |
| 🟢 Green | SSH / RDP / VNC — click to open in Guacamole |
| 🟠 Orange | File transfer (Copyparty, SMB, FTP, NFS, rsync, AFP) |
| ⚫ Grey | Open port, no web UI |

## Scanned Ports (118 total)

| Port | Service | Port | Service | Port | Service |
|------|---------|------|---------|------|---------|
| `21` | FTP | `22` | SSH | `23` | Telnet |
| `25` | SMTP | `53` | DNS | `67` | DHCP |
| `69` | TFTP | `80` | HTTP | `110` | POP3 |
| `111` | RPC/NFS | `123` | NTP | `137` | NetBIOS-NS |
| `139` | NetBIOS-SSN | `143` | IMAP | `161` | SNMP |
| `179` | BGP | `389` | LDAP | `443` | HTTPS |
| `445` | SMB | `465` | SMTPS | `514` | Syslog |
| `515` | LPD (Print) | `548` | AFP | `554` | RTSP |
| `587` | SMTP submission | `623` | IPMI/iDRAC | `631` | IPP (Print) |
| `636` | LDAPS | `873` | rsync | `902` | VMware |
| `993` | IMAPS | `995` | POP3S | `1194` | OpenVPN |
| `1400` | Sonos | `1433` | MSSQL | `1521` | Oracle DB |
| `1880` | Node-RED | `1883` | MQTT | `2049` | NFS |
| `2375` | Docker ⚠️ | `2376` | Docker TLS | `2379` | etcd |
| `2380` | etcd peer | `3000` | Grafana/Node | `3001` | Grafana-alt |
| `3306` | MySQL/MariaDB | `3389` | RDP | `3478` | STUN/TURN |
| `3923` | Copyparty | `4000` | HTTP-alt | `4040` | ngrok |
| `4200` | Angular dev | `4500` | IPSec NAT-T | `4848` | GlassFish |
| `5000` | Synology DSM | `5001` | Synology HTTPS | `5055` | Overseerr |
| `5222` | XMPP | `5269` | XMPP S2S | `5280` | XMPP HTTP |
| `5299` | Ombi | `5349` | STUN/TURN TLS | `5432` | PostgreSQL |
| `5433` | PostgreSQL-alt | `5900` | VNC | `5901` | VNC :1 |
| `5902` | VNC :2 | `5903` | VNC :3 | `6379` | Redis |
| `6380` | Redis-alt | `6443` | k8s API | `6881` | BitTorrent |
| `7000` | HTTP-alt | `7001` | HTTP-alt | `7474` | Neo4j |
| `7878` | Radarr | `8006` | Proxmox | `8007` | Proxmox SPICE |
| `8080` | HTTP-alt | `8081` | HTTP-alt 2 | `8082` | HTTP-alt 3 |
| `8086` | InfluxDB | `8087` | InfluxDB-alt | `8090` | HTTP-alt 4 |
| `8096` | Jellyfin | `8097` | Jellyfin HTTPS | `8112` | Deluge |
| `8123` | Home Assistant | `8200` | Synology Video | `8443` | HTTPS-alt |
| `8448` | Matrix federation | `8686` | Lidarr | `8787` | Readarr |
| `8883` | MQTT TLS | `8888` | Jupyter | `8920` | Jellyfin-alt |
| `8989` | Sonarr | `9000` | Portainer | `9042` | Cassandra |
| `9090` | Prometheus/Cockpit | `9091` | Transmission | `9100` | Node Exporter |
| `9117` | Jackett | `9200` | Elasticsearch | `9300` | ES cluster |
| `9393` | Scrutiny | `9443` | Portainer HTTPS | `9696` | Prowlarr |
| `9999` | HTTP-alt | `10000` | Webmin | `10250` | kubelet |
| `10255` | kubelet read-only | `27017` | MongoDB | `27018` | MongoDB-alt |
| `30266` | Copyparty-alt | `32400` | Plex | `32469` | Plex DLNA |
| `51413` | Transmission torrent | | | | |

## How it works

### Host discovery
`fping -a -g <subnet>` — parallel ICMP pings, streams responding IPs as they reply. ~9s for a /24. No ARP (traffic goes over the Tailscale tunnel).

### Subnet detection
Reads the active exit node's `AllowedIPs` from `tailscale status --json`, filters for private RFC-1918 ranges. Falls back to `ip route` if no AllowedIPs found. Supports multiple subnets.

### Port scanning
`nmap -sT --open -T5 -p<ports>` — TCP connect scan, ~1s per host. TailScan's own `PORT_NAMES` table always wins over nmap's service guesses for accurate labelling.

### Reverse proxy
`/proxy?t=http://ip:port/path` — fetches from the LAN via the exit node. Rewrites HTML `href`/`src`/`action`/`srcset`, rewrites `Location` redirect headers, and injects a JS interceptor for SPA routing (fetch, XHR, history, link clicks, form submit). Known limitation: complex SPAs (TrueNAS, some *arr post-login pages) may still break.

### Guacamole integration
Green chips (SSH port 22, RDP port 3389, VNC ports 5900–5903) call `/api/guac-connect` which creates (or reuses) a connection in Guacamole's database via its REST API, then opens the Guacamole client in a new tab. Connections are auto-named `tailscan-{proto}-{ip}-{port}` — no manual setup needed.

### Device cache
Results cached on disk keyed by exit node IP + subnet. Cached devices load instantly on page open (shown in **purple**), live scan runs in background and updates the view. Port results written back to cache after each scan. 5-minute background port-only rescan after full scan completes.

## Auth

Simple password + session cookie. Set `PASSWORD_HASH` (SHA-256 of your password) and `SECRET_KEY` in `.env`.

```bash
echo -n 'yourpassword' | sha256sum
```

## Setup

### Requirements

- Docker + Docker Compose
- Tailscale installed and running on the host
- The host must be able to use Tailscale exit nodes

### 1. Clone the repo

```bash
git clone https://github.com/PizzaCow/TailScan /opt/tailscan
cd /opt/tailscan
```

### 2. Generate the Guacamole DB init SQL (one time only)

```bash
docker run --rm guacamole/guacamole:latest \
  /opt/guacamole/bin/initdb.sh --postgresql > guacamole/initdb.sql
```

### 3. Create `.env`

```bash
cp .env.example .env
nano .env
```

Fill in:

```env
PASSWORD_HASH=<sha256 of your password>   # echo -n 'yourpassword' | sha256sum
SECRET_KEY=<random string>
POSTGRES_PASSWORD=<pick anything>
GUAC_ADMIN_USER=guacadmin
GUAC_ADMIN_PASS=guacadmin
```

### 4. Start

```bash
docker compose up -d --build
```

- TailScan: `http://<host-ip>:8080`
- Guacamole: `http://<host-ip>:8085/guacamole`

**Change the Guacamole admin password** after first login: Settings → Users.

### Updating

```bash
git pull && docker compose up -d --build
```

### Managing with Dockge

[Dockge](https://github.com/louislam/dockge) is a nice UI for managing Docker Compose stacks. To install:

```bash
mkdir -p /opt/dockge /opt/stacks
curl -o /opt/dockge/compose.yaml https://raw.githubusercontent.com/louislam/dockge/master/compose.yaml
docker compose -f /opt/dockge/compose.yaml up -d
```

Dockge will be at `http://<host-ip>:5001`. Point it at `/opt/stacks` and add TailScan as a stack there.

### Manual / bare-metal (not recommended)

If you can't use Docker:

```bash
# Debian/Ubuntu
apt install fping nmap
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8080

# Rocky/RHEL (fping must be built from source — not in repos)
dnf install -y gcc make nmap
curl -L https://fping.org/dist/fping-5.2.tar.gz | tar xz
cd fping-5.2 && ./configure && make && make install
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8080
```

You'll need to set up Guacamole separately and point `GUAC_URL` at it.

## Notes

- TailScan must run on a Tailscale node that can use exit nodes
- guacd must be able to reach the LAN directly — run it on the same machine as TailScan (not a remote VPS)
- No MAC addresses or vendor lookup — traffic goes over the Tailscale tunnel, not direct Ethernet
- The exit node must be advertising subnet routes for LAN discovery to work
