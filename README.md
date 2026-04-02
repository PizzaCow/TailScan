# TailScan

A fast LAN scanner that runs on your Tailscale network. Connect to an exit node and scan what's on its local network — from anywhere.

## What it does

- Connects to any Tailscale exit node
- Discovers all live hosts on the LAN using **fping** (fast, ~10s for a /24)
- Scans open ports on every device using **nmap** (~1s per host)
- Proxies web UIs directly from your browser through the exit node
- Caches last scan results per network so the page loads instantly

## Stack

- **Python 3** / **FastAPI** / **uvicorn**
- **fping** — host discovery via ICMP (much faster than nmap ping sweep)
- **nmap** — TCP connect port scan, no root required (`-sT`)
- **httpx** — async HTTP for WAN geo lookup and the reverse proxy
- **Tailscale** — peer list and exit node control via `tailscale status --json`

## Scanned Ports (116 total)

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
| `4000` | HTTP-alt | `4040` | ngrok | `4200` | Angular dev |
| `4500` | IPSec NAT-T | `4848` | GlassFish | `5000` | Synology DSM |
| `5001` | Synology HTTPS | `5055` | Overseerr | `5222` | XMPP |
| `5269` | XMPP S2S | `5280` | XMPP HTTP | `5299` | Ombi |
| `5349` | STUN/TURN TLS | `5432` | PostgreSQL | `5433` | PostgreSQL-alt |
| `5900` | VNC | `5901` | VNC :1 | `5902` | VNC :2 |
| `5903` | VNC :3 | `6379` | Redis | `6380` | Redis-alt |
| `6443` | k8s API | `6881` | BitTorrent | `7000` | HTTP-alt |
| `7001` | HTTP-alt | `7474` | Neo4j | `7878` | Radarr |
| `8006` | Proxmox | `8007` | Proxmox SPICE | `8080` | HTTP-alt |
| `8081` | HTTP-alt 2 | `8082` | HTTP-alt 3 | `8086` | InfluxDB |
| `8087` | InfluxDB-alt | `8090` | HTTP-alt 4 | `8096` | Jellyfin |
| `8097` | Jellyfin HTTPS | `8112` | Deluge | `8123` | Home Assistant |
| `8200` | Synology Video | `8443` | HTTPS-alt | `8448` | Matrix federation |
| `8686` | Lidarr | `8787` | Readarr | `8883` | MQTT TLS |
| `8888` | Jupyter | `8920` | Jellyfin-alt | `8989` | Sonarr |
| `9000` | Portainer | `9042` | Cassandra | `9090` | Prometheus/Cockpit |
| `9091` | Transmission | `9100` | Node Exporter | `9117` | Jackett |
| `9200` | Elasticsearch | `9300` | ES cluster | `9393` | Scrutiny |
| `9443` | Portainer HTTPS | `9696` | Prowlarr | `9999` | HTTP-alt |
| `10000` | Webmin | `10250` | kubelet | `10255` | kubelet read-only |
| `27017` | MongoDB | `27018` | MongoDB-alt | `32400` | Plex |
| `32469` | Plex DLNA | `51413` | Transmission torrent | | |

Browsable ports (clickable chips that open through the proxy): `80`, `443`, `1880`, `3000`, `3001`, `4000`, `4200`, `5000`, `5001`, `5055`, `7000`, `7001`, `7878`, `8001`, `8006`, `8007`, `8080`–`8082`, `8090`, `8096`, `8097`, `8123`, `8200`, `8443`, `8686`, `8787`, `8888`, `8920`, `8989`, `9000`, `9090`, `9091`, `9117`, `9393`, `9443`, `9696`, `9999`, `10000`, `32400`.

## How it works

### Host discovery
Uses `fping -a -g <subnet>` which sends ICMP pings to the whole subnet in parallel and streams responding IPs. Typical time: ~9s for 79 hosts on a /24. No ARP (traffic goes over the Tailscale tunnel, not direct LAN).

### Subnet detection
Reads the exit node's `AllowedIPs` from `tailscale status --json` and filters for private RFC-1918 ranges. Falls back to `ip route` if no AllowedIPs are found.

### Port scanning
`nmap -sT --open -T5 -p<ports>` — TCP connect scan, no raw sockets, no root required. ~1s per host. 116 ports covering common services, databases, homelab UIs, and IoT.

### Reverse proxy
`/proxy?t=http://ip:port/path` — fetches from the LAN via the exit node, rewrites HTML links and injects a JS interceptor so SPA routing (Sonarr, Radarr, Proxmox, etc.) works end-to-end.

### Device cache
Results are cached on disk per exit node / subnet. On next page load, cached devices appear instantly in **purple** while the live scan runs in the background. Port results are written back to the cache after each scan.

## Auth

Simple password auth with a session cookie. Set `PASSWORD_HASH` (SHA-256 of your password) and `SECRET_KEY` in `.env`.

```bash
echo -n 'yourpassword' | sha256sum
```

## Setup

### Requirements

```bash
apt install fping nmap
pip install -r requirements.txt
```

### .env

```
PASSWORD_HASH=<sha256 of your password>
SECRET_KEY=<random string>
CACHE_DIR=/tmp/tailscan-cache  # optional
```

### Run

```bash
uvicorn main:app --host 0.0.0.0 --port 8080
```

### systemd service

```ini
[Unit]
Description=TailScan
After=network.target tailscaled.service

[Service]
WorkingDirectory=/opt/tailscan
ExecStart=/usr/local/bin/uvicorn main:app --host 0.0.0.0 --port 8080
Restart=always
EnvironmentFile=/opt/tailscan/.env

[Install]
WantedBy=multi-user.target
```

```bash
cp tailscan.service /etc/systemd/system/
systemctl enable --now tailscan
```

## Notes

- TailScan needs to be on a Tailscale node that can use exit nodes (i.e. `--exit-node` routing works)
- No MAC addresses or vendor lookup — traffic goes over the tunnel, not direct Ethernet
- The exit node must be advertising subnet routes for LAN discovery to work
