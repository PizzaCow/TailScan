"""LAN scanner using fping (discovery) + nmap (port scan) + WAN/geo via ip-api.com."""

import subprocess
import socket
import re
import httpx
import time
import json
import xml.etree.ElementTree as ET
from typing import Generator


def get_wan_geo() -> dict:
    """Get WAN IP + geolocation from ip-api.com."""
    try:
        resp = httpx.get("http://ip-api.com/json", timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return {
            "ip": data.get("query", "unknown"),
            "city": data.get("city", ""),
            "region": data.get("regionName", ""),
            "country": data.get("country", ""),
            "country_code": data.get("countryCode", ""),
            "lat": data.get("lat", 0),
            "lon": data.get("lon", 0),
            "isp": data.get("isp", ""),
            "timezone": data.get("timezone", ""),
        }
    except Exception as e:
        return {"ip": "error", "error": str(e)}


def detect_lan_subnets(exit_node_ip: str | None = None) -> list[str]:
    """
    Return all LAN subnets advertised by the exit node peer (AllowedIPs),
    falling back to the local routing table.  Returns a list so multiple
    subnets (e.g. 192.168.0.0/24 + 10.0.0.0/24) are all scanned.
    """
    subnets: list[str] = []

    # Primary: parse AllowedIPs from tailscale status for the active exit node
    if exit_node_ip:
        try:
            import subprocess, json as _json
            result = subprocess.run(
                ["tailscale", "status", "--json"],
                capture_output=True, text=True, timeout=10
            )
            status = _json.loads(result.stdout)
            for _, peer in status.get("Peer", {}).items():
                ips = peer.get("TailscaleIPs", [])
                if ips and ips[0] == exit_node_ip:
                    for route in peer.get("AllowedIPs", []):
                        if route.startswith("100.") or route in ("0.0.0.0/0", "::/0"):
                            continue
                        if any(route.startswith(p) for p in ("10.", "172.", "192.168.")):
                            subnets.append(route)
        except Exception:
            pass

    if subnets:
        return subnets

    # Fallback: local routing table (no exit node, or AllowedIPs empty)
    SKIP_IFACES = {"docker0", "br-", "cni", "flannel", "cali", "veth", "tailscale"}
    try:
        result = subprocess.run(
            ["ip", "route"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if not parts:
                continue
            subnet = parts[0]
            if subnet == "default":
                continue
            if subnet.startswith("100.") or subnet.startswith("127."):
                continue
            if subnet.startswith("172."):
                continue
            if "dev" in parts:
                dev_idx = parts.index("dev") + 1
                if dev_idx < len(parts):
                    dev = parts[dev_idx]
                    if any(dev.startswith(skip) for skip in SKIP_IFACES):
                        continue
            if "/" in subnet and any(subnet.startswith(p) for p in ("10.", "192.168.")):
                subnets.append(subnet)
    except Exception:
        pass

    return subnets


def detect_lan_subnet(exit_node_ip: str | None = None) -> str | None:
    """Backwards-compat shim — returns first subnet or None."""
    s = detect_lan_subnets(exit_node_ip)
    return s[0] if s else None


def _fping_device(ip: str) -> dict:
    """Build a device dict for a discovered IP — reverse DNS only (no ARP through tunnel)."""
    hostname = ip
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass
    return {
        "ip": ip,
        "hostname": hostname,
        "mac": "N/A",
        "vendor": "N/A (routed)",
        "ping_ms": None,
        "status": "up",
    }


def scan_lan(subnet: str) -> list[dict]:
    """Fast fping ping sweep — discovers live hosts."""
    try:
        result = subprocess.run(
            ["fping", "-a", "-g", subnet],
            capture_output=True, text=True, timeout=60
        )
        ips = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        ips.sort(key=lambda x: tuple(int(o) for o in x.split(".")))
        return [_fping_device(ip) for ip in ips]
    except FileNotFoundError:
        return [{"error": "fping not found — run: apt install fping"}]
    except subprocess.TimeoutExpired:
        return [{"error": "scan timed out"}]
    except Exception as e:
        return [{"error": str(e)}]


def scan_lan_stream(subnet: str) -> Generator[dict, None, None]:
    """
    Stream fping ping sweep — emits one device per line as fping finds it.
    fping -a outputs each alive host immediately as it responds.
    """
    cmd = ["fping", "-a", "-g", subnet]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    except FileNotFoundError:
        yield {"error": "fping not found — run: apt install fping"}
        return

    try:
        for line in proc.stdout:
            ip = line.strip()
            if ip:
                yield _fping_device(ip)
    except Exception as e:
        yield {"error": str(e)}
    finally:
        proc.wait()



PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 137: "NetBIOS", 139: "NetBIOS-SSN",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 548: "AFP", 554: "RTSP", 623: "IPMI",
    631: "IPP (Print)", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1883: "MQTT", 3306: "MySQL",
    3389: "RDP", 5000: "Synology DSM / UPnP", 5432: "PostgreSQL",
    5900: "VNC", 5901: "VNC-1", 6379: "Redis",
    8006: "Proxmox", 8080: "HTTP-alt", 8123: "Home Assistant",
    8443: "HTTPS-alt", 8888: "Jupyter / HTTP-alt",
    9090: "Prometheus", 9100: "Node Exporter",
    10000: "Webmin", 27017: "MongoDB", 32400: "Plex",
    51413: "Transmission",
}

COMMON_PORTS = ",".join(str(p) for p in sorted(PORT_NAMES.keys()))


def scan_ports(ip: str) -> dict:
    """Fast TCP connect scan — no service probing, ~1s per host."""
    try:
        result = subprocess.run(
            ["nmap", "-T5", f"-p{COMMON_PORTS}", "--open", "-oX", "-", ip],
            capture_output=True, text=True, timeout=30
        )
        data = _parse_nmap_ports_xml(result.stdout)
        entry = data.get(ip, {"open_ports": [], "os_guess": ""})
        # Enrich port names from our lookup table
        for p in entry.get("open_ports", []):
            if not p.get("service") or p["service"] == str(p["port"]):
                p["service"] = PORT_NAMES.get(p["port"], f"port {p['port']}")
        return entry
    except FileNotFoundError:
        return {"error": "nmap not found"}
    except subprocess.TimeoutExpired:
        return {"error": "scan timed out"}
    except Exception as e:
        return {"error": str(e)}


def _parse_nmap_xml(xml_output: str) -> list[dict]:
    """Parse nmap XML output into device list."""
    devices = []
    try:
        root = ET.fromstring(xml_output)
        for host in root.findall("host"):
            # Status
            status_el = host.find("status")
            status = status_el.get("state", "unknown") if status_el is not None else "unknown"
            if status != "up":
                continue

            # IP and MAC
            ip = ""
            mac = ""
            vendor = ""
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr", "")
                elif addr.get("addrtype") == "mac":
                    mac = addr.get("addr", "")
                    vendor = addr.get("vendor", "")

            # Hostname
            hostname = ""
            hostnames_el = host.find("hostnames")
            if hostnames_el is not None:
                for hn in hostnames_el.findall("hostname"):
                    hostname = hn.get("name", "")
                    break

            # Ping time from rtt
            ping_ms = None
            times_el = host.find("times")
            if times_el is not None:
                srtt = times_el.get("srtt")
                if srtt:
                    try:
                        ping_ms = round(int(srtt) / 1000, 1)  # microseconds to ms
                    except ValueError:
                        pass

            devices.append({
                "ip": ip,
                "hostname": hostname or ip,
                "mac": mac or "N/A",
                "vendor": vendor or ("N/A (routed)" if not mac else "Unknown"),
                "ping_ms": ping_ms,
                "status": "up",
            })
    except ET.ParseError:
        pass

    # Sort by IP
    def ip_sort_key(d):
        try:
            return tuple(int(x) for x in d["ip"].split("."))
        except Exception:
            return (0, 0, 0, 0)

    devices.sort(key=ip_sort_key)
    return devices


def _parse_nmap_ports_xml(xml_output: str) -> dict:
    """Parse nmap port scan XML. Returns dict keyed by IP."""
    result = {}
    try:
        root = ET.fromstring(xml_output)
        for host in root.findall("host"):
            ip = ""
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr", "")
            if not ip:
                continue

            # Open ports
            open_ports = []
            ports_el = host.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue
                    portid = port_el.get("portid", "")
                    proto = port_el.get("protocol", "tcp")
                    service_el = port_el.find("service")
                    svc_name = ""
                    svc_product = ""
                    svc_version = ""
                    if service_el is not None:
                        svc_name = service_el.get("name", "")
                        svc_product = service_el.get("product", "")
                        svc_version = service_el.get("version", "")
                    label = svc_name or portid
                    if svc_product:
                        label += f" ({svc_product}"
                        if svc_version:
                            label += f" {svc_version}"
                        label += ")"
                    open_ports.append({
                        "port": int(portid),
                        "proto": proto,
                        "service": label,
                    })

            # OS detection
            os_guess = ""
            os_el = host.find("os")
            if os_el is not None:
                matches = os_el.findall("osmatch")
                if matches:
                    best = max(matches, key=lambda m: int(m.get("accuracy", "0")))
                    accuracy = best.get("accuracy", "")
                    name = best.get("name", "")
                    os_guess = f"{name} ({accuracy}%)" if accuracy else name

            result[ip] = {
                "open_ports": open_ports,
                "os_guess": os_guess or "Unknown",
            }
    except ET.ParseError:
        pass
    return result
