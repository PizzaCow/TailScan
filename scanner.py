"""LAN scanner using nmap + WAN/geo via ip-api.com."""

import subprocess
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


def detect_lan_subnet(exit_node_ip: str | None = None) -> str | None:
    """
    Detect the LAN subnet to scan.
    When using an exit node, the remote LAN is not in our routing table.
    We ask ip-api.com (via the exit node) — but for subnet detection we
    look at what Tailscale reports as the exit node's advertised routes,
    or fall back to a standard private-range guess based on WAN geo.

    Simpler approach: use the exit node peer's AllowedIPs from tailscale status
    to find any advertised private subnet, otherwise fall back to ip route.
    """
    # Try to get advertised subnet routes from tailscale status (exit node may advertise its LAN)
    if exit_node_ip:
        try:
            import subprocess, json
            result = subprocess.run(
                ["tailscale", "status", "--json"],
                capture_output=True, text=True, timeout=10
            )
            status = json.loads(result.stdout)
            for _, peer in status.get("Peer", {}).items():
                ips = peer.get("TailscaleIPs", [])
                if ips and ips[0] == exit_node_ip:
                    for route in peer.get("AllowedIPs", []):
                        # Private subnets only, not Tailscale ranges
                        if route.startswith("100.") or route == "0.0.0.0/0" or route == "::/0":
                            continue
                        if any(route.startswith(p) for p in ("10.", "172.", "192.168.")):
                            return route
        except Exception:
            pass

    # Fall back to local routing table — skip Docker/k8s/Tailscale ranges
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
            # Skip Docker/k8s bridge subnets (172.16-31 used by Docker by default)
            if subnet.startswith("172."):
                continue
            # Check the dev interface if present
            if "dev" in parts:
                dev_idx = parts.index("dev") + 1
                if dev_idx < len(parts):
                    dev = parts[dev_idx]
                    if any(dev.startswith(skip) for skip in SKIP_IFACES):
                        continue
            if "/" in subnet and any(subnet.startswith(p) for p in ("10.", "192.168.")):
                return subnet
        return None
    except Exception:
        return None


def scan_lan(subnet: str) -> list[dict]:
    """Fast ping sweep — discovers live hosts."""
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-T5", "--min-parallelism", "100", "--max-parallelism", "256",
             "-oX", "-", subnet],
            capture_output=True, text=True, timeout=60
        )
        return _parse_nmap_xml(result.stdout)
    except FileNotFoundError:
        return [{"error": "nmap not found — run start.sh to install"}]
    except subprocess.TimeoutExpired:
        return [{"error": "scan timed out"}]
    except Exception as e:
        return [{"error": str(e)}]


def scan_lan_stream(subnet: str) -> Generator[dict, None, None]:
    """
    Stream nmap ping sweep — emits one device per host as nmap finds it.
    nmap flushes each <host>...</host> block to XML stdout as it completes.
    """
    cmd = [
        "nmap", "-sn", "-T5",
        "--min-parallelism", "100", "--max-parallelism", "256",
        "-oX", "-", subnet
    ]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    except FileNotFoundError:
        yield {"error": "nmap not found — run start.sh to install"}
        return

    in_host = False
    host_buf = ""
    try:
        for line in proc.stdout:
            stripped = line.strip()
            if "<host " in stripped or stripped == "<host>":
                in_host = True
                host_buf = line
            elif in_host:
                host_buf += line
                if "</host>" in stripped:
                    in_host = False
                    try:
                        devices = _parse_nmap_xml(f"<nmaprun>{host_buf}</nmaprun>")
                        for d in devices:
                            yield d
                    except Exception:
                        pass
                    host_buf = ""
    except Exception as e:
        yield {"error": str(e)}
    finally:
        proc.wait()


# Ports worth scanning: ssh, ftp, telnet, smtp, http, https, smb, rdp, vnc,
# netbios, snmp, mysql, mssql, postgres, redis, mongodb, http-alt, plex,
# homeassistant, synology dsm, unifi, proxmox, esxi, ipmi
COMMON_PORTS = "21,22,23,25,80,443,445,3389,5900,5901,137,161,3306,1433,5432,6379,27017,8080,8443,32400,5000,8123,8888,8006,8001,623"


def scan_ports(ip: str) -> dict:
    """Scan common ports + OS detection on a single IP."""
    try:
        result = subprocess.run(
            ["nmap", "-T4", f"-p{COMMON_PORTS}", "-sV", "--version-intensity", "3",
             "-O", "--osscan-limit", "--send-ip", "-oX", "-", ip],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            result = subprocess.run(
                ["nmap", "-T4", f"-p{COMMON_PORTS}", "-sV", "--version-intensity", "3",
                 "-O", "--osscan-limit", "-oX", "-", ip],
                capture_output=True, text=True, timeout=60
            )
        data = _parse_nmap_ports_xml(result.stdout)
        return data.get(ip, {"open_ports": [], "os_guess": "Unknown"})
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
