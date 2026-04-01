"""
scanner.py — nmap LAN scanner + geolocation via ip-api.com
"""
import asyncio
import ipaddress
import re
import subprocess
import xml.etree.ElementTree as ET
from typing import Any

import httpx


async def get_wan_geo() -> dict:
    """
    Call ip-api.com/json to get current WAN IP + geolocation.
    Returns dict with: ip, city, regionName, country, lat, lon, isp, org
    """
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get("http://ip-api.com/json")
            resp.raise_for_status()
            data = resp.json()
            return {
                "ip": data.get("query", ""),
                "city": data.get("city", ""),
                "region": data.get("regionName", ""),
                "country": data.get("country", ""),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0),
                "isp": data.get("isp", ""),
                "org": data.get("org", ""),
                "timezone": data.get("timezone", ""),
            }
    except Exception as e:
        return {"error": str(e), "ip": "", "city": "", "region": "", "country": ""}


def detect_lan_subnet() -> str | None:
    """
    Detect the LAN subnet that the exit node is routing us through.
    We look for default route and the interface it uses, then find
    the subnet assigned to that interface — excluding Tailscale (100.x) ranges.
    """
    try:
        # Get routing table
        result = subprocess.run(
            ["ip", "route", "show"],
            capture_output=True, text=True, timeout=5
        )
        routes = result.stdout

        # Find default route interface
        default_iface = None
        for line in routes.splitlines():
            if line.startswith("default"):
                parts = line.split()
                if "dev" in parts:
                    idx = parts.index("dev")
                    default_iface = parts[idx + 1]
                break

        if not default_iface:
            return None

        # Get IP addresses for that interface
        result2 = subprocess.run(
            ["ip", "addr", "show", default_iface],
            capture_output=True, text=True, timeout=5
        )
        addr_output = result2.stdout

        # Find inet addresses (not inet6, not Tailscale 100.x)
        for line in addr_output.splitlines():
            line = line.strip()
            if line.startswith("inet ") and "inet6" not in line:
                # e.g. "inet 192.168.1.100/24 brd ..."
                match = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", line)
                if match:
                    cidr = match.group(1)
                    network = ipaddress.ip_interface(cidr).network
                    ip_str = str(network.network_address)
                    # Skip Tailscale IPs (100.64.0.0/10) and loopback
                    if ip_str.startswith("100.") or ip_str.startswith("127."):
                        continue
                    return str(network)

        # Fallback: look for non-default routes that might be the LAN
        for line in routes.splitlines():
            parts = line.split()
            if parts and "/" in parts[0] and not parts[0].startswith("100."):
                try:
                    net = ipaddress.ip_network(parts[0], strict=False)
                    if not net.is_loopback and not net.is_link_local:
                        return str(net)
                except ValueError:
                    continue

    except Exception as e:
        pass

    return None


async def scan_lan(subnet: str) -> list[dict]:
    """
    Run nmap ping sweep on the subnet and return list of hosts.
    Uses -sn (no port scan) --send-ip (IP-based ping, no ARP — works over routed exit nodes).
    Parses XML output for clean results.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sn", "--send-ip", "-oX", "-", subnet,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode not in (0, 1):  # nmap returns 1 when no hosts up
            raise RuntimeError(f"nmap failed (rc={proc.returncode}): {stderr.decode()}")

        return _parse_nmap_xml(stdout.decode())

    except FileNotFoundError:
        raise RuntimeError("nmap is not installed. Run start.sh to install it.")
    except Exception as e:
        raise RuntimeError(f"Scan error: {str(e)}")


def _parse_nmap_xml(xml_str: str) -> list[dict]:
    """Parse nmap XML output into a list of host dicts."""
    hosts = []
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return hosts

    for host in root.findall("host"):
        status_elem = host.find("status")
        if status_elem is None:
            continue
        state = status_elem.get("state", "unknown")

        # Get IP address
        ip = ""
        hostname = ""
        mac = ""
        vendor = ""

        for addr in host.findall("address"):
            addr_type = addr.get("addrtype", "")
            if addr_type == "ipv4":
                ip = addr.get("addr", "")
            elif addr_type == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")

        # Get hostname
        hostnames = host.find("hostnames")
        if hostnames is not None:
            for hn in hostnames.findall("hostname"):
                if hn.get("type") in ("PTR", "user"):
                    hostname = hn.get("name", "")
                    break

        # Get round-trip time (ping ms)
        ping_ms = None
        times = host.find("times")
        if times is not None:
            rtt = times.get("rttvar")
            srtt = times.get("srtt")
            if srtt:
                try:
                    ping_ms = round(int(srtt) / 1000, 1)  # microseconds -> ms
                except ValueError:
                    pass

        if ip:
            hosts.append({
                "ip": ip,
                "hostname": hostname or "",
                "ping_ms": ping_ms,
                "mac": mac or "N/A",
                "vendor": vendor or ("N/A (routed)" if not mac else "Unknown"),
                "status": state,
            })

    # Sort by IP
    try:
        hosts.sort(key=lambda h: ipaddress.ip_address(h["ip"]))
    except Exception:
        pass

    return hosts
