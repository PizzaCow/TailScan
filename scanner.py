"""LAN scanner using nmap + WAN/geo via ip-api.com."""

import subprocess
import re
import httpx
import time
import xml.etree.ElementTree as ET


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


def detect_lan_subnet() -> str | None:
    """Auto-detect the LAN subnet from the routing table."""
    try:
        result = subprocess.run(
            ["ip", "route"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            # Look for default route via an exit node, or just grab non-tailscale, non-default subnets
            # Skip Tailscale ranges (100.64.0.0/10) and loopback
            parts = line.split()
            if not parts:
                continue
            subnet = parts[0]
            if subnet == "default":
                continue
            # Skip tailscale subnet
            if subnet.startswith("100."):
                continue
            if subnet.startswith("127."):
                continue
            # Must be a real subnet (contains /)
            if "/" in subnet:
                return subnet
        return None
    except Exception:
        return None


def scan_lan(subnet: str) -> list[dict]:
    """Run nmap ping sweep on subnet. Returns list of discovered devices."""
    try:
        result = subprocess.run(
            ["nmap", "-sn", "--send-ip", "-oX", "-", subnet],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            # Fallback without --send-ip
            result = subprocess.run(
                ["nmap", "-sn", "-oX", "-", subnet],
                capture_output=True, text=True, timeout=120
            )

        return _parse_nmap_xml(result.stdout)
    except FileNotFoundError:
        return [{"error": "nmap not found — run start.sh to install"}]
    except subprocess.TimeoutExpired:
        return [{"error": "scan timed out"}]
    except Exception as e:
        return [{"error": str(e)}]


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
