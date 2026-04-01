"""
tailscale.py — Tailscale API + CLI wrapper
"""
import asyncio
import json
import os
import subprocess
from typing import Any

import httpx

TS_API_BASE = "https://api.tailscale.com/api/v2"
TS_TAILNET = os.getenv("TS_TAILNET", "-")  # '-' = default tailnet
TS_CLIENT_ID = os.getenv("TS_CLIENT_ID", "")
TS_CLIENT_SECRET = os.getenv("TS_CLIENT_SECRET", "")

# Token cache
_api_token: str | None = None


async def get_api_token() -> str:
    """Get a fresh OAuth token using client credentials flow."""
    global _api_token
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://login.tailscale.com/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": TS_CLIENT_ID,
                "client_secret": TS_CLIENT_SECRET,
            },
        )
        resp.raise_for_status()
        _api_token = resp.json()["access_token"]
    return _api_token


async def _api_get(path: str) -> Any:
    """Make authenticated GET to Tailscale API."""
    token = await get_api_token()
    url = f"{TS_API_BASE}{path}"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
        resp.raise_for_status()
        return resp.json()


async def list_devices() -> list[dict]:
    """Return all devices in the tailnet."""
    data = await _api_get(f"/tailnet/{TS_TAILNET}/devices")
    devices = data.get("devices", [])
    return devices


async def get_tailnet_status() -> dict:
    """
    Run `tailscale status --json` locally and return parsed data.
    This gives real-time peer info including exit node status.
    """
    proc = await asyncio.create_subprocess_exec(
        "tailscale", "status", "--json",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"tailscale status failed: {stderr.decode()}")
    return json.loads(stdout.decode())


def parse_peers(status: dict) -> list[dict]:
    """
    Parse tailscale status JSON into a list of peer dicts with:
    - id, hostname, dns_name, ip, is_exit_node, is_online, is_active_exit_node
    """
    peers = []
    self_node = status.get("Self", {})
    current_exit = status.get("CurrentExitNode", {})
    current_exit_id = current_exit.get("ID", "") if current_exit else ""

    # Include self
    self_entry = {
        "id": self_node.get("ID", ""),
        "hostname": self_node.get("HostName", ""),
        "dns_name": self_node.get("DNSName", "").rstrip("."),
        "ip": (self_node.get("TailscaleIPs") or [""])[0],
        "is_exit_node": False,
        "is_active_exit_node": False,
        "is_online": True,
        "is_self": True,
    }
    peers.append(self_entry)

    for peer_id, peer in (status.get("Peer") or {}).items():
        exit_node = peer.get("ExitNodeOption", False)
        ips = peer.get("TailscaleIPs") or []
        entry = {
            "id": peer.get("ID", peer_id),
            "hostname": peer.get("HostName", ""),
            "dns_name": peer.get("DNSName", "").rstrip("."),
            "ip": ips[0] if ips else "",
            "is_exit_node": exit_node,
            "is_active_exit_node": peer.get("ExitNode", False),
            "is_online": peer.get("Online", False),
            "is_self": False,
        }
        peers.append(entry)

    return peers


async def set_exit_node(ip: str) -> bool:
    """
    Set the active exit node to the given Tailscale IP.
    Pass empty string to disconnect.
    """
    if ip:
        cmd = ["tailscale", "set", f"--exit-node={ip}"]
    else:
        cmd = ["tailscale", "set", "--exit-node="]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        err = stderr.decode().strip()
        raise RuntimeError(f"tailscale set --exit-node failed: {err}")
    return True


async def get_active_exit_node(status: dict | None = None) -> dict | None:
    """Return the currently active exit node peer dict, or None."""
    if status is None:
        status = await get_tailnet_status()
    peers = parse_peers(status)
    for p in peers:
        if p["is_active_exit_node"]:
            return p
    return None
