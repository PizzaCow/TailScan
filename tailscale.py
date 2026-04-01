"""Tailscale API + CLI wrapper."""

import json
import subprocess
import httpx
import os

TAILSCALE_API_BASE = "https://api.tailscale.com/api/v2"


def get_access_token(client_id: str, client_secret: str, code: str, redirect_uri: str) -> dict:
    """Exchange OAuth code for access token."""
    resp = httpx.post(
        "https://api.tailscale.com/api/v2/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
        },
    )
    resp.raise_for_status()
    return resp.json()


def get_devices(tailnet: str, access_token: str) -> list[dict]:
    """Get all devices on the tailnet."""
    resp = httpx.get(
        f"{TAILSCALE_API_BASE}/tailnet/{tailnet}/devices",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    resp.raise_for_status()
    data = resp.json()
    return data.get("devices", [])


def get_local_status() -> dict:
    """Get local tailscale status."""
    result = subprocess.run(
        ["tailscale", "status", "--json"],
        capture_output=True, text=True, timeout=10
    )
    if result.returncode != 0:
        raise RuntimeError(f"tailscale status failed: {result.stderr}")
    return json.loads(result.stdout)


def set_exit_node(ip: str) -> bool:
    """Set exit node by IP. Pass empty string to disconnect."""
    import time
    if ip:
        result = subprocess.run(
            ["tailscale", "set", f"--exit-node={ip}"],
            capture_output=True, text=True, timeout=15
        )
    else:
        result = subprocess.run(
            ["tailscale", "set", "--exit-node="],
            capture_output=True, text=True, timeout=15
        )
    time.sleep(1)  # give tailscaled a moment to update status
    return result.returncode == 0


def get_current_exit_node() -> str | None:
    """Return current exit node IP, or None if not set."""
    try:
        status = get_local_status()
        for _, p in status.get("Peer", {}).items():
            if p.get("ExitNode"):
                ips = p.get("TailscaleIPs", [])
                return ips[0] if ips else None
        return None
    except Exception:
        return None


def get_exit_nodes_local() -> list[dict]:
    """Get exit nodes from local tailscale status."""
    try:
        status = get_local_status()
        nodes = []
        for node_id, peer in status.get("Peer", {}).items():
            if peer.get("ExitNodeOption"):
                ips = peer.get("TailscaleIPs", [])
                nodes.append({
                    "id": node_id,
                    "hostname": peer.get("HostName", "unknown"),
                    "dns_name": peer.get("DNSName", ""),
                    "ip": ips[0] if ips else "",
                    "online": peer.get("Online", False),
                    "active": peer.get("ExitNode", False),
                    "os": peer.get("OS", ""),
                })
        return nodes
    except Exception:
        return []


def get_all_peers_local() -> list[dict]:
    """Get all peers from local tailscale status."""
    try:
        status = get_local_status()
        peers = []
        # Add self
        s = status.get("Self", {})
        ips = s.get("TailscaleIPs", [])
        peers.append({
            "hostname": s.get("HostName", "self"),
            "dns_name": s.get("DNSName", ""),
            "ip": ips[0] if ips else "",
            "online": True,
            "exit_node": False,
            "exit_node_option": False,
            "os": s.get("OS", ""),
            "self": True,
        })
        for _, peer in status.get("Peer", {}).items():
            ips = peer.get("TailscaleIPs", [])
            peers.append({
                "hostname": peer.get("HostName", "unknown"),
                "dns_name": peer.get("DNSName", ""),
                "ip": ips[0] if ips else "",
                "online": peer.get("Online", False),
                "exit_node": peer.get("ExitNode", False),
                "exit_node_option": peer.get("ExitNodeOption", False),
                "os": peer.get("OS", ""),
                "self": False,
            })
        return peers
    except Exception:
        return []
