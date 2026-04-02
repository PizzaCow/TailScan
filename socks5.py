"""
Minimal asyncio SOCKS5 proxy server.

Supports:
  - SOCKS5 with username/password auth (RFC 1929)
  - SOCKS5 with no auth (when SOCKS5_PASSWORD is empty)
  - CONNECT command (TCP forwarding) — covers HTTP, HTTPS, WebSockets
  - IPv4, IPv6, and domain name targets

Usage: started as a background asyncio task from main.py
"""

import asyncio
import logging
import os
import struct
import socket

log = logging.getLogger("socks5")

SOCKS5_HOST = os.getenv("SOCKS5_HOST", "0.0.0.0")
SOCKS5_PORT = int(os.getenv("SOCKS5_PORT", "1080"))
SOCKS5_USER = os.getenv("SOCKS5_USER", "tailscan")
SOCKS5_PASSWORD = os.getenv("SOCKS5_PASSWORD", "")  # empty = no auth required

# SOCKS5 constants
VER = 0x05
NOAUTH = 0x00
USERPASS = 0x02
NO_ACCEPTABLE = 0xFF
CMD_CONNECT = 0x01
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04
REP_SUCCESS = 0x00
REP_FAILURE = 0x01
REP_REFUSED = 0x05
REP_CMD_UNSUPPORTED = 0x07
REP_ATYP_UNSUPPORTED = 0x08


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Forward bytes from reader to writer until EOF or error."""
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _send_reply(writer: asyncio.StreamWriter, rep: int,
                      atyp: int = ATYP_IPV4,
                      bind_addr: bytes = b"\x00\x00\x00\x00",
                      bind_port: int = 0):
    writer.write(bytes([VER, rep, 0x00, atyp]) + bind_addr + struct.pack("!H", bind_port))
    await writer.drain()


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    try:
        # ── Greeting ──────────────────────────────────────────────────────────
        header = await reader.readexactly(2)
        if header[0] != VER:
            writer.close()
            return
        nmethods = header[1]
        methods = set(await reader.readexactly(nmethods))

        use_auth = bool(SOCKS5_PASSWORD)

        if use_auth and USERPASS in methods:
            writer.write(bytes([VER, USERPASS]))
            await writer.drain()

            # ── Username/password sub-negotiation (RFC 1929) ──────────────────
            sub = await reader.readexactly(2)
            if sub[0] != 0x01:
                writer.write(bytes([0x01, 0x01]))
                await writer.drain()
                writer.close()
                return
            ulen = sub[1]
            username = (await reader.readexactly(ulen)).decode(errors="replace")
            plen = (await reader.readexactly(1))[0]
            password = (await reader.readexactly(plen)).decode(errors="replace")

            if username != SOCKS5_USER or password != SOCKS5_PASSWORD:
                log.warning("SOCKS5 auth failure from %s", peer)
                writer.write(bytes([0x01, 0x01]))
                await writer.drain()
                writer.close()
                return
            writer.write(bytes([0x01, 0x00]))  # auth success
            await writer.drain()

        elif NOAUTH in methods and not use_auth:
            writer.write(bytes([VER, NOAUTH]))
            await writer.drain()
        else:
            writer.write(bytes([VER, NO_ACCEPTABLE]))
            await writer.drain()
            writer.close()
            return

        # ── Request ───────────────────────────────────────────────────────────
        req = await reader.readexactly(4)
        if req[0] != VER:
            await _send_reply(writer, REP_FAILURE)
            writer.close()
            return
        cmd = req[1]
        atyp = req[3]

        if cmd != CMD_CONNECT:
            await _send_reply(writer, REP_CMD_UNSUPPORTED)
            writer.close()
            return

        if atyp == ATYP_IPV4:
            raw = await reader.readexactly(4)
            target_host = socket.inet_ntop(socket.AF_INET, raw)
            bind_atyp, bind_addr = ATYP_IPV4, raw
        elif atyp == ATYP_IPV6:
            raw = await reader.readexactly(16)
            target_host = socket.inet_ntop(socket.AF_INET6, raw)
            bind_atyp, bind_addr = ATYP_IPV6, raw
        elif atyp == ATYP_DOMAIN:
            dlen = (await reader.readexactly(1))[0]
            target_host = (await reader.readexactly(dlen)).decode()
            bind_atyp, bind_addr = ATYP_IPV4, b"\x00\x00\x00\x00"
        else:
            await _send_reply(writer, REP_ATYP_UNSUPPORTED)
            writer.close()
            return

        port_bytes = await reader.readexactly(2)
        target_port = struct.unpack("!H", port_bytes)[0]

        # ── Connect to target ─────────────────────────────────────────────────
        try:
            t_reader, t_writer = await asyncio.wait_for(
                asyncio.open_connection(target_host, target_port),
                timeout=10.0,
            )
        except (OSError, asyncio.TimeoutError) as e:
            log.debug("SOCKS5 connect failed %s:%s — %s", target_host, target_port, e)
            await _send_reply(writer, REP_REFUSED)
            writer.close()
            return

        log.debug("SOCKS5 %s CONNECT %s:%s", peer, target_host, target_port)
        await _send_reply(writer, REP_SUCCESS, bind_atyp, bind_addr, target_port)

        # ── Bidirectional pipe ────────────────────────────────────────────────
        await asyncio.gather(
            _pipe(reader, t_writer),
            _pipe(t_reader, writer),
            return_exceptions=True,
        )

    except asyncio.IncompleteReadError:
        pass
    except Exception as e:
        log.debug("SOCKS5 handler error from %s: %s", peer, e)
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def start_socks5_server():
    server = await asyncio.start_server(
        handle_client, SOCKS5_HOST, SOCKS5_PORT
    )
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    auth_mode = "user/pass" if SOCKS5_PASSWORD else "no auth"
    log.info("SOCKS5 proxy listening on %s (%s)", addrs, auth_mode)
    async with server:
        await server.serve_forever()
