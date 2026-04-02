"""
File browser backends for TailScan.
Provides list/download/upload/mkdir/delete for FTP and SMB.
"""

import ftplib
import io
import os
import logging
from typing import Optional

log = logging.getLogger("filebrowser")


# ─── FTP ─────────────────────────────────────────────────────────────────────

def ftp_connect(host: str, port: int, username: str, password: str) -> ftplib.FTP:
    ftp = ftplib.FTP()
    ftp.connect(host, port, timeout=10)
    ftp.login(username or "anonymous", password or "anonymous@")
    ftp.set_pasv(True)
    return ftp


def ftp_list(host: str, port: int, username: str, password: str, path: str) -> list:
    ftp = ftp_connect(host, port, username, password)
    try:
        entries = []
        lines = []
        ftp.retrlines(f"LIST {path}", lines.append)
        for line in lines:
            parts = line.split(None, 8)
            if len(parts) < 9:
                continue
            name = parts[8]
            is_dir = line.startswith("d")
            size = int(parts[4]) if not is_dir else 0
            modified = " ".join(parts[5:8])
            entries.append({
                "name": name,
                "type": "dir" if is_dir else "file",
                "size": size,
                "modified": modified,
            })
        return sorted(entries, key=lambda e: (e["type"] != "dir", e["name"].lower()))
    finally:
        try:
            ftp.quit()
        except Exception:
            pass


def ftp_download(host: str, port: int, username: str, password: str, path: str) -> bytes:
    ftp = ftp_connect(host, port, username, password)
    try:
        buf = io.BytesIO()
        ftp.retrbinary(f"RETR {path}", buf.write)
        return buf.getvalue()
    finally:
        try:
            ftp.quit()
        except Exception:
            pass


def ftp_upload(host: str, port: int, username: str, password: str,
               path: str, data: bytes) -> None:
    ftp = ftp_connect(host, port, username, password)
    try:
        ftp.storbinary(f"STOR {path}", io.BytesIO(data))
    finally:
        try:
            ftp.quit()
        except Exception:
            pass


def ftp_mkdir(host: str, port: int, username: str, password: str, path: str) -> None:
    ftp = ftp_connect(host, port, username, password)
    try:
        ftp.mkd(path)
    finally:
        try:
            ftp.quit()
        except Exception:
            pass


def ftp_delete(host: str, port: int, username: str, password: str,
               path: str, is_dir: bool) -> None:
    ftp = ftp_connect(host, port, username, password)
    try:
        if is_dir:
            ftp.rmd(path)
        else:
            ftp.delete(path)
    finally:
        try:
            ftp.quit()
        except Exception:
            pass


# ─── SMB ─────────────────────────────────────────────────────────────────────

def _smb_conn(host: str, username: str, password: str, port: int = 445):
    import smbclient
    # Always reset the session for this host so stale/bad sessions don't linger
    try:
        smbclient.delete_session(host, port=port)
    except Exception:
        pass
    kwargs = {
        "port": port,
        "auth_protocol": "ntlm",   # force NTLM, avoid Kerberos/SPNEGO failures
        "require_signing": False,   # many NAS/home devices don't enforce signing
    }
    if username:
        kwargs["username"] = username
        kwargs["password"] = password or ""
    else:
        # Guest/anonymous — pass empty strings explicitly
        kwargs["username"] = ""
        kwargs["password"] = ""
    smbclient.register_session(host, **kwargs)


def _smb_unc(host: str, share: str, path: str = "") -> str:
    """Build a UNC path. path should be relative to the share root."""
    if not share:
        raise ValueError("Share name is required for SMB access")
    base = f"\\\\{host}\\{share}"
    if path and path not in ("/", "\\", ""):
        rel = path.strip("/\\").replace("/", "\\")
        if rel:
            return base + "\\" + rel
    return base


def smb_list_shares(host: str, username: str, password: str, port: int = 445) -> list:
    """
    Enumerate SMB shares via smbclient CLI (net utility) or impacket if available.
    Falls back to asking the user to enter the share name manually.
    """
    # Try smbclient CLI (net/smbclient command line tool)
    import subprocess
    creds = []
    if username:
        creds += ["-U", f"{username}%{password}" if password else username]
    else:
        creds += ["-N"]  # no auth / guest
    try:
        result = subprocess.run(
            ["smbclient", "-L", f"//{host}", "--port", str(port)] + creds,
            capture_output=True, text=True, timeout=10
        )
        shares = []
        in_list = False
        for line in result.stdout.splitlines():
            if "Sharename" in line:
                in_list = True
                continue
            if in_list:
                if line.strip() == "" or line.startswith("\t-"):
                    continue
                if line.startswith("\t") or line.startswith("        "):
                    parts = line.split(None, 2)
                    if parts:
                        name = parts[0].strip()
                        stype = parts[1].strip() if len(parts) > 1 else ""
                        if stype not in ("IPC", "Printer"):
                            shares.append({"name": name, "type": "share"})
                else:
                    in_list = False
        if shares:
            return shares
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Try impacket if installed
    try:
        from impacket.smbconnection import SMBConnection
        smb = SMBConnection(host, host, sess_port=port)
        if username:
            smb.login(username, password or "")
        else:
            smb.login("", "")
        shares = []
        for share in smb.listShares():
            name = share["shi1_netname"].get_value().rstrip("\x00")
            stype = share["shi1_type"].get_value()
            if stype == 0:  # DISK
                shares.append({"name": name, "type": "share"})
        smb.logoff()
        return shares
    except ImportError:
        pass
    except Exception as e:
        log.debug("impacket share enum failed: %s", e)

    # Nothing worked — return empty so the UI falls back to manual entry
    return []


def smb_list(host: str, username: str, password: str,
             share: str, path: str, port: int = 445) -> list:
    import smbclient
    if not share:
        # No share specified — return share list as "directories"
        shares = smb_list_shares(host, username, password, port)
        if shares:
            return shares
        raise ValueError("Could not enumerate shares. Please enter a share name.")
    _smb_conn(host, username, password, port)
    unc = _smb_unc(host, share, path)
    entries = []
    for entry in smbclient.scandir(unc):
        try:
            stat = entry.stat()
            size = stat.st_size if not entry.is_dir() else 0
            mtime = stat.st_mtime
        except Exception:
            size, mtime = 0, 0
        entries.append({
            "name": entry.name,
            "type": "dir" if entry.is_dir() else "file",
            "size": size,
            "modified": mtime,
        })
    return sorted(entries, key=lambda e: (e["type"] != "dir", e["name"].lower()))


def smb_download(host: str, username: str, password: str,
                 share: str, path: str, port: int = 445) -> bytes:
    import smbclient
    _smb_conn(host, username, password, port)
    unc = _smb_unc(host, share, path)
    with smbclient.open_file(unc, mode="rb") as f:
        return f.read()


def smb_upload(host: str, username: str, password: str,
               share: str, path: str, data: bytes, port: int = 445) -> None:
    import smbclient
    _smb_conn(host, username, password, port)
    unc = _smb_unc(host, share, path)
    with smbclient.open_file(unc, mode="wb") as f:
        f.write(data)


def smb_mkdir(host: str, username: str, password: str,
              share: str, path: str, port: int = 445) -> None:
    import smbclient
    _smb_conn(host, username, password, port)
    unc = _smb_unc(host, share, path)
    smbclient.mkdir(unc)


def smb_delete(host: str, username: str, password: str,
               share: str, path: str, is_dir: bool, port: int = 445) -> None:
    import smbclient
    _smb_conn(host, username, password, port)
    unc = _smb_unc(host, share, path)
    if is_dir:
        smbclient.rmdir(unc)
    else:
        smbclient.remove(unc)
