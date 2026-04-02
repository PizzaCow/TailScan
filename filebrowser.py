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
    smbclient.register_session(
        host,
        username=username or "guest",
        password=password or "",
        port=port,
    )


def smb_list_shares(host: str, username: str, password: str, port: int = 445) -> list:
    import smbclient
    _smb_conn(host, username, password, port)
    shares = []
    for share in smbclient.listshares(host):
        shares.append({"name": share, "type": "share"})
    return shares


def smb_list(host: str, username: str, password: str,
             share: str, path: str, port: int = 445) -> list:
    import smbclient
    import smbclient.path as smb_path
    _smb_conn(host, username, password, port)
    unc = f"\\\\{host}\\{share}"
    if path and path != "/":
        unc += "\\" + path.strip("/\\").replace("/", "\\")
    entries = []
    for entry in smbclient.scandir(unc):
        stat = entry.stat()
        entries.append({
            "name": entry.name,
            "type": "dir" if entry.is_dir() else "file",
            "size": stat.st_size if not entry.is_dir() else 0,
            "modified": stat.st_mtime,
        })
    return sorted(entries, key=lambda e: (e["type"] != "dir", e["name"].lower()))


def smb_download(host: str, username: str, password: str,
                 share: str, path: str, port: int = 445) -> bytes:
    import smbclient
    _smb_conn(host, username, password, port)
    unc = f"\\\\{host}\\{share}\\" + path.strip("/\\").replace("/", "\\")
    with smbclient.open_file(unc, mode="rb") as f:
        return f.read()


def smb_upload(host: str, username: str, password: str,
               share: str, path: str, data: bytes, port: int = 445) -> None:
    import smbclient
    _smb_conn(host, username, password, port)
    unc = f"\\\\{host}\\{share}\\" + path.strip("/\\").replace("/", "\\")
    with smbclient.open_file(unc, mode="wb") as f:
        f.write(data)


def smb_mkdir(host: str, username: str, password: str,
              share: str, path: str, port: int = 445) -> None:
    import smbclient
    _smb_conn(host, username, password, port)
    unc = f"\\\\{host}\\{share}\\" + path.strip("/\\").replace("/", "\\")
    smbclient.mkdir(unc)


def smb_delete(host: str, username: str, password: str,
               share: str, path: str, is_dir: bool, port: int = 445) -> None:
    import smbclient
    _smb_conn(host, username, password, port)
    unc = f"\\\\{host}\\{share}\\" + path.strip("/\\").replace("/", "\\")
    if is_dir:
        smbclient.rmdir(unc)
    else:
        smbclient.remove(unc)
