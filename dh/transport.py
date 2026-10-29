"""
transport.py – Robust Length-Prefixed JSON Transport over TCP
=============================================================
Provides length-prefixed message framing (4-byte big-endian header),
socket error handling, LAN IP discovery, and wire logging.
"""

from __future__ import annotations

import hashlib
import json
import socket
import struct
import sys
from datetime import datetime
from typing import Any, Optional


def is_virtual_ip(ip: str) -> bool:
    """Check if an IPv4 address belongs to a known virtual switch (WSL, Hyper-V, Docker, VirtualBox)."""
    parts = ip.split(".")
    if len(parts) == 4:
        if parts[0] == "172" and parts[1] in ("17", "18", "19", "28", "29", "30", "31"):
            return True
        if parts[0] == "192" and parts[1] == "168" and parts[2] == "56":
            return True
    return False


def get_lan_ips() -> list[str]:
    """Return all usable IPv4 LAN addresses (excluding 127.0.0.1 and link-local).
    The physical Wi-Fi / Hotspot IP is always prioritized at index 0.
    """
    primary_ip: Optional[str] = None
    ips = set()

    # Strategy 1: Outbound UDP route check
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if not ip.startswith("127.") and not ip.startswith("169.254."):
                primary_ip = ip
                ips.add(ip)
    except Exception:
        pass

    # Strategy 2: Hostname resolution
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and not ip.startswith("169.254."):
                ips.add(ip)
    except Exception:
        pass

    # Separate physical Wi-Fi IPs from virtual Hyper-V/WSL switch IPs
    physical_ips = [ip for ip in ips if not is_virtual_ip(ip)]
    virtual_ips = [ip for ip in ips if is_virtual_ip(ip)]

    # If primary_ip was physical, put it first
    if primary_ip and primary_ip in physical_ips:
        physical_ips.remove(primary_ip)
        result = [primary_ip] + sorted(physical_ips) + sorted(virtual_ips)
    elif physical_ips:
        result = sorted(physical_ips) + sorted(virtual_ips)
    else:
        result = sorted(virtual_ips)

    return result


def recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """Read exactly `num_bytes` from `sock`.

    Returns
    -------
    bytes
        The received bytes.

    Raises
    ------
    ConnectionError
        If socket closes before all requested bytes are read.
    """
    buf = bytearray()
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            if len(buf) == 0:
                return b""  # Clean EOF at message boundary
            raise ConnectionError(
                f"Connection closed prematurely: expected {num_bytes} bytes, got {len(buf)}"
            )
        buf.extend(chunk)
    return bytes(buf)


def send_msg(sock: socket.socket, data: dict[str, Any], show_wire: bool = False,
             actor: str = "WIRE OUT") -> bytes:
    """Send length-prefixed JSON message over `sock`.

    Header: 4-byte big-endian unsigned int indicating payload length.
    Payload: UTF-8 encoded JSON string.
    """
    payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
    header = struct.pack(">I", len(payload))
    packet = header + payload
    sock.sendall(packet)

    if show_wire:
        raw_str = payload.decode("utf-8", errors="replace")
        print(f"  \033[90m[{actor}] > {raw_str}\033[0m", flush=True)

    return packet


def recv_msg(sock: socket.socket, show_wire: bool = False,
             actor: str = "WIRE IN ") -> Optional[dict[str, Any]]:
    """Receive length-prefixed JSON message from `sock`.

    Returns None if connection was cleanly closed at a message boundary.
    """
    header = recv_exact(sock, 4)
    if not header:
        return None  # Peer disconnected cleanly

    length = struct.unpack(">I", header)[0]
    if length > 10 * 1024 * 1024:  # 10 MB sanity check
        raise ValueError(f"Message payload size exceeds limit ({length} bytes)")

    payload = recv_exact(sock, length)
    if len(payload) < length:
        raise ConnectionError("Socket closed before full payload was received")

    if show_wire:
        raw_str = payload.decode("utf-8", errors="replace")
        print(f"  \033[90m[{actor}] < {raw_str}\033[0m", flush=True)

    return json.loads(payload.decode("utf-8"))


def compute_key_fingerprint(key: bytes) -> str:
    """Return the first 8 hex characters of SHA-256(key).

    As required by protocol confirmation step: first 8 hex chars of SHA-256(key).
    """
    return hashlib.sha256(key).hexdigest()[:8]


def ts() -> str:
    """Return current timestamp with millisecond precision."""
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]
