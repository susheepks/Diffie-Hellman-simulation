"""
relay_server.py – Lightweight HTTP Message Relay for DH Web UI Demo
====================================================================
Runs on Alice's machine (Laptop 1). Both Alice's and Bob's Streamlit
browsers POST encrypted messages here and GET pending messages from here.

This is the simplest possible mailbox: no threads, no frameworks, no DB.
Uses Python's built-in http.server + json.

Run:
    python network_demo/relay_server.py --port 6000

Endpoints:
    POST /send        body: {"from":"alice","ciphertext":"hex..."}
    GET  /messages/alice    -> JSON list of pending messages FOR alice
    GET  /messages/bob      -> JSON list of pending messages FOR bob
    GET  /status            -> health check + message counts
    POST /clear             -> clear all mailboxes (reset demo)
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Lock
from urllib.parse import urlparse

# ── Global mailboxes & handshake state (thread-safe with lock) ───────────────
_lock = Lock()
_mailbox: dict[str, list[dict]] = {"alice": [], "bob": []}
_handshake: dict[str, Optional[dict]] = {"alice": None, "bob": None}
_start_time = time.time()


def _get_lan_ips() -> list[str]:
    try:
        from dh.transport import get_lan_ips
        return get_lan_ips()
    except Exception:
        return []


class RelayHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        ts = time.strftime("%H:%M:%S")
        sys.stdout.write(f"[{ts}] RELAY {fmt % args}\n")
        sys.stdout.flush()

    def _send_json(self, code: int, data: object) -> None:
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/")

        if path == "/status":
            with _lock:
                self._send_json(200, {
                    "status": "ok",
                    "uptime_seconds": round(time.time() - _start_time, 1),
                    "pending_for_alice": len(_mailbox["alice"]),
                    "pending_for_bob": len(_mailbox["bob"]),
                    "handshake_alice": _handshake["alice"] is not None,
                    "handshake_bob": _handshake["bob"] is not None,
                })
            return

        if path == "/handshake":
            with _lock:
                self._send_json(200, {
                    "alice": _handshake["alice"],
                    "bob": _handshake["bob"],
                })
            return

        if path.startswith("/messages/"):
            recipient = path.split("/")[-1].lower()
            if recipient not in _mailbox:
                self._send_json(404, {"error": f"Unknown recipient: {recipient}"})
                return
            with _lock:
                msgs = list(_mailbox[recipient])
                _mailbox[recipient] = []          # drain – messages consumed
            self._send_json(200, {"messages": msgs})
            return

        self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")

        if path == "/handshake":
            body = self._read_body()
            party = body.get("party", "").lower()
            data = body.get("data", {})
            if party not in ("alice", "bob"):
                self._send_json(400, {"error": "party must be 'alice' or 'bob'"})
                return
            with _lock:
                _handshake[party] = data
            self.log_message(f"[HANDSHAKE] {party.upper()} published public key")
            self._send_json(200, {"ok": True, "party": party})
            return

        if path == "/send":
            body = self._read_body()
            sender = body.get("from", "").lower()
            ciphertext = body.get("ciphertext", "")
            recipient = "bob" if sender == "alice" else "alice"

            if not ciphertext:
                self._send_json(400, {"error": "Missing ciphertext"})
                return
            if sender not in ("alice", "bob"):
                self._send_json(400, {"error": "from must be 'alice' or 'bob'"})
                return

            msg = {
                "from": sender,
                "ciphertext": ciphertext,
                "ts": time.strftime("%H:%M:%S"),
            }
            with _lock:
                _mailbox[recipient].append(msg)

            self.log_message(
                f"[{sender.upper()} -> {recipient.upper()}] ciphertext({len(ciphertext)//2}B)"
            )
            self._send_json(200, {"ok": True, "queued_for": recipient})
            return

        if path in ("/clear", "/handshake/reset"):
            with _lock:
                _mailbox["alice"] = []
                _mailbox["bob"] = []
                _handshake["alice"] = None
                _handshake["bob"] = None
            self._send_json(200, {"ok": True, "message": "All mailboxes and handshake cleared"})
            return

        self._send_json(404, {"error": "Not found"})


def main():
    parser = argparse.ArgumentParser(description="DH Demo Message Relay Server")
    parser.add_argument("--port", type=int, default=6000, help="Relay server port (default 6000)")
    args = parser.parse_args()

    lan_ips = _get_lan_ips()

    print("\n" + "=" * 65)
    print("  DIFFIE-HELLMAN DEMO - MESSAGE RELAY SERVER")
    print("=" * 65)
    print(f"  Relay listening on 0.0.0.0:{args.port}")
    print()
    if lan_ips:
        for ip in lan_ips:
            print(f"  Alice UI (Laptop 1) relay URL: http://{ip}:{args.port}")
            print(f"  Bob UI   (Laptop 2) relay URL: http://{ip}:{args.port}")
    print()
    print("  In the Streamlit Network Demo tab, set Relay URL on BOTH")
    print(f"  laptops to: http://{lan_ips[0] if lan_ips else '172.20.10.3'}:{args.port}")
    print("=" * 65 + "\n")
    sys.stdout.flush()

    server = HTTPServer(("0.0.0.0", args.port), RelayHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[RELAY] Shutdown requested. Bye!")


if __name__ == "__main__":
    main()

