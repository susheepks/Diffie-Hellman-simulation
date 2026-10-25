"""
bob_client.py – Bob's TCP client for the DH network demo
=========================================================
Bob acts as the client:
  1. Connects to Alice's server on localhost:PORT.
  2. Receives p and g from Alice.
  3. Generates his private key b and public value B.
  4. Receives Alice's public key A.
  5. Sends B to Alice.
  6. Computes shared secret, derives key, prints fingerprint.

Run (after starting alice_server.py):
    python network_demo/bob_client.py
    python network_demo/bob_client.py --preset
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

# Force UTF-8 output on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dh.party import Party
from dh.kdf import derive_key, fingerprint
from dh.protocol import TEXTBOOK_B

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 65432


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def log(msg: str) -> None:
    print(f"[{ts()}] [BOB  ] {msg}", flush=True)


def send_json(conn: socket.socket, data: dict) -> None:
    payload = json.dumps(data).encode() + b"\n"
    conn.sendall(payload)


def recv_json(conn: socket.socket) -> dict:
    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        buf += chunk
    return json.loads(buf.split(b"\n")[0])


def run_client(args: argparse.Namespace) -> None:
    bob_private = TEXTBOOK_B if args.preset else None

    # ── 1. Connect to Alice ──────────────────────────────────────────
    log(f"Connecting to Alice at {args.host}:{args.port}…")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        retries = 0
        while retries < 10:
            try:
                sock.connect((args.host, args.port))
                break
            except ConnectionRefusedError:
                retries += 1
                log(f"Connection refused, retrying ({retries}/10)…")
                time.sleep(0.5)
        else:
            log("Could not connect to Alice. Is alice_server.py running?")
            sys.exit(1)

        log("Connected to Alice!")

        # ── 2. Receive parameters ────────────────────────────────────
        msg = recv_json(sock)
        if msg.get("type") != "params":
            log(f"Expected 'params', got: {msg}")
            return
        p, g = msg["p"], msg["g"]
        log(f"Received public params: p={p}, g={g}")

        # ── 3. Create Bob party ──────────────────────────────────────
        bob = Party("Bob", p, g, private_key=bob_private)
        log(f"Bob's private key b = {bob.private_key}  [KEEP SECRET]")
        log(f"Bob's public key  B = {bob.public_key}")

        # ── 4. Receive Alice's public key ────────────────────────────
        msg = recv_json(sock)
        if msg.get("type") != "public":
            log(f"Expected 'public', got: {msg}")
            return
        alice_public = msg["value"]
        log(f"Received Alice's public key: A = {alice_public}")

        # ── 5. Send Bob's public key ─────────────────────────────────
        send_json(sock, {"type": "public", "value": bob.public_key})
        log(f"Sent public key → Alice: B = {bob.public_key}")

        # ── 6. Compute shared secret ─────────────────────────────────
        bob.receive_public_value(alice_public)
        s = bob.compute_shared_secret()
        key = derive_key(s)
        fp = fingerprint(key)

        log("─" * 50)
        log(f"Shared secret  s = A^b mod p = {alice_public}^{bob.private_key} mod {p}")
        log(f"               s = {s}")
        log(f"Derived key (SHA-256): {key.hex()}")
        log(f"Key fingerprint (first 8 bytes): {fp}")
        log("─" * 50)
        log("✅ Bob has successfully established a shared key with Alice!")

        # ── 7. Receive confirmation ───────────────────────────────────
        msg = recv_json(sock)
        if msg.get("type") == "done":
            alice_fp = msg.get("fingerprint", "?")
            match = "✅ MATCH" if alice_fp == fp else "❌ MISMATCH"
            log(f"Alice's fingerprint: {alice_fp}")
            log(f"Bob's   fingerprint: {fp}")
            log(f"Fingerprint check: {match}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Bob's DH client")
    parser.add_argument("--preset", action="store_true",
                        help="Use textbook preset private key b=15")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Server host")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Server port")
    args = parser.parse_args()

    run_client(args)


if __name__ == "__main__":
    main()
