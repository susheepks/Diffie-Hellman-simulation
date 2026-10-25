"""
alice_server.py – Alice's TCP server for the DH network demo
=============================================================
Alice acts as the server:
  1. Listens on localhost:PORT for Bob.
  2. Generates p and g (or uses textbook preset).
  3. Sends {"type":"params","p":...,"g":...} to Bob.
  4. Sends {"type":"public","value":A} (her public key).
  5. Receives {"type":"public","value":B} from Bob.
  6. Computes shared secret, derives key, prints fingerprint.

Run:
    python network_demo/alice_server.py
    python network_demo/alice_server.py --preset      # textbook example
    python network_demo/alice_server.py --bits 64
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

# Force UTF-8 output on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Allow running from anywhere in the project
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dh.math_utils import generate_safe_prime, find_primitive_root
from dh.party import Party
from dh.kdf import derive_key, fingerprint
from dh.protocol import TEXTBOOK_P, TEXTBOOK_G, TEXTBOOK_A

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 65432


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def log(msg: str) -> None:
    print(f"[{ts()}] [ALICE] {msg}", flush=True)


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


def run_server(args: argparse.Namespace) -> None:
    # ── 1. Generate / select parameters ─────────────────────────────
    if args.preset:
        p, g = TEXTBOOK_P, TEXTBOOK_G
        alice_private = TEXTBOOK_A
        log(f"Using textbook preset: p={p}, g={g}, a={alice_private}")
    else:
        log(f"Generating {args.bits}-bit safe prime (this may take a moment)…")
        t0 = time.perf_counter()
        p, q = generate_safe_prime(args.bits)
        g = find_primitive_root(p, [2, q])
        log(f"Generated in {(time.perf_counter()-t0)*1000:.1f} ms: p={p}, g={g}")
        alice_private = None

    alice = Party("Alice", p, g, private_key=alice_private)
    log(f"Alice's private key a = {alice.private_key}  [KEEP SECRET]")
    log(f"Alice's public key  A = {alice.public_key}")

    # ── 2. Listen for Bob ────────────────────────────────────────────
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.host, args.port))
        srv.listen(1)
        log(f"Listening on {args.host}:{args.port} – waiting for Bob…")
        conn, addr = srv.accept()

    with conn:
        log(f"Bob connected from {addr}")

        # ── 3. Send parameters ───────────────────────────────────────
        send_json(conn, {"type": "params", "p": p, "g": g})
        log(f"Sent params → Bob: {{p={p}, g={g}}}")

        # ── 4. Send Alice's public key ───────────────────────────────
        send_json(conn, {"type": "public", "value": alice.public_key})
        log(f"Sent public key → Bob: A = {alice.public_key}")

        # ── 5. Receive Bob's public key ──────────────────────────────
        msg = recv_json(conn)
        if msg.get("type") != "public":
            log(f"Unexpected message: {msg}")
            return
        bob_public = msg["value"]
        log(f"Received Bob's public key: B = {bob_public}")

        # ── 6. Compute shared secret ─────────────────────────────────
        alice.receive_public_value(bob_public)
        s = alice.compute_shared_secret()
        key = derive_key(s)
        fp = fingerprint(key)

        log("─" * 50)
        log(f"Shared secret  s = B^a mod p = {bob_public}^{alice.private_key} mod {p}")
        log(f"               s = {s}")
        log(f"Derived key (SHA-256): {key.hex()}")
        log(f"Key fingerprint (first 8 bytes): {fp}")
        log("─" * 50)
        log("✅ Alice has successfully established a shared key with Bob!")

        # ── 7. Send confirmation ─────────────────────────────────────
        send_json(conn, {"type": "done", "fingerprint": fp})


def main() -> None:
    parser = argparse.ArgumentParser(description="Alice's DH server")
    parser.add_argument("--preset", action="store_true",
                        help="Use textbook preset (p=23, g=5)")
    parser.add_argument("--bits", type=int, default=64,
                        help="Bit size for prime generation (default: 64)")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Bind host")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Bind port")
    args = parser.parse_args()

    run_server(args)


if __name__ == "__main__":
    main()
