"""
network_demo/alice.py – Alice's Two-Laptop TCP Server
=====================================================
Alice acts as the TCP server:
  1. Binds to 0.0.0.0 on a configurable port (default: 5000).
  2. Prints all detected usable LAN IP addresses so Bob knows where to connect.
  3. Executes the 4-byte length-prefixed JSON protocol with Bob.
  4. Exchanges public keys, derives shared secret, verifies key fingerprint.
  5. Runs an encrypted chat demo over the established key.
  6. Loops to accept new incoming connections when a session ends.

Usage:
    python network_demo/alice.py --port 5000 --preset
    python network_demo/alice.py --port 5000 --bits 64
    python network_demo/alice.py --port 5000 --show-wire
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from pathlib import Path

# Force UTF-8 output on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Allow running from anywhere in project
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dh.math_utils import generate_safe_prime, find_primitive_root, mod_exp
from dh.party import Party
from dh.kdf import derive_key, xor_encrypt, xor_decrypt
from dh.protocol import TEXTBOOK_P, TEXTBOOK_G, TEXTBOOK_A
from dh.transport import get_lan_ips, send_msg, recv_msg, compute_key_fingerprint, ts


def log(msg: str) -> None:
    print(f"[{ts()}] [ALICE] {msg}", flush=True)


def print_banner(port: int, lan_ips: list[str]) -> None:
    print("\n" + "=" * 65)
    print("      🔐 ALICE – DIFFIE-HELLMAN KEY EXCHANGE SERVER (TCP)")
    print("=" * 65)
    print("  Status: Listening on all network interfaces (0.0.0.0)")
    print("  Port:   " + str(port))
    print("\n  👉 TELL BOB TO CONNECT USING:")
    if lan_ips:
        for ip in lan_ips:
            print(f"     \033[1;32mpython network_demo/bob.py --host {ip} --port {port}\033[0m")
    else:
        print(f"     \033[1;32mpython network_demo/bob.py --host <ALICE_IP> --port {port}\033[0m")
    print("\n  (Local test on same machine: python network_demo/bob.py --host 127.0.0.1 --port " + str(port) + ")")
    print("=" * 65 + "\n", flush=True)


def handle_session(conn: socket.socket, addr: tuple[str, int], args: argparse.Namespace) -> None:
    log(f"Connection accepted from {addr[0]}:{addr[1]}")

    # ── Step 1: Receive hello from Bob ───────────────────────────────────────
    hello = recv_msg(conn, show_wire=args.show_wire, actor="ALICE WIRE")
    if not hello or hello.get("type") != "hello":
        log(f"Protocol violation: expected 'hello', got {hello}")
        return
    client_name = hello.get("from", "Bob")
    log(f"Step 1: Received handshake greeting from '{client_name}'")

    # ── Step 2: Prepare & send parameters (p, g) ─────────────────────────────
    if args.preset:
        p, g = TEXTBOOK_P, TEXTBOOK_G
        alice_private = TEXTBOOK_A
        log(f"Step 2: Using textbook preset: p={p}, g={g}")
    else:
        log(f"Step 2: Generating {args.bits}-bit safe prime (p = 2q + 1)...")
        t0 = time.perf_counter()
        p, q = generate_safe_prime(args.bits)
        g = find_primitive_root(p, [2, q])
        elapsed = (time.perf_counter() - t0) * 1000
        log(f"Step 2: Safe prime generated in {elapsed:.1f} ms: p={p}, g={g}")
        alice_private = None

    send_msg(conn, {"type": "params", "p": p, "g": g},
             show_wire=args.show_wire, actor="ALICE WIRE")
    log(f"Sent public parameters to {client_name}: p={p}, g={g}")

    # ── Step 3: Pick private key independently ───────────────────────────────
    alice = Party("Alice", p, g, private_key=alice_private)
    if args.reveal:
        log(f"Step 3: Private key chosen: a = {alice.private_key}")
    else:
        log("Step 3: Private key chosen: a = [GENERATED - KEPT SECRET]")

    # ── Step 4: Exchange public values ───────────────────────────────────────
    # Send Alice's public key A = g^a mod p
    send_msg(conn, {"type": "public", "name": "Alice", "value": alice.public_key},
             show_wire=args.show_wire, actor="ALICE WIRE")
    log(f"Step 4: Sent public key to {client_name}: A = g^a mod p = {alice.public_key}")

    # Receive Bob's public key B
    bob_msg = recv_msg(conn, show_wire=args.show_wire, actor="ALICE WIRE")
    if not bob_msg or bob_msg.get("type") != "public":
        log(f"Protocol violation: expected 'public', got {bob_msg}")
        return
    bob_public = bob_msg["value"]
    log(f"Step 4: Received public key from {client_name}: B = {bob_public}")

    # ── Step 5: Compute shared secret locally ────────────────────────────────
    alice.receive_public_value(bob_public)
    s = alice.compute_shared_secret()
    formula_str = f"s = B^a mod p = {bob_public}^{alice.private_key} mod {p} = {s}"
    log(f"Step 5: Computed shared secret: {formula_str}")

    # ── Step 6: Key derivation and confirmation ──────────────────────────────
    key = derive_key(s)
    my_fp = compute_key_fingerprint(key)
    log(f"Step 6: Derived 256-bit AES/XOR key (SHA-256). Fingerprint: {my_fp}")

    # Send fingerprint confirmation to Bob
    send_msg(conn, {"type": "confirm", "fingerprint": my_fp},
             show_wire=args.show_wire, actor="ALICE WIRE")

    # Receive Bob's fingerprint confirmation
    confirm_msg = recv_msg(conn, show_wire=args.show_wire, actor="ALICE WIRE")
    if not confirm_msg or confirm_msg.get("type") != "confirm":
        log(f"Protocol violation: expected 'confirm', got {confirm_msg}")
        return

    bob_fp = confirm_msg.get("fingerprint")
    if bob_fp == my_fp:
        status_text = f"\033[1;32m✅ MATCH (Fingerprint: {my_fp})\033[0m"
        log(f"Step 6: Key Confirmation: {status_text}")
        print("\n" + "=" * 65)
        print(f"  🎉 SUCCESS: Both parties hold the same key! (Fingerprint: {my_fp})")
        print("=" * 65 + "\n", flush=True)
    else:
        status_text = f"\033[1;31m❌ MISMATCH (Alice: {my_fp}, Bob: {bob_fp})\033[0m"
        log(f"Step 6: Key Confirmation: {status_text}")
        print("\n" + "=" * 65)
        print("  ⚠️ ALERT: KEY MISMATCH! Possible tampering or MITM attack!")
        print("=" * 65 + "\n", flush=True)
        return

    # ── Step 7: Secure Chat Demo over established key ────────────────────────
    print("-----------------------------------------------------------------")
    print("  💬 SECURE CHAT DEMO (End-to-End Encrypted via DH Shared Key)")
    print("  Notice: Demonstration cipher (SHA-256 counter-mode keystream).")
    print("  Type a message and press Enter. Type 'exit' to quit chat session.")
    print("-----------------------------------------------------------------", flush=True)

    # Initial greeting message
    initial_text = "Hello Bob! Secure channel established over Diffie-Hellman."
    ct = xor_encrypt(key, initial_text.encode("utf-8"))
    send_msg(conn, {"type": "chat", "sender": "Alice", "ciphertext": ct.hex()},
             show_wire=args.show_wire, actor="ALICE WIRE")
    log(f"Sent initial encrypted message: \"{initial_text}\"")
    log(f"Ciphertext on wire: {ct.hex()}")

    if args.no_interactive or not sys.stdin.isatty():
        log("Non-interactive mode: Waiting for Bob's response...")
        resp = recv_msg(conn, show_wire=args.show_wire, actor="ALICE WIRE")
        if resp and resp.get("type") == "chat":
            pt = xor_decrypt(key, bytes.fromhex(resp["ciphertext"])).decode("utf-8", errors="replace")
            log(f"Bob replies: \"{pt}\"")
        return

    # Interactive chat loop
    while True:
        try:
            # Wait for Bob's incoming message
            incoming = recv_msg(conn, show_wire=args.show_wire, actor="ALICE WIRE")
            if not incoming or incoming.get("type") == "bye":
                log(f"{client_name} disconnected or ended chat.")
                break

            if incoming.get("type") == "chat":
                raw_hex = incoming.get("ciphertext", "")
                plain = xor_decrypt(key, bytes.fromhex(raw_hex)).decode("utf-8", errors="replace")
                print(f"\n📩 \033[1;34m[{client_name}]\033[0m: {plain}")
                print(f"   \033[90m(Ciphertext on wire: {raw_hex})\033[0m", flush=True)

            # Prompt Alice to type reply
            user_input = input("\n✍️  \033[1;32m[Alice]\033[0m > ").strip()
            if not user_input or user_input.lower() == "exit":
                send_msg(conn, {"type": "bye"}, show_wire=args.show_wire, actor="ALICE WIRE")
                log("Session ended by Alice.")
                break

            out_ct = xor_encrypt(key, user_input.encode("utf-8"))
            send_msg(conn, {"type": "chat", "sender": "Alice", "ciphertext": out_ct.hex()},
                     show_wire=args.show_wire, actor="ALICE WIRE")
            print(f"   \033[90m(Ciphertext sent: {out_ct.hex()})\033[0m", flush=True)

        except (ConnectionError, BrokenPipeError):
            log(f"Connection with {client_name} lost.")
            break
        except Exception as e:
            log(f"Chat error: {e}")
            break


def run_server(args: argparse.Namespace) -> None:
    lan_ips = get_lan_ips()
    print_banner(args.port, lan_ips)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("0.0.0.0", args.port))
        except OSError as e:
            print(f"\n❌ Port {args.port} cannot be bound ({e}).")
            print("   Try a different port, e.g.: python network_demo/alice.py --port 5001\n")
            sys.exit(1)

        srv.listen(5)
        log(f"Listening on 0.0.0.0:{args.port}... Waiting for Bob to connect.")

        while True:
            try:
                conn, addr = srv.accept()
                with conn:
                    handle_session(conn, addr, args)
                log("Session finished. Returning to listening state for next connection...")
                print("\n" + "-" * 65 + "\n")
                if args.once or args.no_interactive:
                    break
            except KeyboardInterrupt:
                log("Shutdown requested by user (Ctrl+C). Closing server.")
                break
            except Exception as e:
                log(f"Session error: {e}")
                time.sleep(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Alice – DH Key Exchange TCP Server")
    parser.add_argument("--port", type=int, default=5000, help="Listen port (default: 5000)")
    parser.add_argument("--preset", action="store_true", help="Use textbook preset (p=23, g=5, a=6)")
    parser.add_argument("--bits", type=int, default=64, help="Bit length for safe prime generation (default: 64)")
    parser.add_argument("--show-wire", action="store_true", help="Print raw wire JSON packets")
    parser.add_argument("--reveal", action="store_true", help="Display private key value in logs")
    parser.add_argument("--no-interactive", action="store_true", help="Non-interactive mode (for testing)")
    parser.add_argument("--once", action="store_true", help="Exit after handling one session")
    args = parser.parse_args()

    run_server(args)


if __name__ == "__main__":
    main()
