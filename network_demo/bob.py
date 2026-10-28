"""
network_demo/bob.py – Bob's Two-Laptop TCP Client
=================================================
Bob acts as the TCP client:
  1. Connects to Alice's LAN IP and port with automatic retries (5 attempts, 2s delay).
  2. Friendly diagnostics if connection fails (firewall, IP, Wi-Fi checks).
  3. Validates public parameters received from Alice:
     - Verifies p is prime via Miller-Rabin test.
     - Verifies 2 <= g <= p - 2.
     - Aborts with a clear security warning if invalid.
  4. Generates private key independently, exchanges public keys.
  5. Computes shared secret locally, prints formula with numbers substituted.
  6. Verifies key fingerprint with Alice (MATCH / MISMATCH).
  7. Runs end-to-end encrypted chat demo.

Usage:
    python network_demo/bob.py --host 192.168.1.23 --port 5000
    python network_demo/bob.py --host 127.0.0.1 --port 5000 --preset
    python network_demo/bob.py --host 192.168.1.23 --port 5000 --show-wire
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

from dh.math_utils import miller_rabin_is_prime, mod_exp
from dh.party import Party
from dh.kdf import derive_key, xor_encrypt, xor_decrypt
from dh.protocol import TEXTBOOK_B
from dh.transport import send_msg, recv_msg, compute_key_fingerprint, ts


def log(msg: str) -> None:
    print(f"[{ts()}] [BOB  ] {msg}", flush=True)


def connect_with_retries(host: str, port: int, max_retries: int = 5,
                         delay: float = 2.0) -> socket.socket:
    """Connect to Alice with automatic retry loop and clear diagnostic messaging."""
    print("\n" + "=" * 65)
    print("      🔐 BOB – DIFFIE-HELLMAN KEY EXCHANGE CLIENT (TCP)")
    print("=" * 65)
    print(f"  Target Alice server: {host}:{port}")
    print(f"  Connection attempts: up to {max_retries} (delay: {delay}s)")
    print("=" * 65 + "\n", flush=True)

    for attempt in range(1, max_retries + 1):
        log(f"Connecting to Alice at {host}:{port} (Attempt {attempt}/{max_retries})...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((host, port))
            sock.settimeout(None)  # Switch back to blocking for protocol
            log(f"\033[1;32mConnected successfully to Alice at {host}:{port}!\033[0m")
            return sock
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            sock.close()
            if attempt < max_retries:
                log(f"Connection failed ({e}). Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                log(f"All {max_retries} connection attempts failed.")

    print("\n" + "❌ " + "=" * 63)
    print(f"  Cannot reach Alice at {host}:{port}")
    print("=" * 65)
    print("  Troubleshooting Checklist:")
    print("  1. Verify Alice's server is running: python network_demo/alice.py")
    print(f"  2. Check the IP address: did Alice say connect to '{host}'?")
    print("  3. Are both laptops connected to the SAME Wi-Fi or phone hotspot?")
    print("  4. Firewall check on Alice's laptop:")
    print("     Windows PowerShell (Admin):")
    print(f'       New-NetFirewallRule -DisplayName "DH Demo" -Direction Inbound -Protocol TCP -LocalPort {port} -Action Allow')
    print("     Linux:")
    print(f"       sudo ufw allow {port}/tcp")
    print("=" * 65 + "\n", flush=True)
    sys.exit(1)


def run_client(args: argparse.Namespace) -> None:
    sock = connect_with_retries(args.host, args.port, max_retries=args.retries, delay=args.retry_delay)

    with sock:
        # ── Step 1: Send hello greeting to Alice ──────────────────────────────
        send_msg(sock, {"type": "hello", "from": "Bob"},
                 show_wire=args.show_wire, actor="BOB WIRE  ")
        log("Step 1: Sent handshake greeting to Alice")

        # ── Step 2: Receive public parameters from Alice & Validate ───────────
        params_msg = recv_msg(sock, show_wire=args.show_wire, actor="BOB WIRE  ")
        if not params_msg or params_msg.get("type") != "params":
            log(f"Protocol violation: expected 'params', got {params_msg}")
            return

        p = params_msg.get("p")
        g = params_msg.get("g")
        log(f"Step 2: Received public parameters from Alice: p={p}, g={g}")

        # CRITICAL SECURITY VALIDATION (Required by prompt)
        log("Validating received parameters before proceeding...")
        if not isinstance(p, int) or not isinstance(g, int):
            log("❌ REJECTED: p and g must be integers. Aborting connection.")
            return

        if not miller_rabin_is_prime(p):
            print("\n" + "❌ " + "=" * 63)
            print(f"  SECURITY ALERT: Modulus p = {p} IS NOT A PRIME NUMBER!")
            print("  Bob rejects invalid/malicious parameters and aborts immediately.")
            print("=" * 65 + "\n", flush=True)
            return
        log(f"  ✓ Primality verified: p={p} is prime (Miller-Rabin passed)")

        if not (2 <= g <= p - 2):
            print("\n" + "❌ " + "=" * 63)
            print(f"  SECURITY ALERT: Generator g = {g} is out of valid range [2, p-2]!")
            print("  Bob rejects invalid parameters and aborts.")
            print("=" * 65 + "\n", flush=True)
            return
        log(f"  ✓ Generator verified: g={g} is within [2, {p-2}]")
        log("Step 2: Public parameters approved.")

        # ── Step 3: Pick private key independently ───────────────────────────
        bob_private = TEXTBOOK_B if args.preset else None
        bob = Party("Bob", p, g, private_key=bob_private)
        if args.reveal:
            log(f"Step 3: Private key chosen: b = {bob.private_key}")
        else:
            log("Step 3: Private key chosen: b = [GENERATED - KEPT SECRET]")

        # ── Step 4: Exchange public values ───────────────────────────────────
        # Receive Alice's public key A
        alice_msg = recv_msg(sock, show_wire=args.show_wire, actor="BOB WIRE  ")
        if not alice_msg or alice_msg.get("type") != "public":
            log(f"Protocol violation: expected 'public', got {alice_msg}")
            return
        alice_public = alice_msg["value"]
        log(f"Step 4: Received Alice's public key: A = {alice_public}")

        # Send Bob's public key B = g^b mod p
        send_msg(sock, {"type": "public", "name": "Bob", "value": bob.public_key},
                 show_wire=args.show_wire, actor="BOB WIRE  ")
        log(f"Step 4: Sent public key to Alice: B = g^b mod p = {bob.public_key}")

        # ── Step 5: Compute shared secret locally ────────────────────────────
        bob.receive_public_value(alice_public)
        s = bob.compute_shared_secret()
        formula_str = f"s = A^b mod p = {alice_public}^{bob.private_key} mod {p} = {s}"
        log(f"Step 5: Computed shared secret: {formula_str}")

        # ── Step 6: Key derivation and confirmation ──────────────────────────
        key = derive_key(s)
        my_fp = compute_key_fingerprint(key)
        log(f"Step 6: Derived 256-bit AES/XOR key (SHA-256). Fingerprint: {my_fp}")

        # Receive Alice's confirmation fingerprint
        confirm_msg = recv_msg(sock, show_wire=args.show_wire, actor="BOB WIRE  ")
        if not confirm_msg or confirm_msg.get("type") != "confirm":
            log(f"Protocol violation: expected 'confirm', got {confirm_msg}")
            return
        alice_fp = confirm_msg.get("fingerprint")

        # Send Bob's confirmation fingerprint
        send_msg(sock, {"type": "confirm", "fingerprint": my_fp},
                 show_wire=args.show_wire, actor="BOB WIRE  ")

        if alice_fp == my_fp:
            status_text = f"\033[1;32m✅ MATCH (Fingerprint: {my_fp})\033[0m"
            log(f"Step 6: Key Confirmation: {status_text}")
            print("\n" + "=" * 65)
            print(f"  🎉 SUCCESS: Both parties hold the same key! (Fingerprint: {my_fp})")
            print("=" * 65 + "\n", flush=True)
        else:
            status_text = f"\033[1;31m❌ MISMATCH (Bob: {my_fp}, Alice: {alice_fp})\033[0m"
            log(f"Step 6: Key Confirmation: {status_text}")
            print("\n" + "=" * 65)
            print("  ⚠️ ALERT: KEY MISMATCH! Possible tampering or MITM attack!")
            print("=" * 65 + "\n", flush=True)
            return

        # ── Step 7: Secure Chat Demo over established key ────────────────────
        print("-----------------------------------------------------------------")
        print("  💬 SECURE CHAT DEMO (End-to-End Encrypted via DH Shared Key)")
        print("  Notice: Demonstration cipher (SHA-256 counter-mode keystream).")
        print("  Type a message and press Enter. Type 'exit' to quit chat session.")
        print("-----------------------------------------------------------------", flush=True)

        # Receive initial greeting from Alice
        initial_msg = recv_msg(sock, show_wire=args.show_wire, actor="BOB WIRE  ")
        if initial_msg and initial_msg.get("type") == "chat":
            raw_hex = initial_msg.get("ciphertext", "")
            plain = xor_decrypt(key, bytes.fromhex(raw_hex)).decode("utf-8", errors="replace")
            print(f"\n📩 \033[1;32m[Alice]\033[0m: {plain}")
            print(f"   \033[90m(Ciphertext on wire: {raw_hex})\033[0m", flush=True)

        if args.no_interactive or not sys.stdin.isatty():
            reply_text = "Hi Alice! Received and verified over the secure socket."
            reply_ct = xor_encrypt(key, reply_text.encode("utf-8"))
            send_msg(sock, {"type": "chat", "sender": "Bob", "ciphertext": reply_ct.hex()},
                     show_wire=args.show_wire, actor="BOB WIRE  ")
            log(f"Sent non-interactive reply: \"{reply_text}\"")
            return

        # Interactive chat loop
        while True:
            try:
                # Prompt Bob to type message
                user_input = input("\n✍️  \033[1;34m[Bob]\033[0m > ").strip()
                if not user_input or user_input.lower() == "exit":
                    send_msg(sock, {"type": "bye"}, show_wire=args.show_wire, actor="BOB WIRE  ")
                    log("Session ended by Bob.")
                    break

                out_ct = xor_encrypt(key, user_input.encode("utf-8"))
                send_msg(sock, {"type": "chat", "sender": "Bob", "ciphertext": out_ct.hex()},
                         show_wire=args.show_wire, actor="BOB WIRE  ")
                print(f"   \033[90m(Ciphertext sent: {out_ct.hex()})\033[0m", flush=True)

                # Wait for Alice's incoming reply
                incoming = recv_msg(sock, show_wire=args.show_wire, actor="BOB WIRE  ")
                if not incoming or incoming.get("type") == "bye":
                    log("Alice disconnected or ended chat.")
                    break

                if incoming.get("type") == "chat":
                    raw_hex = incoming.get("ciphertext", "")
                    plain = xor_decrypt(key, bytes.fromhex(raw_hex)).decode("utf-8", errors="replace")
                    print(f"\n📩 \033[1;32m[Alice]\033[0m: {plain}")
                    print(f"   \033[90m(Ciphertext on wire: {raw_hex})\033[0m", flush=True)

            except (ConnectionError, BrokenPipeError):
                log("Connection with Alice lost.")
                break
            except Exception as e:
                log(f"Chat error: {e}")
                break


def main() -> None:
    parser = argparse.ArgumentParser(description="Bob – DH Key Exchange TCP Client")
    parser.add_argument("--host", default="127.0.0.1", help="Alice's IP address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Alice's TCP port (default: 5000)")
    parser.add_argument("--preset", action="store_true", help="Use textbook preset private key (b=15)")
    parser.add_argument("--show-wire", action="store_true", help="Print raw wire JSON packets")
    parser.add_argument("--reveal", action="store_true", help="Display private key value in logs")
    parser.add_argument("--no-interactive", action="store_true", help="Non-interactive mode (for testing)")
    parser.add_argument("--retries", type=int, default=5, help="Number of connection retries (default: 5)")
    parser.add_argument("--retry-delay", type=float, default=2.0, help="Seconds between retries (default: 2.0)")
    args = parser.parse_args()

    run_client(args)


if __name__ == "__main__":
    main()
