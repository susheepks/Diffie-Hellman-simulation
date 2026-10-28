"""
network_demo/eve_sniffer.py – TCP Proxy / Wire Sniffer & Man-in-the-Middle Relay
================================================================================
Runs as an intermediary TCP proxy between Alice and Bob:
    Bob <=====> Eve (Sniffer / MITM) <=====> Alice

Modes:
  1. Passive Sniffer (default):
     Forwards all packets unchanged, but inspects and prints everything on wire.
     Demonstrates that Eve sees (p, g, A, B, ciphertext), but CANNOT decrypt chat.

  2. Active MITM (--mitm):
     Substitutes public keys with Mallory's own public key M.
     Establishes two independent secrets (s_alice != s_bob).
     Decrypts Alice's messages, prints plaintext, re-encrypts for Bob!

Usage:
    # 1. Start Alice on port 5001:
    python network_demo/alice.py --port 5001 --preset

    # 2. Start Eve sniffer listening on port 5000, relaying to Alice on 5001:
    python network_demo/eve_sniffer.py --listen-port 5000 --alice-host 127.0.0.1 --alice-port 5001

    # 3. Start Bob connecting to Eve on port 5000:
    python network_demo/bob.py --host 127.0.0.1 --port 5000 --preset
"""

from __future__ import annotations

import argparse
import secrets
import socket
import sys
import time
from pathlib import Path

# Force UTF-8 output on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dh.math_utils import mod_exp
from dh.kdf import derive_key, xor_encrypt, xor_decrypt
from dh.transport import send_msg, recv_msg, compute_key_fingerprint, ts


def log_eve(msg: str) -> None:
    print(f"\033[1;33m[{ts()}] [EVE RELAY]\033[0m {msg}", flush=True)


def log_alert(msg: str) -> None:
    print(f"\033[1;31m[{ts()}] [EVE ALERT]\033[0m {msg}", flush=True)


def run_passive_relay(bob_sock: socket.socket, alice_sock: socket.socket) -> None:
    log_eve("Passive Sniffer Mode active: Forwarding packets and inspecting wire traffic.")

    # 1. Bob -> Alice : hello
    msg1 = recv_msg(bob_sock, show_wire=False)
    log_eve(f"Intercepted from Bob: {msg1}")
    send_msg(alice_sock, msg1)

    # 2. Alice -> Bob : params (p, g)
    msg2 = recv_msg(alice_sock, show_wire=False)
    log_eve(f"Intercepted from Alice: {msg2}")
    send_msg(bob_sock, msg2)

    # 3. Alice -> Bob : public key A
    msg3 = recv_msg(alice_sock, show_wire=False)
    log_eve(f"Intercepted from Alice: Public key A = {msg3.get('value')}")
    send_msg(bob_sock, msg3)

    # 4. Bob -> Alice : public key B
    msg4 = recv_msg(bob_sock, show_wire=False)
    log_eve(f"Intercepted from Bob:   Public key B = {msg4.get('value')}")
    send_msg(alice_sock, msg4)

    # 5. Alice -> Bob : confirmation fingerprint
    msg5 = recv_msg(alice_sock, show_wire=False)
    log_eve(f"Intercepted Alice's confirmation: {msg5}")
    send_msg(bob_sock, msg5)

    # 6. Bob -> Alice : confirmation fingerprint
    msg6 = recv_msg(bob_sock, show_wire=False)
    log_eve(f"Intercepted Bob's confirmation:   {msg6}")
    send_msg(alice_sock, msg6)

    print("\n" + "=" * 65)
    print("  🕵️ EVE'S WIRE SUMMARY (PASSIVE SNIFFER):")
    print(f"  • Modulus p = {msg2.get('p')}")
    print(f"  • Base    g = {msg2.get('g')}")
    print(f"  • Alice A = {msg3.get('value')}")
    print(f"  • Bob   B = {msg4.get('value')}")
    print("  • Eve CANNOT compute shared secret without Discrete Logarithm!")
    print("=" * 65 + "\n", flush=True)

    # Chat relay loop
    while True:
        try:
            # Check for traffic from either socket
            alice_sock.settimeout(0.2)
            try:
                a_msg = recv_msg(alice_sock, show_wire=False)
                if a_msg:
                    if a_msg.get("type") == "chat":
                        ct = a_msg.get("ciphertext", "")
                        log_eve(f"Captured encrypted chat (Alice -> Bob): {ct}")
                        log_eve("  (Eve sees only ciphertext bytes; cannot decrypt!)")
                    send_msg(bob_sock, a_msg)
            except socket.timeout:
                pass

            bob_sock.settimeout(0.2)
            try:
                b_msg = recv_msg(bob_sock, show_wire=False)
                if b_msg:
                    if b_msg.get("type") == "chat":
                        ct = b_msg.get("ciphertext", "")
                        log_eve(f"Captured encrypted chat (Bob -> Alice): {ct}")
                        log_eve("  (Eve sees only ciphertext bytes; cannot decrypt!)")
                    send_msg(alice_sock, b_msg)
            except socket.timeout:
                pass

        except (ConnectionError, BrokenPipeError):
            log_eve("Connection closed by peer.")
            break


def run_mitm_relay(bob_sock: socket.socket, alice_sock: socket.socket) -> None:
    log_alert("⚠️ ACTIVE MAN-IN-THE-MIDDLE (MITM) ATTACK IN PROGRESS!")

    # 1. Bob -> Alice : hello
    msg1 = recv_msg(bob_sock, show_wire=False)
    log_eve(f"Intercepted Bob's hello: {msg1}")
    send_msg(alice_sock, msg1)

    # 2. Alice -> Bob : params (p, g)
    msg2 = recv_msg(alice_sock, show_wire=False)
    p = msg2["p"]
    g = msg2["g"]
    log_eve(f"Intercepted params: p={p}, g={g}")
    send_msg(bob_sock, msg2)

    # Mallory chooses her own private key m
    m = secrets.randbelow(p - 3) + 2
    M = mod_exp(g, m, p)
    log_alert(f"Mallory generates private key m={m}, computes public key M={M}")

    # 3. Alice -> Bob : public key A  ===> TAMPERED: Send M instead!
    msg3 = recv_msg(alice_sock, show_wire=False)
    alice_real_A = msg3["value"]
    log_alert(f"Alice sent A = {alice_real_A} ---> Mallory REPLACES with M = {M} to Bob!")
    send_msg(bob_sock, {"type": "public", "name": "Alice", "value": M})

    # 4. Bob -> Alice : public key B  ===> TAMPERED: Send M instead!
    msg4 = recv_msg(bob_sock, show_wire=False)
    bob_real_B = msg4["value"]
    log_alert(f"Bob sent B = {bob_real_B} ---> Mallory REPLACES with M = {M} to Alice!")
    send_msg(alice_sock, {"type": "public", "name": "Bob", "value": M})

    # Mallory computes TWO independent shared secrets:
    # Key 1 with Alice: s_alice = A^m mod p
    # Key 2 with Bob:   s_bob   = B^m mod p
    s_alice = mod_exp(alice_real_A, m, p)
    s_bob   = mod_exp(bob_real_B,   m, p)

    key_alice = derive_key(s_alice)
    key_bob   = derive_key(s_bob)

    fp_alice = compute_key_fingerprint(key_alice)
    fp_bob   = compute_key_fingerprint(key_bob)

    print("\n" + "=" * 65)
    print("  🦹 MALLORY ESTABLISHED TWO SEPARATE ENCRYPTED TUNNELS:")
    print(f"  • With Alice: Secret s_alice = {s_alice} | Fingerprint: {fp_alice}")
    print(f"  • With Bob:   Secret s_bob   = {s_bob} | Fingerprint: {fp_bob}")
    print("=" * 65 + "\n", flush=True)

    # 5. Alice sends confirmation to Bob (Mallory intercepts)
    conf_a = recv_msg(alice_sock, show_wire=False)
    log_alert(f"Alice sent confirmation: {conf_a.get('fingerprint')}")
    # Forward Mallory's fp with Bob to Bob
    send_msg(bob_sock, {"type": "confirm", "fingerprint": fp_bob})

    # 6. Bob sends confirmation to Alice (Mallory intercepts)
    conf_b = recv_msg(bob_sock, show_wire=False)
    log_alert(f"Bob sent confirmation:   {conf_b.get('fingerprint')}")
    # Forward Mallory's fp with Alice to Alice
    send_msg(alice_sock, {"type": "confirm", "fingerprint": fp_alice})

    # Intercept & eavesdrop / modify chat
    log_alert("EAVESDROPPING CHAT: Decrypting with key_alice, re-encrypting with key_bob!")
    while True:
        try:
            alice_sock.settimeout(0.2)
            try:
                a_msg = recv_msg(alice_sock, show_wire=False)
                if a_msg and a_msg.get("type") == "chat":
                    ct_hex = a_msg.get("ciphertext", "")
                    pt = xor_decrypt(key_alice, bytes.fromhex(ct_hex)).decode("utf-8", errors="replace")
                    print(f"\n🕵️ \033[1;31m[MITM INTERCEPTED ALICE]\033[0m: \"{pt}\"")
                    # Re-encrypt with key_bob and forward to Bob
                    tampered_pt = f"{pt} [EVE WAS HERE 🦹]"
                    re_ct = xor_encrypt(key_bob, tampered_pt.encode("utf-8"))
                    send_msg(bob_sock, {"type": "chat", "sender": "Alice", "ciphertext": re_ct.hex()})
            except socket.timeout:
                pass

            bob_sock.settimeout(0.2)
            try:
                b_msg = recv_msg(bob_sock, show_wire=False)
                if b_msg and b_msg.get("type") == "chat":
                    ct_hex = b_msg.get("ciphertext", "")
                    pt = xor_decrypt(key_bob, bytes.fromhex(ct_hex)).decode("utf-8", errors="replace")
                    print(f"\n🕵️ \033[1;31m[MITM INTERCEPTED BOB]\033[0m: \"{pt}\"")
                    re_ct = xor_encrypt(key_alice, pt.encode("utf-8"))
                    send_msg(alice_sock, {"type": "chat", "sender": "Bob", "ciphertext": re_ct.hex()})
            except socket.timeout:
                pass
        except (ConnectionError, BrokenPipeError):
            break


def main() -> None:
    parser = argparse.ArgumentParser(description="Eve Sniffer & MITM Relay")
    parser.add_argument("--listen-port", type=int, default=5000, help="Port to listen for Bob (default: 5000)")
    parser.add_argument("--alice-host", default="127.0.0.1", help="Alice's IP address (default: 127.0.0.1)")
    parser.add_argument("--alice-port", type=int, default=5001, help="Alice's port (default: 5001)")
    parser.add_argument("--mitm", action="store_true", help="Active Man-in-the-Middle attack mode")
    args = parser.parse_args()

    mode_title = "ACTIVE MAN-IN-THE-MIDDLE (MITM)" if args.mitm else "PASSIVE SNIFFER"
    print("\n" + "=" * 65)
    print(f"      🕵️ EVE TCP PROXY RELAY – {mode_title}")
    print("=" * 65)
    print(f"  Listening for Bob on:  0.0.0.0:{args.listen_port}")
    print(f"  Forwarding to Alice:   {args.alice_host}:{args.alice_port}")
    print("=" * 65 + "\n", flush=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", args.listen_port))
        listener.listen(1)
        log_eve(f"Waiting for Bob to connect on port {args.listen_port}...")

        bob_conn, bob_addr = listener.accept()
        log_eve(f"Bob connected from {bob_addr[0]}:{bob_addr[1]}")

        log_eve(f"Connecting upstream to Alice at {args.alice_host}:{args.alice_port}...")
        alice_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        alice_sock.connect((args.alice_host, args.alice_port))
        log_eve("Connected to Alice! Beginning interception.")

        if args.mitm:
            run_mitm_relay(bob_conn, alice_sock)
        else:
            run_passive_relay(bob_conn, alice_sock)


if __name__ == "__main__":
    main()
