"""
cli.py – Command-line demo for Diffie-Hellman Key Exchange
===========================================================
Usage examples:
    python cli.py                          # textbook preset
    python cli.py --mode auto --bits 64   # auto 64-bit prime
    python cli.py --mode manual --p 23 --g 5
    python cli.py --mode auto --bits 32 --mitm    # show MITM attack
    python cli.py --mode auto --bits 20 --eve     # show Eve brute force
    python cli.py --verbose-steps                  # show square-and-multiply
"""

from __future__ import annotations

import argparse
import sys
import textwrap
from typing import Optional

# Force UTF-8 output on Windows terminals (handles arrows, bullets, etc.)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ── Ensure the project root is on the path ──────────────────────────
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from dh.protocol import DHProtocol, DHMode
from dh.attacks import Eve, Mallory, timing_attack_benchmark
from dh.kdf import derive_key, xor_encrypt, xor_decrypt, fingerprint
from dh.math_utils import mod_exp_steps
from dh.party import Party


# ANSI colour helpers (disabled on Windows if no colour support)
def _c(code: str, text: str) -> str:
    if sys.stdout.isatty() or sys.platform != "win32":
        return f"\033[{code}m{text}\033[0m"
    return text

RED    = lambda t: _c("91", t)
GREEN  = lambda t: _c("92", t)
YELLOW = lambda t: _c("93", t)
CYAN   = lambda t: _c("96", t)
BOLD   = lambda t: _c("1",  t)


SEPARATOR = "=" * 70


def print_header(title: str) -> None:
    print()
    print(SEPARATOR)
    print(BOLD(f"  {title}"))
    print(SEPARATOR)


def print_log(log: list[dict], show_private: bool = False) -> None:
    actor_colors = {
        "Alice": GREEN,
        "Bob": CYAN,
        "Public Channel": YELLOW,
        "System": BOLD,
        "Mallory": RED,
        "Eve": RED,
    }
    for entry in log:
        actor = entry["actor"]
        color = actor_colors.get(actor, lambda x: x)
        step_label = BOLD(f"Step {entry['step']:02d}")
        print(f"\n  {step_label} | {color(actor)} | {entry['action']}")
        detail = entry["detail"]
        # Hide private keys unless requested
        if not show_private and "private key" in entry["action"].lower():
            detail = "[HIDDEN – use --reveal to show private keys]"
        for line in detail.splitlines():
            print(f"           {line}")


def run_textbook(args: argparse.Namespace) -> None:
    print_header("Textbook Example: p=23, g=5, a=6, b=15")

    proto = DHProtocol(DHMode.TEXTBOOK)
    proto.run()
    print_log(proto.log, show_private=args.reveal)

    # Show square-and-multiply trace if requested
    if args.verbose_steps and proto.alice:
        print()
        print(BOLD("  Square-and-Multiply trace for A = 5^6 mod 23:"))
        steps = mod_exp_steps(5, 6, 23)
        for s in steps:
            print(f"    {s['description']}")

    # Summary table
    print()
    print(BOLD("  Summary Table"))
    print("  " + "-" * 50)
    table = proto.summary_table()
    for k, v in table.items():
        label = k.ljust(30)
        val = str(v)
        if "private" in k.lower():
            val = RED(val) if args.reveal else RED("[HIDDEN]")
        else:
            val = GREEN(val)
        print(f"  {label} {val}")

    # KDF + XOR demo
    print()
    print(BOLD("  Shared Key Demo (SHA-256 KDF + XOR cipher)"))
    print("  " + "-" * 50)
    s = proto.alice.shared_secret  # type: ignore
    key = derive_key(s)
    print(f"  Shared secret s = {s}")
    print(f"  Derived key   K = {key.hex()}")
    print(f"  Fingerprint     = {fingerprint(key)}")

    message = b"Hello Bob, this is Alice! (demo only)"
    ciphertext = xor_encrypt(key, message)
    decrypted  = xor_decrypt(key, ciphertext)
    print(f"\n  Alice encrypts: {message.decode()!r}")
    print(f"  Ciphertext hex: {ciphertext.hex()}")
    print(f"  Bob decrypts:   {decrypted.decode()!r}")
    assert decrypted == message
    print(f"\n  {GREEN('✅ Both parties decrypted correctly using the shared key!')}")


def run_auto(args: argparse.Namespace) -> None:
    print_header(f"Auto Mode – {args.bits}-bit {'safe ' if args.safe else ''}prime")

    proto = DHProtocol(
        DHMode.AUTO,
        bits=args.bits,
        use_safe_prime=args.safe,
    )
    proto.run()
    print_log(proto.log, show_private=args.reveal)

    if proto.success:
        print(f"\n  {GREEN('✅ Shared secret verified!')} s = {proto.alice.shared_secret}")  # type: ignore
    else:
        print(f"\n  {RED('❌ Shared secret MISMATCH – this is a bug!')}")

    if args.verbose_steps and proto.alice:
        print()
        print(BOLD(f"  Square-and-multiply trace for A = {proto.g}^{proto.alice.private_key} mod {proto.p}:"))
        steps = mod_exp_steps(proto.g, proto.alice.private_key, proto.p)  # type: ignore
        for s in steps[:10]:  # limit output
            print(f"    {s['description']}")
        if len(steps) > 10:
            print(f"    … ({len(steps) - 10} more steps)")


def run_manual(args: argparse.Namespace) -> None:
    if args.p is None or args.g is None:
        print(RED("ERROR: --mode manual requires --p and --g"))
        sys.exit(1)

    print_header(f"Manual Mode – p={args.p}, g={args.g}")
    proto = DHProtocol(
        DHMode.MANUAL,
        p=args.p,
        g=args.g,
        alice_private=args.alice_private,
        bob_private=args.bob_private,
    )
    try:
        proto.run()
    except ValueError as e:
        print(RED(f"\n  Validation Error: {e}"))
        sys.exit(1)

    print_log(proto.log, show_private=args.reveal)

    if proto.success:
        print(f"\n  {GREEN('✅ Shared secret verified!')} s = {proto.alice.shared_secret}")  # type: ignore
    else:
        print(f"\n  {RED('❌ Shared secret MISMATCH!')}")


def run_eve(args: argparse.Namespace) -> None:
    print_header(f"Security Demo – Eve (Brute-Force Discrete Log) on {args.bits}-bit prime")

    proto = DHProtocol(DHMode.AUTO, bits=args.bits, use_safe_prime=False)
    proto.run()

    p, g = proto.p, proto.g
    alice = proto.alice  # type: ignore
    bob   = proto.bob    # type: ignore

    print(f"  Public channel: p={p}, g={g}")
    print(f"  Alice sends:    A = {alice.public_key}")
    print(f"  Bob   sends:    B = {bob.public_key}")
    print()
    print(BOLD("  Eve starts brute-force DLP: find a s.t. g^a ≡ A (mod p)…"))

    eve = Eve(p, g, alice.public_key, timeout_seconds=args.timeout)
    result = eve.brute_force(big_b=bob.public_key)

    if result["success"]:
        print(GREEN(f"  Eve found a = {result['recovered_a']} in {result['elapsed_ms']:.1f} ms"))
        print(GREEN(f"  Eve computes shared secret = {result['recovered_secret']}"))
        print(GREEN(f"  Actual shared secret       = {alice.shared_secret}"))
        match = result["recovered_secret"] == alice.shared_secret
        print(GREEN("  ✅ Eve's secret matches!") if match else RED("  ❌ Mismatch"))
    elif result["timed_out"]:
        print(YELLOW(f"  Eve timed out after {result['elapsed_ms']:.0f} ms "
                     f"({result['iterations']:,} iterations)"))
        print(YELLOW(f"  For {args.bits}-bit p, brute force is infeasible!"))
    else:
        print(RED(f"  Eve failed (iterated {result['iterations']:,} values)"))

    # Benchmark
    if args.benchmark:
        print()
        print(BOLD("  Benchmark: brute-force time vs. bit size"))
        print("  " + "-" * 50)
        print(f"  {'Bits':>6}  {'Time (ms)':>12}  {'Iterations':>14}  {'Result'}")
        print("  " + "-" * 50)
        sizes = [8, 12, 16, 20, 24]
        results = timing_attack_benchmark(sizes, timeout=2.0)
        for r in results:
            status = "timed out" if r["timed_out"] else ("found" if r["success"] else "not found")
            print(f"  {r['bits']:>6}  {r['elapsed_ms']:>12.1f}  {r['iterations']:>14,}  {status}")


def run_mitm(args: argparse.Namespace) -> None:
    print_header("Security Demo – Man-in-the-Middle (Mallory)")

    proto = DHProtocol(DHMode.AUTO, bits=args.bits)
    proto.run()
    p, g = proto.p, proto.g

    # Create fresh Alice and Bob (before exchange)
    alice = Party("Alice", p, g)
    bob   = Party("Bob",   p, g)

    mallory = Mallory(p, g)
    result = mallory.intercept_exchange(alice, bob)

    print_log(result["log"])

    print()
    print(BOLD("  MITM Summary"))
    print("  " + "-" * 50)
    print(f"  {'Alice believes shared secret =':40} {result['alice_secret']}")
    print(f"  {'Bob believes shared secret =':40} {result['bob_secret']}")
    print(f"  {'Mallory knows (shared with Alice):':40} {result['mallory_s_alice']}")
    print(f"  {'Mallory knows (shared with Bob):':40} {result['mallory_s_bob']}")
    print()
    if result["alice_secret"] != result["bob_secret"]:
        print(RED("  ❌ Alice and Bob hold DIFFERENT secrets! MITM succeeded."))
    else:
        print(YELLOW("  ⚠ Keys coincidentally match (rare). Mallory still deceives both."))
    print()
    print(YELLOW("  FIX: Authenticate public keys with digital signatures / certificates."))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Diffie-Hellman Key Exchange – CLI Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          python cli.py                              # textbook preset
          python cli.py --mode auto --bits 128      # 128-bit prime
          python cli.py --mode manual --p 23 --g 5 # manual params
          python cli.py --mode auto --eve --bits 20 # Eve attack
          python cli.py --mode auto --mitm          # MITM demo
          python cli.py --verbose-steps --reveal    # show all internals
        """),
    )
    parser.add_argument("--mode", choices=["textbook", "auto", "manual"],
                        default="textbook", help="Protocol mode (default: textbook)")
    parser.add_argument("--bits", type=int, default=32,
                        help="Prime bit size for auto mode (default: 32)")
    parser.add_argument("--safe", action="store_true", default=True,
                        help="Use safe prime in auto mode (default: True)")
    parser.add_argument("--no-safe", dest="safe", action="store_false",
                        help="Disable safe prime")
    parser.add_argument("--p", type=int, default=None,
                        help="Manual prime p")
    parser.add_argument("--g", type=int, default=None,
                        help="Manual generator g")
    parser.add_argument("--alice-private", type=int, default=None,
                        help="Force Alice's private key (for reproducibility)")
    parser.add_argument("--bob-private", type=int, default=None,
                        help="Force Bob's private key")
    parser.add_argument("--reveal", action="store_true",
                        help="Show private keys in output")
    parser.add_argument("--verbose-steps", action="store_true",
                        help="Show square-and-multiply intermediate steps")
    parser.add_argument("--eve", action="store_true",
                        help="Run Eve brute-force attack demo")
    parser.add_argument("--benchmark", action="store_true",
                        help="Benchmark brute-force across bit sizes (with --eve)")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="Eve timeout in seconds (default: 5)")
    parser.add_argument("--mitm", action="store_true",
                        help="Run Man-in-the-Middle demo")

    args = parser.parse_args()

    if args.eve:
        run_eve(args)
    elif args.mitm:
        run_mitm(args)
    elif args.mode == "textbook":
        run_textbook(args)
    elif args.mode == "auto":
        run_auto(args)
    elif args.mode == "manual":
        run_manual(args)


if __name__ == "__main__":
    main()
