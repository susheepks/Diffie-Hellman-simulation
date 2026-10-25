"""
protocol.py – Orchestrates the Diffie-Hellman exchange
=======================================================
DHProtocol coordinates the full lifecycle:
  1. Parameter selection (manual / auto / textbook preset)
  2. Party creation (Alice, Bob)
  3. Public value exchange
  4. Shared secret computation and verification
  5. Step-by-step log generation for educational display

Three modes are supported, controlled by DHMode:
  MANUAL   – caller supplies p, g (and optionally private keys)
  AUTO     – protocol generates p and g of a requested bit size
  TEXTBOOK – the classic p=23, g=5, a=6, b=15 preset from textbooks

Log entries
-----------
Each step appended to `self.log` is a dict with keys:
  step   : int   – sequential step index
  actor  : str   – "System", "Alice", "Bob", or "Public Channel"
  action : str   – short label
  detail : str   – human-readable sentence with formulas and values
  value  : any   – the raw numeric or string result (for programmatic use)
"""

from __future__ import annotations

import time
from enum import Enum, auto
from typing import Optional

from .math_utils import (
    generate_prime,
    generate_safe_prime,
    find_primitive_root,
    is_primitive_root,
    miller_rabin_is_prime,
    _factorize_p_minus_1,
)
from .party import Party


class DHMode(Enum):
    MANUAL = auto()
    AUTO = auto()
    TEXTBOOK = auto()


# Textbook preset constants (Stallings / Forouzan example)
TEXTBOOK_P: int = 23
TEXTBOOK_G: int = 5
TEXTBOOK_A: int = 6   # Alice's private key
TEXTBOOK_B: int = 15  # Bob's private key
TEXTBOOK_BIG_A: int = 8    # g^a mod p = 5^6 mod 23 = 8
TEXTBOOK_BIG_B: int = 19   # g^b mod p = 5^15 mod 23 = 19
TEXTBOOK_SECRET: int = 2   # shared secret


class DHProtocol:
    """Full Diffie-Hellman key exchange with step-by-step logging.

    Usage
    -----
    # Textbook preset
    proto = DHProtocol(DHMode.TEXTBOOK)
    proto.run()
    print(proto.log)

    # Auto-generated 256-bit safe prime
    proto = DHProtocol(DHMode.AUTO, bits=256)
    proto.run()

    # Manual parameters
    proto = DHProtocol(DHMode.MANUAL, p=23, g=5)
    proto.run()
    """

    def __init__(
        self,
        mode: DHMode = DHMode.TEXTBOOK,
        *,
        bits: int = 64,
        p: Optional[int] = None,
        g: Optional[int] = None,
        alice_private: Optional[int] = None,
        bob_private: Optional[int] = None,
        use_safe_prime: bool = True,
    ) -> None:
        """
        Parameters
        ----------
        mode          : One of DHMode.MANUAL / AUTO / TEXTBOOK.
        bits          : Bit length for AUTO mode prime generation.
        p             : Prime modulus for MANUAL mode.
        g             : Generator for MANUAL mode.
        alice_private : Force Alice's private key (for TEXTBOOK / testing).
        bob_private   : Force Bob's private key (for TEXTBOOK / testing).
        use_safe_prime: Use safe prime (p=2q+1) in AUTO mode for fast
                        primitive-root verification.
        """
        self.mode = mode
        self.bits = bits
        self._p_input = p
        self._g_input = g
        self._alice_private = alice_private
        self._bob_private = bob_private
        self.use_safe_prime = use_safe_prime

        # Set after run()
        self.p: int = 0
        self.g: int = 0
        self.alice: Optional[Party] = None
        self.bob: Optional[Party] = None
        self.success: bool = False
        self.log: list[dict] = []
        self._step = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _log(self, actor: str, action: str, detail: str, value=None) -> dict:
        """Append and return a log entry."""
        self._step += 1
        entry = {
            "step": self._step,
            "actor": actor,
            "action": action,
            "detail": detail,
            "value": value,
        }
        self.log.append(entry)
        return entry

    def _setup_textbook(self) -> None:
        self.p = TEXTBOOK_P
        self.g = TEXTBOOK_G
        if self._alice_private is None:
            self._alice_private = TEXTBOOK_A
        if self._bob_private is None:
            self._bob_private = TEXTBOOK_B
        self._log(
            "System", "Preset loaded",
            f"Using textbook example: p={self.p}, g={self.g}, "
            f"a={self._alice_private}, b={self._bob_private}",
            {"p": self.p, "g": self.g},
        )

    def _setup_manual(self) -> None:
        if self._p_input is None or self._g_input is None:
            raise ValueError("MANUAL mode requires both p and g to be supplied.")
        p, g = self._p_input, self._g_input

        # Validate p
        if not miller_rabin_is_prime(p):
            raise ValueError(f"p={p} is not prime.")
        # Validate g
        if not (1 < g < p - 1):
            raise ValueError(f"g={g} must satisfy 1 < g < p-1 (p={p}).")
        # Check if g is a primitive root (informational, not hard error)
        factors = _factorize_p_minus_1(p)
        g_is_prim = is_primitive_root(g, p, factors)
        note = "" if g_is_prim else " (WARNING: g is NOT a primitive root mod p — the subgroup may be small)"

        self.p, self.g = p, g
        self._log(
            "System", "Manual parameters validated",
            f"p={p} ✓ prime, g={g}{note}",
            {"p": p, "g": g, "g_is_primitive_root": g_is_prim},
        )

    def _setup_auto(self) -> None:
        bits = self.bits
        self._log("System", "Generating parameters",
                  f"Generating a {bits}-bit {'safe ' if self.use_safe_prime else ''}prime…")
        t0 = time.perf_counter()
        if self.use_safe_prime and bits >= 8:
            p, q = generate_safe_prime(bits)
            # For safe prime p=2q+1, p-1=2q.  Any g with g^2 ≢ 1 and g^q ≢ 1
            # is a primitive root.  find_primitive_root handles this correctly.
            factors = [2, q]
        else:
            p = generate_prime(bits)
            factors = None  # find_primitive_root will factor p-1

        g = find_primitive_root(p, factors)
        elapsed = time.perf_counter() - t0

        self.p, self.g = p, g
        self._log(
            "System", "Parameters generated",
            f"p = {p}\ng = {g}\n"
            f"(generation took {elapsed*1000:.1f} ms, "
            f"{'safe prime' if self.use_safe_prime else 'standard prime'})",
            {"p": p, "g": g, "elapsed_ms": round(elapsed * 1000, 2)},
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> bool:
        """Execute the full Diffie-Hellman protocol and populate self.log.

        Returns
        -------
        bool
            True if Alice's and Bob's shared secrets match (always True for a
            correctly implemented protocol; False signals a bug or MITM).
        """
        self.log.clear()
        self._step = 0

        # ── Step 1: agree on public parameters ──────────────────────
        if self.mode == DHMode.TEXTBOOK:
            self._setup_textbook()
        elif self.mode == DHMode.MANUAL:
            self._setup_manual()
        else:
            self._setup_auto()

        p, g = self.p, self.g
        self._log(
            "Public Channel", "Parameters announced",
            f"Alice and Bob agree on the public values:\n"
            f"  • Prime modulus p = {p}\n"
            f"  • Generator    g = {g}",
            {"p": p, "g": g},
        )

        # ── Step 2: each party generates its private + public key ────
        alice = Party("Alice", p, g, private_key=self._alice_private)
        bob   = Party("Bob",   p, g, private_key=self._bob_private)
        self.alice, self.bob = alice, bob

        self._log(
            "Alice", "Private key chosen",
            f"Alice picks secret private key a = {alice.private_key} "
            f"(random, 1 < a < p-1, never shared)",
            alice.private_key,
        )
        self._log(
            "Bob", "Private key chosen",
            f"Bob picks secret private key b = {bob.private_key} "
            f"(random, 1 < b < p-1, never shared)",
            bob.private_key,
        )

        # ── Step 3: compute public keys ──────────────────────────────
        self._log(
            "Alice", "Public key computed",
            f"A = g^a mod p = {g}^{alice.private_key} mod {p} = {alice.public_key}",
            alice.public_key,
        )
        self._log(
            "Bob", "Public key computed",
            f"B = g^b mod p = {g}^{bob.private_key} mod {p} = {bob.public_key}",
            bob.public_key,
        )

        # ── Step 4: exchange public keys ─────────────────────────────
        alice.receive_public_value(bob.public_key)
        bob.receive_public_value(alice.public_key)

        self._log(
            "Public Channel", "Public keys exchanged",
            f"Alice sends A = {alice.public_key} → Bob\n"
            f"Bob sends   B = {bob.public_key} → Alice",
            {"A": alice.public_key, "B": bob.public_key},
        )

        # ── Step 5: compute shared secrets ───────────────────────────
        s_alice = alice.compute_shared_secret()
        self._log(
            "Alice", "Shared secret computed",
            f"s = B^a mod p = {bob.public_key}^{alice.private_key} mod {p} = {s_alice}",
            s_alice,
        )

        s_bob = bob.compute_shared_secret()
        self._log(
            "Bob", "Shared secret computed",
            f"s = A^b mod p = {alice.public_key}^{bob.private_key} mod {p} = {s_bob}",
            s_bob,
        )

        # ── Step 6: verification ─────────────────────────────────────
        self.success = (s_alice == s_bob)
        status = "✅ SUCCESS" if self.success else "❌ FAILURE"
        self._log(
            "System", "Verification",
            f"{status}: Alice's secret = {s_alice}, Bob's secret = {s_bob}. "
            f"{'Both parties hold the same shared secret!' if self.success else 'MISMATCH — something is wrong!'}",
            {"alice_secret": s_alice, "bob_secret": s_bob, "match": self.success},
        )

        return self.success

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def summary_table(self) -> dict:
        """Return a flat dict suitable for tabular display."""
        if self.alice is None or self.bob is None:
            raise RuntimeError("Call run() first.")
        return {
            "p (public prime)":       self.p,
            "g (public generator)":   self.g,
            "a (Alice private)":      self.alice.private_key,
            "b (Bob private)":        self.bob.private_key,
            "A = g^a mod p (Alice public)": self.alice.public_key,
            "B = g^b mod p (Bob public)":   self.bob.public_key,
            "s (shared secret)":      self.alice.shared_secret,
        }
