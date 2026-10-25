"""
attacks.py – Security demonstrations for Diffie-Hellman
========================================================
Two attack scenarios are modelled here:

1. Eve (passive eavesdropper)
   ---------------------------
   Eve observes the public channel and sees: p, g, A, B.
   She wants to recover the shared secret s = g^(ab) mod p.
   To do this she must solve the Discrete Logarithm Problem (DLP):
       find a such that g^a ≡ A (mod p)
   For small p this is feasible by brute force (baby-step giant-step is
   omitted to keep the code simple, but `bsgs_discrete_log` is included
   as a bonus for small p).

2. Mallory (Man-in-the-Middle)
   ----------------------------
   Mallory sits between Alice and Bob, intercepting the public channel.
   Instead of forwarding A and B, she substitutes her own public values:
     • She performs a full DH exchange with Alice (Mallory ↔ Alice).
     • She performs a separate DH exchange with Bob  (Mallory ↔ Bob).
   Result:
     • Alice thinks she shares s1 with Bob, but actually shares s1 with Mallory.
     • Bob thinks he shares s2 with Alice, but actually shares s2 with Mallory.
     • Mallory knows both s1 and s2 and can decrypt/re-encrypt all traffic.

   Fix: Authenticate the public values (e.g., sign them with a long-term key
   or use a certificate).  DH alone (without authentication) does not prevent
   MITM.

Note on timing
--------------
Brute-force DLP is O(p) in the worst case.  We time-limit the search and
return None after `timeout_seconds` to keep the demo responsive.
"""

from __future__ import annotations

import secrets
import time
from typing import Optional

from .math_utils import mod_exp, generate_prime, find_primitive_root
from .party import Party


# ---------------------------------------------------------------------------
# Eve – passive eavesdropper / brute-force discrete log
# ---------------------------------------------------------------------------

class Eve:
    """Passive eavesdropper who attempts to crack DH by brute-force DLP.

    She has read-only access to the public channel: p, g, A (= g^a mod p).
    She iterates g^1, g^2, … until she finds g^x ≡ A, giving her a.

    This is feasible only for small p (≲ 2^32).  For larger p we report
    failure and the time taken (showing infeasibility).

    Parameters
    ----------
    p, g : public parameters
    big_a : Alice's public value (g^a mod p)
    timeout_seconds : stop brute force after this many seconds
    """

    def __init__(self, p: int, g: int, big_a: int,
                 timeout_seconds: float = 10.0) -> None:
        self.p = p
        self.g = g
        self.big_a = big_a
        self.timeout = timeout_seconds
        self.recovered_private: Optional[int] = None
        self.recovered_secret: Optional[int] = None
        self.elapsed: float = 0.0
        self.iterations: int = 0
        self.timed_out: bool = False

    def brute_force(self, big_b: Optional[int] = None) -> dict:
        """Attempt brute-force discrete log of big_a = g^a mod p.

        Optionally, if big_b (Bob's public value) is provided, also compute
        the shared secret s = big_b^a mod p once a is found.

        Returns
        -------
        dict with keys:
            success        : bool
            recovered_a    : int | None
            recovered_secret : int | None
            elapsed_ms     : float
            iterations     : int
            timed_out      : bool
        """
        p, g, A = self.p, self.g, self.big_a
        t0 = time.perf_counter()
        current = 1
        for x in range(1, p):
            current = (current * g) % p
            self.iterations += 1
            if current == A:
                self.recovered_private = x
                if big_b is not None:
                    self.recovered_secret = mod_exp(big_b, x, p)
                self.elapsed = time.perf_counter() - t0
                self.timed_out = False
                return self._result()
            if time.perf_counter() - t0 > self.timeout:
                self.elapsed = time.perf_counter() - t0
                self.timed_out = True
                return self._result()

        self.elapsed = time.perf_counter() - t0
        return self._result()

    def _result(self) -> dict:
        return {
            "success": self.recovered_private is not None,
            "recovered_a": self.recovered_private,
            "recovered_secret": self.recovered_secret,
            "elapsed_ms": round(self.elapsed * 1000, 3),
            "iterations": self.iterations,
            "timed_out": self.timed_out,
        }


def bsgs_discrete_log(g: int, h: int, p: int) -> Optional[int]:
    """Baby-step Giant-step algorithm for discrete log: find x s.t. g^x ≡ h (mod p).

    Time and space complexity: O(√p).  Significantly faster than brute force
    for p up to ~2^40.

    Parameters
    ----------
    g : generator
    h : target value (h = g^x mod p)
    p : prime modulus

    Returns
    -------
    int | None
        The discrete log x, or None if not found within √p steps.
    """
    import math as _math
    m = int(_math.isqrt(p)) + 1
    # Baby steps: compute g^j mod p for j = 0..m-1
    baby: dict[int, int] = {}
    gj = 1
    for j in range(m):
        baby[gj] = j
        gj = (gj * g) % p

    # Giant steps: compute h * (g^{-m})^i mod p for i = 0..m-1
    # g^{-m} mod p = pow(g, p-1-m, p) by Fermat's little theorem
    g_inv_m = mod_exp(g, p - 1 - m, p)
    giant = h
    for i in range(m):
        if giant in baby:
            x = i * m + baby[giant]
            if x > 0:
                return x
        giant = (giant * g_inv_m) % p
    return None


def timing_attack_benchmark(bit_sizes: list[int] = None,
                             timeout: float = 2.0) -> list[dict]:
    """Benchmark brute-force DLP time vs. prime bit size.

    For each bit size, generate a small random prime, run brute force
    (or time out), and record the result.  Used by the UI to draw the
    "infeasibility graph".

    Parameters
    ----------
    bit_sizes : list of bit sizes to test (default: 8, 12, 16, 20, 24, 28, 32)
    timeout   : seconds before giving up on a single size

    Returns
    -------
    list[dict] with keys: bits, elapsed_ms, iterations, timed_out, p
    """
    if bit_sizes is None:
        bit_sizes = [8, 12, 16, 20, 24, 28, 32]
    results = []
    for bits in bit_sizes:
        p = generate_prime(bits)
        g = find_primitive_root(p)
        # Pick a random private key
        a = secrets.randbelow(p - 3) + 2
        big_a = mod_exp(g, a, p)
        eve = Eve(p, g, big_a, timeout_seconds=timeout)
        res = eve.brute_force()
        results.append({
            "bits": bits,
            "p": p,
            "elapsed_ms": res["elapsed_ms"],
            "iterations": res["iterations"],
            "timed_out": res["timed_out"],
            "success": res["success"],
        })
    return results


# ---------------------------------------------------------------------------
# Mallory – Man-in-the-Middle attacker
# ---------------------------------------------------------------------------

class Mallory:
    """Man-in-the-Middle attacker.

    Mallory intercepts the public channel between Alice and Bob.
    She conducts TWO independent DH exchanges:
      1. Mallory ↔ Alice  (Mallory pretends to be Bob)
      2. Mallory ↔ Bob    (Mallory pretends to be Alice)

    After the attack:
      • Alice and Mallory share secret s1.
      • Bob and Mallory share secret s2.
      • s1 ≠ s2 in general.
      • Mallory can decrypt messages from Alice (using s1), read them,
        re-encrypt with s2, and forward to Bob—without either noticing.

    Fix: use authenticated DH (signed public keys or certificates).

    Parameters
    ----------
    p, g : public parameters (same ones Alice and Bob agreed on)
    """

    def __init__(self, p: int, g: int) -> None:
        self.p = p
        self.g = g
        # Mallory generates TWO private keys: one for each conversation
        self.mallory_for_alice = Party("Mallory→Alice", p, g)
        self.mallory_for_bob   = Party("Mallory→Bob",   p, g)
        self.shared_with_alice: Optional[int] = None
        self.shared_with_bob:   Optional[int] = None
        self.log: list[dict] = []

    def intercept_exchange(
        self,
        alice: Party,
        bob: Party,
    ) -> dict:
        """Perform the full MITM interception.

        Instead of forwarding Alice's A to Bob and Bob's B to Alice,
        Mallory substitutes her own public values.

        Parameters
        ----------
        alice : Party (Alice) – already has her public key computed
        bob   : Party (Bob)   – already has his public key computed

        Returns
        -------
        dict  with keys:
            alice_secret   : int   (what Alice computed)
            bob_secret     : int   (what Bob computed)
            mallory_s_alice: int   (Mallory's key shared with Alice)
            mallory_s_bob  : int   (Mallory's key shared with Bob)
            same_secret    : bool  (should be False – MITM succeeded)
            log            : list[dict]
        """
        p, g = self.p, self.g
        mA = self.mallory_for_alice  # Mallory's persona facing Alice
        mB = self.mallory_for_bob    # Mallory's persona facing Bob

        self.log.clear()
        step = [0]

        def lg(actor, action, detail, value=None):
            step[0] += 1
            entry = {"step": step[0], "actor": actor,
                     "action": action, "detail": detail, "value": value}
            self.log.append(entry)

        # Alice → Mallory (Mallory intercepts Alice's public value)
        lg("Alice", "Sends public key",
           f"Alice sends A = {alice.public_key} on the public channel",
           alice.public_key)
        lg("Mallory", "Intercepts Alice's public key",
           f"Mallory intercepts A = {alice.public_key}  ← Alice never knows",
           alice.public_key)

        # Bob → Mallory (Mallory intercepts Bob's public value)
        lg("Bob", "Sends public key",
           f"Bob sends B = {bob.public_key} on the public channel",
           bob.public_key)
        lg("Mallory", "Intercepts Bob's public key",
           f"Mallory intercepts B = {bob.public_key}  ← Bob never knows",
           bob.public_key)

        # Mallory sends her OWN public value to Alice (pretending to be Bob)
        lg("Mallory", "Sends fake B to Alice",
           f"Mallory sends M_A = {mA.public_key} to Alice (pretending to be Bob)",
           mA.public_key)

        # Mallory sends her OWN public value to Bob (pretending to be Alice)
        lg("Mallory", "Sends fake A to Bob",
           f"Mallory sends M_B = {mB.public_key} to Bob (pretending to be Alice)",
           mB.public_key)

        # Alice computes shared secret with Mallory (thinking it's Bob)
        alice.receive_public_value(mA.public_key)
        s_alice = alice.compute_shared_secret()
        lg("Alice", "Computes shared secret",
           f"Alice computes s = M_A^a mod p = {mA.public_key}^{alice.private_key} mod {p} = {s_alice}  "
           f"← Alice THINKS this is shared with Bob",
           s_alice)

        # Bob computes shared secret with Mallory (thinking it's Alice)
        bob.receive_public_value(mB.public_key)
        s_bob = bob.compute_shared_secret()
        lg("Bob", "Computes shared secret",
           f"Bob computes s = M_B^b mod p = {mB.public_key}^{bob.private_key} mod {p} = {s_bob}  "
           f"← Bob THINKS this is shared with Alice",
           s_bob)

        # Mallory computes both shared secrets
        mA.receive_public_value(alice.public_key)
        self.shared_with_alice = mA.compute_shared_secret()
        lg("Mallory", "Derives key with Alice",
           f"Mallory: s1 = A^m_a mod p = {alice.public_key}^{mA.private_key} mod {p} = {self.shared_with_alice}",
           self.shared_with_alice)

        mB.receive_public_value(bob.public_key)
        self.shared_with_bob = mB.compute_shared_secret()
        lg("Mallory", "Derives key with Bob",
           f"Mallory: s2 = B^m_b mod p = {bob.public_key}^{mB.private_key} mod {p} = {self.shared_with_bob}",
           self.shared_with_bob)

        # Summary
        mitm_succeeded = (s_alice != s_bob)
        lg("System", "MITM Result",
           f"Alice's secret: {s_alice}\n"
           f"Bob's   secret: {s_bob}\n"
           f"Mallory knows:  s1={self.shared_with_alice} (with Alice), "
           f"s2={self.shared_with_bob} (with Bob)\n"
           f"MITM {'SUCCEEDED' if mitm_succeeded else 'did not separate keys (coincidence)'}!\n"
           f"FIX: Sign public keys with long-term identity keys (certificates).",
           {"mitm_succeeded": mitm_succeeded})

        return {
            "alice_secret": s_alice,
            "bob_secret": s_bob,
            "mallory_s_alice": self.shared_with_alice,
            "mallory_s_bob": self.shared_with_bob,
            "same_secret": not mitm_succeeded,
            "log": self.log,
        }
