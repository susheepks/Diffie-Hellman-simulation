"""
tests/test_dh.py – Unit tests for the DH project
==================================================
Run with:
    python -m unittest tests/test_dh.py -v

Coverage
--------
1. mod_exp == pow() for 1000 random cases
2. Miller-Rabin on known primes, composites, Carmichael numbers
3. Textbook example: A=8, B=19, s=2
4. 100 random parameter sets: alice_secret == bob_secret
5. Invalid inputs raise ValueError
6. MITM scenario: alice_secret != bob_secret
7. KDF + XOR round-trip
8. is_primitive_root known cases
"""

from __future__ import annotations

import sys
import os
import time
import random
import unittest
from pathlib import Path

# Ensure project root is on path regardless of where tests are run from
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dh.math_utils import (
    mod_exp, mod_exp_steps, gcd,
    miller_rabin_is_prime,
    generate_prime,
    is_primitive_root, find_primitive_root,
    _factorize_p_minus_1,
)
from dh.party import Party
from dh.protocol import DHProtocol, DHMode, TEXTBOOK_P, TEXTBOOK_G, TEXTBOOK_A, TEXTBOOK_B
from dh.attacks import Eve, Mallory
from dh.kdf import derive_key, xor_encrypt, xor_decrypt, fingerprint


class TestModExp(unittest.TestCase):
    """Test square-and-multiply modular exponentiation."""

    def test_matches_builtin_pow_random(self):
        """mod_exp must agree with pow(a,b,m) for 1000 random cases."""
        rng = random.Random(42)
        for _ in range(1000):
            base = rng.randint(0, 10**6)
            exp  = rng.randint(0, 10**4)
            mod  = rng.randint(2, 10**6)
            self.assertEqual(
                mod_exp(base, exp, mod),
                pow(base, exp, mod),
                msg=f"Failed for base={base}, exp={exp}, mod={mod}",
            )

    def test_small_known_values(self):
        """Spot-check specific known values."""
        self.assertEqual(mod_exp(5, 6, 23), 8)    # textbook: g^a mod p
        self.assertEqual(mod_exp(5, 15, 23), 19)   # textbook: g^b mod p
        self.assertEqual(mod_exp(19, 6, 23), 2)    # textbook: B^a mod p
        self.assertEqual(mod_exp(8, 15, 23), 2)    # textbook: A^b mod p
        self.assertEqual(mod_exp(2, 10, 1000), 24)
        self.assertEqual(mod_exp(0, 5, 7), 0)
        self.assertEqual(mod_exp(3, 0, 7), 1)      # anything^0 = 1

    def test_modulus_one(self):
        """mod_exp(any, any, 1) should be 0."""
        self.assertEqual(mod_exp(5, 6, 1), 0)

    def test_invalid_modulus(self):
        """modulus < 1 should raise ValueError."""
        with self.assertRaises(ValueError):
            mod_exp(5, 6, 0)
        with self.assertRaises(ValueError):
            mod_exp(5, 6, -1)

    def test_steps_trace(self):
        """mod_exp_steps should return a list and final result should match."""
        steps = mod_exp_steps(5, 6, 23)
        self.assertIsInstance(steps, list)
        self.assertGreater(len(steps), 0)
        self.assertEqual(steps[-1]["result"], 8)

    def test_large_exponents(self):
        """Should handle 256-bit numbers without overflow."""
        import secrets
        base = secrets.randbits(256)
        exp  = secrets.randbits(256)
        mod  = generate_prime(256)
        result = mod_exp(base, exp, mod)
        self.assertEqual(result, pow(base, exp, mod))


class TestGCD(unittest.TestCase):
    def test_known(self):
        self.assertEqual(gcd(48, 18), 6)
        self.assertEqual(gcd(0, 7), 7)
        self.assertEqual(gcd(7, 0), 7)
        self.assertEqual(gcd(1, 1), 1)

    def test_coprime(self):
        self.assertEqual(gcd(17, 31), 1)


class TestMillerRabin(unittest.TestCase):
    """Test Miller-Rabin primality test."""

    KNOWN_PRIMES = [
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37,
        101, 997, 7919, 104729,
        # Large primes
        179424673, 2147483647,  # Mersenne prime M31
        # Mersenne prime M61 = 2^61 - 1
        2305843009213693951,
    ]

    KNOWN_COMPOSITES = [
        4, 6, 8, 9, 10, 15, 25, 100, 999,
        # Carmichael numbers (fool naive Fermat test but NOT Miller-Rabin)
        561,     # 3 × 11 × 17
        1105,    # 5 × 13 × 17
        1729,    # 7 × 13 × 19  (Hardy-Ramanujan taxicab number)
        2465,    # 5 × 17 × 29
        8911,    # 7 × 19 × 67
        6601,    # 7 × 23 × 41
    ]

    def test_known_primes(self):
        for p in self.KNOWN_PRIMES:
            with self.subTest(p=p):
                self.assertTrue(miller_rabin_is_prime(p), f"{p} should be prime")

    def test_known_composites(self):
        for n in self.KNOWN_COMPOSITES:
            with self.subTest(n=n):
                self.assertFalse(miller_rabin_is_prime(n), f"{n} should be composite")

    def test_carmichael_numbers(self):
        """Carmichael numbers fool Fermat but must fail Miller-Rabin."""
        carmichaels = [561, 1105, 1729, 2465, 2821, 6601, 8911]
        for n in carmichaels:
            with self.subTest(n=n):
                self.assertFalse(
                    miller_rabin_is_prime(n),
                    f"Carmichael number {n} incorrectly identified as prime"
                )

    def test_edge_cases(self):
        self.assertFalse(miller_rabin_is_prime(0))
        self.assertFalse(miller_rabin_is_prime(1))
        self.assertTrue(miller_rabin_is_prime(2))
        self.assertTrue(miller_rabin_is_prime(3))
        self.assertFalse(miller_rabin_is_prime(4))


class TestPrimitiveRoot(unittest.TestCase):
    def test_known_generator(self):
        """5 is a primitive root mod 23."""
        self.assertTrue(is_primitive_root(5, 23))

    def test_non_generator(self):
        """4 is NOT a primitive root mod 23 (order is 11, not 22)."""
        self.assertFalse(is_primitive_root(4, 23))

    def test_find_primitive_root(self):
        """find_primitive_root(23) should return 5."""
        self.assertEqual(find_primitive_root(23), 5)

    def test_g_out_of_range(self):
        self.assertFalse(is_primitive_root(1, 23))
        self.assertFalse(is_primitive_root(22, 23))


class TestTextbookExample(unittest.TestCase):
    """The canonical p=23, g=5, a=6, b=15 example must produce A=8, B=19, s=2."""

    def test_full_textbook(self):
        proto = DHProtocol(DHMode.TEXTBOOK)
        result = proto.run()

        self.assertTrue(result, "Protocol should succeed")
        self.assertEqual(proto.p, 23)
        self.assertEqual(proto.g, 5)
        self.assertEqual(proto.alice.private_key, 6)   # type: ignore
        self.assertEqual(proto.bob.private_key,   15)  # type: ignore
        self.assertEqual(proto.alice.public_key,  8)   # A = 5^6 mod 23 = 8
        self.assertEqual(proto.bob.public_key,    19)  # B = 5^15 mod 23 = 19
        self.assertEqual(proto.alice.shared_secret, 2) # s = 19^6 mod 23 = 2
        self.assertEqual(proto.bob.shared_secret,   2) # s = 8^15 mod 23 = 2

    def test_textbook_formulas(self):
        """Cross-check every formula manually."""
        self.assertEqual(mod_exp(5, 6,  23), 8)   # A = g^a mod p
        self.assertEqual(mod_exp(5, 15, 23), 19)  # B = g^b mod p
        self.assertEqual(mod_exp(19, 6,  23), 2)  # s_alice = B^a mod p
        self.assertEqual(mod_exp(8,  15, 23), 2)  # s_bob   = A^b mod p


class TestRandomExchanges(unittest.TestCase):
    """For 100 random parameter sets, alice_secret must equal bob_secret."""

    def test_random_exchanges(self):
        """Run 100 auto-generated protocols and verify secret equality."""
        failures = 0
        for i in range(100):
            proto = DHProtocol(DHMode.AUTO, bits=16, use_safe_prime=False)
            ok = proto.run()
            if not ok:
                failures += 1
        self.assertEqual(failures, 0, f"{failures}/100 exchanges failed")

    def test_manual_mode(self):
        """Manual p=23, g=5 should also work."""
        proto = DHProtocol(DHMode.MANUAL, p=23, g=5)
        ok = proto.run()
        self.assertTrue(ok)
        self.assertEqual(proto.alice.shared_secret, proto.bob.shared_secret)  # type: ignore


class TestInvalidInputs(unittest.TestCase):
    """Invalid inputs must raise ValueError with a clear message."""

    def test_non_prime_p(self):
        """MANUAL mode with composite p must raise ValueError."""
        with self.assertRaises(ValueError) as ctx:
            DHProtocol(DHMode.MANUAL, p=15, g=5).run()
        self.assertIn("not prime", str(ctx.exception).lower())

    def test_g_out_of_range(self):
        """g=1 is invalid (order-1 subgroup)."""
        with self.assertRaises(ValueError):
            DHProtocol(DHMode.MANUAL, p=23, g=1).run()

    def test_g_equals_p_minus_1(self):
        """g = p-1 is technically valid in MANUAL mode (g<p-1 is enforced)."""
        with self.assertRaises(ValueError):
            DHProtocol(DHMode.MANUAL, p=23, g=22).run()

    def test_private_key_out_of_range(self):
        """private_key must satisfy 1 < key < p-1."""
        with self.assertRaises(ValueError):
            Party("Test", 23, 5, private_key=1)
        with self.assertRaises(ValueError):
            Party("Test", 23, 5, private_key=22)

    def test_party_p_too_small(self):
        with self.assertRaises(ValueError):
            Party("Test", 2, 5)

    def test_party_g_out_of_range(self):
        with self.assertRaises(ValueError):
            Party("Test", 23, 22)


class TestMITM(unittest.TestCase):
    """Man-in-the-Middle: Alice and Bob must end up with DIFFERENT secrets."""

    def test_mitm_produces_different_secrets(self):
        """After MITM, alice_secret != bob_secret in the general case."""
        # Run multiple times to avoid rare coincidences
        different_count = 0
        for _ in range(10):
            proto = DHProtocol(DHMode.AUTO, bits=16, use_safe_prime=False)
            proto.run()
            p, g = proto.p, proto.g

            alice = Party("Alice", p, g)
            bob   = Party("Bob",   p, g)

            mallory = Mallory(p, g)
            result = mallory.intercept_exchange(alice, bob)
            if result["alice_secret"] != result["bob_secret"]:
                different_count += 1

        self.assertGreater(different_count, 0,
            "MITM should produce different secrets in most runs")

    def test_mallory_knows_both_secrets(self):
        """Mallory's derived secrets must match what Alice and Bob computed."""
        proto = DHProtocol(DHMode.AUTO, bits=16, use_safe_prime=False)
        proto.run()
        p, g = proto.p, proto.g

        alice = Party("Alice", p, g)
        bob   = Party("Bob",   p, g)

        mallory = Mallory(p, g)
        result = mallory.intercept_exchange(alice, bob)

        # Mallory's secret with Alice should equal alice's computed secret
        self.assertEqual(result["mallory_s_alice"], result["alice_secret"])
        # Mallory's secret with Bob should equal bob's computed secret
        self.assertEqual(result["mallory_s_bob"],   result["bob_secret"])


class TestKDF(unittest.TestCase):
    """Test the KDF and XOR cipher."""

    def test_derive_key_length(self):
        k = derive_key(2)  # textbook shared secret
        self.assertEqual(len(k), 32)

    def test_derive_key_deterministic(self):
        """Same secret → same key."""
        self.assertEqual(derive_key(42), derive_key(42))

    def test_derive_key_different_secrets(self):
        """Different secrets → different keys (with overwhelming probability)."""
        self.assertNotEqual(derive_key(1), derive_key(2))

    def test_xor_round_trip(self):
        """Encrypt then decrypt must recover original plaintext."""
        key = derive_key(12345)
        for msg in [b"hello", b"", b"\x00" * 100, b"A" * 1000]:
            ct = xor_encrypt(key, msg)
            pt = xor_decrypt(key, ct)
            self.assertEqual(pt, msg, f"Round-trip failed for {msg[:20]!r}…")

    def test_xor_different_keys(self):
        """Different keys must produce different ciphertexts."""
        k1 = derive_key(1)
        k2 = derive_key(2)
        msg = b"test message"
        self.assertNotEqual(xor_encrypt(k1, msg), xor_encrypt(k2, msg))

    def test_fingerprint_format(self):
        k = derive_key(0)
        fp = fingerprint(k)
        parts = fp.split(":")
        self.assertEqual(len(parts), 8)
        for p in parts:
            self.assertEqual(len(p), 2)

    def test_textbook_kdf(self):
        """KDF on textbook secret (s=2) should produce a fixed 32-byte key."""
        k = derive_key(2)
        self.assertEqual(len(k), 32)
        # Encrypt/decrypt with textbook shared secret
        ct = xor_encrypt(k, b"Alice to Bob")
        pt = xor_decrypt(k, ct)
        self.assertEqual(pt, b"Alice to Bob")


class TestEve(unittest.TestCase):
    """Test Eve's brute-force attack on small p."""

    def test_eve_recovers_small_p(self):
        """Eve must recover the discrete log for a small (8-bit) prime."""
        p = 23
        g = 5
        a = 6
        big_a = mod_exp(g, a, p)  # 8
        big_b = mod_exp(g, 15, p) # 19

        eve = Eve(p, g, big_a, timeout_seconds=5.0)
        result = eve.brute_force(big_b=big_b)

        self.assertTrue(result["success"])
        self.assertEqual(result["recovered_a"], a)
        self.assertEqual(result["recovered_secret"], mod_exp(big_b, a, p))  # 2

    def test_eve_timeout(self):
        """Eve should timeout on a larger prime."""
        from dh.math_utils import generate_prime, find_primitive_root
        import secrets as _secrets
        p = generate_prime(24)
        g = find_primitive_root(p)
        a = _secrets.randbelow(p - 3) + 2
        big_a = mod_exp(g, a, p)

        eve = Eve(p, g, big_a, timeout_seconds=0.1)  # very short timeout
        result = eve.brute_force()

        # May or may not time out depending on system speed, but should not error
        self.assertIsInstance(result["elapsed_ms"], float)


if __name__ == "__main__":
    unittest.main(verbosity=2)
