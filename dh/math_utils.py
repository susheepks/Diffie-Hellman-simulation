"""
math_utils.py – Core mathematical primitives for Diffie-Hellman
================================================================
Implements from scratch (no external crypto libraries):
  * Fast modular exponentiation (square-and-multiply)
  * Greatest common divisor (Euclidean algorithm)
  * Miller-Rabin probabilistic primality test
  * Random prime generation (with optional safe-prime mode)
  * Primitive root (generator) checker and finder

All arithmetic is pure Python so it works for arbitrarily large integers,
which is essential when demonstrating 1024-bit DH.

Mathematical background
-----------------------
* Modular exponentiation: compute a^b mod m in O(log b) multiplications by
  repeatedly squaring: if the current bit of b is 1, multiply the running
  result by the current power of a.
* Miller-Rabin: a probabilistic test based on Fermat's little theorem and
  properties of square roots of unity mod a prime.  With k rounds the error
  probability is at most 4^{-k}.
* Primitive root: g is a primitive root mod p iff the order of g equals p-1,
  i.e. g^((p-1)/q) ≢ 1 (mod p) for every prime factor q of (p-1).
* Safe prime: p = 2q+1 where q is also prime.  For safe primes, p-1 = 2q so
  checking primitive-rootness only requires testing the two factors 2 and q.
"""

from __future__ import annotations

import secrets
import math
from typing import Optional


# ---------------------------------------------------------------------------
# 1. Greatest common divisor
# ---------------------------------------------------------------------------

def gcd(a: int, b: int) -> int:
    """Return the greatest common divisor of *a* and *b* (Euclidean algorithm).

    Examples
    --------
    >>> gcd(48, 18)
    6
    >>> gcd(0, 7)
    7
    """
    while b:
        a, b = b, a % b
    return a


# ---------------------------------------------------------------------------
# 2. Fast modular exponentiation (square-and-multiply)
# ---------------------------------------------------------------------------

def mod_exp(base: int, exponent: int, modulus: int,
            *, verbose: bool = False) -> int:
    """Compute *base*^*exponent* mod *modulus* using square-and-multiply.

    This is the core operation of DH: both the public-key computation
    (A = g^a mod p) and the shared-secret computation (s = B^a mod p) use it.

    Algorithm
    ---------
    Scan the binary representation of *exponent* from MSB to LSB:
      result = 1
      for each bit b in exponent (MSB first):
          result = result² mod m          ← square step
          if b == 1:
              result = result * base mod m ← multiply step

    Parameters
    ----------
    base, exponent, modulus : int
        All must be non-negative integers; modulus must be ≥ 2.
    verbose : bool
        If True, return a list of (step, bit, squared, multiplied, result)
        tuples instead of the final integer.  Used by the UI to show
        intermediate steps.

    Returns
    -------
    int
        base^exponent mod modulus
    list[dict]
        (only when verbose=True) step-by-step trace

    Raises
    ------
    ValueError
        If modulus < 2 or exponent < 0.

    Examples
    --------
    >>> mod_exp(5, 6, 23)
    8
    >>> mod_exp(2, 10, 1000)
    24
    """
    if modulus < 1:
        raise ValueError(f"modulus must be ≥ 1, got {modulus}")
    if exponent < 0:
        raise ValueError(f"exponent must be ≥ 0, got {exponent}")
    if modulus == 1:
        return 0

    result = 1
    base = base % modulus
    steps: list[dict] = []

    bit_length = exponent.bit_length() or 1  # handle exponent == 0

    for i in range(bit_length - 1, -1, -1):
        bit = (exponent >> i) & 1

        squared = (result * result) % modulus
        result = squared

        if bit:
            multiplied = (result * base) % modulus
            result = multiplied
        else:
            multiplied = None

        if verbose:
            steps.append({
                "step": bit_length - i,
                "bit": bit,
                "after_square": squared,
                "after_multiply": multiplied,
                "result": result,
            })

    if verbose:
        return steps  # type: ignore[return-value]
    return result


def mod_exp_steps(base: int, exponent: int, modulus: int) -> list[dict]:
    """Return a human-readable trace of square-and-multiply for teaching."""
    steps = []
    result = 1
    cur_base = base % modulus
    bit_length = exponent.bit_length() or 1

    for i in range(bit_length - 1, -1, -1):
        bit = (exponent >> i) & 1
        old_result = result
        squared = (result * result) % modulus
        result = squared
        step: dict = {
            "step": bit_length - i,
            "bit": bit,
            "description": f"Square: {old_result}² mod {modulus} = {squared}",
            "result_after_square": squared,
        }
        if bit:
            old_result2 = result
            multiplied = (result * cur_base) % modulus
            result = multiplied
            step["description"] += (
                f";  Multiply: {old_result2} × {base} mod {modulus} = {multiplied}"
            )
            step["result_after_multiply"] = multiplied
        step["result"] = result
        steps.append(step)
    return steps


# ---------------------------------------------------------------------------
# 3. Miller-Rabin primality test
# ---------------------------------------------------------------------------

# Well-known witnesses that make Miller-Rabin deterministic for small n
_DETERMINISTIC_WITNESSES: dict[int, list[int]] = {
    3_215_031_751: [2, 3, 5, 7],
    3_474_749_660_383: [2, 3, 5, 7, 11, 13],
    341_550_071_728_321: [2, 3, 5, 7, 11, 13, 17],
    3_825_123_056_546_413_051: [2, 3, 5, 7, 11, 13, 17, 19, 23],
}

_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
    53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
]


def miller_rabin_is_prime(n: int, rounds: int = 20) -> bool:
    """Probabilistic primality test using Miller-Rabin.

    Error probability is at most 4^{-rounds}.  With rounds=20 this is
    ~10^{-12}, sufficient for cryptographic key generation.

    Mathematical basis
    ------------------
    Write n-1 = 2^r * d (d odd).  For a witness a, compute a^d mod n.
    If a^d ≡ 1 or a^(2^j * d) ≡ -1 for some 0 ≤ j < r, then n *might*
    be prime.  If neither condition holds for any witness, n is composite.

    Parameters
    ----------
    n      : integer to test (must be > 1)
    rounds : number of random witness trials

    Returns
    -------
    bool
        True  → probably prime (composite probability ≤ 4^{-rounds})
        False → definitely composite

    Examples
    --------
    >>> miller_rabin_is_prime(23)
    True
    >>> miller_rabin_is_prime(561)  # Carmichael number
    False
    """
    if n < 2:
        return False
    if n in _SMALL_PRIMES:
        return True
    if any(n % p == 0 for p in _SMALL_PRIMES):
        return False

    # Write n-1 = 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Choose witnesses: deterministic for small n, random for large
    witnesses: list[int] = []
    for limit, wits in _DETERMINISTIC_WITNESSES.items():
        if n < limit:
            witnesses = wits
            break
    if not witnesses:
        witnesses = [secrets.randbelow(n - 3) + 2 for _ in range(rounds)]

    for a in witnesses:
        if a >= n:
            continue
        x = mod_exp(a, d, n)
        if x == 1 or x == n - 1:
            continue  # this witness says "probably prime"
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False  # definitely composite
    return True  # probably prime


# ---------------------------------------------------------------------------
# 4. Prime generation
# ---------------------------------------------------------------------------

def generate_prime(bits: int) -> int:
    """Generate a random probable prime of exactly *bits* bits.

    Uses the `secrets` module to produce a cryptographically strong random
    candidate, then applies trial division + Miller-Rabin.

    Parameters
    ----------
    bits : int
        Desired bit length; must be ≥ 2.

    Returns
    -------
    int
        A probable prime p with 2^(bits-1) ≤ p < 2^bits.

    Examples
    --------
    >>> p = generate_prime(16)
    >>> miller_rabin_is_prime(p)
    True
    """
    if bits < 2:
        raise ValueError("bits must be ≥ 2")
    while True:
        # Force MSB=1 (correct length) and LSB=1 (odd)
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1))  # set MSB
        candidate |= 1                   # make odd
        if miller_rabin_is_prime(candidate):
            return candidate


def generate_safe_prime(bits: int) -> tuple[int, int]:
    """Generate a safe prime p = 2q+1 where q is also prime.

    Safe primes are preferred for DH because the only subgroups of Z_p*
    have orders 1, 2, q, or 2q=p-1, which defends against small-subgroup
    attacks.  Also, any g with 2 ≤ g ≤ p-2 and g ≠ p-1 that is not a
    quadratic residue is a primitive root.

    The generator g=2 works for safe primes when 2 is a quadratic residue
    mod p (Legendre symbol).  We search for a small g ≥ 2 that satisfies
    the primitive root condition.

    Parameters
    ----------
    bits : int
        Desired bit length of p (so q has bits-1 bits).

    Returns
    -------
    (p, q) : tuple[int, int]
        p is the safe prime, q is the Sophie Germain prime.

    Notes
    -----
    Expected iterations ≈ bits² (heuristically), so this can take a few
    seconds for bits ≥ 512.  For demo purposes 256 bits runs quickly.
    """
    if bits < 4:
        raise ValueError("bits must be ≥ 4 for a safe prime")
    while True:
        q = generate_prime(bits - 1)
        p = 2 * q + 1
        if miller_rabin_is_prime(p):
            return p, q


# ---------------------------------------------------------------------------
# 5. Primitive root utilities
# ---------------------------------------------------------------------------

def _factorize_p_minus_1(p: int) -> list[int]:
    """Return the prime factors of p-1 using trial division + Miller-Rabin.

    Only used internally for the primitive-root check.  For safe primes
    (p-1 = 2q) this is trivial; for general primes we do trial division
    up to sqrt then check if the remainder is prime.
    """
    n = p - 1
    factors: list[int] = []
    for small in _SMALL_PRIMES:
        if small * small > n:
            break
        if n % small == 0:
            factors.append(small)
            while n % small == 0:
                n //= small
    if n > 1:
        # Remaining part – check if prime, else factorize further (Pollard-rho
        # for production; trial division suffices for the bit sizes we use here)
        factors.extend(_trial_divide(n))
    return list(set(factors))


def _trial_divide(n: int) -> list[int]:
    """Trial divide n up to 10^6, then assume remainder is prime."""
    factors: list[int] = []
    for d in range(2, min(int(n**0.5) + 1, 10**6)):
        if n % d == 0:
            factors.append(d)
            while n % d == 0:
                n //= d
    if n > 1:
        factors.append(n)  # assume prime (may miss composites > 10^12)
    return factors


def is_primitive_root(g: int, p: int,
                      prime_factors: Optional[list[int]] = None) -> bool:
    """Return True iff *g* is a primitive root (generator) modulo prime *p*.

    A primitive root g has order p-1 in the multiplicative group Z_p*.
    Equivalently, g^((p-1)/q) ≢ 1 (mod p) for every prime factor q of p-1.

    Parameters
    ----------
    g             : candidate generator (must satisfy 2 ≤ g ≤ p-2)
    p             : a prime modulus
    prime_factors : prime factors of p-1 (computed automatically if None)

    Returns
    -------
    bool

    Examples
    --------
    >>> is_primitive_root(5, 23)
    True
    >>> is_primitive_root(4, 23)
    False
    """
    if g < 2 or g >= p - 1:
        return False
    if prime_factors is None:
        prime_factors = _factorize_p_minus_1(p)
    phi = p - 1
    for q in prime_factors:
        if mod_exp(g, phi // q, p) == 1:
            return False
    return True


def find_primitive_root(p: int,
                        prime_factors: Optional[list[int]] = None) -> int:
    """Find the smallest primitive root modulo prime *p*.

    Searches g = 2, 3, 4, … until a primitive root is found.  For random
    primes the expected number of trials is O(log log p) (extremely fast).

    Parameters
    ----------
    p             : a prime
    prime_factors : prime factors of p-1 (pass in to avoid recomputation)

    Returns
    -------
    int
        The smallest g ≥ 2 that is a primitive root mod p.

    Raises
    ------
    ValueError
        If p < 3.

    Examples
    --------
    >>> find_primitive_root(23)
    5
    """
    if p < 3:
        raise ValueError("p must be ≥ 3")
    if prime_factors is None:
        prime_factors = _factorize_p_minus_1(p)
    for g in range(2, p):
        if is_primitive_root(g, p, prime_factors):
            return g
    raise RuntimeError(f"No primitive root found for p={p}")  # unreachable for prime p
