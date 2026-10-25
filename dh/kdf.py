"""
kdf.py – Key Derivation and Demonstration Cipher
=================================================
After both parties hold the same shared secret integer s, two steps are needed
before using it for symmetric encryption:

1. Key Derivation (KDF)
   The integer s may be biased (small or have a specific structure).
   We hash it with SHA-256 to produce a uniformly distributed 256-bit key:
       K = SHA-256( s.to_bytes(...) )
   This follows the pattern used in real protocols (TLS, Signal, etc.).

2. Demo XOR stream cipher (counter mode)
   To prove both parties hold the same key without introducing AES, we use a
   simple keystream derived from K:
       keystream_block_i = SHA-256(K || i.to_bytes(4, 'big'))
   Plaintext is XOR-ed with the keystream byte by byte.
   This is a *teaching demo only* – it is not production-safe (e.g., it lacks
   authentication and nonce management).

WARNING
-------
The XOR cipher here is for educational demonstration of shared-key possession
ONLY.  Do NOT use it for real data.
"""

from __future__ import annotations

import hashlib
import struct


def _int_to_bytes(n: int) -> bytes:
    """Convert a non-negative integer to its big-endian byte representation."""
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


def derive_key(shared_secret: int, info: bytes = b"DH-demo-v1") -> bytes:
    """Derive a 256-bit symmetric key from the DH shared secret.

    Uses HKDF-Extract style: K = SHA-256(info || shared_secret_bytes).
    For a real implementation, use a proper HKDF (RFC 5869).

    Parameters
    ----------
    shared_secret : int
        The integer produced by the DH exchange.
    info : bytes
        Domain-separation / context string.

    Returns
    -------
    bytes
        32-byte (256-bit) symmetric key.

    Example
    -------
    >>> k = derive_key(2)  # textbook shared secret
    >>> len(k)
    32
    """
    secret_bytes = _int_to_bytes(shared_secret)
    h = hashlib.sha256()
    h.update(info)
    h.update(secret_bytes)
    return h.digest()


def _keystream(key: bytes, length: int) -> bytes:
    """Generate *length* pseudorandom bytes from *key* using SHA-256 counter mode.

    keystream = SHA-256(key || 0) || SHA-256(key || 1) || …
    Truncated to *length* bytes.
    """
    output = bytearray()
    block = 0
    while len(output) < length:
        h = hashlib.sha256()
        h.update(key)
        h.update(struct.pack(">I", block))
        output.extend(h.digest())
        block += 1
    return bytes(output[:length])


def xor_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt *plaintext* with the SHA-256 counter-mode keystream.

    Parameters
    ----------
    key       : 32-byte key from derive_key()
    plaintext : arbitrary bytes

    Returns
    -------
    bytes
        Ciphertext of the same length as plaintext.

    Example
    -------
    >>> k = derive_key(2)
    >>> ct = xor_encrypt(k, b"Hello, Bob!")
    >>> xor_decrypt(k, ct)
    b'Hello, Bob!'
    """
    ks = _keystream(key, len(plaintext))
    return bytes(p ^ k for p, k in zip(plaintext, ks))


def xor_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt *ciphertext* encrypted with xor_encrypt().

    XOR is its own inverse: decrypt = encrypt.
    Provided as a separate function for clarity.

    Parameters
    ----------
    key        : 32-byte key from derive_key()
    ciphertext : bytes produced by xor_encrypt()

    Returns
    -------
    bytes
        Recovered plaintext.
    """
    return xor_encrypt(key, ciphertext)  # XOR is self-inverse


def fingerprint(key: bytes) -> str:
    """Return a short hex fingerprint (first 8 bytes) of the key.

    Used to visually compare keys on both sides without printing the full key.

    Example
    -------
    >>> fingerprint(b'\\x00' * 32)
    '00:00:00:00:00:00:00:00'
    """
    return ":".join(f"{b:02x}" for b in key[:8])
