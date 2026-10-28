"""
dh – Diffie-Hellman Key Exchange library
=========================================
Public API surface exposed at the package level for convenience.
"""

from .math_utils import (
    mod_exp,
    miller_rabin_is_prime,
    generate_prime,
    generate_safe_prime,
    is_primitive_root,
    find_primitive_root,
    gcd,
)
from .party import Party
from .protocol import DHProtocol, DHMode
from .attacks import Eve, Mallory
from .kdf import derive_key, xor_encrypt, xor_decrypt
from .transport import get_lan_ips, send_msg, recv_msg, compute_key_fingerprint

__all__ = [
    "mod_exp",
    "miller_rabin_is_prime",
    "generate_prime",
    "generate_safe_prime",
    "is_primitive_root",
    "find_primitive_root",
    "gcd",
    "Party",
    "DHProtocol",
    "DHMode",
    "Eve",
    "Mallory",
    "derive_key",
    "xor_encrypt",
    "xor_decrypt",
    "get_lan_ips",
    "send_msg",
    "recv_msg",
    "compute_key_fingerprint",
]
