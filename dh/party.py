"""
party.py – The Party class representing Alice or Bob
=====================================================
Each party in a Diffie-Hellman exchange holds:
  * a name (for display)
  * the shared public parameters p and g
  * its own private key a (or b) – chosen with secrets.randbelow
  * its public value A = g^a mod p
  * (after exchange) the computed shared secret

Design note
-----------
Private keys are generated with the `secrets` module (CSPRNG), never
with `random`.  This mirrors real-world practice.

The Party never sends its private key; the protocol only calls
`receive_public_value()` with the *other* party's public value, then
`compute_shared_secret()` derives s = received_value^private_key mod p.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Optional

from .math_utils import mod_exp


@dataclass
class Party:
    """Represents one participant in a Diffie-Hellman key exchange.

    Parameters
    ----------
    name         : Human-readable label, e.g. "Alice".
    p            : Public prime modulus.
    g            : Public generator (primitive root mod p, or at least 2 ≤ g ≤ p-2).
    private_key  : If provided, use this value instead of generating one.
                   Must satisfy 1 < private_key < p-1.  Intended for the
                   textbook preset (a=6, b=15) and for testing only.
    """

    name: str
    p: int
    g: int
    private_key: Optional[int] = field(default=None, repr=False)

    # Computed automatically after __post_init__
    public_key: int = field(init=False)

    # Set after the exchange
    _received_public: Optional[int] = field(default=None, init=False, repr=False)
    _shared_secret: Optional[int] = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        """Validate parameters and compute the public key."""
        if self.p < 3:
            raise ValueError(f"p must be ≥ 3, got {self.p}")
        if not (2 <= self.g <= self.p - 2):
            raise ValueError(
                f"g must satisfy 2 ≤ g ≤ p-2; got g={self.g}, p={self.p}"
            )

        if self.private_key is None:
            # Generate a random private key in the range (1, p-1)
            # secrets.randbelow(p-2) gives [0, p-3), so add 2 → (1, p-1)
            self.private_key = secrets.randbelow(self.p - 3) + 2
        else:
            if not (1 < self.private_key < self.p - 1):
                raise ValueError(
                    f"private_key must satisfy 1 < key < p-1; "
                    f"got {self.private_key} with p={self.p}"
                )

        # A = g^a mod p  (or B = g^b mod p for Bob)
        self.public_key = mod_exp(self.g, self.private_key, self.p)

    # ------------------------------------------------------------------
    # Exchange API
    # ------------------------------------------------------------------

    def receive_public_value(self, other_public: int) -> None:
        """Store the other party's public key received over the public channel.

        Parameters
        ----------
        other_public : int
            The public value sent by the other party (A or B).

        Raises
        ------
        ValueError
            If the received value is outside the valid range [2, p-2].
        """
        if not (2 <= other_public <= self.p - 2):
            raise ValueError(
                f"Received public value {other_public} is out of range [2, {self.p-2}]"
            )
        self._received_public = other_public

    def compute_shared_secret(self) -> int:
        """Compute and cache the shared secret.

        Formula
        -------
        Alice computes:  s = B^a mod p
        Bob   computes:  s = A^b mod p

        Both yield the same value because:
            (g^b)^a ≡ g^(ab) ≡ (g^a)^b  (mod p)

        Returns
        -------
        int
            The shared secret s.

        Raises
        ------
        RuntimeError
            If `receive_public_value` has not been called first.
        """
        if self._received_public is None:
            raise RuntimeError(
                f"{self.name} has not received the other party's public value yet."
            )
        self._shared_secret = mod_exp(
            self._received_public, self.private_key, self.p  # type: ignore[arg-type]
        )
        return self._shared_secret

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def shared_secret(self) -> Optional[int]:
        """The shared secret, or None if not yet computed."""
        return self._shared_secret

    @property
    def received_public(self) -> Optional[int]:
        """The other party's public value, or None if not yet received."""
        return self._received_public

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def summary(self) -> dict:
        """Return a dictionary suitable for display or serialization."""
        return {
            "name": self.name,
            "p": self.p,
            "g": self.g,
            "private_key": self.private_key,  # ← keep hidden in UI!
            "public_key": self.public_key,
            "received_public": self._received_public,
            "shared_secret": self._shared_secret,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"Party(name={self.name!r}, "
            f"public_key={self.public_key}, "
            f"shared_secret={self._shared_secret})"
        )
