"""BIP340 Schnorr verification, wrapping ``secp256k1lab.bip340``."""

from __future__ import annotations

from secp256k1lab import bip340

__all__ = ["verify_schnorr"]


def verify_schnorr(sig64: bytes, pubkey_xonly: bytes, msg: bytes) -> bool:
    """Verify a 64-byte BIP340 Schnorr signature over ``msg``.

    ``pubkey_xonly`` is the 32-byte x-only public key. Returns ``False`` for
    malformed inputs rather than raising.
    """
    if len(sig64) != 64 or len(pubkey_xonly) != 32:
        return False
    try:
        return bip340.schnorr_verify(msg, pubkey_xonly, sig64)
    except (ValueError, AssertionError):
        return False
