"""Taproot x-only public-key tweaking (BIP341), on ``secp256k1lab``.

Given an internal x-only key P and a 32-byte tweak t, the output key is
``Q = P + t*G`` (P lifted to even-y). Returns Q's x-only bytes and its y parity,
which the control-block commitment check compares against.
"""

from __future__ import annotations

from secp256k1lab.secp256k1 import G, GE, Scalar

__all__ = ["taproot_tweak_pubkey"]


def taproot_tweak_pubkey(internal_xonly: bytes, tweak32: bytes) -> tuple[bytes, int] | None:
    """Return ``(output_xonly, parity)`` for the tweaked key, or ``None``.

    ``parity`` is 0 if the output point has even y, else 1 -- matching the low
    bit of a Taproot control block.
    """
    if len(internal_xonly) != 32 or len(tweak32) != 32:
        return None
    try:
        P = GE.lift_x(int.from_bytes(internal_xonly, "big"))
    except (ValueError, AssertionError):
        return None
    t = int.from_bytes(tweak32, "big")
    if t >= GE.ORDER:
        return None
    Q = P + (Scalar(t) * G if t != 0 else GE())
    if Q.infinity:
        return None
    return Q.to_bytes_xonly(), 0 if Q.has_even_y() else 1
