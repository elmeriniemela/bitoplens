"""ECDSA verification and DER encoding checks for secp256k1.

``secp256k1lab`` deliberately ships no ECDSA, so this module implements verify
(and the BIP66 strict-DER / low-S / hashtype checks) on top of its ``FE`` /
``GE`` / ``Scalar`` / ``G`` primitives. Only *verification* is needed -- the
simulator never signs with ECDSA.
"""

from __future__ import annotations

from secp256k1lab.secp256k1 import G, GE, Scalar

__all__ = [
    "verify_ecdsa",
    "parse_der",
    "is_valid_der_encoding",
    "is_low_s",
    "SECP256K1_ORDER",
    "SECP256K1_HALF_ORDER",
]

SECP256K1_ORDER = GE.ORDER
SECP256K1_HALF_ORDER = GE.ORDER // 2


def parse_der(sig: bytes) -> tuple[int, int] | None:
    """Leniently parse a DER ECDSA signature into ``(r, s)``.

    Returns ``None`` if the structure is unparseable. Strict BIP66 conformance
    is a separate check (:func:`is_valid_der_encoding`).
    """
    try:
        if len(sig) < 6 or sig[0] != 0x30:
            return None
        if sig[2] != 0x02:
            return None
        rlen = sig[3]
        if 4 + rlen + 2 > len(sig):
            return None
        r = int.from_bytes(sig[4 : 4 + rlen], "big")
        s_off = 4 + rlen
        if sig[s_off] != 0x02:
            return None
        slen = sig[s_off + 1]
        if s_off + 2 + slen > len(sig):
            return None
        s = int.from_bytes(sig[s_off + 2 : s_off + 2 + slen], "big")
        return r, s
    except (IndexError, ValueError):
        return None


def is_valid_der_encoding(sig: bytes) -> bool:
    """BIP66 strict DER check on a signature *including* its hashtype byte.

    Mirrors Bitcoin Core's ``IsValidSignatureEncoding``.
    """
    n = len(sig)
    if n < 9 or n > 73:
        return False
    if sig[0] != 0x30:
        return False
    if sig[1] != n - 3:
        return False
    lenR = sig[3]
    if 5 + lenR >= n:
        return False
    lenS = sig[5 + lenR]
    if lenR + lenS + 7 != n:
        return False
    if sig[2] != 0x02:
        return False
    if lenR == 0:
        return False
    if sig[4] & 0x80:
        return False
    if lenR > 1 and sig[4] == 0x00 and not (sig[5] & 0x80):
        return False
    if sig[6 + lenR] != 0x02:
        return False
    if lenS == 0:
        return False
    if sig[6 + lenR] != 0x02:
        return False
    if sig[6 + lenR + 1] & 0x80:
        return False
    if lenS > 1 and sig[6 + lenR + 1] == 0x00 and not (sig[6 + lenR + 2] & 0x80):
        return False
    return True


def is_low_s(sig: bytes) -> bool:
    """Return True if the DER signature (with hashtype byte) has a low S value."""
    parsed = parse_der(sig[:-1] if sig else sig)
    if parsed is None:
        return False
    _r, s = parsed
    return s <= SECP256K1_HALF_ORDER


def verify_ecdsa(sig_der: bytes, pubkey: bytes, msg32: bytes) -> bool:
    """Verify a DER ECDSA signature (no hashtype byte) over the 32-byte hash.

    Returns ``False`` for any malformed input rather than raising.
    """
    parsed = parse_der(sig_der)
    if parsed is None:
        return False
    r, s = parsed
    n = SECP256K1_ORDER
    if not (1 <= r < n and 1 <= s < n):
        return False
    try:
        P = GE.from_bytes(pubkey)
    except (ValueError, AssertionError):
        return False
    z = int.from_bytes(msg32, "big") % n
    try:
        w = pow(s, -1, n)
    except ValueError:
        return False
    u1 = (z * w) % n
    u2 = (r * w) % n
    R = GE.batch_mul((Scalar(u1), G), (Scalar(u2), P))
    if R.infinity:
        return False
    return (int(R.x) % n) == r
