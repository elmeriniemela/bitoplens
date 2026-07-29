"""Test-only helpers: a small ECDSA signer built on secp256k1lab.

The library itself never signs (it's a verifier/debugger), but tests need to
construct valid signatures to exercise CHECKSIG / CHECKMULTISIG / CLTV / CSV and
the various SIGHASH types. This deterministic signer is for tests only.
"""

from __future__ import annotations

import bitoplens.crypto  # noqa: F401  (runs the vendored-secp256k1lab path bootstrap)
from secp256k1lab.secp256k1 import G, Scalar

from bitoplens.primitives.hashing import hash256

ORDER = Scalar.SIZE
HALF = ORDER // 2


def pubkey(d: int, *, compressed: bool = True) -> bytes:
    P = Scalar(d) * G
    return P.to_bytes_compressed() if compressed else P.to_bytes_uncompressed()


def _enc_int(x: int) -> bytes:
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def _der(r: int, s: int) -> bytes:
    body = _enc_int(r) + _enc_int(s)
    return b"\x30" + bytes([len(body)]) + body


def ecdsa_sign(msg32: bytes, d: int) -> bytes:
    """Deterministic low-S ECDSA signature (DER, no hashtype byte)."""
    z = int.from_bytes(msg32, "big") % ORDER
    counter = 0
    while True:
        k = int.from_bytes(hash256(d.to_bytes(32, "big") + msg32 + bytes([counter])), "big") % ORDER
        counter += 1
        if k == 0:
            continue
        R = Scalar(k) * G
        r = int(R.x) % ORDER
        if r == 0:
            continue
        s = (pow(k, -1, ORDER) * (z + r * d)) % ORDER
        if s == 0:
            continue
        if s > HALF:
            s = ORDER - s
        return _der(r, s)


def sign_input(checker_sighash, d: int, hashtype: int = 0x01) -> bytes:
    """Given a 32-byte sighash, return a DER signature + hashtype byte."""
    return ecdsa_sign(checker_sighash, d) + bytes([hashtype])


# --------------------------------------------------------------------------- #
# Taproot (BIP340/341/342) signing helpers
# --------------------------------------------------------------------------- #

from secp256k1lab import bip340  # noqa: E402

from bitoplens.primitives.hashing import tagged_hash  # noqa: E402


def xonly_pubkey(d: int) -> bytes:
    return bip340.pubkey_gen(d.to_bytes(32, "big"))


def even_y_seckey(d: int) -> tuple[int, bytes]:
    """Return ``(d_even, internal_xonly)`` where ``d_even*G`` has even y."""
    P = Scalar(d) * G
    d_even = d if P.has_even_y() else ORDER - d
    return d_even, (Scalar(d_even) * G).to_bytes_xonly()


def taproot_output(internal_d: int, merkle_root: bytes = b""):
    """Return ``(output_xonly, parity, tweaked_seckey, internal_xonly, tweak)``."""
    d_even, internal_xonly = even_y_seckey(internal_d)
    tweak = tagged_hash("TapTweak", internal_xonly + merkle_root)
    q = (d_even + int.from_bytes(tweak, "big")) % ORDER
    Q = Scalar(q) * G
    return Q.to_bytes_xonly(), (0 if Q.has_even_y() else 1), q, internal_xonly, tweak


def schnorr_sign(msg32: bytes, d: int) -> bytes:
    return bip340.schnorr_sign(msg32, d.to_bytes(32, "big"), b"\x00" * 32)
