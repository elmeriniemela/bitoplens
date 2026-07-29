"""Address encoding: base58check (P2PKH/P2SH) and bech32/bech32m (segwit).

Only the encode direction (script -> address) is needed for the visualizer's
transaction panel. Implements BIP173 (bech32) and BIP350 (bech32m).
"""

from __future__ import annotations

from bitoplens.primitives.hashing import hash256
from bitoplens.script.opcodes import classify_script

__all__ = ["script_to_address", "base58check_encode", "bech32_encode"]

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

BECH32_CONST = 1
BECH32M_CONST = 0x2BC830A3


def base58check_encode(payload: bytes) -> str:
    """Base58Check-encode ``payload`` (version byte + data)."""
    checksum = hash256(payload)[:4]
    data = payload + checksum
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    # Preserve leading zero bytes as '1'.
    for b in data:
        if b == 0:
            out = "1" + out
        else:
            break
    return out


def _polymod(values) -> int:
    generators = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= generators[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def bech32_encode(hrp: str, witver: int, program: bytes) -> str:
    """Encode a segwit address (bech32 for v0, bech32m for v1+)."""
    data = [witver] + _convertbits(program, 8, 5)
    const = BECH32_CONST if witver == 0 else BECH32M_CONST
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in data + checksum)


def script_to_address(script_pubkey: bytes, hrp: str = "bc") -> str | None:
    """Return a canonical address string for a standard scriptPubKey, or None.

    ``hrp`` is the bech32 human-readable prefix (``bc`` mainnet, ``tb`` testnet,
    ``bcrt`` regtest); base58 version bytes are mainnet.
    """
    b = bytes(script_pubkey)
    kind = classify_script(b)
    if kind == "P2PKH":
        return base58check_encode(b"\x00" + b[3:23])
    if kind == "P2SH":
        return base58check_encode(b"\x05" + b[2:22])
    if kind == "P2WPKH":
        return bech32_encode(hrp, 0, b[2:22])
    if kind == "P2WSH":
        return bech32_encode(hrp, 0, b[2:34])
    if kind == "P2TR":
        return bech32_encode(hrp, 1, b[2:34])
    if kind.startswith("witness v"):
        version = int(kind.split()[1][1:])
        return bech32_encode(hrp, version, b[2:])
    return None
