"""Bitcoin script numbers (``CScriptNum``) and the boolean cast.

Script integers are stored as little-endian, sign-magnitude byte vectors: the
high bit of the most-significant byte is the sign, and there is no fixed width.
Arithmetic opcodes operate on at most 4-byte operands (``CHECKLOCKTIMEVERIFY``
allows 5). "Minimal encoding" forbids redundant trailing ``0x00`` padding.
"""

from __future__ import annotations

__all__ = [
    "encode_num",
    "decode_num",
    "cast_to_bool",
    "MAX_NUM_SIZE",
]

MAX_NUM_SIZE = 4


def encode_num(value: int) -> bytes:
    """Encode a Python ``int`` as a minimally-encoded script number."""
    if value == 0:
        return b""
    result = bytearray()
    negative = value < 0
    abs_val = -value if negative else value
    while abs_val:
        result.append(abs_val & 0xFF)
        abs_val >>= 8
    # If the top byte already uses the sign bit, add an extra byte to carry the
    # sign; otherwise fold the sign into the existing top byte.
    if result[-1] & 0x80:
        result.append(0x80 if negative else 0x00)
    elif negative:
        result[-1] |= 0x80
    return bytes(result)


def decode_num(data: bytes, *, require_minimal: bool = True, max_size: int = MAX_NUM_SIZE) -> int:
    """Decode a script-number byte vector into a Python ``int``.

    Raises :class:`ValueError` if ``data`` exceeds ``max_size`` bytes, or if
    ``require_minimal`` is set and the encoding has redundant padding.
    """
    if len(data) > max_size:
        raise ValueError(f"script number overflow: {len(data)} > {max_size} bytes")
    if not data:
        return 0
    if require_minimal:
        # The most significant byte must carry meaning: it may not be 0x00 or
        # 0x80 unless the next byte down already sets the sign bit.
        if (data[-1] & 0x7F) == 0:
            if len(data) <= 1 or (data[-2] & 0x80) == 0:
                raise ValueError("non-minimally encoded script number")
    result = 0
    for i, byte in enumerate(data):
        result |= byte << (8 * i)
    # Apply the sign bit from the most-significant byte.
    if data[-1] & 0x80:
        result &= ~(0x80 << (8 * (len(data) - 1)))
        return -result
    return result


def cast_to_bool(data: bytes) -> bool:
    """Mirror Bitcoin Core's ``CastToBool``.

    A byte vector is true unless every byte is zero, allowing a trailing
    ``0x80`` sign bit on the last byte (so negative zero is still false).
    """
    for i, byte in enumerate(data):
        if byte != 0:
            if i == len(data) - 1 and byte == 0x80:
                return False
            return True
    return False
