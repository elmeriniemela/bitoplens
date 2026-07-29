"""Low-level (de)serialization helpers for Bitcoin's wire format.

Bitcoin uses little-endian integers and a "compact size" length prefix
(a.k.a. varint) for counts and byte-vector lengths. :class:`Cursor` is a small
forward reader over a ``bytes`` buffer that the transaction and script parsers
use to consume fields without index bookkeeping.
"""

from __future__ import annotations

__all__ = [
    "Cursor",
    "read_compact_size",
    "encode_compact_size",
]


class Cursor:
    """A forward-only reader over a ``bytes`` buffer.

    Every ``read_*`` advances the internal position and raises
    :class:`ValueError` on truncation, so parsers can assume well-formed input
    once a read returns.
    """

    __slots__ = ("data", "pos")

    def __init__(self, data: bytes, pos: int = 0):
        self.data = bytes(data)
        self.pos = pos

    def __len__(self) -> int:
        return len(self.data)

    @property
    def remaining(self) -> int:
        return len(self.data) - self.pos

    def eof(self) -> bool:
        return self.pos >= len(self.data)

    def read(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ValueError(
                f"unexpected end of data: wanted {n} bytes at offset {self.pos}, "
                f"only {self.remaining} remain"
            )
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def read_byte(self) -> int:
        return self.read(1)[0]

    def read_int(self, n: int) -> int:
        """Read an ``n``-byte little-endian unsigned integer."""
        return int.from_bytes(self.read(n), "little")

    def read_uint16(self) -> int:
        return self.read_int(2)

    def read_uint32(self) -> int:
        return self.read_int(4)

    def read_uint64(self) -> int:
        return self.read_int(8)

    def read_int64(self) -> int:
        return int.from_bytes(self.read(8), "little", signed=True)

    def read_compact_size(self) -> int:
        return read_compact_size(self)

    def read_var_bytes(self) -> bytes:
        """Read a compact-size length prefix followed by that many bytes."""
        return self.read(self.read_compact_size())


def read_compact_size(cur: Cursor) -> int:
    """Read a Bitcoin compact-size (varint) from ``cur``."""
    first = cur.read_byte()
    if first < 0xFD:
        return first
    if first == 0xFD:
        return cur.read_int(2)
    if first == 0xFE:
        return cur.read_int(4)
    return cur.read_int(8)


def encode_compact_size(value: int) -> bytes:
    """Serialize ``value`` as a Bitcoin compact-size (varint)."""
    if value < 0:
        raise ValueError("compact size cannot be negative")
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + value.to_bytes(8, "little")
    raise ValueError("compact size out of range")
