"""Bitcoin transaction data model and (de)serialization.

Supports both the legacy and BIP144 segwit wire formats. Transaction ids are
computed over the legacy (witness-stripped) serialization; the witness id
(wtxid) over the full serialization.

`txid` bytes are stored in *internal* (little-endian) byte order as they appear
on the wire; use :meth:`OutPoint.txid_hex` / :meth:`Transaction.txid_hex` for
the reversed, human-facing hex.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from bitoplens.primitives.hashing import hash256
from bitoplens.primitives.serialize import Cursor, encode_compact_size

__all__ = ["OutPoint", "TxIn", "TxOut", "Transaction"]


@dataclass
class OutPoint:
    """A reference to a previous output: 32-byte txid + output index."""

    txid: bytes  # internal byte order (little-endian), 32 bytes
    vout: int

    def serialize(self) -> bytes:
        return self.txid + self.vout.to_bytes(4, "little")

    @classmethod
    def parse(cls, cur: Cursor) -> "OutPoint":
        return cls(cur.read(32), cur.read_uint32())

    def txid_hex(self) -> str:
        """Human-facing txid (big-endian hex, i.e. reversed on-wire bytes)."""
        return self.txid[::-1].hex()

    @classmethod
    def from_hex(cls, txid_hex: str, vout: int) -> "OutPoint":
        """Build from a display txid (big-endian hex) and an output index."""
        return cls(bytes.fromhex(txid_hex)[::-1], vout)


@dataclass
class TxIn:
    """A transaction input."""

    prevout: OutPoint
    script_sig: bytes = b""
    sequence: int = 0xFFFFFFFF
    witness: list[bytes] = field(default_factory=list)

    def serialize(self) -> bytes:
        return (
            self.prevout.serialize()
            + encode_compact_size(len(self.script_sig))
            + self.script_sig
            + self.sequence.to_bytes(4, "little")
        )

    @classmethod
    def parse(cls, cur: Cursor) -> "TxIn":
        prevout = OutPoint.parse(cur)
        script_sig = cur.read_var_bytes()
        sequence = cur.read_uint32()
        return cls(prevout, script_sig, sequence)


@dataclass
class TxOut:
    """A transaction output: value in satoshis + scriptPubKey."""

    value: int
    script_pubkey: bytes

    def serialize(self) -> bytes:
        return (
            self.value.to_bytes(8, "little")
            + encode_compact_size(len(self.script_pubkey))
            + self.script_pubkey
        )

    @classmethod
    def parse(cls, cur: Cursor) -> "TxOut":
        value = cur.read_uint64()
        script = cur.read_var_bytes()
        return cls(value, script)


@dataclass
class Transaction:
    """A Bitcoin transaction."""

    version: int = 2
    vin: list[TxIn] = field(default_factory=list)
    vout: list[TxOut] = field(default_factory=list)
    locktime: int = 0

    @property
    def has_witness(self) -> bool:
        return any(inp.witness for inp in self.vin)

    def serialize(self, *, include_witness: bool | None = None) -> bytes:
        """Serialize to the wire format.

        ``include_witness`` defaults to True when any input carries witness data
        (BIP144), else the legacy format. Pass ``False`` to force the legacy
        (txid) serialization.
        """
        if include_witness is None:
            include_witness = self.has_witness
        out = bytearray()
        out += self.version.to_bytes(4, "little")
        if include_witness:
            out += b"\x00\x01"  # segwit marker + flag
        out += encode_compact_size(len(self.vin))
        for inp in self.vin:
            out += inp.serialize()
        out += encode_compact_size(len(self.vout))
        for o in self.vout:
            out += o.serialize()
        if include_witness:
            for inp in self.vin:
                out += encode_compact_size(len(inp.witness))
                for item in inp.witness:
                    out += encode_compact_size(len(item)) + item
        out += self.locktime.to_bytes(4, "little")
        return bytes(out)

    @classmethod
    def parse(cls, data) -> "Transaction":
        """Parse a transaction from raw ``bytes`` or a hex ``str``."""
        if isinstance(data, str):
            data = bytes.fromhex(data)
        cur = Cursor(data)
        version = cur.read_uint32()
        marker = cur.data[cur.pos]
        segwit = False
        if marker == 0x00:
            # segwit marker; the following flag byte must be non-zero.
            cur.read_byte()  # consume marker
            flag = cur.read_byte()
            if flag == 0x00:
                raise ValueError("invalid segwit flag byte")
            segwit = True
        n_in = cur.read_compact_size()
        vin = [TxIn.parse(cur) for _ in range(n_in)]
        n_out = cur.read_compact_size()
        vout = [TxOut.parse(cur) for _ in range(n_out)]
        if segwit:
            for inp in vin:
                n_items = cur.read_compact_size()
                inp.witness = [cur.read_var_bytes() for _ in range(n_items)]
        locktime = cur.read_uint32()
        return cls(version, vin, vout, locktime)

    def txid(self) -> bytes:
        """Transaction id (internal byte order): hash256 of legacy serialization."""
        return hash256(self.serialize(include_witness=False))

    def wtxid(self) -> bytes:
        """Witness transaction id (internal byte order).

        Equals :meth:`txid` when the transaction carries no witness (BIP144
        omits the marker/flag in that case).
        """
        return hash256(self.serialize())

    def txid_hex(self) -> str:
        return self.txid()[::-1].hex()

    def wtxid_hex(self) -> str:
        return self.wtxid()[::-1].hex()
