"""The :class:`Script` wrapper, its strict opcode parser, and a builder.

Parsing here is *strict* (unlike :func:`bitoplens.script.opcodes.disassemble`,
which is lenient for display): a truncated push raises :class:`ScriptParseError`
so the interpreter can surface a ``BAD_OPCODE`` error at the right step.
"""

from __future__ import annotations

from dataclasses import dataclass

from bitoplens.primitives.scriptnum import encode_num
from bitoplens.script import opcodes as op
from bitoplens.script.opcodes import disassemble, opcode_name

__all__ = [
    "Script",
    "ScriptOp",
    "ScriptParseError",
    "ScriptBuilder",
    "check_minimal_push",
    "op_length",
    "find_and_delete",
]


class ScriptParseError(ValueError):
    """Raised when a script contains a truncated / malformed push."""


@dataclass(frozen=True)
class ScriptOp:
    """One parsed operation.

    ``data`` is the pushed bytes for a *direct push* opcode (0x01..0x4e) and
    ``None`` for every other opcode (including OP_0 / OP_1NEGATE / OP_1..OP_16,
    which the interpreter pushes itself). ``offset`` is the byte position of the
    opcode within the script.
    """

    offset: int
    opcode: int
    data: bytes | None = None

    @property
    def name(self) -> str:
        return opcode_name(self.opcode)


class Script(bytes):
    """A Bitcoin script: raw ``bytes`` plus parsing/disassembly helpers."""

    def ops(self):
        """Iterate parsed :class:`ScriptOp`, raising on a truncated push."""
        data = bytes(self)
        i = 0
        n = len(data)
        while i < n:
            offset = i
            opcode = data[i]
            i += 1
            if opcode <= 0x4B:
                if opcode == 0x00:
                    yield ScriptOp(offset, opcode, None)
                    continue
                end = i + opcode
                if end > n:
                    raise ScriptParseError(f"truncated push at offset {offset}")
                yield ScriptOp(offset, opcode, data[i:end])
                i = end
            elif opcode <= 0x4E:
                size_len = {0x4C: 1, 0x4D: 2, 0x4E: 4}[opcode]
                if i + size_len > n:
                    raise ScriptParseError(f"truncated pushdata length at offset {offset}")
                push_len = int.from_bytes(data[i : i + size_len], "little")
                i += size_len
                end = i + push_len
                if end > n:
                    raise ScriptParseError(f"truncated pushdata at offset {offset}")
                yield ScriptOp(offset, opcode, data[i:end])
                i = end
            else:
                yield ScriptOp(offset, opcode, None)

    def is_push_only(self) -> bool:
        """True if the script contains only push opcodes (<= OP_16)."""
        try:
            return all(o.opcode <= op.OP_16 for o in self.ops())
        except ScriptParseError:
            return False

    def disassemble(self):
        return disassemble(bytes(self))

    def asm(self) -> str:
        """A human-readable, space-separated assembly string (for display)."""
        parts = []
        for _pos, name, data in disassemble(bytes(self)):
            if data:
                parts.append(data.hex())
            else:
                parts.append(name)
        return " ".join(parts)

    def __repr__(self) -> str:  # pragma: no cover - display only
        return f"Script({self.asm()!r})"


def check_minimal_push(data: bytes, opcode: int) -> bool:
    """Return True if ``data`` was pushed with its minimal opcode (BIP62).

    Mirrors Bitcoin Core's ``CheckMinimalPush``.
    """
    n = len(data)
    if n == 0:
        return opcode == op.OP_0
    if n == 1 and 1 <= data[0] <= 16:
        return opcode == op.OP_1 + (data[0] - 1)
    if n == 1 and data[0] == 0x81:
        return opcode == op.OP_1NEGATE
    if n <= 75:
        return opcode == n
    if n <= 255:
        return opcode == op.OP_PUSHDATA1
    if n <= 65535:
        return opcode == op.OP_PUSHDATA2
    return True


def op_length(script: bytes, i: int) -> int:
    """Return the total byte length of the opcode at offset ``i`` in ``script``.

    Counts the push-data for direct/PUSHDATA ops. A truncated push returns the
    number of bytes that remain, so this never runs past the end.
    """
    n = len(script)
    op = script[i]
    j = i + 1
    if op < 0x4C:
        j += op
    elif op == 0x4C:
        if j >= n:
            return n - i
        j += 1 + script[j]
    elif op == 0x4D:
        if j + 1 >= n:
            return n - i
        j += 2 + int.from_bytes(script[j : j + 2], "little")
    elif op == 0x4E:
        if j + 3 >= n:
            return n - i
        j += 4 + int.from_bytes(script[j : j + 4], "little")
    return min(j, n) - i


def find_and_delete(script: bytes, pattern: bytes) -> bytes:
    """Remove every occurrence of ``pattern`` from ``script`` at op boundaries.

    Mirrors Bitcoin Core's ``FindAndDelete``: at each opcode boundary, if the
    following bytes equal ``pattern`` it is dropped; otherwise the whole opcode
    (with its push-data) is copied. Used by the legacy signature hash.
    """
    script = bytes(script)
    pattern = bytes(pattern)
    if not pattern:
        return script
    out = bytearray()
    i = 0
    n = len(script)
    plen = len(pattern)
    while i < n:
        if script[i : i + plen] == pattern:
            i += plen
            continue
        step = op_length(script, i)
        out += script[i : i + step]
        i += step
    return bytes(out)


def _encode_push(data: bytes) -> bytes:
    """Serialize a minimal data push for ``data`` (raw bytes, no small-int opt)."""
    n = len(data)
    if n < op.OP_PUSHDATA1:
        return bytes([n]) + data
    if n <= 0xFF:
        return bytes([op.OP_PUSHDATA1, n]) + data
    if n <= 0xFFFF:
        return bytes([op.OP_PUSHDATA2]) + n.to_bytes(2, "little") + data
    return bytes([op.OP_PUSHDATA4]) + n.to_bytes(4, "little") + data


class ScriptBuilder:
    """Fluent builder for constructing scripts programmatically.

    ``push`` chooses the minimal encoding (OP_0 / OP_1NEGATE / OP_1..OP_16 for
    small integers, otherwise a data push). ``op`` appends a raw opcode byte.
    """

    def __init__(self):
        self._parts: list[bytes] = []

    def op(self, opcode: int) -> "ScriptBuilder":
        if not 0 <= opcode <= 0xFF:
            raise ValueError("opcode out of range")
        self._parts.append(bytes([opcode]))
        return self

    def push(self, data) -> "ScriptBuilder":
        """Push ``bytes`` (data) or an ``int`` (as a minimal number)."""
        if isinstance(data, int):
            return self.push_int(data)
        self._parts.append(_encode_push(bytes(data)))
        return self

    def push_int(self, value: int) -> "ScriptBuilder":
        if value == 0:
            return self.op(op.OP_0)
        if value == -1:
            return self.op(op.OP_1NEGATE)
        if 1 <= value <= 16:
            return self.op(op.OP_1 + value - 1)
        self._parts.append(_encode_push(encode_num(value)))
        return self

    def raw(self, data: bytes) -> "ScriptBuilder":
        """Append raw bytes verbatim (already-encoded script fragment)."""
        self._parts.append(bytes(data))
        return self

    def build(self) -> Script:
        return Script(b"".join(self._parts))
