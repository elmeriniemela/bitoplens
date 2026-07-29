"""Bitcoin script opcodes: constants, name/description tables, and category sets.

The ``_OPCODE_NAMES`` / ``_OPCODE_DESCRIPTIONS`` tables and the
``opcode_name`` / ``opcode_description`` / ``disassemble`` / ``classify_script``
helpers are adapted from ``pybitcoinkernel``'s ``debugger.py`` (MIT), which in
turn mirrors Bitcoin Core's ``src/script/script.h``.
"""

from __future__ import annotations

__all__ = [
    "opcode_name",
    "opcode_description",
    "disassemble",
    "classify_script",
    "OPCODE_NAMES",
    "DISABLED_OPCODES",
    "CONDITIONAL_OPCODES",
    "is_op_success",
]

# --------------------------------------------------------------------------- #
# Opcode constants (from Bitcoin Core's script.h).
# --------------------------------------------------------------------------- #

# Push value
OP_0 = 0x00
OP_FALSE = OP_0
OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_PUSHDATA4 = 0x4E
OP_1NEGATE = 0x4F
OP_RESERVED = 0x50
OP_1 = 0x51
OP_TRUE = OP_1
OP_2 = 0x52
OP_3 = 0x53
OP_4 = 0x54
OP_5 = 0x55
OP_6 = 0x56
OP_7 = 0x57
OP_8 = 0x58
OP_9 = 0x59
OP_10 = 0x5A
OP_11 = 0x5B
OP_12 = 0x5C
OP_13 = 0x5D
OP_14 = 0x5E
OP_15 = 0x5F
OP_16 = 0x60

# Control
OP_NOP = 0x61
OP_VER = 0x62
OP_IF = 0x63
OP_NOTIF = 0x64
OP_VERIF = 0x65
OP_VERNOTIF = 0x66
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_VERIFY = 0x69
OP_RETURN = 0x6A

# Stack ops
OP_TOALTSTACK = 0x6B
OP_FROMALTSTACK = 0x6C
OP_2DROP = 0x6D
OP_2DUP = 0x6E
OP_3DUP = 0x6F
OP_2OVER = 0x70
OP_2ROT = 0x71
OP_2SWAP = 0x72
OP_IFDUP = 0x73
OP_DEPTH = 0x74
OP_DROP = 0x75
OP_DUP = 0x76
OP_NIP = 0x77
OP_OVER = 0x78
OP_PICK = 0x79
OP_ROLL = 0x7A
OP_ROT = 0x7B
OP_SWAP = 0x7C
OP_TUCK = 0x7D

# Splice ops (disabled)
OP_CAT = 0x7E
OP_SUBSTR = 0x7F
OP_LEFT = 0x80
OP_RIGHT = 0x81
OP_SIZE = 0x82

# Bit logic
OP_INVERT = 0x83
OP_AND = 0x84
OP_OR = 0x85
OP_XOR = 0x86
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_RESERVED1 = 0x89
OP_RESERVED2 = 0x8A

# Numeric
OP_1ADD = 0x8B
OP_1SUB = 0x8C
OP_2MUL = 0x8D
OP_2DIV = 0x8E
OP_NEGATE = 0x8F
OP_ABS = 0x90
OP_NOT = 0x91
OP_0NOTEQUAL = 0x92
OP_ADD = 0x93
OP_SUB = 0x94
OP_MUL = 0x95
OP_DIV = 0x96
OP_MOD = 0x97
OP_LSHIFT = 0x98
OP_RSHIFT = 0x99
OP_BOOLAND = 0x9A
OP_BOOLOR = 0x9B
OP_NUMEQUAL = 0x9C
OP_NUMEQUALVERIFY = 0x9D
OP_NUMNOTEQUAL = 0x9E
OP_LESSTHAN = 0x9F
OP_GREATERTHAN = 0xA0
OP_LESSTHANOREQUAL = 0xA1
OP_GREATERTHANOREQUAL = 0xA2
OP_MIN = 0xA3
OP_MAX = 0xA4
OP_WITHIN = 0xA5

# Crypto
OP_RIPEMD160 = 0xA6
OP_SHA1 = 0xA7
OP_SHA256 = 0xA8
OP_HASH160 = 0xA9
OP_HASH256 = 0xAA
OP_CODESEPARATOR = 0xAB
OP_CHECKSIG = 0xAC
OP_CHECKSIGVERIFY = 0xAD
OP_CHECKMULTISIG = 0xAE
OP_CHECKMULTISIGVERIFY = 0xAF

# Expansion / soft-fork NOPs
OP_NOP1 = 0xB0
OP_CHECKLOCKTIMEVERIFY = 0xB1
OP_NOP2 = OP_CHECKLOCKTIMEVERIFY
OP_CHECKSEQUENCEVERIFY = 0xB2
OP_NOP3 = OP_CHECKSEQUENCEVERIFY
OP_NOP4 = 0xB3
OP_NOP5 = 0xB4
OP_NOP6 = 0xB5
OP_NOP7 = 0xB6
OP_NOP8 = 0xB7
OP_NOP9 = 0xB8
OP_NOP10 = 0xB9

# Tapscript
OP_CHECKSIGADD = 0xBA

OP_INVALIDOPCODE = 0xFF


# --------------------------------------------------------------------------- #
# Name and description tables (verbatim from pybitcoinkernel/debugger.py).
# --------------------------------------------------------------------------- #

# Opcode value -> name, from src/script/script.h. Direct pushes (0x01..0x4b)
# have no OP_ name and are handled specially in opcode_name().
OPCODE_NAMES = {
    0x00: "OP_0",
    0x4C: "OP_PUSHDATA1",
    0x4D: "OP_PUSHDATA2",
    0x4E: "OP_PUSHDATA4",
    0x4F: "OP_1NEGATE",
    0x50: "OP_RESERVED",
    0x51: "OP_1",
    0x52: "OP_2",
    0x53: "OP_3",
    0x54: "OP_4",
    0x55: "OP_5",
    0x56: "OP_6",
    0x57: "OP_7",
    0x58: "OP_8",
    0x59: "OP_9",
    0x5A: "OP_10",
    0x5B: "OP_11",
    0x5C: "OP_12",
    0x5D: "OP_13",
    0x5E: "OP_14",
    0x5F: "OP_15",
    0x60: "OP_16",
    0x61: "OP_NOP",
    0x62: "OP_VER",
    0x63: "OP_IF",
    0x64: "OP_NOTIF",
    0x65: "OP_VERIF",
    0x66: "OP_VERNOTIF",
    0x67: "OP_ELSE",
    0x68: "OP_ENDIF",
    0x69: "OP_VERIFY",
    0x6A: "OP_RETURN",
    0x6B: "OP_TOALTSTACK",
    0x6C: "OP_FROMALTSTACK",
    0x6D: "OP_2DROP",
    0x6E: "OP_2DUP",
    0x6F: "OP_3DUP",
    0x70: "OP_2OVER",
    0x71: "OP_2ROT",
    0x72: "OP_2SWAP",
    0x73: "OP_IFDUP",
    0x74: "OP_DEPTH",
    0x75: "OP_DROP",
    0x76: "OP_DUP",
    0x77: "OP_NIP",
    0x78: "OP_OVER",
    0x79: "OP_PICK",
    0x7A: "OP_ROLL",
    0x7B: "OP_ROT",
    0x7C: "OP_SWAP",
    0x7D: "OP_TUCK",
    0x7E: "OP_CAT",
    0x7F: "OP_SUBSTR",
    0x80: "OP_LEFT",
    0x81: "OP_RIGHT",
    0x82: "OP_SIZE",
    0x83: "OP_INVERT",
    0x84: "OP_AND",
    0x85: "OP_OR",
    0x86: "OP_XOR",
    0x87: "OP_EQUAL",
    0x88: "OP_EQUALVERIFY",
    0x89: "OP_RESERVED1",
    0x8A: "OP_RESERVED2",
    0x8B: "OP_1ADD",
    0x8C: "OP_1SUB",
    0x8D: "OP_2MUL",
    0x8E: "OP_2DIV",
    0x8F: "OP_NEGATE",
    0x90: "OP_ABS",
    0x91: "OP_NOT",
    0x92: "OP_0NOTEQUAL",
    0x93: "OP_ADD",
    0x94: "OP_SUB",
    0x95: "OP_MUL",
    0x96: "OP_DIV",
    0x97: "OP_MOD",
    0x98: "OP_LSHIFT",
    0x99: "OP_RSHIFT",
    0x9A: "OP_BOOLAND",
    0x9B: "OP_BOOLOR",
    0x9C: "OP_NUMEQUAL",
    0x9D: "OP_NUMEQUALVERIFY",
    0x9E: "OP_NUMNOTEQUAL",
    0x9F: "OP_LESSTHAN",
    0xA0: "OP_GREATERTHAN",
    0xA1: "OP_LESSTHANOREQUAL",
    0xA2: "OP_GREATERTHANOREQUAL",
    0xA3: "OP_MIN",
    0xA4: "OP_MAX",
    0xA5: "OP_WITHIN",
    0xA6: "OP_RIPEMD160",
    0xA7: "OP_SHA1",
    0xA8: "OP_SHA256",
    0xA9: "OP_HASH160",
    0xAA: "OP_HASH256",
    0xAB: "OP_CODESEPARATOR",
    0xAC: "OP_CHECKSIG",
    0xAD: "OP_CHECKSIGVERIFY",
    0xAE: "OP_CHECKMULTISIG",
    0xAF: "OP_CHECKMULTISIGVERIFY",
    0xB0: "OP_NOP1",
    0xB1: "OP_CHECKLOCKTIMEVERIFY",
    0xB2: "OP_CHECKSEQUENCEVERIFY",
    0xB3: "OP_NOP4",
    0xB4: "OP_NOP5",
    0xB5: "OP_NOP6",
    0xB6: "OP_NOP7",
    0xB7: "OP_NOP8",
    0xB8: "OP_NOP9",
    0xB9: "OP_NOP10",
    0xBA: "OP_CHECKSIGADD",
    0xFF: "OP_INVALIDOPCODE",
}


def opcode_name(opcode: int) -> str:
    """Return the mnemonic for a one-byte ``opcode`` (e.g. ``"OP_DUP"``).

    Direct data pushes (``0x01``..``0x4b``) become ``"OP_PUSHBYTES_<n>"``,
    matching Bitcoin Core's disassembly. Unassigned opcodes render as
    ``"OP_UNKNOWN_0x<hex>"``.
    """
    name = OPCODE_NAMES.get(opcode)
    if name is not None:
        return name
    if 0x01 <= opcode <= 0x4B:
        return f"OP_PUSHBYTES_{opcode}"
    return f"OP_UNKNOWN_0x{opcode:02x}"


# Opcode value -> a one-line plain-English description of its effect. Data
# pushes (0x00..0x4e) and the OP_1..OP_16 range are described in
# opcode_description() so the count/number can be interpolated.
_OPCODE_DESCRIPTIONS = {
    0x4F: "Push the number -1.",
    0x50: "Reserved; makes the script invalid if executed.",
    0x61: "Do nothing.",
    0x62: "Reserved; makes the script invalid if executed.",
    0x63: "If the top stack value is true, run the following block (pops it).",
    0x64: "If the top stack value is false, run the following block (pops it).",
    0x65: "Reserved; makes the script invalid even when not executed.",
    0x66: "Reserved; makes the script invalid even when not executed.",
    0x67: "Run the following block if the matching OP_IF/OP_NOTIF did not.",
    0x68: "End an OP_IF / OP_NOTIF / OP_ELSE block.",
    0x69: "Fail the script unless the top stack value is true; then pop it.",
    0x6A: "Fail the script immediately (marks an output unspendable).",
    0x6B: "Move the top stack item to the alt stack.",
    0x6C: "Move the top alt-stack item back to the main stack.",
    0x6D: "Remove the top two stack items.",
    0x6E: "Duplicate the top two stack items.",
    0x6F: "Duplicate the top three stack items.",
    0x70: "Copy the second pair of items to the top.",
    0x71: "Move the third pair of items to the top.",
    0x72: "Swap the top two pairs of items.",
    0x73: "Duplicate the top stack item if it is non-zero.",
    0x74: "Push the current stack depth (number of items).",
    0x75: "Remove the top stack item.",
    0x76: "Duplicate the top stack item.",
    0x77: "Remove the second-from-top stack item.",
    0x78: "Copy the second-from-top item to the top.",
    0x79: "Copy the item n-deep (n taken from the top) to the top.",
    0x7A: "Move the item n-deep (n taken from the top) to the top.",
    0x7B: "Rotate the top three items (third item moves to the top).",
    0x7C: "Swap the top two items.",
    0x7D: "Copy the top item and insert it below the second item.",
    0x7E: "Disabled: concatenate two byte vectors.",
    0x7F: "Disabled: extract a substring.",
    0x80: "Disabled: keep the left part of a string.",
    0x81: "Disabled: keep the right part of a string.",
    0x82: "Push the byte length of the top item (without removing it).",
    0x83: "Disabled: bitwise NOT.",
    0x84: "Disabled: bitwise AND.",
    0x85: "Disabled: bitwise OR.",
    0x86: "Disabled: bitwise XOR.",
    0x87: "Push true if the top two items are equal, else false.",
    0x88: "Fail the script unless the top two items are equal.",
    0x89: "Reserved; makes the script invalid if executed.",
    0x8A: "Reserved; makes the script invalid if executed.",
    0x8B: "Add 1 to the top number.",
    0x8C: "Subtract 1 from the top number.",
    0x8D: "Disabled: multiply the top number by 2.",
    0x8E: "Disabled: divide the top number by 2.",
    0x8F: "Negate the top number.",
    0x90: "Replace the top number with its absolute value.",
    0x91: "Push true if the top number is 0, else false.",
    0x92: "Push true if the top number is not 0, else false.",
    0x93: "Add the top two numbers.",
    0x94: "Subtract the top number from the second-from-top number.",
    0x95: "Disabled: multiply the top two numbers.",
    0x96: "Disabled: divide the second number by the top.",
    0x97: "Disabled: remainder of the division.",
    0x98: "Disabled: left bit-shift.",
    0x99: "Disabled: right bit-shift.",
    0x9A: "Push true if both numbers are non-zero.",
    0x9B: "Push true if either number is non-zero.",
    0x9C: "Push true if the two numbers are equal.",
    0x9D: "Fail the script unless the two numbers are equal.",
    0x9E: "Push true if the two numbers are not equal.",
    0x9F: "Push true if the second number is less than the top.",
    0xA0: "Push true if the second number is greater than the top.",
    0xA1: "Push true if the second number is less than or equal to the top.",
    0xA2: "Push true if the second number is greater than or equal to the top.",
    0xA3: "Push the smaller of the top two numbers.",
    0xA4: "Push the larger of the top two numbers.",
    0xA5: "Push true if x is within the range [min, max).",
    0xA6: "Replace the top item with its RIPEMD-160 hash.",
    0xA7: "Replace the top item with its SHA-1 hash.",
    0xA8: "Replace the top item with its SHA-256 hash.",
    0xA9: "Replace the top item with RIPEMD160(SHA256(item)).",
    0xAA: "Replace the top item with SHA256(SHA256(item)).",
    0xAB: "Mark where signing of the script starts (for later signatures).",
    0xAC: "Check a signature against a pubkey; push true or false.",
    0xAD: "Check a signature against a pubkey; fail the script if invalid.",
    0xAE: "Check M-of-N signatures against N pubkeys; push true or false.",
    0xAF: "Check M-of-N signatures; fail the script if invalid.",
    0xB0: "Do nothing (reserved for future soft-fork upgrades).",
    0xB1: "Fail unless the tx locktime is at/after the top value (BIP65).",
    0xB2: "Fail unless the input's relative locktime is satisfied (BIP112).",
    0xB3: "Do nothing (reserved for future soft-fork upgrades).",
    0xB4: "Do nothing (reserved for future soft-fork upgrades).",
    0xB5: "Do nothing (reserved for future soft-fork upgrades).",
    0xB6: "Do nothing (reserved for future soft-fork upgrades).",
    0xB7: "Do nothing (reserved for future soft-fork upgrades).",
    0xB8: "Do nothing (reserved for future soft-fork upgrades).",
    0xB9: "Do nothing (reserved for future soft-fork upgrades).",
    0xBA: "Tapscript: add 1 to a counter if the signature is valid (BIP342).",
    0xFF: "Invalid opcode; always fails the script.",
}


def opcode_description(opcode: int) -> str:
    """Return a short plain-English description of what ``opcode`` does."""
    if opcode == 0x00:
        return "Push an empty byte vector (represents false / zero)."
    if 0x01 <= opcode <= 0x4B:
        return f"Push the next {opcode} bytes onto the stack."
    if opcode == 0x4C:
        return "Push bytes counted by the next 1-byte length."
    if opcode == 0x4D:
        return "Push bytes counted by the next 2-byte little-endian length."
    if opcode == 0x4E:
        return "Push bytes counted by the next 4-byte little-endian length."
    if 0x51 <= opcode <= 0x60:
        return f"Push the number {opcode - 0x50}."
    return _OPCODE_DESCRIPTIONS.get(opcode, "")


def disassemble(script: bytes):
    """Disassemble ``script`` into a list of ``(opcode_pos, mnemonic, data)``.

    ``data`` is the pushed bytes for push operations, otherwise ``b""``.
    Truncated pushes at the end of the script are reported with whatever bytes
    remain, so malformed scripts still disassemble rather than raise.
    """
    script = bytes(script)
    out = []
    i = 0
    pos = 0
    n = len(script)
    while i < n:
        op = script[i]
        i += 1
        data = b""
        if 1 <= op <= 0x4B:
            data = script[i : i + op]
            i += op
        elif op == 0x4C:
            if i < n:
                ln = script[i]
                i += 1
                data = script[i : i + ln]
                i += ln
        elif op == 0x4D:
            if i + 1 < n:
                ln = int.from_bytes(script[i : i + 2], "little")
                i += 2
                data = script[i : i + ln]
                i += ln
        elif op == 0x4E:
            if i + 3 < n:
                ln = int.from_bytes(script[i : i + 4], "little")
                i += 4
                data = script[i : i + ln]
                i += ln
        out.append((pos, opcode_name(op), data))
        pos += 1
    return out


def classify_script(script: bytes) -> str:
    """Best-effort classification of ``script`` into a standard output type."""
    b = bytes(script)
    n = len(b)
    if n == 0:
        return ""
    if b[0] == 0x6A:  # OP_RETURN
        return "OP_RETURN"
    if n == 25 and b[0:3] == b"\x76\xa9\x14" and b[23:25] == b"\x88\xac":
        return "P2PKH"
    if n == 23 and b[0:2] == b"\xa9\x14" and b[22] == 0x87:
        return "P2SH"
    if n == 22 and b[0:2] == b"\x00\x14":
        return "P2WPKH"
    if n == 34 and b[0:2] == b"\x00\x20":
        return "P2WSH"
    if n == 34 and b[0:2] == b"\x51\x20":
        return "P2TR"
    if (n == 35 and b[0] == 0x21 and b[34] == 0xAC) or (n == 67 and b[0] == 0x41 and b[66] == 0xAC):
        return "P2PK"
    if n >= 4 and 0x51 <= b[0] <= 0x60 and 0x51 <= b[-2] <= 0x60 and b[-1] == 0xAE:
        return "multisig"
    if n >= 4 and n == b[1] + 2 and (b[0] == 0x00 or 0x51 <= b[0] <= 0x60) and 0x02 <= b[1] <= 0x28:
        return f"witness v{0 if b[0] == 0x00 else b[0] - 0x50} program"
    return ""


# --------------------------------------------------------------------------- #
# Category sets used by the interpreter.
# --------------------------------------------------------------------------- #

# Disabled in BASE / WITNESS_V0: fail even inside an unexecuted branch.
DISABLED_OPCODES = frozenset(
    {
        OP_CAT,
        OP_SUBSTR,
        OP_LEFT,
        OP_RIGHT,
        OP_INVERT,
        OP_AND,
        OP_OR,
        OP_XOR,
        OP_2MUL,
        OP_2DIV,
        OP_MUL,
        OP_DIV,
        OP_MOD,
        OP_LSHIFT,
        OP_RSHIFT,
    }
)

# The OP_IF/OP_NOTIF/OP_ELSE/OP_ENDIF group is still walked in an unexecuted
# branch (to track nesting), unlike every other opcode.
CONDITIONAL_OPCODES = frozenset({OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF})


# BIP342: opcodes that make a tapscript unconditionally succeed (OP_SUCCESSx).
_OP_SUCCESS = (
    {80, 98}
    | set(range(126, 130))
    | set(range(131, 135))
    | {137, 138}
    | {141, 142}
    | set(range(149, 154))
    | set(range(187, 255))
)


def is_op_success(opcode: int) -> bool:
    """Return ``True`` if ``opcode`` is an OP_SUCCESSx (tapscript, BIP342)."""
    return opcode in _OP_SUCCESS
