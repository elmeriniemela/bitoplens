"""Script verification flags and the signature-hashing version enum.

``ScriptVerificationFlags`` mirrors the ``SCRIPT_VERIFY_*`` bits in Bitcoin
Core's ``src/script/interpreter.h``. ``SigVersion`` mirrors ``SigVersion`` in
the same file.
"""

from __future__ import annotations

import enum

__all__ = ["ScriptVerificationFlags", "SigVersion"]


class ScriptVerificationFlags(enum.IntFlag):
    """Consensus/standardness verification flags."""

    NONE = 0
    P2SH = 1 << 0
    STRICTENC = 1 << 1
    DERSIG = 1 << 2
    LOW_S = 1 << 3
    NULLDUMMY = 1 << 4
    SIGPUSHONLY = 1 << 5
    MINIMALDATA = 1 << 6
    DISCOURAGE_UPGRADABLE_NOPS = 1 << 7
    CLEANSTACK = 1 << 8
    CHECKLOCKTIMEVERIFY = 1 << 9
    CHECKSEQUENCEVERIFY = 1 << 10
    WITNESS = 1 << 11
    DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = 1 << 12
    MINIMALIF = 1 << 13
    NULLFAIL = 1 << 14
    WITNESS_PUBKEYTYPE = 1 << 15
    CONST_SCRIPTCODE = 1 << 16
    TAPROOT = 1 << 17
    DISCOURAGE_UPGRADABLE_PUBKEYTYPE = 1 << 18
    DISCOURAGE_OP_SUCCESS = 1 << 19
    DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = 1 << 20

    @classmethod
    def all(cls) -> "ScriptVerificationFlags":
        """Every defined flag OR'd together (the strictest verification)."""
        result = cls.NONE
        for flag in cls:
            result |= flag
        return result


class SigVersion(enum.IntEnum):
    """The signature-hashing regime a script is evaluated under."""

    BASE = 0
    WITNESS_V0 = 1
    TAPROOT = 2
    TAPSCRIPT = 3
