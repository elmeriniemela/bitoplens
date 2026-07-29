"""Script error codes and the interpreter's exception type.

``ScriptError`` mirrors Bitcoin Core's ``src/script/script_error.h`` (values
adapted verbatim from ``pybitcoinkernel``) so the same vocabulary is used when
comparing against Core's ``script_tests.json`` vectors.
"""

from __future__ import annotations

import enum

__all__ = ["ScriptError", "ScriptException"]


class ScriptError(enum.IntEnum):
    """Reason a script evaluation ended, mirroring ``script_error.h``.

    ``OK`` (0) means the script ran to completion; whether the *verification*
    passed is a separate check on the final stack.
    """

    OK = 0
    UNKNOWN_ERROR = 1
    EVAL_FALSE = 2
    OP_RETURN = 3
    SCRIPTNUM = 4
    SCRIPT_SIZE = 5
    PUSH_SIZE = 6
    OP_COUNT = 7
    STACK_SIZE = 8
    SIG_COUNT = 9
    PUBKEY_COUNT = 10
    VERIFY = 11
    EQUALVERIFY = 12
    CHECKMULTISIGVERIFY = 13
    CHECKSIGVERIFY = 14
    NUMEQUALVERIFY = 15
    BAD_OPCODE = 16
    DISABLED_OPCODE = 17
    INVALID_STACK_OPERATION = 18
    INVALID_ALTSTACK_OPERATION = 19
    UNBALANCED_CONDITIONAL = 20
    NEGATIVE_LOCKTIME = 21
    UNSATISFIED_LOCKTIME = 22
    SIG_HASHTYPE = 23
    SIG_DER = 24
    MINIMALDATA = 25
    SIG_PUSHONLY = 26
    SIG_HIGH_S = 27
    SIG_NULLDUMMY = 28
    PUBKEYTYPE = 29
    CLEANSTACK = 30
    MINIMALIF = 31
    SIG_NULLFAIL = 32
    DISCOURAGE_UPGRADABLE_NOPS = 33
    DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = 34
    DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = 35
    DISCOURAGE_OP_SUCCESS = 36
    DISCOURAGE_UPGRADABLE_PUBKEYTYPE = 37
    WITNESS_PROGRAM_WRONG_LENGTH = 38
    WITNESS_PROGRAM_WITNESS_EMPTY = 39
    WITNESS_PROGRAM_MISMATCH = 40
    WITNESS_MALLEATED = 41
    WITNESS_MALLEATED_P2SH = 42
    WITNESS_UNEXPECTED = 43
    WITNESS_PUBKEYTYPE = 44
    SCHNORR_SIG_SIZE = 45
    SCHNORR_SIG_HASHTYPE = 46
    SCHNORR_SIG = 47
    TAPROOT_WRONG_CONTROL_SIZE = 48
    TAPSCRIPT_VALIDATION_WEIGHT = 49
    TAPSCRIPT_CHECKMULTISIG = 50
    TAPSCRIPT_MINIMALIF = 51
    TAPSCRIPT_EMPTY_PUBKEY = 52
    OP_CODESEPARATOR = 53
    SIG_FINDANDDELETE = 54


class ScriptException(Exception):
    """Raised inside the interpreter to abort evaluation with a ``ScriptError``."""

    def __init__(self, error: ScriptError, message: str = ""):
        self.error = error
        super().__init__(message or error.name)
