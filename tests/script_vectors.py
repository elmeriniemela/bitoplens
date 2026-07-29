"""Adapter for Bitcoin Core's ``script_tests.json`` vector suite.

Parses Core's test-script mini-language (``core_read.cpp``'s ParseScript),
reconstructs the crediting/spending transaction pair exactly as Core's
``script_tests.cpp`` does, runs our interpreter, and compares the resulting
:class:`ScriptError` against the expected value.
"""

from __future__ import annotations

import json
import os
import re

from bitoplens.primitives.scriptnum import encode_num
from bitoplens.script import opcodes as OP
from bitoplens.script.script import _encode_push
from bitoplens.tx.transaction import OutPoint, Transaction, TxIn, TxOut
from bitoplens.vm.checker import TransactionSignatureChecker
from bitoplens.vm.errors import ScriptError
from bitoplens.vm.flags import ScriptVerificationFlags as VF
from bitoplens.vm.interpreter import Interpreter

DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "script_tests.json")

_NUM_RE = re.compile(r"^-?[0-9]+$")

# Opcode name -> value, accepting both "OP_DUP" and "DUP" forms.
_OP_NAMES: dict[str, int] = {}
for _val, _name in OP.OPCODE_NAMES.items():
    _OP_NAMES[_name] = _val
    _OP_NAMES[_name.replace("OP_", "", 1)] = _val
_OP_NAMES.update(
    {
        "TRUE": OP.OP_1,
        "FALSE": OP.OP_0,
        "OP_TRUE": OP.OP_1,
        "OP_FALSE": OP.OP_0,
        "NOP2": OP.OP_CHECKLOCKTIMEVERIFY,
        "OP_NOP2": OP.OP_CHECKLOCKTIMEVERIFY,
        "NOP3": OP.OP_CHECKSEQUENCEVERIFY,
        "OP_NOP3": OP.OP_CHECKSEQUENCEVERIFY,
        "CHECKSIGADD": OP.OP_CHECKSIGADD,
    }
)

# JSON error name -> our ScriptError name (a couple of Core spellings differ).
_ERR_ALIAS = {"NULLFAIL": "SIG_NULLFAIL"}


def _tokenize(s: str):
    toks = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c.isspace():
            i += 1
            continue
        if c == "'":
            j = s.index("'", i + 1)
            toks.append(s[i : j + 1])
            i = j + 1
        else:
            j = i
            while j < n and not s[j].isspace():
                j += 1
            toks.append(s[i:j])
            i = j
    return toks


def _push_num(n: int) -> bytes:
    if n == 0:
        return bytes([OP.OP_0])
    if n == -1:
        return bytes([OP.OP_1NEGATE])
    if 1 <= n <= 16:
        return bytes([OP.OP_1 + n - 1])
    return _encode_push(encode_num(n))


def parse_test_script(s: str) -> bytes:
    """Parse Core's test-script format into raw script bytes."""
    out = bytearray()
    for w in _tokenize(s):
        if w == "":
            continue
        if _NUM_RE.match(w):
            out += _push_num(int(w))
        elif w.startswith("0x"):
            out += bytes.fromhex(w[2:])
        elif len(w) >= 2 and w[0] == "'" and w[-1] == "'":
            out += _encode_push(w[1:-1].encode("latin-1"))
        else:
            key = w if w in _OP_NAMES else ("OP_" + w)
            if key not in _OP_NAMES:
                raise KeyError(f"unknown opcode token: {w!r}")
            out += bytes([_OP_NAMES[key]])
    return bytes(out)


def parse_flags(s: str) -> VF:
    flags = VF.NONE
    for name in s.replace(",", " ").split():
        flags |= getattr(VF, name)
    return flags


def _build_credit(script_pubkey: bytes, amount: int) -> Transaction:
    return Transaction(
        version=1,
        vin=[TxIn(OutPoint(b"\x00" * 32, 0xFFFFFFFF), bytes([0x00, 0x00]), 0xFFFFFFFF)],
        vout=[TxOut(amount, script_pubkey)],
        locktime=0,
    )


def _build_spend(script_sig: bytes, witness, credit: Transaction) -> Transaction:
    return Transaction(
        version=1,
        vin=[TxIn(OutPoint(credit.txid(), 0), script_sig, 0xFFFFFFFF, list(witness))],
        vout=[TxOut(credit.vout[0].value, b"")],
        locktime=0,
    )


def load_cases():
    """Yield runnable cases as dicts; rows with ``#`` placeholders are skipped."""
    with open(DATA_PATH) as fh:
        rows = json.load(fh)
    for idx, row in enumerate(rows):
        if len(row) < 4:
            continue  # comment-only row
        if isinstance(row[0], list):
            witness_hex = row[0][:-1]
            amount = int(round(float(row[0][-1]) * 1e8))
            script_sig_s, script_pubkey_s, flags_s, expected = row[1], row[2], row[3], row[4]
        else:
            witness_hex = []
            amount = 0
            script_sig_s, script_pubkey_s, flags_s, expected = row[0], row[1], row[2], row[3]
        blob = script_sig_s + " " + script_pubkey_s + " ".join(witness_hex)
        if "#" in blob:
            continue  # dynamic taproot placeholder, needs harness synthesis
        yield {
            "idx": idx,
            "script_sig": parse_test_script(script_sig_s),
            "script_pubkey": parse_test_script(script_pubkey_s),
            "witness": [bytes.fromhex(w) for w in witness_hex],
            "amount": amount,
            "flags": parse_flags(flags_s),
            "expected": expected,
            "comment": row[5] if len(row) > 5 else "",
        }


def run_case(case) -> tuple[bool, ScriptError]:
    """Run one parsed case; return (valid, error)."""
    credit = _build_credit(case["script_pubkey"], case["amount"])
    spend = _build_spend(case["script_sig"], case["witness"], credit)
    checker = TransactionSignatureChecker(
        spend, 0, amount=case["amount"], spent_outputs=[credit.vout[0]]
    )
    interp = Interpreter(case["flags"], checker)
    trace = interp.verify(case["script_sig"], case["script_pubkey"], case["witness"])
    return trace.valid, ScriptError(trace.error)


def expected_error(case) -> ScriptError:
    name = _ERR_ALIAS.get(case["expected"], case["expected"])
    return ScriptError[name]
