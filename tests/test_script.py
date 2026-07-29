"""Tests for opcode tables, script parsing, and the builder."""

from __future__ import annotations

import pytest

from bitoplens.script import opcodes as op
from bitoplens.script.opcodes import classify_script, is_op_success, opcode_name
from bitoplens.script.script import (
    Script,
    ScriptBuilder,
    ScriptParseError,
    check_minimal_push,
)


def test_opcode_names():
    assert opcode_name(0x76) == "OP_DUP"
    assert opcode_name(0xAC) == "OP_CHECKSIG"
    assert opcode_name(0x14) == "OP_PUSHBYTES_20"
    assert opcode_name(0xBB) == "OP_UNKNOWN_0xbb"


def test_op_success_set():
    assert is_op_success(0x50)  # 80
    assert is_op_success(0xBB)  # 187
    assert is_op_success(0xFE)  # 254
    assert not is_op_success(0xAC)  # OP_CHECKSIG
    assert not is_op_success(0xFF)  # OP_INVALIDOPCODE


def test_parse_p2pkh_ops():
    # OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    h = bytes(range(20))
    spk = Script(bytes([op.OP_DUP, op.OP_HASH160, 0x14]) + h + bytes([op.OP_EQUALVERIFY, op.OP_CHECKSIG]))
    ops = list(spk.ops())
    assert [o.opcode for o in ops] == [op.OP_DUP, op.OP_HASH160, 0x14, op.OP_EQUALVERIFY, op.OP_CHECKSIG]
    assert ops[2].data == h
    assert ops[0].data is None
    assert classify_script(spk) == "P2PKH"


def test_parse_pushdata_variants():
    data = b"\xaa" * 300
    spk = ScriptBuilder().push(data).build()
    ops = list(spk.ops())
    assert len(ops) == 1
    assert ops[0].opcode == op.OP_PUSHDATA2
    assert ops[0].data == data


def test_truncated_push_raises():
    with pytest.raises(ScriptParseError):
        list(Script(bytes([0x05, 0x01, 0x02])).ops())  # says push 5, only 2 present


def test_is_push_only():
    assert Script(bytes([0x01, 0xAA, op.OP_1, op.OP_16])).is_push_only()
    assert not Script(bytes([op.OP_DUP])).is_push_only()


def test_builder_small_ints():
    assert ScriptBuilder().push_int(0).build() == bytes([op.OP_0])
    assert ScriptBuilder().push_int(-1).build() == bytes([op.OP_1NEGATE])
    assert ScriptBuilder().push_int(5).build() == bytes([op.OP_5])
    assert ScriptBuilder().push_int(16).build() == bytes([op.OP_16])
    # 17 is beyond OP_16, so it becomes a data push of the number encoding.
    assert ScriptBuilder().push_int(17).build() == bytes([0x01, 0x11])


@pytest.mark.parametrize(
    "data,opcode,minimal",
    [
        (b"", op.OP_0, True),
        (b"", 0x01, False),
        (b"\x05", op.OP_5, True),
        (b"\x05", 0x01, False),
        (b"\x81", op.OP_1NEGATE, True),
        (b"\x11", 0x01, True),
        (b"\xaa" * 75, 75, True),
        (b"\xaa" * 76, op.OP_PUSHDATA1, True),
        (b"\xaa" * 76, op.OP_PUSHDATA2, False),
    ],
)
def test_check_minimal_push(data, opcode, minimal):
    assert check_minimal_push(data, opcode) is minimal


def test_asm_roundtrip_display():
    spk = ScriptBuilder().op(op.OP_DUP).op(op.OP_HASH160).push(bytes(20)).op(op.OP_EQUALVERIFY).op(op.OP_CHECKSIG).build()
    assert spk.asm() == "OP_DUP OP_HASH160 " + ("00" * 20) + " OP_EQUALVERIFY OP_CHECKSIG"
