"""Taproot tests: key-path, script-path, tapscript opcodes (BIP340/341/342)."""

from __future__ import annotations

from bitoplens.script import opcodes as OP
from bitoplens.script.script import ScriptBuilder
from bitoplens.tx.sighash import PrecomputedTransactionData, taproot_sighash
from bitoplens.tx.transaction import OutPoint, Transaction, TxIn, TxOut
from bitoplens.vm.checker import TransactionSignatureChecker
from bitoplens.vm.errors import ScriptError
from bitoplens.vm.flags import ScriptVerificationFlags as VF
from bitoplens.vm.interpreter import Interpreter
from bitoplens.vm.taproot import tapleaf_hash

from tests.helpers import schnorr_sign, taproot_output, xonly_pubkey

AMOUNT = 200_000
FLAGS = VF.P2SH | VF.WITNESS | VF.TAPROOT
LEAF = 0xC0


def _tx():
    return Transaction(
        version=2,
        vin=[TxIn(OutPoint(b"\x44" * 32, 0), b"", 0xFFFFFFFF)],
        vout=[TxOut(190_000, ScriptBuilder().op(OP.OP_1).build())],
    )


def _verify(spk, tx, witness, spent, flags=FLAGS):
    checker = TransactionSignatureChecker(tx, 0, amount=AMOUNT, spent_outputs=spent)
    return Interpreter(flags, checker).verify(b"", bytes(spk), witness)


def test_taproot_keypath():
    out_xonly, parity, q, internal_xonly, tweak = taproot_output(0xABC123)
    spk = bytes([0x51, 0x20]) + out_xonly
    tx = _tx()
    spent = [TxOut(AMOUNT, spk)]
    pre = PrecomputedTransactionData.compute(tx, spent)
    sighash = taproot_sighash(tx, 0, spent, 0x00, pre, ext_flag=0)
    sig = schnorr_sign(sighash, q)
    tr = _verify(spk, tx, [sig], spent)
    assert tr.valid, tr.error_name
    assert tr.spend_kind == "p2tr-keypath"


def test_taproot_keypath_wrong_sig_fails():
    out_xonly, parity, q, *_ = taproot_output(0xABC123)
    spk = bytes([0x51, 0x20]) + out_xonly
    tx = _tx()
    spent = [TxOut(AMOUNT, spk)]
    pre = PrecomputedTransactionData.compute(tx, spent)
    sighash = taproot_sighash(tx, 0, spent, 0x00, pre, ext_flag=0)
    sig = bytearray(schnorr_sign(sighash, q))
    sig[5] ^= 0xFF
    assert _verify(spk, tx, [bytes(sig)], spent).error == ScriptError.SCHNORR_SIG


def test_taproot_keypath_with_annex():
    out_xonly, parity, q, *_ = taproot_output(0x5151)
    spk = bytes([0x51, 0x20]) + out_xonly
    tx = _tx()
    spent = [TxOut(AMOUNT, spk)]
    annex = b"\x50" + b"\xde\xad\xbe\xef"
    pre = PrecomputedTransactionData.compute(tx, spent)
    sighash = taproot_sighash(tx, 0, spent, 0x00, pre, ext_flag=0, annex=annex)
    sig = schnorr_sign(sighash, q)
    tr = _verify(spk, tx, [sig, annex], spent)
    assert tr.valid, tr.error_name


def _scriptpath_setup(leaf_script, internal_d=0x999):
    leaf = tapleaf_hash(LEAF, bytes(leaf_script))
    out_xonly, parity, q, internal_xonly, tweak = taproot_output(internal_d, merkle_root=leaf)
    spk = bytes([0x51, 0x20]) + out_xonly
    control = bytes([LEAF | parity]) + internal_xonly
    return spk, control, leaf


def test_taproot_scriptpath_checksig():
    d = 0x7777
    pk = xonly_pubkey(d)
    leaf_script = bytes([0x20]) + pk + bytes([OP.OP_CHECKSIG])
    spk, control, leaf = _scriptpath_setup(leaf_script)
    tx = _tx()
    spent = [TxOut(AMOUNT, spk)]
    pre = PrecomputedTransactionData.compute(tx, spent)
    sighash = taproot_sighash(tx, 0, spent, 0x00, pre, ext_flag=1, tapleaf_hash=leaf)
    sig = schnorr_sign(sighash, d)
    tr = _verify(spk, tx, [sig, leaf_script, control], spent)
    assert tr.valid, tr.error_name
    assert tr.spend_kind == "p2tr-scriptpath"
    assert tr.control_block and tr.control_block["tapleaf_hash"] == leaf.hex()


def test_taproot_scriptpath_bad_commitment():
    d = 0x7777
    pk = xonly_pubkey(d)
    leaf_script = bytes([0x20]) + pk + bytes([OP.OP_CHECKSIG])
    spk, control, leaf = _scriptpath_setup(leaf_script)
    # Tamper the internal key in the control block -> commitment mismatch.
    bad_control = bytearray(control)
    bad_control[5] ^= 0xFF
    tx = _tx()
    spent = [TxOut(AMOUNT, spk)]
    pre = PrecomputedTransactionData.compute(tx, spent)
    sighash = taproot_sighash(tx, 0, spent, 0x00, pre, ext_flag=1, tapleaf_hash=leaf)
    sig = schnorr_sign(sighash, d)
    assert _verify(spk, tx, [sig, leaf_script, bytes(bad_control)], spent).error == ScriptError.WITNESS_PROGRAM_MISMATCH


def test_taproot_checksigadd_1of2():
    d1, d2 = 0x1234, 0x5678
    pk1, pk2 = xonly_pubkey(d1), xonly_pubkey(d2)
    # <pk1> CHECKSIG <pk2> CHECKSIGADD OP_1 NUMEQUAL
    leaf_script = (
        bytes([0x20]) + pk1 + bytes([OP.OP_CHECKSIG])
        + bytes([0x20]) + pk2 + bytes([OP.OP_CHECKSIGADD, OP.OP_1, OP.OP_NUMEQUAL])
    )
    spk, control, leaf = _scriptpath_setup(leaf_script)
    tx = _tx()
    spent = [TxOut(AMOUNT, spk)]
    pre = PrecomputedTransactionData.compute(tx, spent)
    sighash = taproot_sighash(tx, 0, spent, 0x00, pre, ext_flag=1, tapleaf_hash=leaf)
    sig1 = schnorr_sign(sighash, d1)
    # Initial tapscript stack (bottom->top) = [<empty for pk2>, sig1 for pk1]
    tr = _verify(spk, tx, [b"", sig1, leaf_script, control], spent)
    assert tr.valid, tr.error_name


def test_tapscript_checkmultisig_banned():
    # OP_CHECKMULTISIG is invalid under tapscript.
    leaf_script = ScriptBuilder().op(OP.OP_1).op(OP.OP_CHECKMULTISIG).build()
    spk, control, leaf = _scriptpath_setup(bytes(leaf_script))
    tx = _tx()
    spent = [TxOut(AMOUNT, spk)]
    tr = _verify(spk, tx, [bytes(leaf_script), control], spent)
    assert tr.error == ScriptError.TAPSCRIPT_CHECKMULTISIG


def test_tapscript_op_success():
    # A leaf containing OP_SUCCESS80 (0x50) is unconditionally valid.
    leaf_script = bytes([0x50])
    spk, control, leaf = _scriptpath_setup(leaf_script)
    tx = _tx()
    spent = [TxOut(AMOUNT, spk)]
    tr = _verify(spk, tx, [leaf_script, control], spent)
    assert tr.valid, tr.error_name
    # But discouraged when the flag is set.
    assert (
        _verify(spk, tx, [leaf_script, control], spent, FLAGS | VF.DISCOURAGE_OP_SUCCESS).error
        == ScriptError.DISCOURAGE_OP_SUCCESS
    )


def test_tapscript_minimalif():
    # Under tapscript OP_IF requires a minimal boolean; a 2-byte value fails.
    d = 0x333
    pk = xonly_pubkey(d)
    # OP_IF <pk> CHECKSIG ELSE <pk> CHECKSIG ENDIF -- but feed a non-minimal bool.
    leaf_script = bytes([OP.OP_IF, 0x20]) + pk + bytes([OP.OP_CHECKSIG, OP.OP_ELSE, OP.OP_1, OP.OP_ENDIF])
    spk, control, leaf = _scriptpath_setup(leaf_script)
    tx = _tx()
    spent = [TxOut(AMOUNT, spk)]
    # push a non-minimal truthy value (0x0100) as the IF condition
    tr = _verify(spk, tx, [b"\x01\x00", leaf_script, control], spent)
    assert tr.error == ScriptError.TAPSCRIPT_MINIMALIF
