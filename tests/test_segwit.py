"""SegWit v0 tests: P2WPKH, P2WSH, P2SH-wrapped, and malleation rules."""

from __future__ import annotations

from bitoplens.primitives.hashing import hash160, sha256
from bitoplens.script import opcodes as OP
from bitoplens.script.script import ScriptBuilder
from bitoplens.tx.sighash import bip143_sighash
from bitoplens.tx.transaction import OutPoint, Transaction, TxIn, TxOut
from bitoplens.vm.checker import TransactionSignatureChecker
from bitoplens.vm.errors import ScriptError
from bitoplens.vm.flags import ScriptVerificationFlags as VF
from bitoplens.vm.interpreter import Interpreter

from tests.helpers import ecdsa_sign, pubkey

AMOUNT = 150_000
FLAGS = VF.P2SH | VF.WITNESS


def _tx(sequence=0xFFFFFFFE):
    return Transaction(
        version=2,
        vin=[TxIn(OutPoint(b"\x33" * 32, 0), b"", sequence)],
        vout=[TxOut(140_000, ScriptBuilder().op(OP.OP_1).build())],
    )


def _verify(spk, tx, witness, script_sig=b"", flags=FLAGS, amount=AMOUNT):
    checker = TransactionSignatureChecker(tx, 0, amount=amount)
    return Interpreter(flags, checker).verify(bytes(script_sig), bytes(spk), witness)


def _wsign(tx, script_code, d, hashtype=0x01):
    sh = bip143_sighash(tx, 0, script_code, AMOUNT, hashtype)
    return ecdsa_sign(sh, d) + bytes([hashtype])


def test_p2wpkh():
    d = 0xF00D
    pk = pubkey(d, compressed=True)
    program = hash160(pk)
    spk = bytes([0x00, 0x14]) + program
    synthetic = bytes([OP.OP_DUP, OP.OP_HASH160, 0x14]) + program + bytes([OP.OP_EQUALVERIFY, OP.OP_CHECKSIG])
    tx = _tx()
    sig = _wsign(tx, synthetic, d)
    tr = _verify(spk, tx, [sig, pk])
    assert tr.valid, tr.error_name
    assert any(r.role == "witnessScript" for r in tr.runs)


def test_p2wpkh_wrong_key_fails():
    d = 0xF00D
    pk = pubkey(d, compressed=True)
    program = hash160(pk)
    spk = bytes([0x00, 0x14]) + program
    synthetic = bytes([OP.OP_DUP, OP.OP_HASH160, 0x14]) + program + bytes([OP.OP_EQUALVERIFY, OP.OP_CHECKSIG])
    tx = _tx()
    sig = _wsign(tx, synthetic, d)
    # Present a different pubkey in the witness -> HASH160 mismatch (EQUALVERIFY).
    assert not _verify(spk, tx, [sig, pubkey(0xBAD, compressed=True)]).valid


def test_p2wsh_p2pk():
    d = 0xBEEF
    pk = pubkey(d, compressed=True)
    witness_script = ScriptBuilder().push(pk).op(OP.OP_CHECKSIG).build()
    program = sha256(witness_script)
    spk = bytes([0x00, 0x20]) + program
    tx = _tx()
    sig = _wsign(tx, bytes(witness_script), d)
    tr = _verify(spk, tx, [sig, bytes(witness_script)])
    assert tr.valid, tr.error_name


def test_p2wsh_multisig():
    ds = [0x1, 0x2, 0x3]
    pks = [pubkey(d, compressed=True) for d in ds]
    ws = ScriptBuilder().op(OP.OP_2).push(pks[0]).push(pks[1]).push(pks[2]).op(OP.OP_3).op(OP.OP_CHECKMULTISIG).build()
    program = sha256(ws)
    spk = bytes([0x00, 0x20]) + program
    tx = _tx()
    sig1 = _wsign(tx, bytes(ws), ds[0])
    sig2 = _wsign(tx, bytes(ws), ds[1])
    # witness: dummy, sig1, sig2, witnessScript
    tr = _verify(spk, tx, [b"", sig1, sig2, bytes(ws)])
    assert tr.valid, tr.error_name


def test_p2sh_p2wpkh():
    d = 0xC0DE
    pk = pubkey(d, compressed=True)
    program = hash160(pk)
    redeem = bytes([0x00, 0x14]) + program
    spk = ScriptBuilder().op(OP.OP_HASH160).push(hash160(redeem)).op(OP.OP_EQUAL).build()
    synthetic = bytes([OP.OP_DUP, OP.OP_HASH160, 0x14]) + program + bytes([OP.OP_EQUALVERIFY, OP.OP_CHECKSIG])
    tx = _tx()
    sig = _wsign(tx, synthetic, d)
    script_sig = ScriptBuilder().push(redeem).build()
    tr = _verify(spk, tx, [sig, pk], script_sig=script_sig)
    assert tr.valid, tr.error_name


def test_witness_malleated_nonempty_scriptsig():
    d = 0xF00D
    pk = pubkey(d, compressed=True)
    program = hash160(pk)
    spk = bytes([0x00, 0x14]) + program
    tx = _tx()
    synthetic = bytes([OP.OP_DUP, OP.OP_HASH160, 0x14]) + program + bytes([OP.OP_EQUALVERIFY, OP.OP_CHECKSIG])
    sig = _wsign(tx, synthetic, d)
    # A non-empty scriptSig on a native witness spend is malleation.
    ss = ScriptBuilder().op(OP.OP_1).build()
    assert _verify(spk, tx, [sig, pk], script_sig=ss).error == ScriptError.WITNESS_MALLEATED


def test_witness_unexpected():
    # scriptPubKey is a plain OP_1 (not a witness program) but a witness is given.
    spk = ScriptBuilder().op(OP.OP_1).build()
    tx = _tx()
    assert _verify(spk, tx, [b"\x00"]).error == ScriptError.WITNESS_UNEXPECTED


def test_p2wpkh_witness_pubkeytype():
    # Uncompressed pubkey rejected under WITNESS_PUBKEYTYPE.
    d = 0xF00D
    pk_u = pubkey(d, compressed=False)
    program = hash160(pk_u)
    spk = bytes([0x00, 0x14]) + program
    synthetic = bytes([OP.OP_DUP, OP.OP_HASH160, 0x14]) + program + bytes([OP.OP_EQUALVERIFY, OP.OP_CHECKSIG])
    tx = _tx()
    sig = _wsign(tx, synthetic, d)
    assert _verify(spk, tx, [sig, pk_u]).valid  # accepted without the flag
    assert (
        _verify(spk, tx, [sig, pk_u], flags=FLAGS | VF.WITNESS_PUBKEYTYPE).error
        == ScriptError.WITNESS_PUBKEYTYPE
    )
