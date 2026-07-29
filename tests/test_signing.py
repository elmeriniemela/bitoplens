"""End-to-end legacy signing tests (ECDSA + legacy sighash)."""

from __future__ import annotations

from bitoplens.script import opcodes as OP
from bitoplens.script.script import ScriptBuilder
from bitoplens.tx.sighash import legacy_sighash
from bitoplens.tx.transaction import OutPoint, Transaction, TxIn, TxOut
from bitoplens.vm.checker import TransactionSignatureChecker
from bitoplens.vm.errors import ScriptError
from bitoplens.vm.flags import ScriptVerificationFlags as VF
from bitoplens.vm.interpreter import Interpreter

from tests.helpers import ecdsa_sign, pubkey

# Block-170 tx (Satoshi -> Hal Finney): a real P2PK spend.
BLOCK170_TX = (
    "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37"
    "04000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c6"
    "1548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221"
    "a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b"
    "99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a"
    "0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49"
    "840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e16"
    "0bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"
)
# The pubkey of the coinbase output being spent (block 9, output 0).
BLOCK9_PUBKEY = (
    "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2"
    "e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3"
)


def test_block170_p2pk_real_signature():
    tx = Transaction.parse(BLOCK170_TX)
    prev_spk = bytes([0x41]) + bytes.fromhex(BLOCK9_PUBKEY) + bytes([0xAC])
    checker = TransactionSignatureChecker(tx, 0)
    tr = Interpreter(VF.NONE, checker).verify(tx.vin[0].script_sig, prev_spk)
    assert tr.valid
    assert tr.error == ScriptError.OK
    # The CHECKSIG step exposes the computed sighash.
    sig_steps = [s for r in tr.runs for s in r.steps if s.sig_check]
    assert sig_steps and sig_steps[-1].sig_check.valid


# --------------------------------------------------------------------------- #
# Constructed spends (we sign them ourselves)
# --------------------------------------------------------------------------- #

def _spending_tx(sequence=0xFFFFFFFF, version=1, locktime=0):
    return Transaction(
        version=version,
        vin=[TxIn(OutPoint(b"\x11" * 32, 0), b"", sequence)],
        vout=[TxOut(50_000, ScriptBuilder().op(OP.OP_1).build())],
        locktime=locktime,
    )


def _verify(spk, script_sig, tx, flags=VF.P2SH):
    checker = TransactionSignatureChecker(tx, 0)
    return Interpreter(flags, checker).verify(bytes(script_sig), bytes(spk))


def test_p2pk_constructed():
    d = 0xA11CE
    pk = pubkey(d, compressed=True)
    spk = ScriptBuilder().push(pk).op(OP.OP_CHECKSIG).build()
    tx = _spending_tx()
    sh = legacy_sighash(tx, 0, spk, 0x01)
    sig = ecdsa_sign(sh, d) + b"\x01"
    script_sig = ScriptBuilder().push(sig).build()
    assert _verify(spk, script_sig, tx).valid


def test_p2pkh_constructed():
    from bitoplens.primitives.hashing import hash160

    d = 0xB0B
    pk = pubkey(d, compressed=True)
    spk = (
        ScriptBuilder()
        .op(OP.OP_DUP).op(OP.OP_HASH160).push(hash160(pk)).op(OP.OP_EQUALVERIFY).op(OP.OP_CHECKSIG)
        .build()
    )
    tx = _spending_tx()
    sh = legacy_sighash(tx, 0, spk, 0x01)
    sig = ecdsa_sign(sh, d) + b"\x01"
    script_sig = ScriptBuilder().push(sig).push(pk).build()
    tr = _verify(spk, script_sig, tx)
    assert tr.valid
    # A wrong pubkey (different key) must fail EQUALVERIFY.
    wrong = ScriptBuilder().push(sig).push(pubkey(0xDEAD)).build()
    assert not _verify(spk, wrong, tx).valid


def test_p2pkh_tampered_sig_fails():
    from bitoplens.primitives.hashing import hash160

    d = 0xB0B
    pk = pubkey(d)
    spk = (
        ScriptBuilder()
        .op(OP.OP_DUP).op(OP.OP_HASH160).push(hash160(pk)).op(OP.OP_EQUALVERIFY).op(OP.OP_CHECKSIG)
        .build()
    )
    tx = _spending_tx()
    sh = legacy_sighash(tx, 0, spk, 0x01)
    sig = bytearray(ecdsa_sign(sh, d) + b"\x01")
    sig[10] ^= 0xFF  # corrupt
    script_sig = ScriptBuilder().push(bytes(sig)).push(pk).build()
    assert not _verify(spk, script_sig, tx).valid


def test_multisig_2of3():
    ds = [0x1111, 0x2222, 0x3333]
    pks = [pubkey(d) for d in ds]
    spk = (
        ScriptBuilder().op(OP.OP_2).push(pks[0]).push(pks[1]).push(pks[2]).op(OP.OP_3).op(OP.OP_CHECKMULTISIG)
        .build()
    )
    tx = _spending_tx()
    sh = legacy_sighash(tx, 0, spk, 0x01)
    # Sign with keys 1 and 2 (must be in pubkey order).
    sig1 = ecdsa_sign(sh, ds[0]) + b"\x01"
    sig2 = ecdsa_sign(sh, ds[1]) + b"\x01"
    script_sig = ScriptBuilder().op(OP.OP_0).push(sig1).push(sig2).build()
    assert _verify(spk, script_sig, tx).valid
    # Out-of-order signatures fail.
    bad = ScriptBuilder().op(OP.OP_0).push(sig2).push(sig1).build()
    assert not _verify(spk, bad, tx).valid


def test_multisig_nulldummy():
    ds = [0x1111, 0x2222]
    pks = [pubkey(d) for d in ds]
    spk = ScriptBuilder().op(OP.OP_1).push(pks[0]).push(pks[1]).op(OP.OP_2).op(OP.OP_CHECKMULTISIG).build()
    tx = _spending_tx()
    sh = legacy_sighash(tx, 0, spk, 0x01)
    sig1 = ecdsa_sign(sh, ds[0]) + b"\x01"
    # Non-empty dummy element violates NULLDUMMY.
    script_sig = ScriptBuilder().op(OP.OP_1).push(sig1).build()
    assert _verify(spk, script_sig, tx, VF.P2SH).valid
    assert _verify(spk, script_sig, tx, VF.P2SH | VF.NULLDUMMY).error == ScriptError.SIG_NULLDUMMY


def test_p2sh_multisig():
    from bitoplens.primitives.hashing import hash160

    ds = [0x1111, 0x2222, 0x3333]
    pks = [pubkey(d) for d in ds]
    redeem = (
        ScriptBuilder().op(OP.OP_2).push(pks[0]).push(pks[1]).push(pks[2]).op(OP.OP_3).op(OP.OP_CHECKMULTISIG)
        .build()
    )
    spk = ScriptBuilder().op(OP.OP_HASH160).push(hash160(redeem)).op(OP.OP_EQUAL).build()
    tx = _spending_tx()
    sh = legacy_sighash(tx, 0, redeem, 0x01)
    sig1 = ecdsa_sign(sh, ds[0]) + b"\x01"
    sig2 = ecdsa_sign(sh, ds[1]) + b"\x01"
    script_sig = ScriptBuilder().op(OP.OP_0).push(sig1).push(sig2).push(bytes(redeem)).build()
    tr = _verify(spk, script_sig, tx, VF.P2SH)
    assert tr.valid
    assert any(r.role == "redeemScript" for r in tr.runs)


def test_cltv():
    d = 0xC17E
    pk = pubkey(d)
    spk = (
        ScriptBuilder().push_int(500).op(OP.OP_CHECKLOCKTIMEVERIFY).op(OP.OP_DROP).push(pk).op(OP.OP_CHECKSIG)
        .build()
    )
    tx = _spending_tx(sequence=0xFFFFFFFE, locktime=600)
    sh = legacy_sighash(tx, 0, spk, 0x01)
    sig = ecdsa_sign(sh, d) + b"\x01"
    script_sig = ScriptBuilder().push(sig).build()
    assert _verify(spk, script_sig, tx, VF.P2SH | VF.CHECKLOCKTIMEVERIFY).valid
    # Locktime not reached -> unsatisfied.
    early = _spending_tx(sequence=0xFFFFFFFE, locktime=499)
    sh2 = legacy_sighash(early, 0, spk, 0x01)
    sig2 = ecdsa_sign(sh2, d) + b"\x01"
    ss2 = ScriptBuilder().push(sig2).build()
    assert _verify(spk, ss2, early, VF.P2SH | VF.CHECKLOCKTIMEVERIFY).error == ScriptError.UNSATISFIED_LOCKTIME


def test_csv():
    d = 0xC5F
    pk = pubkey(d)
    spk = (
        ScriptBuilder().push_int(10).op(OP.OP_CHECKSEQUENCEVERIFY).op(OP.OP_DROP).push(pk).op(OP.OP_CHECKSIG)
        .build()
    )
    tx = _spending_tx(sequence=20, version=2)
    sh = legacy_sighash(tx, 0, spk, 0x01)
    sig = ecdsa_sign(sh, d) + b"\x01"
    script_sig = ScriptBuilder().push(sig).build()
    assert _verify(spk, script_sig, tx, VF.P2SH | VF.CHECKSEQUENCEVERIFY).valid


def test_sighash_single_and_none():
    d = 0x5164
    pk = pubkey(d)
    spk = ScriptBuilder().push(pk).op(OP.OP_CHECKSIG).build()
    for ht in (0x02, 0x03, 0x81, 0x82, 0x83):  # NONE, SINGLE, ALL|ACP, NONE|ACP, SINGLE|ACP
        tx = _spending_tx()
        sh = legacy_sighash(tx, 0, spk, ht)
        sig = ecdsa_sign(sh, d) + bytes([ht])
        script_sig = ScriptBuilder().push(sig).build()
        assert _verify(spk, script_sig, tx).valid, f"hashtype {ht:#x}"
