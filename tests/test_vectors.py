"""Validation against the official BIP341 wallet test vectors.

This is the strongest correctness check: it exercises the Taproot output-key
derivation, the BIP143/BIP341 sighash midstates, the key-path sighash, and the
full interpreter against *real* consensus signatures -- independent of our own
test signer.
"""

from __future__ import annotations

import json
import os

import pytest

from bitoplens.crypto.taproot import taproot_tweak_pubkey
from bitoplens.primitives.hashing import tagged_hash
from bitoplens.tx.sighash import PrecomputedTransactionData, taproot_sighash
from bitoplens.tx.transaction import Transaction, TxOut
from bitoplens.vm.checker import TransactionSignatureChecker
from bitoplens.vm.flags import ScriptVerificationFlags as VF
from bitoplens.vm.interpreter import Interpreter

_DATA = os.path.join(os.path.dirname(__file__), "data", "bip341_wallet_vectors.json")

if not os.path.exists(_DATA):  # pragma: no cover
    pytest.skip("BIP341 vectors not vendored", allow_module_level=True)

with open(_DATA) as _fh:
    VECTORS = json.load(_fh)


def test_output_key_derivation():
    """scriptPubKey vectors: internal key + merkle root -> output key/spk."""
    for case in VECTORS["scriptPubKey"]:
        internal = bytes.fromhex(case["given"]["internalPubkey"])
        mr = case["intermediary"]["merkleRoot"]
        merkle_root = b"" if mr is None else bytes.fromhex(mr)
        tweak = tagged_hash("TapTweak", internal + merkle_root)
        assert tweak.hex() == case["intermediary"]["tweak"]
        tweaked = taproot_tweak_pubkey(internal, tweak)
        assert tweaked is not None
        out_xonly, _parity = tweaked
        assert out_xonly.hex() == case["intermediary"]["tweakedPubkey"]
        assert case["expected"]["scriptPubKey"] == "5120" + out_xonly.hex()


def _load_keypath(group):
    tx = Transaction.parse(group["given"]["rawUnsignedTx"])
    spent = [
        TxOut(u["amountSats"], bytes.fromhex(u["scriptPubKey"]))
        for u in group["given"]["utxosSpent"]
    ]
    return tx, spent


def test_keypath_midstates():
    for group in VECTORS["keyPathSpending"]:
        tx, spent = _load_keypath(group)
        pre = PrecomputedTransactionData.compute(tx, spent)
        inter = group["intermediary"]
        assert pre.sha_prevouts.hex() == inter["hashPrevouts"]
        assert pre.sha_amounts.hex() == inter["hashAmounts"]
        assert pre.sha_scriptpubkeys.hex() == inter["hashScriptPubkeys"]
        assert pre.sha_sequences.hex() == inter["hashSequences"]
        assert pre.sha_outputs.hex() == inter["hashOutputs"]


def test_keypath_sighash_matches():
    for group in VECTORS["keyPathSpending"]:
        tx, spent = _load_keypath(group)
        pre = PrecomputedTransactionData.compute(tx, spent)
        for inp in group["inputSpending"]:
            i = inp["given"]["txinIndex"]
            ht = inp["given"]["hashType"]
            sh = taproot_sighash(tx, i, spent, ht, pre, ext_flag=0)
            assert sh.hex() == inp["intermediary"]["sigHash"].lower(), f"input {i}"


def test_keypath_full_verify_with_real_signatures():
    for group in VECTORS["keyPathSpending"]:
        tx, spent = _load_keypath(group)
        for inp in group["inputSpending"]:
            i = inp["given"]["txinIndex"]
            witness = [bytes.fromhex(w) for w in inp["expected"]["witness"]]
            tx.vin[i].witness = witness
            checker = TransactionSignatureChecker(
                tx, i, amount=spent[i].value, spent_outputs=spent
            )
            interp = Interpreter(VF.P2SH | VF.WITNESS | VF.TAPROOT, checker)
            trace = interp.verify(b"", bytes(spent[i].script_pubkey), witness)
            assert trace.valid, f"input {i}: {trace.error_name}"
