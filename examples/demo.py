"""bitoplens demo: simulate a few scripts and write interactive HTML traces.

Run from the repo root:  python examples/demo.py
Then open the generated *.html files in a browser.
"""

from __future__ import annotations

import bitoplens as bl
from bitoplens.primitives.hashing import hash160, sha256
from bitoplens.script import opcodes as OP
from bitoplens.script.script import ScriptBuilder
from bitoplens.tx.sighash import legacy_sighash
from bitoplens.tx.transaction import OutPoint, Transaction, TxIn, TxOut
from bitoplens.vm.flags import ScriptVerificationFlags as VF

# The test-only signer lives under tests/, imported here just for the demo.
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.helpers import ecdsa_sign, pubkey  # noqa: E402


def hash_lock_demo():
    """A simple hash-preimage lock -- no signatures, no tx needed."""
    secret = b"open sesame"
    spk = ScriptBuilder().op(OP.OP_SHA256).push(sha256(secret)).op(OP.OP_EQUAL).build()
    sig = ScriptBuilder().push(secret).build()
    trace = bl.run_script(spk, sig)
    bl.visualize(trace, "examples/hashlock.html")
    print(f"hash lock: valid={trace.valid} -> examples/hashlock.html")


def p2pkh_demo():
    """A full P2PKH spend with a real ECDSA signature."""
    d = 0xB0B
    pk = pubkey(d)
    spk = (
        ScriptBuilder().op(OP.OP_DUP).op(OP.OP_HASH160).push(hash160(pk))
        .op(OP.OP_EQUALVERIFY).op(OP.OP_CHECKSIG).build()
    )
    tx = Transaction(
        version=1,
        vin=[TxIn(OutPoint(b"\x11" * 32, 0), b"", 0xFFFFFFFF)],
        vout=[TxOut(90_000, bytes.fromhex("0014") + bytes(20))],
    )
    sighash = legacy_sighash(tx, 0, spk, 0x01)
    tx.vin[0].script_sig = ScriptBuilder().push(ecdsa_sign(sighash, d) + b"\x01").push(pk).build()
    trace = bl.run(spk, tx=tx, input_index=0, spent_outputs=[TxOut(100_000, spk)], flags=VF.P2SH)
    bl.visualize(trace, "examples/p2pkh.html")
    print(f"p2pkh: valid={trace.valid} -> examples/p2pkh.html")


if __name__ == "__main__":
    hash_lock_demo()
    p2pkh_demo()
