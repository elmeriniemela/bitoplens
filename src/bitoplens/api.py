"""High-level entry points: run scripts, verify tx inputs, and visualize.

- :func:`run_script` -- quick simulation of a scriptSig/scriptPubKey pair with
  no transaction context (signature opcodes will fail without a checker).
- :func:`run` -- verify one input of a real transaction against its previous
  output, with full signature checking.
- :func:`visualize` -- render a trace (or a transaction) to a self-contained
  interactive HTML page.
"""

from __future__ import annotations

from bitoplens.script.opcodes import classify_script, disassemble
from bitoplens.trace.model import VerificationTrace
from bitoplens.tx.address import script_to_address
from bitoplens.tx.transaction import Transaction
from bitoplens.vm.checker import TransactionSignatureChecker
from bitoplens.vm.flags import ScriptVerificationFlags as VF
from bitoplens.vm.interpreter import Interpreter

__all__ = ["run_script", "run", "visualize", "transaction_view"]


def _asm(script: bytes) -> str:
    parts = []
    for _pos, name, data in disassemble(bytes(script)):
        parts.append(data.hex() if data else name)
    return " ".join(parts)


def transaction_view(tx: Transaction, input_index: int | None = None, spent_outputs=None) -> dict:
    """Build a JSON-friendly view of ``tx`` for the visualizer's tx panel."""
    vin = []
    for i, txin in enumerate(tx.vin):
        prev_spk = None
        if spent_outputs is not None and i < len(spent_outputs):
            prev_spk = bytes(spent_outputs[i].script_pubkey).hex()
        vin.append(
            {
                "index": i,
                "txid": txin.prevout.txid_hex(),
                "vout": txin.prevout.vout,
                "script_sig": bytes(txin.script_sig).hex(),
                "script_sig_asm": _asm(txin.script_sig),
                "sequence": txin.sequence,
                "witness": [w.hex() for w in txin.witness],
                "prev_script_pubkey": prev_spk,
                "is_target": (i == input_index),
            }
        )
    vout = []
    for i, txout in enumerate(tx.vout):
        vout.append(
            {
                "index": i,
                "value": txout.value,
                "script_pubkey": bytes(txout.script_pubkey).hex(),
                "script_pubkey_asm": _asm(txout.script_pubkey),
                "type": classify_script(txout.script_pubkey),
                "address": script_to_address(txout.script_pubkey),
            }
        )
    return {
        "txid": tx.txid_hex(),
        "wtxid": tx.wtxid_hex(),
        "version": tx.version,
        "locktime": tx.locktime,
        "vin": vin,
        "vout": vout,
        "input_index": input_index,
    }


def run_script(
    script_pubkey: bytes,
    script_sig: bytes = b"",
    *,
    flags: VF = VF.NONE,
    checker=None,
) -> VerificationTrace:
    """Simulate a scriptSig/scriptPubKey pair without a transaction context."""
    return Interpreter(flags, checker).verify(bytes(script_sig), bytes(script_pubkey))


def run(
    script_pubkey: bytes,
    *,
    tx: Transaction,
    input_index: int,
    spent_outputs=None,
    flags: VF = VF.P2SH,
) -> VerificationTrace:
    """Verify input ``input_index`` of ``tx`` against ``script_pubkey``."""
    amount = 0
    if spent_outputs is not None and input_index < len(spent_outputs):
        amount = spent_outputs[input_index].value
    checker = TransactionSignatureChecker(tx, input_index, amount, spent_outputs)
    interp = Interpreter(flags, checker)
    txin = tx.vin[input_index]
    trace = interp.verify(txin.script_sig, bytes(script_pubkey), txin.witness)
    trace.input_index = input_index
    trace.transaction = transaction_view(tx, input_index, spent_outputs)
    return trace


def visualize(trace_or_tx, path: str | None = None) -> str:
    """Render ``trace_or_tx`` to a self-contained HTML page.

    Accepts a :class:`VerificationTrace` or a :class:`Transaction`. Returns the
    HTML string; if ``path`` is given, also writes it there.
    """
    from bitoplens.viz.render import render, render_transaction

    if isinstance(trace_or_tx, Transaction):
        html = render_transaction(trace_or_tx)
    else:
        html = render(trace_or_tx)
    if path is not None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
    return html
