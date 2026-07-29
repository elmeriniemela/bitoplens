"""bitoplens -- a pure-Python Bitcoin Script simulator and visualizer.

Quick start::

    import bitoplens as bl
    trace = bl.run_script(script_pubkey, script_sig, flags=bl.ScriptVerificationFlags.NONE)
    bl.visualize(trace, "trace.html")
"""

from __future__ import annotations

from bitoplens.api import run, run_script, transaction_view, visualize
from bitoplens.script.opcodes import classify_script, disassemble
from bitoplens.script.script import Script, ScriptBuilder
from bitoplens.trace.model import VerificationTrace
from bitoplens.tx.transaction import OutPoint, Transaction, TxIn, TxOut
from bitoplens.vm.checker import TransactionSignatureChecker
from bitoplens.vm.errors import ScriptError, ScriptException
from bitoplens.vm.flags import ScriptVerificationFlags, SigVersion
from bitoplens.vm.interpreter import Interpreter

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "run",
    "run_script",
    "visualize",
    "transaction_view",
    "Script",
    "ScriptBuilder",
    "classify_script",
    "disassemble",
    "Transaction",
    "TxIn",
    "TxOut",
    "OutPoint",
    "Interpreter",
    "TransactionSignatureChecker",
    "VerificationTrace",
    "ScriptVerificationFlags",
    "SigVersion",
    "ScriptError",
    "ScriptException",
]
