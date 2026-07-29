"""Per-execution data threaded through the interpreter (mirrors Core's
``ScriptExecutionData``).

Most fields are only meaningful for Taproot/tapscript execution and are filled
in by the Taproot dispatch in :mod:`bitoplens.vm.taproot`; for legacy and
SegWit v0 scripts the defaults are inert.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["ScriptExecutionData"]


@dataclass
class ScriptExecutionData:
    # Tapleaf hash (BIP341); set for tapscript execution.
    tapleaf_hash: bytes | None = None
    # Position of the last executed OP_CODESEPARATOR (tapscript sighash);
    # 0xFFFFFFFF means "none seen".
    codeseparator_pos: int = 0xFFFFFFFF
    # The 32-byte annex hash, if an annex was present.
    annex: bytes | None = None
    # Remaining tapscript validation-weight budget (BIP342).
    validation_weight: int = 0
    # Whether validation_weight / tapleaf tracking is active.
    tapscript: bool = False
