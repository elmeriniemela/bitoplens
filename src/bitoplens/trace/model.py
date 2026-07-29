"""The execution-trace data model.

These dataclasses are what both the Python API and the HTML visualizer consume.
Every :class:`ExecutionStep` carries a full immutable snapshot of machine state
*after* the step, so the viewer can scrub the execution without re-running it.
All stack items are ``bytes``; :func:`to_jsonable` renders the whole trace into
plain JSON-serializable structures (bytes -> hex) for embedding in the viewer.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

__all__ = [
    "StackDelta",
    "SigCheckDetail",
    "ExecutionStep",
    "ScriptRun",
    "VerificationTrace",
    "to_jsonable",
]


@dataclass(frozen=True)
class StackDelta:
    """How the main stack changed in one step (for push/pop highlighting)."""

    popped: int = 0
    pushed: tuple[bytes, ...] = ()


@dataclass(frozen=True)
class SigCheckDetail:
    """Details captured at a CHECKSIG / CHECKMULTISIG / CHECKSIGADD step."""

    sig: bytes
    pubkey: bytes
    sighash: bytes
    script_code: bytes
    sig_version: int
    valid: bool


@dataclass
class ExecutionStep:
    """One executed (or skipped) opcode plus the resulting machine state."""

    step: int  # global monotonic index across the whole verification
    run_index: int
    op_index: int  # nth operation within this run's script
    script_offset: int  # byte offset of the opcode within the script
    opcode: int
    opcode_name: str
    description: str
    pushdata: bytes = b""
    executed: bool = True  # False when skipped by an inactive IF branch
    stack: tuple[bytes, ...] = ()
    altstack: tuple[bytes, ...] = ()
    exec_stack: tuple[bool, ...] = ()  # vfExec (OP_IF nesting)
    op_count: int = 0
    delta: StackDelta | None = None
    sig_check: SigCheckDetail | None = None
    note: str = ""
    error: int | None = None


@dataclass
class ScriptRun:
    """One contiguous evaluation of a single script."""

    index: int
    role: str  # "scriptSig" | "scriptPubKey" | "redeemScript" | "witnessScript" | "tapscript"
    sig_version: int
    script: bytes
    script_type: str
    initial_stack: tuple[bytes, ...]
    steps: list[ExecutionStep] = field(default_factory=list)
    final_stack: tuple[bytes, ...] = ()
    error: int = 0  # ScriptError.OK


@dataclass
class VerificationTrace:
    """The full result of one input's script verification."""

    valid: bool
    error: int
    flags: int
    runs: list[ScriptRun] = field(default_factory=list)
    input_index: int = 0
    transaction: dict | None = None  # a serialized tx view for the viz panel
    spend_kind: str = ""  # "" | "p2tr-keypath" | "p2tr-scriptpath"
    control_block: dict | None = None

    @property
    def error_name(self) -> str:
        from bitoplens.vm.errors import ScriptError

        return ScriptError(self.error).name


# --------------------------------------------------------------------------- #
# JSON rendering
# --------------------------------------------------------------------------- #

def _convert(value):
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    if isinstance(value, tuple):
        return [_convert(v) for v in value]
    if isinstance(value, list):
        return [_convert(v) for v in value]
    if isinstance(value, dict):
        return {k: _convert(v) for k, v in value.items()}
    return value


def to_jsonable(trace: VerificationTrace) -> dict:
    """Render ``trace`` into nested dict/list/str/int/bool (bytes -> hex)."""
    return _convert(asdict(trace))
