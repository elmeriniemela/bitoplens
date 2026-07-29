"""The stepping Bitcoin Script interpreter.

The evaluation loop mirrors Bitcoin Core's ``EvalScript`` / ``VerifyScript``
closely: the per-iteration order (push-size check, opcode count, disabled-opcode
rejection, then the fExec-gated switch) matters for matching consensus error
codes. Every processed opcode is recorded as an :class:`ExecutionStep` with a
full state snapshot, so the trace can be replayed by the visualizer.

Signature-checking opcodes delegate to an injected ``checker`` (see
:mod:`bitoplens.vm.checker`); without one they raise, so the crypto-free subset
of scripts runs with ``checker=None``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from bitoplens.primitives.hashing import hash160, hash256, ripemd160, sha1, sha256
from bitoplens.primitives.scriptnum import cast_to_bool, decode_num, encode_num
from bitoplens.script import opcodes as OP
from bitoplens.script.opcodes import (
    classify_script,
    opcode_description,
    opcode_name,
)
from bitoplens.script.script import (
    Script,
    ScriptParseError,
    _encode_push,
    check_minimal_push,
    find_and_delete,
)
from bitoplens.trace.model import (
    ExecutionStep,
    ScriptRun,
    SigCheckDetail,
    StackDelta,
    VerificationTrace,
)
from bitoplens.vm.checker import check_pubkey_encoding, check_signature_encoding
from bitoplens.vm.errors import ScriptError, ScriptException
from bitoplens.vm.execdata import ScriptExecutionData
from bitoplens.vm.flags import ScriptVerificationFlags as VF
from bitoplens.vm.flags import SigVersion
from bitoplens.vm.taproot import TAPROOT_LEAF_TAPSCRIPT, verify_taproot_commitment

__all__ = ["Interpreter", "verify_scripts"]

MAX_SCRIPT_ELEMENT_SIZE = 520
MAX_OPS_PER_SCRIPT = 201
MAX_STACK_SIZE = 1000
MAX_SCRIPT_SIZE = 10000
MAX_PUBKEYS_PER_MULTISIG = 20
LOCKTIME_THRESHOLD = 500_000_000
SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31


@dataclass
class _Frame:
    """Mutable per-script evaluation state."""

    script: bytes
    sig_version: int
    execdata: ScriptExecutionData
    require_minimal: bool
    op_count: int = 0
    # Byte offset just after the most recent executed OP_CODESEPARATOR (legacy
    # script_code starts here). 0 means "from the beginning".
    codeseparator_offset: int = 0
    current_op_index: int = 0
    exec_stack: list = field(default_factory=list)
    altstack: list = field(default_factory=list)


@dataclass
class _StepResult:
    note: str = ""
    sig_check: SigCheckDetail | None = None


def _is_p2sh(spk: bytes) -> bool:
    return (
        len(spk) == 23
        and spk[0] == OP.OP_HASH160
        and spk[1] == 0x14
        and spk[22] == OP.OP_EQUAL
    )


def _witness_program(spk: bytes) -> tuple[int, bytes] | None:
    """If ``spk`` is a witness program, return ``(version, program_bytes)``.

    A witness program is: a version opcode (OP_0 or OP_1..OP_16) followed by a
    single direct push of 2..40 bytes, and nothing else.
    """
    spk = bytes(spk)
    n = len(spk)
    if n < 4 or n > 42:
        return None
    v0 = spk[0]
    if v0 != OP.OP_0 and not (OP.OP_1 <= v0 <= OP.OP_16):
        return None
    push_len = spk[1]
    if not (0x02 <= push_len <= 0x28) or n != push_len + 2:
        return None
    version = 0 if v0 == OP.OP_0 else v0 - (OP.OP_1 - 1)
    return version, spk[2:]


def _compact_size_len(n: int) -> int:
    if n < 0xFD:
        return 1
    if n <= 0xFFFF:
        return 3
    if n <= 0xFFFFFFFF:
        return 5
    return 9


def _witness_serialized_size(witness: list) -> int:
    """Serialized byte size of a witness stack (BIP342 validation-weight base)."""
    size = _compact_size_len(len(witness))
    for item in witness:
        size += _compact_size_len(len(item)) + len(item)
    return size


class Interpreter:
    """Verifies scriptSig/scriptPubKey pairs and records an execution trace."""

    def __init__(self, flags: VF = VF.NONE, checker=None):
        self.flags = VF(flags)
        self.checker = checker
        self.runs: list[ScriptRun] = []
        self._step_counter = 0
        self._pending_sig: SigCheckDetail | None = None
        self._spend_kind = ""
        self._control_block = None

    # ------------------------------------------------------------------ #
    # Top-level verification
    # ------------------------------------------------------------------ #

    def verify(self, script_sig: bytes, script_pubkey: bytes, witness=None) -> VerificationTrace:
        """Run scriptSig then scriptPubKey, with P2SH and SegWit, returning a trace."""
        flags = self.flags
        witness = list(witness) if witness else []
        error = ScriptError.OK
        valid = False
        try:
            if flags & VF.SIGPUSHONLY and not Script(script_sig).is_push_only():
                raise ScriptException(ScriptError.SIG_PUSHONLY)

            stack: list[bytes] = []
            self._eval_script(script_sig, stack, SigVersion.BASE, "scriptSig")
            stack_copy = list(stack)
            self._eval_script(script_pubkey, stack, SigVersion.BASE, "scriptPubKey")

            if not stack or not cast_to_bool(stack[-1]):
                raise ScriptException(ScriptError.EVAL_FALSE)

            had_witness = False
            wp = _witness_program(script_pubkey)
            if flags & VF.WITNESS and wp is not None:
                had_witness = True
                if len(script_sig) != 0:
                    raise ScriptException(ScriptError.WITNESS_MALLEATED)
                stack = self._verify_witness_program(witness, wp[0], wp[1])

            # P2SH: re-run the serialized redeem script from the scriptSig.
            elif flags & VF.P2SH and _is_p2sh(script_pubkey):
                if not Script(script_sig).is_push_only():
                    raise ScriptException(ScriptError.SIG_PUSHONLY)
                redeem = stack_copy.pop() if stack_copy else b""
                stack = stack_copy
                wp = _witness_program(redeem)
                if flags & VF.WITNESS and wp is not None:
                    had_witness = True
                    # scriptSig must be exactly a single push of the redeem script.
                    if bytes(script_sig) != _encode_push(redeem):
                        raise ScriptException(ScriptError.WITNESS_MALLEATED_P2SH)
                    stack = self._verify_witness_program(witness, wp[0], wp[1])
                else:
                    self._eval_script(redeem, stack, SigVersion.BASE, "redeemScript")
                    if not stack or not cast_to_bool(stack[-1]):
                        raise ScriptException(ScriptError.EVAL_FALSE)

            if flags & VF.CLEANSTACK:
                if len(stack) != 1:
                    raise ScriptException(ScriptError.CLEANSTACK)

            # A witness present but never consumed is a malleability vector.
            if flags & VF.WITNESS and not had_witness and witness:
                raise ScriptException(ScriptError.WITNESS_UNEXPECTED)

            valid = True
        except ScriptException as exc:
            error = exc.error
            valid = False

        return VerificationTrace(
            valid=valid,
            error=int(error),
            flags=int(flags),
            runs=self.runs,
            spend_kind=self._spend_kind,
            control_block=self._control_block,
        )

    def _verify_witness_program(self, witness: list, version: int, program: bytes) -> list:
        """Verify a witness program; returns the final stack or raises."""
        if version == 0:
            if len(program) == 32:  # P2WSH
                if len(witness) == 0:
                    raise ScriptException(ScriptError.WITNESS_PROGRAM_WITNESS_EMPTY)
                witness_script = witness[-1]
                stack = list(witness[:-1])
                if sha256(witness_script) != program:
                    raise ScriptException(ScriptError.WITNESS_PROGRAM_MISMATCH)
                self._check_witness_stack_sizes(stack)
                self._eval_script(witness_script, stack, SigVersion.WITNESS_V0, "witnessScript")
            elif len(program) == 20:  # P2WPKH
                if len(witness) != 2:
                    raise ScriptException(ScriptError.WITNESS_PROGRAM_MISMATCH)
                stack = list(witness)
                self._check_witness_stack_sizes(stack)
                synthetic = bytes([OP.OP_DUP, OP.OP_HASH160, 0x14]) + program + bytes(
                    [OP.OP_EQUALVERIFY, OP.OP_CHECKSIG]
                )
                self._eval_script(synthetic, stack, SigVersion.WITNESS_V0, "witnessScript")
            else:
                raise ScriptException(ScriptError.WITNESS_PROGRAM_WRONG_LENGTH)
            if len(stack) != 1:
                raise ScriptException(ScriptError.CLEANSTACK)
            if not cast_to_bool(stack[-1]):
                raise ScriptException(ScriptError.EVAL_FALSE)
            return stack

        # Witness v1 (Taproot) is handled by the Taproot module (Phase 6).
        if version == 1 and len(program) == 32 and (self.flags & VF.TAPROOT):
            return self._verify_taproot(witness, program)

        if self.flags & VF.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM:
            raise ScriptException(ScriptError.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
        # Unknown witness versions are treated as anyone-can-spend (soft-fork room).
        return [b"\x01"]

    def _check_witness_stack_sizes(self, stack):
        for item in stack:
            if len(item) > MAX_SCRIPT_ELEMENT_SIZE:
                raise ScriptException(ScriptError.PUSH_SIZE)

    def _verify_taproot(self, witness, program) -> list:
        """Verify a witness-v1 (Taproot) spend: key-path or script-path."""
        stack = list(witness)
        annex = None
        if len(stack) >= 2 and len(stack[-1]) > 0 and stack[-1][0] == 0x50:
            annex = stack.pop()
        if len(stack) == 0:
            raise ScriptException(ScriptError.WITNESS_PROGRAM_WITNESS_EMPTY)

        execdata = ScriptExecutionData(annex=annex)

        if len(stack) == 1:
            # ---- Key-path spend -----------------------------------------
            self._spend_kind = "p2tr-keypath"
            sig = stack[0]
            if len(sig) not in (64, 65):
                raise ScriptException(ScriptError.SCHNORR_SIG_SIZE)
            if len(sig) == 65 and sig[64] not in self._VALID_SCHNORR_HASHTYPES:
                raise ScriptException(ScriptError.SCHNORR_SIG_HASHTYPE)
            ok, sighash = self._require_checker().check_schnorr_sig(
                sig, program, SigVersion.TAPROOT, execdata
            )
            self._record_keypath(program, sig, sighash, ok)
            if not ok:
                raise ScriptException(ScriptError.SCHNORR_SIG)
            return [b"\x01"]

        # ---- Script-path spend ------------------------------------------
        self._spend_kind = "p2tr-scriptpath"
        control = stack.pop()
        script = stack.pop()
        if len(control) < 33 or (len(control) - 33) % 32 != 0:
            raise ScriptException(ScriptError.TAPROOT_WRONG_CONTROL_SIZE)
        ok, leaf = verify_taproot_commitment(control, program, script)
        leaf_version = control[0] & 0xFE
        self._control_block = {
            "leaf_version": leaf_version,
            "parity": control[0] & 0x01,
            "internal_key": control[1:33].hex(),
            "merkle_path": [control[33 + 32 * i : 65 + 32 * i].hex() for i in range((len(control) - 33) // 32)],
            "tapleaf_hash": leaf.hex(),
        }
        if not ok:
            raise ScriptException(ScriptError.WITNESS_PROGRAM_MISMATCH)
        execdata.tapleaf_hash = leaf
        execdata.tapscript = True

        # Unknown leaf versions are not executed (reserved for future upgrades).
        if leaf_version != TAPROOT_LEAF_TAPSCRIPT:
            if self.flags & VF.DISCOURAGE_UPGRADABLE_TAPROOT_VERSION:
                raise ScriptException(ScriptError.DISCOURAGE_UPGRADABLE_TAPROOT_VERSION)
            return [b"\x01"]

        # An OP_SUCCESSx anywhere in a tapscript makes it unconditionally valid.
        if self._has_op_success(script):
            if self.flags & VF.DISCOURAGE_OP_SUCCESS:
                raise ScriptException(ScriptError.DISCOURAGE_OP_SUCCESS)
            return [b"\x01"]

        execdata.validation_weight = 50 + _witness_serialized_size(witness)
        self._check_witness_stack_sizes(stack)
        self._eval_script(script, stack, SigVersion.TAPSCRIPT, "tapscript", execdata)
        if len(stack) != 1:
            raise ScriptException(ScriptError.CLEANSTACK)
        if not cast_to_bool(stack[-1]):
            raise ScriptException(ScriptError.EVAL_FALSE)
        return stack

    def _has_op_success(self, script: bytes) -> bool:
        try:
            for sop in Script(script).ops():
                if OP.is_op_success(sop.opcode):
                    return True
        except ScriptParseError:
            raise ScriptException(ScriptError.BAD_OPCODE)
        return False

    def _record_keypath(self, program, sig, sighash, ok):
        run = ScriptRun(
            index=len(self.runs),
            role="keypath",
            sig_version=int(SigVersion.TAPROOT),
            script=bytes(program),
            script_type="P2TR key-path",
            initial_stack=(sig,),
        )
        self.runs.append(run)
        run.steps.append(
            ExecutionStep(
                step=self._step_counter,
                run_index=run.index,
                op_index=0,
                script_offset=0,
                opcode=OP.OP_CHECKSIG,
                opcode_name="CHECKSIG (key-path)",
                description="BIP341 key-path Schnorr signature check against the output key.",
                executed=True,
                stack=(program,),
                sig_check=SigCheckDetail(
                    sig=sig, pubkey=program, sighash=sighash, script_code=b"",
                    sig_version=int(SigVersion.TAPROOT), valid=ok,
                ),
                note="signature valid" if ok else "signature invalid",
                error=None if ok else int(ScriptError.SCHNORR_SIG),
            )
        )
        self._step_counter += 1
        run.final_stack = (program,)
        if not ok:
            run.error = int(ScriptError.SCHNORR_SIG)

    # ------------------------------------------------------------------ #
    # Single-script evaluation
    # ------------------------------------------------------------------ #

    def _eval_script(
        self,
        script_bytes: bytes,
        stack: list,
        sig_version: SigVersion,
        role: str,
        execdata: ScriptExecutionData | None = None,
    ) -> ScriptRun:
        run_index = len(self.runs)
        run = ScriptRun(
            index=run_index,
            role=role,
            sig_version=int(sig_version),
            script=bytes(script_bytes),
            script_type=classify_script(script_bytes),
            initial_stack=tuple(stack),
        )
        self.runs.append(run)

        if execdata is None:
            execdata = ScriptExecutionData()
        frame = _Frame(
            script=bytes(script_bytes),
            sig_version=int(sig_version),
            execdata=execdata,
            require_minimal=bool(self.flags & VF.MINIMALDATA),
        )

        # Tapscript has no 10000-byte / 201-op limits; legacy/v0 do.
        if sig_version in (SigVersion.BASE, SigVersion.WITNESS_V0) and len(script_bytes) > MAX_SCRIPT_SIZE:
            self._record_terminal(run, ScriptError.SCRIPT_SIZE)
            run.error = int(ScriptError.SCRIPT_SIZE)
            raise ScriptException(ScriptError.SCRIPT_SIZE)

        op_index = 0
        try:
            ops = list(Script(script_bytes).ops())
        except ScriptParseError:
            self._record_terminal(run, ScriptError.BAD_OPCODE)
            run.error = int(ScriptError.BAD_OPCODE)
            raise ScriptException(ScriptError.BAD_OPCODE)

        for sop in ops:
            executing = all(frame.exec_stack)
            frame.current_op_index = op_index
            pre = list(stack)
            err: ScriptError | None = None
            result = _StepResult()
            self._pending_sig = None
            try:
                result = self._step(sop, executing, stack, frame) or _StepResult()
                if len(stack) + len(frame.altstack) > MAX_STACK_SIZE:
                    raise ScriptException(ScriptError.STACK_SIZE)
            except ScriptException as exc:
                err = exc.error

            self._append_step(
                run, run_index, op_index, sop, executing, stack, frame, pre, result, err
            )
            op_index += 1

            if err is not None:
                run.error = int(err)
                run.final_stack = tuple(stack)
                raise ScriptException(err)

        if frame.exec_stack:
            self._record_terminal(run, ScriptError.UNBALANCED_CONDITIONAL)
            run.error = int(ScriptError.UNBALANCED_CONDITIONAL)
            raise ScriptException(ScriptError.UNBALANCED_CONDITIONAL)

        run.final_stack = tuple(stack)
        return run

    # ------------------------------------------------------------------ #
    # Step recording
    # ------------------------------------------------------------------ #

    def _append_step(self, run, run_index, op_index, sop, executing, stack, frame, pre, result, err):
        post = stack
        delta = None
        if executing and err is None:
            common = 0
            minlen = min(len(pre), len(post))
            while common < minlen and pre[common] == post[common]:
                common += 1
            delta = StackDelta(popped=len(pre) - common, pushed=tuple(post[common:]))
        step = ExecutionStep(
            step=self._step_counter,
            run_index=run_index,
            op_index=op_index,
            script_offset=sop.offset,
            opcode=sop.opcode,
            opcode_name=opcode_name(sop.opcode),
            description=opcode_description(sop.opcode),
            pushdata=sop.data or b"",
            executed=executing,
            stack=tuple(stack),
            altstack=tuple(frame.altstack),
            exec_stack=tuple(frame.exec_stack),
            op_count=frame.op_count,
            delta=delta,
            sig_check=result.sig_check or self._pending_sig,
            note=result.note,
            error=int(err) if err is not None else None,
        )
        run.steps.append(step)
        self._step_counter += 1

    def _record_terminal(self, run, error):
        """Record a synthetic terminal step for errors raised outside the loop."""
        step = ExecutionStep(
            step=self._step_counter,
            run_index=run.index,
            op_index=len(run.steps),
            script_offset=len(run.script),
            opcode=OP.OP_INVALIDOPCODE,
            opcode_name="(end)",
            description="",
            executed=True,
            stack=tuple(),
            note=ScriptError(error).name,
            error=int(error),
        )
        run.steps.append(step)
        self._step_counter += 1

    # ------------------------------------------------------------------ #
    # Per-opcode processing
    # ------------------------------------------------------------------ #

    def _step(self, sop, executing, stack, frame) -> _StepResult | None:
        op = sop.opcode

        if sop.data is not None and len(sop.data) > MAX_SCRIPT_ELEMENT_SIZE:
            raise ScriptException(ScriptError.PUSH_SIZE)

        if op > OP.OP_16:
            frame.op_count += 1
            if frame.op_count > MAX_OPS_PER_SCRIPT and frame.sig_version in (
                SigVersion.BASE,
                SigVersion.WITNESS_V0,
            ):
                raise ScriptException(ScriptError.OP_COUNT)

        # Disabled opcodes fail even inside an unexecuted branch (legacy/v0).
        if frame.sig_version != SigVersion.TAPSCRIPT and op in OP.DISABLED_OPCODES:
            raise ScriptException(ScriptError.DISABLED_OPCODE)

        # Data pushes (0x00..OP_PUSHDATA4) only when executing.
        if executing and op <= OP.OP_PUSHDATA4:
            pushval = sop.data if sop.data is not None else b""
            if frame.require_minimal and not check_minimal_push(pushval, op):
                raise ScriptException(ScriptError.MINIMALDATA)
            stack.append(pushval)
            return _StepResult()

        # Everything else runs when executing, except the OP_IF..OP_ENDIF group
        # which is always processed (to keep conditional nesting balanced).
        if executing or (OP.OP_IF <= op <= OP.OP_ENDIF):
            return self._execute(op, sop, stack, frame, executing)
        return _StepResult()

    def _execute(self, op, sop, stack, frame, executing) -> _StepResult:
        alt = frame.altstack

        def need(n):
            if len(stack) < n:
                raise ScriptException(ScriptError.INVALID_STACK_OPERATION)

        def num(data, max_size=4):
            return decode_num(data, require_minimal=frame.require_minimal, max_size=max_size)

        # -- Push-value opcodes handled in the switch (OP_1NEGATE / OP_1..OP_16)
        if op == OP.OP_1NEGATE:
            stack.append(encode_num(-1))
            return _StepResult()
        if OP.OP_1 <= op <= OP.OP_16:
            stack.append(encode_num(op - (OP.OP_1 - 1)))
            return _StepResult()

        # -- Reserved / invalid ---------------------------------------------
        if op in (OP.OP_RESERVED, OP.OP_VER, OP.OP_RESERVED1, OP.OP_RESERVED2):
            raise ScriptException(ScriptError.BAD_OPCODE)
        if op in (OP.OP_VERIF, OP.OP_VERNOTIF):
            # Invalid even when not executed (already reachable here).
            raise ScriptException(ScriptError.BAD_OPCODE)

        # -- Control flow ---------------------------------------------------
        if op in (OP.OP_IF, OP.OP_NOTIF):
            value = False
            if executing:
                need(1)
                top = stack[-1]
                if frame.sig_version == SigVersion.TAPSCRIPT:
                    if len(top) > 1 or (len(top) == 1 and top[0] != 1):
                        raise ScriptException(ScriptError.TAPSCRIPT_MINIMALIF)
                elif self.flags & VF.MINIMALIF:
                    if len(top) > 1 or (len(top) == 1 and top[0] != 1):
                        raise ScriptException(ScriptError.MINIMALIF)
                value = cast_to_bool(top)
                if op == OP.OP_NOTIF:
                    value = not value
                stack.pop()
            frame.exec_stack.append(value)
            return _StepResult(note="branch taken" if value else "branch not taken")
        if op == OP.OP_ELSE:
            if not frame.exec_stack:
                raise ScriptException(ScriptError.UNBALANCED_CONDITIONAL)
            frame.exec_stack[-1] = not frame.exec_stack[-1]
            return _StepResult()
        if op == OP.OP_ENDIF:
            if not frame.exec_stack:
                raise ScriptException(ScriptError.UNBALANCED_CONDITIONAL)
            frame.exec_stack.pop()
            return _StepResult()
        if op == OP.OP_VERIFY:
            need(1)
            if not cast_to_bool(stack[-1]):
                raise ScriptException(ScriptError.VERIFY)
            stack.pop()
            return _StepResult(note="VERIFY passed")
        if op == OP.OP_RETURN:
            raise ScriptException(ScriptError.OP_RETURN)

        if op == OP.OP_NOP:
            return _StepResult()

        # -- Alt stack ------------------------------------------------------
        if op == OP.OP_TOALTSTACK:
            need(1)
            alt.append(stack.pop())
            return _StepResult()
        if op == OP.OP_FROMALTSTACK:
            if not alt:
                raise ScriptException(ScriptError.INVALID_ALTSTACK_OPERATION)
            stack.append(alt.pop())
            return _StepResult()

        # -- Stack ops ------------------------------------------------------
        if op == OP.OP_2DROP:
            need(2)
            stack.pop(); stack.pop()
            return _StepResult()
        if op == OP.OP_2DUP:
            need(2)
            stack.extend(stack[-2:])
            return _StepResult()
        if op == OP.OP_3DUP:
            need(3)
            stack.extend(stack[-3:])
            return _StepResult()
        if op == OP.OP_2OVER:
            need(4)
            stack.extend(stack[-4:-2])
            return _StepResult()
        if op == OP.OP_2ROT:
            need(6)
            a, b = stack[-6], stack[-5]
            del stack[-6:-4]
            stack.extend([a, b])
            return _StepResult()
        if op == OP.OP_2SWAP:
            need(4)
            stack[-4], stack[-3], stack[-2], stack[-1] = stack[-2], stack[-1], stack[-4], stack[-3]
            return _StepResult()
        if op == OP.OP_IFDUP:
            need(1)
            if cast_to_bool(stack[-1]):
                stack.append(stack[-1])
            return _StepResult()
        if op == OP.OP_DEPTH:
            stack.append(encode_num(len(stack)))
            return _StepResult()
        if op == OP.OP_DROP:
            need(1)
            stack.pop()
            return _StepResult()
        if op == OP.OP_DUP:
            need(1)
            stack.append(stack[-1])
            return _StepResult()
        if op == OP.OP_NIP:
            need(2)
            del stack[-2]
            return _StepResult()
        if op == OP.OP_OVER:
            need(2)
            stack.append(stack[-2])
            return _StepResult()
        if op in (OP.OP_PICK, OP.OP_ROLL):
            need(2)
            n = num(stack.pop())
            if n < 0 or n >= len(stack):
                raise ScriptException(ScriptError.INVALID_STACK_OPERATION)
            item = stack[-n - 1]
            if op == OP.OP_ROLL:
                del stack[-n - 1]
            stack.append(item)
            return _StepResult()
        if op == OP.OP_ROT:
            need(3)
            stack[-3], stack[-2], stack[-1] = stack[-2], stack[-1], stack[-3]
            return _StepResult()
        if op == OP.OP_SWAP:
            need(2)
            stack[-2], stack[-1] = stack[-1], stack[-2]
            return _StepResult()
        if op == OP.OP_TUCK:
            need(2)
            stack.insert(-2, stack[-1])
            return _StepResult()
        if op == OP.OP_SIZE:
            need(1)
            stack.append(encode_num(len(stack[-1])))
            return _StepResult()

        # -- Equality -------------------------------------------------------
        if op in (OP.OP_EQUAL, OP.OP_EQUALVERIFY):
            need(2)
            b = stack.pop()
            a = stack.pop()
            equal = a == b
            if op == OP.OP_EQUALVERIFY:
                if not equal:
                    raise ScriptException(ScriptError.EQUALVERIFY)
                return _StepResult(note="EQUALVERIFY passed")
            stack.append(b"\x01" if equal else b"")
            return _StepResult()

        # -- Unary numeric --------------------------------------------------
        if op in (OP.OP_1ADD, OP.OP_1SUB, OP.OP_NEGATE, OP.OP_ABS, OP.OP_NOT, OP.OP_0NOTEQUAL):
            need(1)
            n = num(stack.pop())
            if op == OP.OP_1ADD:
                n += 1
            elif op == OP.OP_1SUB:
                n -= 1
            elif op == OP.OP_NEGATE:
                n = -n
            elif op == OP.OP_ABS:
                n = abs(n)
            elif op == OP.OP_NOT:
                n = int(n == 0)
            elif op == OP.OP_0NOTEQUAL:
                n = int(n != 0)
            stack.append(encode_num(n))
            return _StepResult()

        # -- Binary numeric -------------------------------------------------
        if op in (
            OP.OP_ADD, OP.OP_SUB, OP.OP_BOOLAND, OP.OP_BOOLOR, OP.OP_NUMEQUAL,
            OP.OP_NUMEQUALVERIFY, OP.OP_NUMNOTEQUAL, OP.OP_LESSTHAN, OP.OP_GREATERTHAN,
            OP.OP_LESSTHANOREQUAL, OP.OP_GREATERTHANOREQUAL, OP.OP_MIN, OP.OP_MAX,
        ):
            need(2)
            b = num(stack.pop())
            a = num(stack.pop())
            if op == OP.OP_ADD:
                r = a + b
            elif op == OP.OP_SUB:
                r = a - b
            elif op == OP.OP_BOOLAND:
                r = int(a != 0 and b != 0)
            elif op == OP.OP_BOOLOR:
                r = int(a != 0 or b != 0)
            elif op == OP.OP_NUMEQUAL:
                r = int(a == b)
            elif op == OP.OP_NUMEQUALVERIFY:
                if a != b:
                    raise ScriptException(ScriptError.NUMEQUALVERIFY)
                return _StepResult(note="NUMEQUALVERIFY passed")
            elif op == OP.OP_NUMNOTEQUAL:
                r = int(a != b)
            elif op == OP.OP_LESSTHAN:
                r = int(a < b)
            elif op == OP.OP_GREATERTHAN:
                r = int(a > b)
            elif op == OP.OP_LESSTHANOREQUAL:
                r = int(a <= b)
            elif op == OP.OP_GREATERTHANOREQUAL:
                r = int(a >= b)
            elif op == OP.OP_MIN:
                r = min(a, b)
            else:  # OP_MAX
                r = max(a, b)
            stack.append(encode_num(r))
            return _StepResult()

        if op == OP.OP_WITHIN:
            need(3)
            mx = num(stack.pop())
            mn = num(stack.pop())
            x = num(stack.pop())
            stack.append(b"\x01" if (mn <= x < mx) else b"")
            return _StepResult()

        # -- Hashing --------------------------------------------------------
        if op in (OP.OP_RIPEMD160, OP.OP_SHA1, OP.OP_SHA256, OP.OP_HASH160, OP.OP_HASH256):
            need(1)
            data = stack.pop()
            if op == OP.OP_RIPEMD160:
                digest = ripemd160(data)
            elif op == OP.OP_SHA1:
                digest = sha1(data)
            elif op == OP.OP_SHA256:
                digest = sha256(data)
            elif op == OP.OP_HASH160:
                digest = hash160(data)
            else:
                digest = hash256(data)
            stack.append(digest)
            return _StepResult()

        if op == OP.OP_CODESEPARATOR:
            frame.codeseparator_offset = sop.offset + 1
            # Legacy/v0 use the byte offset; tapscript (BIP341) uses the opcode
            # position in the sighash extension.
            if frame.sig_version == SigVersion.TAPSCRIPT:
                frame.execdata.codeseparator_pos = frame.current_op_index
            return _StepResult()

        # -- Signature checking (delegated) --------------------------------
        if op in (OP.OP_CHECKSIG, OP.OP_CHECKSIGVERIFY):
            return self._op_checksig(op, stack, frame)
        if op in (OP.OP_CHECKMULTISIG, OP.OP_CHECKMULTISIGVERIFY):
            return self._op_checkmultisig(op, stack, frame)
        if op == OP.OP_CHECKSIGADD:
            return self._op_checksigadd(stack, frame)

        # -- Locktime NOPs --------------------------------------------------
        if op == OP.OP_CHECKLOCKTIMEVERIFY:
            if not (self.flags & VF.CHECKLOCKTIMEVERIFY):
                return self._nop(op)
            return self._op_cltv(stack)
        if op == OP.OP_CHECKSEQUENCEVERIFY:
            if not (self.flags & VF.CHECKSEQUENCEVERIFY):
                return self._nop(op)
            return self._op_csv(stack)

        if op in (OP.OP_NOP1, OP.OP_NOP4, OP.OP_NOP5, OP.OP_NOP6, OP.OP_NOP7, OP.OP_NOP8, OP.OP_NOP9, OP.OP_NOP10):
            return self._nop(op)

        # Unknown opcode.
        raise ScriptException(ScriptError.BAD_OPCODE)

    def _nop(self, op) -> _StepResult:
        if self.flags & VF.DISCOURAGE_UPGRADABLE_NOPS:
            raise ScriptException(ScriptError.DISCOURAGE_UPGRADABLE_NOPS)
        return _StepResult()

    # ------------------------------------------------------------------ #
    # Signature opcodes
    # ------------------------------------------------------------------ #

    def _require_checker(self):
        if self.checker is None:
            raise ScriptException(ScriptError.UNKNOWN_ERROR)
        return self.checker

    def _script_code(self, frame, *sigs: bytes) -> bytes:
        """Subscript from the last OP_CODESEPARATOR; legacy FindAndDeletes sigs."""
        subscript = frame.script[frame.codeseparator_offset :]
        if frame.sig_version == SigVersion.BASE:
            for sig in sigs:
                if sig:
                    subscript = find_and_delete(subscript, _encode_push(sig))
        return subscript

    _VALID_SCHNORR_HASHTYPES = (0x01, 0x02, 0x03, 0x81, 0x82, 0x83)

    def _checksig_schnorr(self, sig: bytes, pubkey: bytes, frame) -> bool:
        """BIP342 tapscript signature check; returns success or raises."""
        checker = self._require_checker()
        if len(sig) > 0:
            frame.execdata.validation_weight -= 50
            if frame.execdata.validation_weight < 0:
                raise ScriptException(ScriptError.TAPSCRIPT_VALIDATION_WEIGHT)
        if len(pubkey) == 0:
            raise ScriptException(ScriptError.PUBKEYTYPE)
        if len(pubkey) == 32:
            if len(sig) == 0:
                return False
            if len(sig) not in (64, 65):
                raise ScriptException(ScriptError.SCHNORR_SIG_SIZE)
            if len(sig) == 65 and sig[64] not in self._VALID_SCHNORR_HASHTYPES:
                raise ScriptException(ScriptError.SCHNORR_SIG_HASHTYPE)
            ok, sighash = checker.check_schnorr_sig(sig, pubkey, frame.sig_version, frame.execdata)
            self._pending_sig = SigCheckDetail(
                sig=sig, pubkey=pubkey, sighash=sighash, script_code=b"",
                sig_version=int(frame.sig_version), valid=ok,
            )
            if not ok:
                raise ScriptException(ScriptError.SCHNORR_SIG)
            return True
        # Unknown pubkey type -> upgradeable (treated as valid unless discouraged).
        if len(sig) > 0 and (self.flags & VF.DISCOURAGE_UPGRADABLE_PUBKEYTYPE):
            raise ScriptException(ScriptError.DISCOURAGE_UPGRADABLE_PUBKEYTYPE)
        return len(sig) > 0

    def _op_checksig(self, op, stack, frame) -> _StepResult:
        if frame.sig_version == SigVersion.TAPSCRIPT:
            if len(stack) < 2:
                raise ScriptException(ScriptError.INVALID_STACK_OPERATION)
            pubkey = stack[-1]
            sig = stack[-2]
            success = self._checksig_schnorr(sig, pubkey, frame)
            stack.pop()
            stack.pop()
            if op == OP.OP_CHECKSIGVERIFY:
                if not success:
                    raise ScriptException(ScriptError.CHECKSIGVERIFY)
                return _StepResult(note="CHECKSIGVERIFY passed")
            stack.append(b"\x01" if success else b"")
            return _StepResult(note="signature valid" if success else "signature invalid")

        checker = self._require_checker()
        if len(stack) < 2:
            raise ScriptException(ScriptError.INVALID_STACK_OPERATION)
        pubkey = stack[-1]
        sig = stack[-2]
        script_code = self._script_code(frame, sig)
        check_signature_encoding(sig, self.flags)
        check_pubkey_encoding(pubkey, self.flags, frame.sig_version)

        valid, sighash = (False, b"")
        if sig:
            valid, sighash = checker.check_ecdsa_sig(sig, pubkey, script_code, frame.sig_version)
        self._pending_sig = SigCheckDetail(
            sig=sig, pubkey=pubkey, sighash=sighash, script_code=script_code,
            sig_version=int(frame.sig_version), valid=valid,
        )
        if not valid and (self.flags & VF.NULLFAIL) and len(sig) > 0:
            raise ScriptException(ScriptError.SIG_NULLFAIL)

        stack.pop()  # pubkey
        stack.pop()  # sig
        if op == OP.OP_CHECKSIGVERIFY:
            if not valid:
                raise ScriptException(ScriptError.CHECKSIGVERIFY)
            return _StepResult(note="CHECKSIGVERIFY passed")
        stack.append(b"\x01" if valid else b"")
        return _StepResult(note="signature valid" if valid else "signature invalid")

    def _op_checkmultisig(self, op, stack, frame) -> _StepResult:
        checker = self._require_checker()
        if frame.sig_version == SigVersion.TAPSCRIPT:
            raise ScriptException(ScriptError.TAPSCRIPT_CHECKMULTISIG)

        i = 1
        if len(stack) < i:
            raise ScriptException(ScriptError.INVALID_STACK_OPERATION)
        keys_count = decode_num(stack[-i], require_minimal=frame.require_minimal)
        if keys_count < 0 or keys_count > MAX_PUBKEYS_PER_MULTISIG:
            raise ScriptException(ScriptError.PUBKEY_COUNT)
        frame.op_count += keys_count
        if frame.op_count > MAX_OPS_PER_SCRIPT:
            raise ScriptException(ScriptError.OP_COUNT)
        i += 1
        ikey = i  # stacktop(-ikey) is the first pubkey
        ikey2 = keys_count + 2
        i += keys_count
        if len(stack) < i:
            raise ScriptException(ScriptError.INVALID_STACK_OPERATION)
        sigs_count = decode_num(stack[-i], require_minimal=frame.require_minimal)
        if sigs_count < 0 or sigs_count > keys_count:
            raise ScriptException(ScriptError.SIG_COUNT)
        i += 1
        isig = i  # stacktop(-isig) is the first signature
        i += sigs_count
        if len(stack) < i:
            raise ScriptException(ScriptError.INVALID_STACK_OPERATION)

        sigs = [stack[-(isig + k)] for k in range(sigs_count)]
        script_code = self._script_code(frame, *sigs)

        success = True
        n_sigs = sigs_count
        n_keys = keys_count
        cur_sig = isig
        cur_key = ikey
        last_detail = None
        while success and n_sigs > 0:
            sig = stack[-cur_sig]
            pubkey = stack[-cur_key]
            check_signature_encoding(sig, self.flags)
            check_pubkey_encoding(pubkey, self.flags, frame.sig_version)
            ok, sighash = (False, b"")
            if sig:
                ok, sighash = checker.check_ecdsa_sig(sig, pubkey, script_code, frame.sig_version)
            last_detail = SigCheckDetail(
                sig=sig, pubkey=pubkey, sighash=sighash, script_code=script_code,
                sig_version=int(frame.sig_version), valid=ok,
            )
            if ok:
                cur_sig += 1
                n_sigs -= 1
            cur_key += 1
            n_keys -= 1
            if n_sigs > n_keys:
                success = False
        self._pending_sig = last_detail

        # Clean up the consumed stack items (i-1 of them), enforcing NULLFAIL.
        to_pop = i - 1
        for _ in range(to_pop):
            if not success and (self.flags & VF.NULLFAIL) and ikey2 == 0 and len(stack[-1]) > 0:
                raise ScriptException(ScriptError.SIG_NULLFAIL)
            if ikey2 > 0:
                ikey2 -= 1
            stack.pop()

        # The extra dummy element (CHECKMULTISIG off-by-one bug).
        if len(stack) < 1:
            raise ScriptException(ScriptError.INVALID_STACK_OPERATION)
        if (self.flags & VF.NULLDUMMY) and len(stack[-1]) > 0:
            raise ScriptException(ScriptError.SIG_NULLDUMMY)
        stack.pop()

        if op == OP.OP_CHECKMULTISIGVERIFY:
            if not success:
                raise ScriptException(ScriptError.CHECKMULTISIGVERIFY)
            return _StepResult(note="CHECKMULTISIGVERIFY passed")
        stack.append(b"\x01" if success else b"")
        return _StepResult(note="multisig valid" if success else "multisig invalid")

    def _op_checksigadd(self, stack, frame) -> _StepResult:
        # CHECKSIGADD exists only in tapscript.
        if frame.sig_version != SigVersion.TAPSCRIPT:
            raise ScriptException(ScriptError.BAD_OPCODE)
        if len(stack) < 3:
            raise ScriptException(ScriptError.INVALID_STACK_OPERATION)
        pubkey = stack[-1]
        n = decode_num(stack[-2], require_minimal=frame.require_minimal)
        sig = stack[-3]
        success = self._checksig_schnorr(sig, pubkey, frame)
        stack.pop()  # pubkey
        stack.pop()  # n
        stack.pop()  # sig
        stack.append(encode_num(n + (1 if success else 0)))
        return _StepResult(note=("counter +1" if success else "counter unchanged"))

    def _op_cltv(self, stack) -> _StepResult:
        checker = self._require_checker()
        if len(stack) < 1:
            raise ScriptException(ScriptError.INVALID_STACK_OPERATION)
        locktime = decode_num(stack[-1], require_minimal=False, max_size=5)
        if locktime < 0:
            raise ScriptException(ScriptError.NEGATIVE_LOCKTIME)
        if not checker.check_locktime(locktime):
            raise ScriptException(ScriptError.UNSATISFIED_LOCKTIME)
        return _StepResult(note="locktime satisfied")

    def _op_csv(self, stack) -> _StepResult:
        checker = self._require_checker()
        if len(stack) < 1:
            raise ScriptException(ScriptError.INVALID_STACK_OPERATION)
        sequence = decode_num(stack[-1], require_minimal=False, max_size=5)
        if sequence < 0:
            raise ScriptException(ScriptError.NEGATIVE_LOCKTIME)
        if sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG:
            return _StepResult()
        if not checker.check_sequence(sequence):
            raise ScriptException(ScriptError.UNSATISFIED_LOCKTIME)
        return _StepResult(note="sequence satisfied")


def verify_scripts(script_sig, script_pubkey, flags=VF.NONE, checker=None, witness=None):
    """Convenience: verify one scriptSig/scriptPubKey pair, return the trace."""
    return Interpreter(flags, checker).verify(bytes(script_sig), bytes(script_pubkey), witness)
