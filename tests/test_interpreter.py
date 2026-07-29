"""Tests for the crypto-free interpreter and the execution trace."""

from __future__ import annotations

import pytest

from bitoplens.primitives.hashing import hash160, sha256
from bitoplens.script import opcodes as OP
from bitoplens.script.script import ScriptBuilder
from bitoplens.vm.errors import ScriptError
from bitoplens.vm.flags import ScriptVerificationFlags as VF
from bitoplens.vm.interpreter import verify_scripts


def run(sig, spk, flags=VF.NONE):
    return verify_scripts(bytes(sig), bytes(spk), flags)


# --------------------------------------------------------------------------- #
# Simple valid / invalid outcomes
# --------------------------------------------------------------------------- #

def test_true_script():
    spk = ScriptBuilder().op(OP.OP_1).build()
    tr = run(b"", spk)
    assert tr.valid
    assert tr.error == ScriptError.OK


def test_false_script():
    spk = ScriptBuilder().op(OP.OP_0).build()
    tr = run(b"", spk)
    assert not tr.valid
    assert tr.error == ScriptError.EVAL_FALSE


def test_op_return():
    spk = ScriptBuilder().op(OP.OP_RETURN).build()
    tr = run(b"", spk)
    assert not tr.valid
    assert tr.error == ScriptError.OP_RETURN


def test_equal_from_scriptsig():
    # scriptSig pushes 42; scriptPubKey pushes 42 and checks equality.
    sig = ScriptBuilder().push(b"\x2a").build()
    spk = ScriptBuilder().push(b"\x2a").op(OP.OP_EQUAL).build()
    tr = run(sig, spk)
    assert tr.valid


def test_verify_failure():
    spk = ScriptBuilder().op(OP.OP_0).op(OP.OP_VERIFY).op(OP.OP_1).build()
    tr = run(b"", spk)
    assert not tr.valid
    assert tr.error == ScriptError.VERIFY


# --------------------------------------------------------------------------- #
# Arithmetic
# --------------------------------------------------------------------------- #

def test_arithmetic():
    # (2 + 3) == 5
    spk = ScriptBuilder().op(OP.OP_2).op(OP.OP_3).op(OP.OP_ADD).op(OP.OP_5).op(OP.OP_NUMEQUAL).build()
    assert run(b"", spk).valid


def test_within():
    # 5 within [1, 10)
    spk = ScriptBuilder().op(OP.OP_5).op(OP.OP_1).op(OP.OP_10).op(OP.OP_WITHIN).build()
    assert run(b"", spk).valid


def test_1add_negate():
    spk = ScriptBuilder().op(OP.OP_5).op(OP.OP_1ADD).push_int(6).op(OP.OP_NUMEQUAL).build()
    assert run(b"", spk).valid


# --------------------------------------------------------------------------- #
# Conditionals
# --------------------------------------------------------------------------- #

def test_if_else_taken():
    # 1 IF 1 ELSE 0 ENDIF  -> true
    spk = ScriptBuilder().op(OP.OP_1).op(OP.OP_IF).op(OP.OP_1).op(OP.OP_ELSE).op(OP.OP_0).op(OP.OP_ENDIF).build()
    assert run(b"", spk).valid


def test_if_else_not_taken():
    # 0 IF 0 ELSE 1 ENDIF  -> true
    spk = ScriptBuilder().op(OP.OP_0).op(OP.OP_IF).op(OP.OP_0).op(OP.OP_ELSE).op(OP.OP_1).op(OP.OP_ENDIF).build()
    tr = run(b"", spk)
    assert tr.valid
    # The skipped opcode (inner OP_0) must be recorded as not executed.
    spk_run = tr.runs[-1]
    skipped = [s for s in spk_run.steps if not s.executed]
    assert any(s.opcode == OP.OP_0 for s in skipped)


def test_unbalanced_conditional():
    spk = ScriptBuilder().op(OP.OP_1).op(OP.OP_IF).op(OP.OP_1).build()  # no ENDIF
    tr = run(b"", spk)
    assert tr.error == ScriptError.UNBALANCED_CONDITIONAL


def test_endif_without_if():
    spk = ScriptBuilder().op(OP.OP_1).op(OP.OP_ENDIF).build()
    tr = run(b"", spk)
    assert tr.error == ScriptError.UNBALANCED_CONDITIONAL


# --------------------------------------------------------------------------- #
# Hash preimage + P2SH (crypto-free)
# --------------------------------------------------------------------------- #

def test_hash_preimage():
    secret = b"open sesame"
    spk = ScriptBuilder().op(OP.OP_SHA256).push(sha256(secret)).op(OP.OP_EQUAL).build()
    sig = ScriptBuilder().push(secret).build()
    assert run(sig, spk).valid
    # Wrong preimage fails.
    bad = ScriptBuilder().push(b"nope").build()
    assert not run(bad, spk).valid


def test_p2sh_hash_lock():
    # redeem script: OP_SHA256 <hash> OP_EQUAL, wrapped in P2SH.
    secret = b"p2sh secret"
    redeem = ScriptBuilder().op(OP.OP_SHA256).push(sha256(secret)).op(OP.OP_EQUAL).build()
    spk = ScriptBuilder().op(OP.OP_HASH160).push(hash160(redeem)).op(OP.OP_EQUAL).build()
    sig = ScriptBuilder().push(secret).push(bytes(redeem)).build()
    tr = run(sig, spk, VF.P2SH)
    assert tr.valid
    # There should be a redeemScript run.
    assert any(r.role == "redeemScript" for r in tr.runs)


def test_p2sh_wrong_redeem():
    secret = b"secret"
    redeem = ScriptBuilder().op(OP.OP_SHA256).push(sha256(secret)).op(OP.OP_EQUAL).build()
    spk = ScriptBuilder().op(OP.OP_HASH160).push(hash160(redeem)).op(OP.OP_EQUAL).build()
    # Push a different redeem script whose hash won't match.
    other = ScriptBuilder().op(OP.OP_1).build()
    sig = ScriptBuilder().push(secret).push(bytes(other)).build()
    tr = run(sig, spk, VF.P2SH)
    assert not tr.valid


# --------------------------------------------------------------------------- #
# Flag-gated errors
# --------------------------------------------------------------------------- #

def test_disabled_opcode():
    spk = ScriptBuilder().op(OP.OP_1).op(OP.OP_CAT).build()
    tr = run(b"", spk)
    assert tr.error == ScriptError.DISABLED_OPCODE


def test_disabled_opcode_even_in_skipped_branch():
    # 0 IF OP_CAT ENDIF 1 -> still DISABLED_OPCODE even though branch is skipped.
    spk = ScriptBuilder().op(OP.OP_0).op(OP.OP_IF).op(OP.OP_CAT).op(OP.OP_ENDIF).op(OP.OP_1).build()
    tr = run(b"", spk)
    assert tr.error == ScriptError.DISABLED_OPCODE


def test_minimaldata_violation():
    # Push 1 via a 1-byte pushdata instead of OP_1 -> MINIMALDATA when the flag set.
    spk = ScriptBuilder().raw(bytes([0x01, 0x01])).build()
    assert run(b"", spk, VF.MINIMALDATA).error == ScriptError.MINIMALDATA
    # Without the flag it is accepted (and leaves true on the stack).
    assert run(b"", spk).valid


def test_cleanstack_violation():
    # Two truthy items left on the stack; CLEANSTACK requires exactly one.
    spk = ScriptBuilder().op(OP.OP_1).op(OP.OP_1).build()
    assert run(b"", spk, VF.P2SH | VF.CLEANSTACK).error == ScriptError.CLEANSTACK
    assert run(b"", spk).valid  # top is true, no cleanstack requirement


def test_sigpushonly():
    # scriptSig with a non-push opcode fails under SIGPUSHONLY.
    sig = ScriptBuilder().op(OP.OP_1).op(OP.OP_DUP).build()
    spk = ScriptBuilder().op(OP.OP_EQUAL).build()
    assert run(sig, spk, VF.SIGPUSHONLY).error == ScriptError.SIG_PUSHONLY


def test_push_size_limit():
    big = ScriptBuilder().push(b"\x00" * 521).build()
    assert run(b"", big).error == ScriptError.PUSH_SIZE


def test_discourage_nops():
    spk = ScriptBuilder().op(OP.OP_NOP1).op(OP.OP_1).build()
    assert run(b"", spk).valid
    assert run(b"", spk, VF.DISCOURAGE_UPGRADABLE_NOPS).error == ScriptError.DISCOURAGE_UPGRADABLE_NOPS


# --------------------------------------------------------------------------- #
# Trace shape
# --------------------------------------------------------------------------- #

def test_trace_records_steps_and_deltas():
    spk = ScriptBuilder().op(OP.OP_2).op(OP.OP_3).op(OP.OP_ADD).build()
    tr = run(b"", spk)
    spk_run = tr.runs[-1]
    names = [s.opcode_name for s in spk_run.steps]
    assert names == ["OP_2", "OP_3", "OP_ADD"]
    add_step = spk_run.steps[-1]
    # OP_ADD pops two, pushes one.
    assert add_step.delta.popped == 2
    assert len(add_step.delta.pushed) == 1
    # Global step index is monotonic across runs.
    all_steps = [s.step for r in tr.runs for s in r.steps]
    assert all_steps == sorted(all_steps)


def test_stack_snapshots_are_independent():
    spk = ScriptBuilder().op(OP.OP_1).op(OP.OP_DUP).build()
    tr = run(b"", spk)
    steps = tr.runs[-1].steps
    assert steps[0].stack == (b"\x01",)
    assert steps[1].stack == (b"\x01", b"\x01")
