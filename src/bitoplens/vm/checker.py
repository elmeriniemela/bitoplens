"""Signature checkers and the flag-gated encoding checks.

The interpreter delegates the actual signature math to a
:class:`BaseSignatureChecker` (so it never touches the transaction directly),
and calls :func:`check_signature_encoding` / :func:`check_pubkey_encoding` for
the BIP62/BIP66/strict-encoding policy that depends on verification flags.
"""

from __future__ import annotations

from bitoplens.crypto.ecdsa import is_low_s, is_valid_der_encoding, verify_ecdsa
from bitoplens.crypto.schnorr import verify_schnorr
from bitoplens.tx.sighash import (
    SIGHASH_ANYONECANPAY,
    SIGHASH_SINGLE,
    PrecomputedTransactionData,
    legacy_sighash,
    taproot_sighash,
)
from bitoplens.vm.errors import ScriptError, ScriptException
from bitoplens.vm.flags import ScriptVerificationFlags as VF
from bitoplens.vm.flags import SigVersion

__all__ = [
    "BaseSignatureChecker",
    "TransactionSignatureChecker",
    "check_signature_encoding",
    "check_pubkey_encoding",
]

LOCKTIME_THRESHOLD = 500_000_000
SEQUENCE_FINAL = 0xFFFFFFFF
SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31
SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22
SEQUENCE_LOCKTIME_MASK = 0x0000FFFF


# --------------------------------------------------------------------------- #
# Encoding policy (flag-dependent, done in the interpreter's context)
# --------------------------------------------------------------------------- #

def _is_defined_hashtype(sig: bytes) -> bool:
    if not sig:
        return False
    ht = sig[-1] & ~SIGHASH_ANYONECANPAY
    return 1 <= ht <= SIGHASH_SINGLE


def _is_compressed_or_uncompressed(pubkey: bytes) -> bool:
    if len(pubkey) == 33:
        return pubkey[0] in (0x02, 0x03)
    if len(pubkey) == 65:
        return pubkey[0] == 0x04
    return False


def _is_compressed(pubkey: bytes) -> bool:
    return len(pubkey) == 33 and pubkey[0] in (0x02, 0x03)


def check_signature_encoding(sig: bytes, flags: VF) -> None:
    """Raise if ``sig`` violates the strict-DER / low-S / hashtype rules."""
    if len(sig) == 0:
        return
    if (flags & (VF.DERSIG | VF.LOW_S | VF.STRICTENC)) and not is_valid_der_encoding(sig):
        raise ScriptException(ScriptError.SIG_DER)
    if flags & VF.LOW_S and not is_low_s(sig):
        raise ScriptException(ScriptError.SIG_HIGH_S)
    if flags & VF.STRICTENC and not _is_defined_hashtype(sig):
        raise ScriptException(ScriptError.SIG_HASHTYPE)


def check_pubkey_encoding(pubkey: bytes, flags: VF, sig_version: int) -> None:
    """Raise if ``pubkey`` violates the strict / witness pubkey-type rules."""
    if flags & VF.STRICTENC and not _is_compressed_or_uncompressed(pubkey):
        raise ScriptException(ScriptError.PUBKEYTYPE)
    if (
        sig_version == SigVersion.WITNESS_V0
        and flags & VF.WITNESS_PUBKEYTYPE
        and not _is_compressed(pubkey)
    ):
        raise ScriptException(ScriptError.WITNESS_PUBKEYTYPE)


# --------------------------------------------------------------------------- #
# Signature checkers
# --------------------------------------------------------------------------- #

class BaseSignatureChecker:
    """A checker that fails every signature (used when no tx context exists)."""

    def check_ecdsa_sig(self, sig, pubkey, script_code, sig_version) -> tuple[bool, bytes]:
        return (False, b"")

    def check_schnorr_sig(self, sig, pubkey, sig_version, execdata) -> tuple[bool, bytes]:
        return (False, b"")

    def check_locktime(self, locktime: int) -> bool:
        return False

    def check_sequence(self, sequence: int) -> bool:
        return False


class TransactionSignatureChecker(BaseSignatureChecker):
    """Checks signatures against a concrete transaction input."""

    def __init__(self, tx, input_index, amount=0, spent_outputs=None, precomputed=None):
        self.tx = tx
        self.input_index = input_index
        self.amount = amount
        self.spent_outputs = spent_outputs
        self.precomputed = precomputed

    def _taproot_precomputed(self):
        if self.precomputed is None or not self.precomputed.sha_prevouts:
            self.precomputed = PrecomputedTransactionData.compute(self.tx, self.spent_outputs)
        return self.precomputed

    def check_schnorr_sig(self, sig, pubkey, sig_version, execdata) -> tuple[bool, bytes]:
        """Verify a BIP340 Schnorr signature (64 or 65 bytes) under BIP341/342."""
        if len(sig) == 64:
            hash_type = 0x00  # SIGHASH_DEFAULT
            sig64 = sig
        elif len(sig) == 65:
            hash_type = sig[64]
            if hash_type == 0x00:
                return (False, b"")  # explicit 0x00 is not allowed
            sig64 = sig[:64]
        else:
            return (False, b"")
        ext_flag = 1 if sig_version == SigVersion.TAPSCRIPT else 0
        annex = getattr(execdata, "annex", None)
        tapleaf = execdata.tapleaf_hash if ext_flag else None
        csp = execdata.codeseparator_pos if ext_flag else 0xFFFFFFFF
        sighash = taproot_sighash(
            self.tx,
            self.input_index,
            self.spent_outputs,
            hash_type,
            self._taproot_precomputed(),
            ext_flag=ext_flag,
            annex=annex,
            tapleaf_hash=tapleaf,
            codeseparator_pos=csp,
        )
        return (verify_schnorr(sig64, pubkey, sighash), sighash)

    def check_ecdsa_sig(self, sig, pubkey, script_code, sig_version) -> tuple[bool, bytes]:
        if len(sig) == 0:
            return (False, b"")
        hashtype = sig[-1]
        der = sig[:-1]
        if sig_version == SigVersion.BASE:
            sighash = legacy_sighash(self.tx, self.input_index, script_code, hashtype)
        elif sig_version == SigVersion.WITNESS_V0:
            from bitoplens.tx.sighash import bip143_sighash

            sighash = bip143_sighash(
                self.tx, self.input_index, script_code, self.amount, hashtype, self.precomputed
            )
        else:
            raise ScriptException(ScriptError.UNKNOWN_ERROR)
        return (verify_ecdsa(der, pubkey, sighash), sighash)

    def check_locktime(self, locktime: int) -> bool:
        tx_locktime = self.tx.locktime
        # Both must be the same kind (block height vs unix time).
        if not (
            (tx_locktime < LOCKTIME_THRESHOLD and locktime < LOCKTIME_THRESHOLD)
            or (tx_locktime >= LOCKTIME_THRESHOLD and locktime >= LOCKTIME_THRESHOLD)
        ):
            return False
        if locktime > tx_locktime:
            return False
        # A final input (sequence 0xffffffff) disables locktime.
        if self.tx.vin[self.input_index].sequence == SEQUENCE_FINAL:
            return False
        return True

    def check_sequence(self, sequence: int) -> bool:
        tx_sequence = self.tx.vin[self.input_index].sequence
        if self.tx.version < 2:
            return False
        if tx_sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG:
            return False
        mask = SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK
        tx_masked = tx_sequence & mask
        seq_masked = sequence & mask
        if not (
            (tx_masked < SEQUENCE_LOCKTIME_TYPE_FLAG and seq_masked < SEQUENCE_LOCKTIME_TYPE_FLAG)
            or (tx_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG and seq_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG)
        ):
            return False
        if seq_masked > tx_masked:
            return False
        return True
