"""Signature-hash (sighash) computation.

Phase 3 implements the legacy algorithm (BASE sig version). BIP143 (SegWit v0)
and BIP341 (Taproot) are added in later phases; :class:`PrecomputedTransactionData`
is the shared cache their midstates live in.
"""

from __future__ import annotations

from dataclasses import dataclass

from bitoplens.primitives.hashing import hash256, sha256, tagged_hash
from bitoplens.primitives.serialize import encode_compact_size
from bitoplens.script.script import find_and_delete

__all__ = [
    "SIGHASH_ALL",
    "SIGHASH_NONE",
    "SIGHASH_SINGLE",
    "SIGHASH_ANYONECANPAY",
    "SIGHASH_DEFAULT",
    "legacy_sighash",
    "bip143_sighash",
    "taproot_sighash",
    "PrecomputedTransactionData",
]

SIGHASH_DEFAULT = 0x00

SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80

_OP_CODESEPARATOR = bytes([0xAB])
_ONE = (1).to_bytes(32, "little")


def legacy_sighash(tx, input_index: int, script_code: bytes, hashtype: int) -> bytes:
    """Compute the legacy (pre-SegWit) signature hash.

    ``script_code`` is the subscript being signed (the caller has already run
    FindAndDelete on the signature); OP_CODESEPARATORs are stripped here.
    """
    base = hashtype & 0x1F
    anyonecanpay = bool(hashtype & SIGHASH_ANYONECANPAY)

    # The SIGHASH_SINGLE "bug": signing an input with no matching output yields
    # the constant hash 1.
    if base == SIGHASH_SINGLE and input_index >= len(tx.vout):
        return _ONE

    script_code = find_and_delete(bytes(script_code), _OP_CODESEPARATOR)

    out = bytearray()
    out += tx.version.to_bytes(4, "little")

    # Inputs
    if anyonecanpay:
        inputs = [(input_index, tx.vin[input_index])]
    else:
        inputs = list(enumerate(tx.vin))
    out += encode_compact_size(len(inputs))
    for i, txin in inputs:
        out += txin.prevout.serialize()
        if i == input_index:
            out += encode_compact_size(len(script_code)) + script_code
        else:
            out += encode_compact_size(0)
        if i == input_index:
            seq = txin.sequence
        elif base in (SIGHASH_NONE, SIGHASH_SINGLE):
            seq = 0
        else:
            seq = txin.sequence
        out += seq.to_bytes(4, "little")

    # Outputs
    if base == SIGHASH_NONE:
        out += encode_compact_size(0)
    elif base == SIGHASH_SINGLE:
        out += encode_compact_size(input_index + 1)
        for i in range(input_index + 1):
            if i < input_index:
                # blanked output: value -1, empty script
                out += (0xFFFFFFFFFFFFFFFF).to_bytes(8, "little") + encode_compact_size(0)
            else:
                out += tx.vout[i].serialize()
    else:  # SIGHASH_ALL (or unknown -> treated as ALL, per consensus)
        out += encode_compact_size(len(tx.vout))
        for o in tx.vout:
            out += o.serialize()

    out += tx.locktime.to_bytes(4, "little")
    out += (hashtype & 0xFFFFFFFF).to_bytes(4, "little")
    return hash256(bytes(out))


def bip143_sighash(
    tx,
    input_index: int,
    script_code: bytes,
    amount: int,
    hashtype: int,
    precomputed: "PrecomputedTransactionData | None" = None,
) -> bytes:
    """Compute the BIP143 (SegWit v0) signature hash for one input."""
    base = hashtype & 0x1F
    anyonecanpay = bool(hashtype & SIGHASH_ANYONECANPAY)
    if precomputed is None or not precomputed.ready:
        precomputed = PrecomputedTransactionData.compute(tx)

    zero = b"\x00" * 32
    if not anyonecanpay:
        hash_prevouts = precomputed.hash_prevouts
    else:
        hash_prevouts = zero
    if not anyonecanpay and base != SIGHASH_SINGLE and base != SIGHASH_NONE:
        hash_sequence = precomputed.hash_sequence
    else:
        hash_sequence = zero
    if base != SIGHASH_SINGLE and base != SIGHASH_NONE:
        hash_outputs = precomputed.hash_outputs
    elif base == SIGHASH_SINGLE and input_index < len(tx.vout):
        hash_outputs = hash256(tx.vout[input_index].serialize())
    else:
        hash_outputs = zero

    txin = tx.vin[input_index]
    out = bytearray()
    out += tx.version.to_bytes(4, "little")
    out += hash_prevouts
    out += hash_sequence
    out += txin.prevout.serialize()
    out += encode_compact_size(len(script_code)) + bytes(script_code)
    out += amount.to_bytes(8, "little")
    out += txin.sequence.to_bytes(4, "little")
    out += hash_outputs
    out += tx.locktime.to_bytes(4, "little")
    out += (hashtype & 0xFFFFFFFF).to_bytes(4, "little")
    return hash256(bytes(out))


def taproot_sighash(
    tx,
    input_index: int,
    spent_outputs,
    hash_type: int,
    precomputed: "PrecomputedTransactionData",
    *,
    ext_flag: int = 0,
    annex: bytes | None = None,
    tapleaf_hash: bytes | None = None,
    codeseparator_pos: int = 0xFFFFFFFF,
) -> bytes:
    """Compute the BIP341 Taproot signature hash (``TapSighash``).

    ``ext_flag`` is 0 for key-path spends and 1 for tapscript (BIP342), in
    which case ``tapleaf_hash`` / ``codeseparator_pos`` extend the message.
    """
    base = hash_type & 0x03
    anyonecanpay = bool(hash_type & SIGHASH_ANYONECANPAY)

    ss = bytearray()
    ss += bytes([hash_type])
    ss += tx.version.to_bytes(4, "little")
    ss += tx.locktime.to_bytes(4, "little")
    if not anyonecanpay:
        ss += precomputed.sha_prevouts
        ss += precomputed.sha_amounts
        ss += precomputed.sha_scriptpubkeys
        ss += precomputed.sha_sequences
    if base not in (SIGHASH_NONE, SIGHASH_SINGLE):
        ss += precomputed.sha_outputs
    spend_type = (ext_flag * 2) + (1 if annex is not None else 0)
    ss += bytes([spend_type])
    if anyonecanpay:
        ss += tx.vin[input_index].prevout.serialize()
        ss += spent_outputs[input_index].value.to_bytes(8, "little")
        spk = bytes(spent_outputs[input_index].script_pubkey)
        ss += encode_compact_size(len(spk)) + spk
        ss += tx.vin[input_index].sequence.to_bytes(4, "little")
    else:
        ss += input_index.to_bytes(4, "little")
    if annex is not None:
        ss += sha256(encode_compact_size(len(annex)) + annex)
    if base == SIGHASH_SINGLE:
        ss += sha256(tx.vout[input_index].serialize())
    if ext_flag == 1:
        ss += tapleaf_hash or (b"\x00" * 32)
        ss += bytes([0x00])  # key version
        ss += codeseparator_pos.to_bytes(4, "little")
    return tagged_hash("TapSighash", b"\x00" + bytes(ss))


@dataclass
class PrecomputedTransactionData:
    """Cache of per-transaction sighash midstates, reused across inputs.

    Populated by :meth:`compute`. The legacy algorithm does not use it; BIP143
    uses the ``hash_*`` fields and BIP341 (Phase 6) the ``sha_*`` midstates.
    """

    # BIP143 (SegWit v0)
    hash_prevouts: bytes = b""
    hash_sequence: bytes = b""
    hash_outputs: bytes = b""
    # BIP341 (Taproot) midstates
    sha_prevouts: bytes = b""
    sha_amounts: bytes = b""
    sha_scriptpubkeys: bytes = b""
    sha_sequences: bytes = b""
    sha_outputs: bytes = b""
    ready: bool = False

    @classmethod
    def compute(cls, tx, spent_outputs=None) -> "PrecomputedTransactionData":
        """Precompute the BIP143 hashes (and BIP341 midstates if spent outputs
        are supplied) once for reuse across all inputs of ``tx``."""
        prevouts = b"".join(i.prevout.serialize() for i in tx.vin)
        sequences = b"".join(i.sequence.to_bytes(4, "little") for i in tx.vin)
        outputs = b"".join(o.serialize() for o in tx.vout)
        pd = cls(
            hash_prevouts=hash256(prevouts),
            hash_sequence=hash256(sequences),
            hash_outputs=hash256(outputs),
            ready=True,
        )
        if spent_outputs is not None:
            from hashlib import sha256 as _sha

            pd.sha_prevouts = _sha(prevouts).digest()
            pd.sha_sequences = _sha(sequences).digest()
            pd.sha_outputs = _sha(outputs).digest()
            pd.sha_amounts = _sha(
                b"".join(o.value.to_bytes(8, "little") for o in spent_outputs)
            ).digest()
            pd.sha_scriptpubkeys = _sha(
                b"".join(
                    encode_compact_size(len(o.script_pubkey)) + bytes(o.script_pubkey)
                    for o in spent_outputs
                )
            ).digest()
        return pd
