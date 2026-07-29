"""Taproot control-block parsing and the BIP341 commitment check.

The control block is ``leaf_version_and_parity (1) || internal_key (32) ||
merkle_path (32*m)``. We fold the merkle path from the tapleaf hash to a root,
tweak the internal key by ``TapTweak(internal_key || root)``, and check the
resulting x-only key (and its y-parity) matches the witness program.
"""

from __future__ import annotations

from dataclasses import dataclass

from bitoplens.crypto.taproot import taproot_tweak_pubkey
from bitoplens.primitives.hashing import tagged_hash
from bitoplens.primitives.serialize import encode_compact_size

__all__ = [
    "TAPROOT_LEAF_TAPSCRIPT",
    "ControlBlock",
    "parse_control_block",
    "tapleaf_hash",
    "compute_merkle_root",
    "verify_taproot_commitment",
]

TAPROOT_LEAF_TAPSCRIPT = 0xC0
_CONTROL_BASE_SIZE = 33
_MAX_MERKLE_DEPTH = 128


@dataclass
class ControlBlock:
    leaf_version: int
    parity: int
    internal_key: bytes
    merkle_path: list


def parse_control_block(control: bytes) -> ControlBlock:
    """Parse a Taproot control block, or raise ``ValueError`` on bad size."""
    n = len(control)
    if n < _CONTROL_BASE_SIZE or (n - _CONTROL_BASE_SIZE) % 32 != 0:
        raise ValueError("wrong control block size")
    depth = (n - _CONTROL_BASE_SIZE) // 32
    if depth > _MAX_MERKLE_DEPTH:
        raise ValueError("merkle path too deep")
    leaf_version = control[0] & 0xFE
    parity = control[0] & 0x01
    internal_key = control[1:33]
    path = [control[33 + 32 * i : 65 + 32 * i] for i in range(depth)]
    return ControlBlock(leaf_version, parity, internal_key, path)


def tapleaf_hash(leaf_version: int, script: bytes) -> bytes:
    """``TapLeaf(leaf_version || compact_size(script) || script)``."""
    return tagged_hash(
        "TapLeaf", bytes([leaf_version]) + encode_compact_size(len(script)) + bytes(script)
    )


def compute_merkle_root(leaf: bytes, path: list) -> bytes:
    """Fold ``leaf`` up the merkle ``path`` using lexicographically-ordered
    ``TapBranch`` hashes."""
    k = leaf
    for elem in path:
        if k <= elem:
            k = tagged_hash("TapBranch", k + elem)
        else:
            k = tagged_hash("TapBranch", elem + k)
    return k


def verify_taproot_commitment(control: bytes, program: bytes, script: bytes) -> tuple[bool, bytes]:
    """Return ``(ok, tapleaf_hash)`` for a script-path commitment.

    ``program`` is the 32-byte witness-v1 program (the output x-only key).
    """
    cb = parse_control_block(control)
    leaf = tapleaf_hash(cb.leaf_version, script)
    root = compute_merkle_root(leaf, cb.merkle_path)
    tweak = tagged_hash("TapTweak", cb.internal_key + root)
    tweaked = taproot_tweak_pubkey(cb.internal_key, tweak)
    if tweaked is None:
        return (False, leaf)
    q_xonly, parity = tweaked
    ok = q_xonly == bytes(program) and parity == cb.parity
    return (ok, leaf)
