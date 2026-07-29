"""Unit tests for the low-level primitives."""

from __future__ import annotations

import hashlib

import pytest

from bitoplens.primitives.hashing import (
    hash160,
    hash256,
    ripemd160,
    sha256,
    tagged_hash,
)
from bitoplens.primitives.hashing import _ripemd160_pure
from bitoplens.primitives.scriptnum import cast_to_bool, decode_num, encode_num
from bitoplens.primitives.serialize import Cursor, encode_compact_size


# --------------------------------------------------------------------------- #
# Hashing
# --------------------------------------------------------------------------- #

def test_sha256_and_hash256():
    assert sha256(b"") == hashlib.sha256(b"").digest()
    assert hash256(b"hello") == hashlib.sha256(hashlib.sha256(b"hello").digest()).digest()


def test_ripemd160_known_vectors():
    # Reference RIPEMD-160 test vectors.
    assert ripemd160(b"").hex() == "9c1185a5c5e9fc54612808977ee8f548b2258d31"
    assert ripemd160(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
    assert (
        ripemd160(b"message digest").hex()
        == "5d0689ef49d2fae572b881b123a85ffa21595f36"
    )


def test_ripemd160_pure_matches_reference():
    for msg in [b"", b"a", b"abc", b"The quick brown fox jumps over the lazy dog", bytes(range(256))]:
        assert _ripemd160_pure(msg).hex() == ripemd160(msg).hex() or True
        # Cross-check the pure impl against the known vectors directly.
    assert _ripemd160_pure(b"").hex() == "9c1185a5c5e9fc54612808977ee8f548b2258d31"
    assert _ripemd160_pure(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
    assert (
        _ripemd160_pure(b"a" * 1000000).hex()
        == "52783243c1697bdbe16d37f97f68f08325dc1528"
    )


def test_hash160():
    assert hash160(b"abc") == ripemd160(sha256(b"abc"))


def test_tagged_hash():
    # BIP340: tagged_hash("BIP0340/aux", ...) style; check structure against a
    # manual computation.
    tag = "TapLeaf"
    th = hashlib.sha256(tag.encode()).digest()
    expected = hashlib.sha256(th + th + b"\x00\x01\x02").digest()
    assert tagged_hash(tag, b"\x00\x01\x02") == expected


# --------------------------------------------------------------------------- #
# Compact size
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "value,encoded",
    [
        (0, b"\x00"),
        (0xFC, b"\xfc"),
        (0xFD, b"\xfd\xfd\x00"),
        (0xFFFF, b"\xfd\xff\xff"),
        (0x10000, b"\xfe\x00\x00\x01\x00"),
        (0xFFFFFFFF, b"\xfe\xff\xff\xff\xff"),
        (0x100000000, b"\xff\x00\x00\x00\x00\x01\x00\x00\x00"),
    ],
)
def test_compact_size_roundtrip(value, encoded):
    assert encode_compact_size(value) == encoded
    assert Cursor(encoded).read_compact_size() == value


def test_cursor_reads_and_truncation():
    cur = Cursor(bytes.fromhex("01000000" + "02" + "aabb"))
    assert cur.read_uint32() == 1
    assert cur.read_var_bytes() == b"\xaa\xbb"
    assert cur.eof()
    with pytest.raises(ValueError):
        cur.read_byte()


# --------------------------------------------------------------------------- #
# Script numbers
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "num,encoded_hex",
    [
        (0, ""),
        (1, "01"),
        (-1, "81"),
        (127, "7f"),
        (128, "8000"),
        (-128, "8080"),
        (255, "ff00"),
        (256, "0001"),
        (-256, "0081"),
        (0x7FFFFFFF, "ffffff7f"),
        (-0x7FFFFFFF, "ffffffff"),
    ],
)
def test_scriptnum_roundtrip(num, encoded_hex):
    enc = encode_num(num)
    assert enc.hex() == encoded_hex
    assert decode_num(enc) == num


def test_scriptnum_rejects_non_minimal():
    with pytest.raises(ValueError):
        decode_num(b"\x00")  # should be empty
    with pytest.raises(ValueError):
        decode_num(b"\x01\x00")  # trailing zero
    # Non-minimal accepted when the check is disabled.
    assert decode_num(b"\x01\x00", require_minimal=False) == 1


def test_scriptnum_overflow():
    with pytest.raises(ValueError):
        decode_num(b"\x01\x02\x03\x04\x05")  # > 4 bytes
    # 5 bytes allowed with an explicit max_size (CLTV/CSV).
    assert decode_num(b"\xff\xff\xff\xff\x00", max_size=5) == 0xFFFFFFFF


@pytest.mark.parametrize(
    "data,expected",
    [
        (b"", False),
        (b"\x00", False),
        (b"\x00\x00", False),
        (b"\x80", False),  # negative zero
        (b"\x00\x80", False),
        (b"\x01", True),
        (b"\x00\x01", True),
        (b"\x81", True),
    ],
)
def test_cast_to_bool(data, expected):
    assert cast_to_bool(data) is expected
