"""Address encoding tests (base58check + bech32/bech32m)."""

from __future__ import annotations

import json
import os

from bitoplens.tx.address import base58check_encode, script_to_address


def test_p2pkh_address():
    # hash160 of all-zeros -> known mainnet P2PKH address.
    spk = bytes([0x76, 0xA9, 0x14]) + bytes(20) + bytes([0x88, 0xAC])
    assert script_to_address(spk) == base58check_encode(b"\x00" + bytes(20))
    assert script_to_address(spk).startswith("1")


def test_p2sh_address():
    spk = bytes([0xA9, 0x14]) + bytes(20) + bytes([0x87])
    assert script_to_address(spk).startswith("3")


def test_p2wpkh_bech32():
    # BIP173 example: witness v0, 20-byte program of 0x751e...
    program = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
    spk = bytes([0x00, 0x14]) + program
    assert script_to_address(spk, "bc") == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"


def test_p2tr_bech32m_from_bip341_vectors():
    data = os.path.join(os.path.dirname(__file__), "data", "bip341_wallet_vectors.json")
    if not os.path.exists(data):
        return
    vectors = json.load(open(data))
    for case in vectors["scriptPubKey"]:
        spk = bytes.fromhex(case["expected"]["scriptPubKey"])
        expected = case["expected"]["bip350Address"]
        assert script_to_address(spk, "bc") == expected
