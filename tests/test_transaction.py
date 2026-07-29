"""Tests for transaction parsing / serialization / txid."""

from __future__ import annotations

from bitoplens.tx.transaction import OutPoint, Transaction, TxIn, TxOut

# The famous block-170 transaction (Satoshi -> Hal Finney), a legacy tx.
BLOCK170_TX = (
    "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37"
    "04000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c6"
    "1548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221"
    "a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b"
    "99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a"
    "0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49"
    "840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e16"
    "0bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"
)
BLOCK170_TXID = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"


def test_parse_serialize_roundtrip_legacy():
    tx = Transaction.parse(BLOCK170_TX)
    assert tx.version == 1
    assert len(tx.vin) == 1
    assert len(tx.vout) == 2
    assert not tx.has_witness
    assert tx.serialize().hex() == BLOCK170_TX


def test_legacy_txid():
    tx = Transaction.parse(BLOCK170_TX)
    assert tx.txid_hex() == BLOCK170_TXID
    # No witness => wtxid == txid.
    assert tx.wtxid_hex() == BLOCK170_TXID


def test_outpoint_display_and_values():
    tx = Transaction.parse(BLOCK170_TX)
    assert tx.vout[0].value == 1000000000  # 10 BTC
    assert tx.vout[1].value == 4000000000  # 40 BTC
    op0 = tx.vin[0].prevout
    assert op0.vout == 0
    assert len(op0.txid) == 32


def test_segwit_roundtrip():
    tx = Transaction(
        version=2,
        vin=[
            TxIn(
                prevout=OutPoint.from_hex("11" * 32, 0),
                script_sig=b"",
                sequence=0xFFFFFFFE,
                witness=[b"\x30\x44" + b"\xaa" * 40, b"\x02" + b"\xbb" * 32],
            )
        ],
        vout=[TxOut(value=12345, script_pubkey=bytes([0x00, 0x14]) + bytes(20))],
        locktime=0,
    )
    assert tx.has_witness
    raw = tx.serialize()
    # Segwit marker+flag present right after the version.
    assert raw[4:6] == b"\x00\x01"
    reparsed = Transaction.parse(raw)
    assert reparsed.serialize() == raw
    assert reparsed.vin[0].witness == tx.vin[0].witness
    # Legacy serialization strips the witness and changes the txid basis.
    assert tx.txid() != tx.wtxid()
    assert Transaction.parse(tx.serialize(include_witness=False)).serialize(
        include_witness=False
    ) == tx.serialize(include_witness=False)


def test_from_hex_outpoint_reversal():
    op = OutPoint.from_hex("ab" + "00" * 31, 3)
    # Display hex is reversed relative to internal bytes.
    assert op.txid[-1] == 0xAB
    assert op.txid_hex() == "ab" + "00" * 31
