"""Tests for the HTML visualizer output."""

from __future__ import annotations

import json
import re

import bitoplens as bl
from bitoplens.primitives.hashing import hash160
from bitoplens.script import opcodes as OP
from bitoplens.script.script import ScriptBuilder
from bitoplens.tx.sighash import legacy_sighash
from bitoplens.tx.transaction import OutPoint, Transaction, TxIn, TxOut
from bitoplens.vm.flags import ScriptVerificationFlags as VF

from tests.helpers import ecdsa_sign, pubkey


def _p2pkh_trace():
    d = 0xB0B
    pk = pubkey(d)
    spk = (
        ScriptBuilder().op(OP.OP_DUP).op(OP.OP_HASH160).push(hash160(pk))
        .op(OP.OP_EQUALVERIFY).op(OP.OP_CHECKSIG).build()
    )
    tx = Transaction(
        version=1,
        vin=[TxIn(OutPoint(b"\x11" * 32, 0), b"", 0xFFFFFFFF)],
        vout=[TxOut(90_000, ScriptBuilder().op(OP.OP_1).build())],
    )
    sh = legacy_sighash(tx, 0, spk, 0x01)
    sig = ecdsa_sign(sh, d) + b"\x01"
    tx.vin[0].script_sig = ScriptBuilder().push(sig).push(pk).build()
    return bl.run(spk, tx=tx, input_index=0, spent_outputs=[TxOut(100_000, spk)], flags=VF.P2SH)


def test_render_is_self_contained_and_embeds_trace():
    trace = _p2pkh_trace()
    assert trace.valid
    html = bl.visualize(trace)
    assert html.lstrip().startswith("<!doctype html>")
    # No external resource requests (CDN-free).
    assert "http://" not in html and "https://" not in html
    assert "src=" not in html.replace('id="', "")  # no external script/img src
    # The trace JSON is embedded and parses.
    m = re.search(r'<script id="trace" type="application/json">(.*?)</script>', html, re.S)
    assert m, "trace blob not found"
    data = json.loads(m.group(1))
    assert data["valid"] is True
    assert data["runs"] and data["runs"][0]["steps"]
    # The marker token was fully replaced.
    assert "__BITOPLENS_TRACE__" not in html


def test_render_escapes_script_close():
    # Ensure any "</..." inside the JSON can't break out of the script tag.
    trace = _p2pkh_trace()
    html = bl.visualize(trace)
    body = html.split('type="application/json">', 1)[1].split("</script>", 1)[0]
    assert "</script" not in body.lower()


def test_visualize_writes_file(tmp_path):
    trace = _p2pkh_trace()
    out = tmp_path / "trace.html"
    bl.visualize(trace, str(out))
    assert out.exists() and out.stat().st_size > 1000


def test_visualize_transaction_only():
    tx = Transaction(
        version=2,
        vin=[TxIn(OutPoint(b"\x22" * 32, 1), b"", 0xFFFFFFFE)],
        vout=[TxOut(50_000, ScriptBuilder().op(OP.OP_0).push(bytes(20)).build())],
    )
    html = bl.visualize(tx)
    assert "TRANSACTION" in html
    assert "__BITOPLENS_TRACE__" not in html
