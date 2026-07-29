#!/usr/bin/env python3
"""Fetch a transaction from mempool.space and render its script trace as HTML.

Usage:
    python scripts/visualize_tx.py <txid> [options]

Examples:
    python scripts/visualize_tx.py f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
    python scripts/visualize_tx.py <txid> --input 2 --open
    python scripts/visualize_tx.py <txid> --network testnet --tx-only

It downloads the raw transaction and each input's previous output (the coin it
spends), verifies every input with bitoplens, prints a per-input verdict, and
writes a self-contained interactive HTML page for one input (or the whole tx).
Only Python's standard library is used for networking.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

# --- Make bitoplens importable from a source checkout (no install needed) ---
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(_ROOT, "src"), os.path.join(_ROOT, "vendor", "secp256k1lab", "src")):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

import bitoplens as bl  # noqa: E402
from bitoplens.tx.transaction import Transaction, TxOut  # noqa: E402
from bitoplens.vm.flags import ScriptVerificationFlags as VF  # noqa: E402

# mempool.space API base per network.
_NETWORKS = {
    "mainnet": "https://mempool.space/api",
    "testnet": "https://mempool.space/testnet/api",
    "testnet4": "https://mempool.space/testnet4/api",
    "signet": "https://mempool.space/signet/api",
}

# Active consensus soft-fork rules -- any confirmed transaction must satisfy
# these. Policy/standardness flags (LOW_S, STRICTENC, ...) are left off by
# default so a valid mined tx never shows a spurious INVALID; use --all-flags
# to turn on the strictest set.
CONSENSUS_FLAGS = (
    VF.P2SH | VF.DERSIG | VF.CHECKLOCKTIMEVERIFY | VF.CHECKSEQUENCEVERIFY
    | VF.WITNESS | VF.NULLDUMMY | VF.TAPROOT
)


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "bitoplens"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"HTTP {exc.code} fetching {url}: {exc.reason}")
    except urllib.error.URLError as exc:
        raise SystemExit(f"network error fetching {url}: {exc.reason}")


def fetch_transaction(txid: str, network: str = "mainnet"):
    """Return ``(tx, spent_outputs, meta)`` for ``txid`` from mempool.space.

    ``spent_outputs`` is one :class:`TxOut` per input (the coin it spends), or
    ``None`` entries for a coinbase input. ``meta`` is the raw API JSON.
    """
    base = _NETWORKS[network]
    raw_hex = _get(f"{base}/tx/{txid}/hex").decode().strip()
    meta = json.loads(_get(f"{base}/tx/{txid}"))
    tx = Transaction.parse(raw_hex)
    if tx.txid_hex() != txid:
        raise SystemExit(f"txid mismatch: requested {txid}, parsed {tx.txid_hex()}")

    spent = []
    for vin in meta["vin"]:
        if vin.get("is_coinbase") or vin.get("prevout") is None:
            spent.append(None)
        else:
            prev = vin["prevout"]
            spent.append(TxOut(prev["value"], bytes.fromhex(prev["scriptpubkey"])))
    return tx, spent, meta


def main(argv=None):
    ap = argparse.ArgumentParser(description="Render a mempool.space transaction as a bitoplens HTML trace.")
    ap.add_argument("txid", help="transaction id (hex)")
    ap.add_argument("-i", "--input", type=int, default=None,
                    help="input index to visualize (default: first spendable input)")
    ap.add_argument("-o", "--output", default=None, help="output HTML path (default: <txid>.html)")
    ap.add_argument("-n", "--network", choices=sorted(_NETWORKS), default="mainnet")
    ap.add_argument("--tx-only", action="store_true", help="render the transaction structure only (no execution)")
    ap.add_argument("--all-flags", action="store_true", help="verify with every flag (strictest standardness)")
    ap.add_argument("--open", action="store_true", help="open the result in a web browser")
    args = ap.parse_args(argv)

    flags = VF.all() if args.all_flags else CONSENSUS_FLAGS
    tx, spent, meta = fetch_transaction(args.txid, args.network)
    out_path = args.output or f"{args.txid}.html"

    print(f"tx {args.txid}  ({args.network})  {len(tx.vin)} in / {len(tx.vout)} out")

    if args.tx_only:
        bl.visualize(tx, out_path)
        print(f"wrote transaction view -> {out_path}")
        return _maybe_open(out_path, args.open)

    # Verify every (non-coinbase) input and print a summary.
    verdicts = {}
    for i, prevout in enumerate(spent):
        if prevout is None:
            print(f"  input {i}: coinbase (no script to verify)")
            continue
        trace = bl.run(prevout.script_pubkey, tx=tx, input_index=i, spent_outputs=spent, flags=flags)
        verdicts[i] = trace
        mark = "OK " if trace.valid else "BAD"
        kind = trace.spend_kind or (trace.runs[-1].script_type if trace.runs else "")
        print(f"  input {i}: {mark}  {trace.error_name:<22} {kind}")

    if not verdicts:
        # Coinbase-only: fall back to the transaction view.
        bl.visualize(tx, out_path)
        print(f"no spendable inputs; wrote transaction view -> {out_path}")
        return _maybe_open(out_path, args.open)

    # Choose which input to render.
    idx = args.input if args.input is not None else next(iter(verdicts))
    if idx not in verdicts:
        raise SystemExit(f"input {idx} is not a verifiable input (choices: {sorted(verdicts)})")
    bl.visualize(verdicts[idx], out_path)
    print(f"wrote input {idx} trace -> {out_path}")
    return _maybe_open(out_path, args.open)


def _maybe_open(path: str, do_open: bool):
    if do_open:
        import webbrowser

        webbrowser.open("file://" + os.path.abspath(path))


if __name__ == "__main__":
    main()
