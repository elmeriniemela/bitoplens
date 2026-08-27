# bitoplens

A pure-Python **Bitcoin Script simulator and visualizer**. `bitoplens` executes
Bitcoin scripts step-by-step on a virtual machine, records the full machine
state at every opcode, and renders an interactive, self-contained HTML page that
lets you step through the execution and inspect the stack, the transaction, and
(for Taproot) the script tree.

- **Pure Python, no native build.** Zero pip runtime dependencies. secp256k1
  crypto is provided by [`secp256k1lab`](https://github.com/secp256k1lab/secp256k1lab),
  vendored as a git submodule (also pure Python).
- **Full script coverage:** legacy (P2PK / P2PKH / P2SH / multisig), SegWit v0
  (P2WPKH / P2WSH, BIP143), and Taproot (P2TR key-path & script-path, Schnorr
  BIP340, tapscript BIP342, BIP341 sighash).
- **Introspectable interpreter:** the VM is a stepper; every step captures the
  main stack, alt stack, conditional (`OP_IF`) state, and signature-check
  details — the same data feeds both the Python API and the HTML viewer.

## Quick start

```python
import bitoplens as bl
from bitoplens.script import opcodes as OP
from bitoplens.script.script import ScriptBuilder
from bitoplens.primitives.hashing import sha256

# A hash-preimage lock, no transaction needed.
spk = ScriptBuilder().op(OP.OP_SHA256).push(sha256(b"open sesame")).op(OP.OP_EQUAL).build()
sig = ScriptBuilder().push(b"open sesame").build()

trace = bl.run_script(spk, sig)
print(trace.valid)                 # True
bl.visualize(trace, "trace.html")  # self-contained interactive HTML
```

For full transaction verification (legacy, SegWit v0, Taproot) use
`bl.run(script_pubkey, tx=..., input_index=..., spent_outputs=..., flags=...)`.
See `examples/demo.py`.

### Visualize a real transaction

`scripts/visualize_tx.py` fetches a transaction (and each input's previous
output) from mempool.space, verifies every input, and writes an interactive
HTML trace — standard library only, no extra dependencies:

```sh
python scripts/visualize_tx.py <txid> --open        # render input 0, open in browser
python scripts/visualize_tx.py <txid> --input 2     # a specific input
python scripts/visualize_tx.py <txid> --network testnet --tx-only
```

It prints a per-input verdict, e.g.:

```
tx f4184fc5…31e9e16  (mainnet)  1 in / 2 out
  input 0: OK   OK                     P2PK
```

## Install
```sh
pip install bitoplens
```

To install the latest development version directly from GitHub, use
`pip install git+https://github.com/elmeriniemela/bitoplens.git`.

## Development
```sh
git submodule update --init --recursive   # if cloning fresh
pip install -e '.[dev]'
```

## Releasing

Releases are published to PyPI by GitHub Actions using trusted publishing. To
publish a version:

1. Update `version` in `pyproject.toml` and `__version__` in
   `src/bitoplens/__init__.py`.
2. Push the change and wait for the test workflow to pass.
3. Create and push a tag matching the version, for example `v0.1.0`.

The `pypi` GitHub environment must be configured as a trusted publisher for the
`elmeriniemela/bitoplens` repository and the `publish.yml` workflow. The publish
workflow can also be run manually to validate the release build; manual runs do
not upload to PyPI.

## Testing

The interpreter is validated against upstream consensus vectors, vendored under
`tests/data/`:

- **Bitcoin Core `script_tests.json`** — all ~1230 runnable cases pass with an
  exact `ScriptError` match (dynamically-synthesized Taproot rows are skipped).
- **BIP341 wallet vectors** — Taproot output-key derivation, sighash midstates,
  key-path sighashes, and full verification against real Schnorr signatures.
- The real **block-170** transaction (historic P2PK) plus constructed spends
  for every script type.

```sh
pytest -q
```
