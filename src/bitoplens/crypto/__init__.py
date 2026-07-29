"""Crypto facade over the vendored, pure-Python ``secp256k1lab``.

``secp256k1lab`` provides secp256k1 field/group arithmetic and BIP340 Schnorr;
ECDSA (which it does not implement) lives in :mod:`bitoplens.crypto.ecdsa`,
built on the same primitives. Taproot x-only tweaking is in
:mod:`bitoplens.crypto.taproot`.

When installed, ``secp256k1lab`` is importable directly (shipped from the git
submodule at ``vendor/secp256k1lab``). For a source checkout that has not been
installed, we add the submodule's ``src`` directory to ``sys.path`` as a
fallback so the package still works.
"""

from __future__ import annotations

import os
import sys


def _bootstrap_secp256k1lab() -> None:
    try:
        import secp256k1lab  # noqa: F401
        return
    except ImportError:
        pass
    here = os.path.dirname(os.path.abspath(__file__))
    # src/bitoplens/crypto -> repo root -> vendor/secp256k1lab/src
    candidate = os.path.abspath(
        os.path.join(here, "..", "..", "..", "vendor", "secp256k1lab", "src")
    )
    if os.path.isdir(os.path.join(candidate, "secp256k1lab")):
        sys.path.insert(0, candidate)


_bootstrap_secp256k1lab()

from bitoplens.crypto.ecdsa import verify_ecdsa  # noqa: E402
from bitoplens.crypto.schnorr import verify_schnorr  # noqa: E402
from bitoplens.crypto.taproot import taproot_tweak_pubkey  # noqa: E402

__all__ = ["verify_ecdsa", "verify_schnorr", "taproot_tweak_pubkey"]
