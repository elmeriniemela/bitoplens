"""Pytest bootstrap: ensure the repo root and the vendored secp256k1lab are
importable when running from a source checkout."""

import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

_VENDOR = os.path.join(_ROOT, "vendor", "secp256k1lab", "src")
if os.path.isdir(os.path.join(_VENDOR, "secp256k1lab")) and _VENDOR not in sys.path:
    sys.path.insert(0, _VENDOR)
