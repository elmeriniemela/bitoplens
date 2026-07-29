"""Render an execution trace (or a transaction) to self-contained HTML.

The viewer template (``templates/viewer.html``) is fully self-contained -- inline
CSS and JS, no external requests. We inject the trace as a JSON blob in place of
a marker token; the page's vanilla JS replays it.
"""

from __future__ import annotations

import json
from importlib.resources import files

from bitoplens.trace.model import VerificationTrace, to_jsonable

__all__ = ["render", "render_transaction"]

_MARKER = "__BITOPLENS_TRACE__"


def _template() -> str:
    return (files("bitoplens.viz") / "templates" / "viewer.html").read_text(encoding="utf-8")


def _inject(payload: dict) -> str:
    blob = json.dumps(payload, separators=(",", ":"))
    # Neutralize any "</script>" that could close the embedding script tag.
    blob = blob.replace("</", "<\\/")
    return _template().replace(_MARKER, blob)


def render(trace: VerificationTrace) -> str:
    """Render a :class:`VerificationTrace` to an interactive HTML string."""
    return _inject(to_jsonable(trace))


def render_transaction(tx) -> str:
    """Render a transaction-only view (no script execution)."""
    from bitoplens.api import transaction_view

    payload = {
        "valid": True,
        "error": 0,
        "flags": 0,
        "runs": [],
        "input_index": 0,
        "transaction": transaction_view(tx),
        "spend_kind": "",
        "control_block": None,
    }
    return _inject(payload)
