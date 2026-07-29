"""Run Bitcoin Core's ``script_tests.json`` suite through our interpreter.

Rows with ``#`` placeholders (dynamically-synthesized Taproot cases) are
skipped by the loader; everything else is expected to match Core's exact
``ScriptError`` verdict.
"""

from __future__ import annotations

import os

import pytest

from tests import script_vectors as sv

if not os.path.exists(sv.DATA_PATH):  # pragma: no cover
    pytest.skip("script_tests.json not vendored", allow_module_level=True)

CASES = list(sv.load_cases())


def test_suite_is_substantial():
    # Guard against a truncated/empty vector file silently passing.
    assert len(CASES) > 1000


@pytest.mark.parametrize("case", CASES, ids=[str(c["idx"]) for c in CASES])
def test_script_vector(case):
    valid, error = sv.run_case(case)
    expected = sv.expected_error(case)
    assert (expected == 0) == valid, f"validity mismatch: got valid={valid}, expected {expected.name}"
    assert error == expected, f"got {error.name}, expected {expected.name}  [{case['comment']}]"
