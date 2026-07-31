"""Tests for binsifter.core.subprocess_timeout - the generic hard-timeout
subprocess wrapper built to guard capa_scan.py against vivisect's confirmed
real-world pathological slowness (see that module's docstring).

Worker functions used here must be real top-level module functions (not
closures/lambdas) since multiprocessing's "spawn" context needs to reimport
them by name in the child interpreter - matches the same constraint
run_with_timeout's own docstring places on its caller.
"""

from __future__ import annotations

import time

import pytest

from binsifter.core.subprocess_timeout import run_with_timeout


def _add_one(x: int) -> int:
    return x + 1


def _sleep_forever_ish(seconds: float) -> str:
    time.sleep(seconds)
    return "finished"  # never reached in the timeout test - sleep exceeds the budget


def _raise_value_error() -> None:
    raise ValueError("deliberate failure for test_function_error_becomes_runtime_error")


def test_fast_function_returns_normally():
    result = run_with_timeout(_add_one, (41,), timeout_seconds=10)
    assert result == 42


def test_slow_function_is_forcibly_terminated_within_budget():
    start = time.monotonic()
    with pytest.raises(TimeoutError, match=r"timed out after 0\.5s"):
        run_with_timeout(_sleep_forever_ish, (5.0,), timeout_seconds=0.5)
    elapsed = time.monotonic() - start
    # Proves the child was actually killed, not merely waited out: total
    # time must be well under the 5s the worker itself asked to sleep for.
    assert elapsed < 3.0


def test_custom_label_appears_in_timeout_message():
    with pytest.raises(TimeoutError, match=r"^capa analysis timed out after 0\.2s$"):
        run_with_timeout(_sleep_forever_ish, (2.0,), timeout_seconds=0.2, label="capa analysis")


def test_function_error_becomes_runtime_error():
    with pytest.raises(RuntimeError, match="deliberate failure for test_function_error_becomes_runtime_error"):
        run_with_timeout(_raise_value_error, (), timeout_seconds=10)
