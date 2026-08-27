"""Tests for binsifter.core.capa_scan's scan_file_with_timeout() wrapper -
the safety net added 2026-07-30 after confirming certain real-world modern
Windows binaries (bash.exe, curl.exe, notepad.exe) can get vivisect's
aarch64 register-context construction stuck for 30-90+ seconds. See
capa_scan.py and subprocess_timeout.py's docstrings for the full incident
and why a subprocess-based timeout (not signal.alarm) is required.

Uses the repo's own smoketest fixtures (real capa rules + a real, small
PE) rather than mocks, since the whole point of this wrapper is running
genuine capa/vivisect analysis in a child process - a mock would just prove
the plumbing works with fake data, not that a real capa call survives the
process boundary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from binsifter.core.capa_scan import scan_file_with_timeout

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CAPA_RULES_DIR = str(_REPO_ROOT / "smoketest" / "capa_rules")
_SMALL_SAMPLE = str(_REPO_ROOT / "smoketest" / "samples" / "calc.exe")

# smoketest/samples/ is deliberately gitignored (see smoketest/README.md) -
# it holds real Windows executables the developer copies in locally from
# their own machine (e.g. C:\Windows\System32\calc.exe), never committed.
# An environment that hasn't staged that folder (any fresh checkout, and
# any non-Windows dev sandbox with no Windows executable to copy in at
# all) genuinely can't run either test below - that's a missing-fixture
# gap, not a code bug, so skip rather than hard-fail when it's absent.
_SKIP_REASON = (
    f"{_SMALL_SAMPLE} not present - smoketest/samples/ is gitignored and must be "
    "staged locally per smoketest/README.md (copy a real small Windows .exe in); "
    "not available in a non-Windows dev sandbox with no Windows executable to copy."
)
pytestmark = pytest.mark.skipif(not Path(_SMALL_SAMPLE).is_file(), reason=_SKIP_REASON)


def test_scan_file_with_timeout_returns_real_result_for_a_small_file():
    """A generous timeout against a genuinely small/fast file should behave
    exactly like scan_file() itself - proves the subprocess round-trip
    (spawn, reload rules, run real capa/vivisect analysis, serialize the
    CapaResult back through the queue) works end-to-end, not just that the
    timeout-kill path works."""
    result = scan_file_with_timeout(_SMALL_SAMPLE, _CAPA_RULES_DIR, timeout_seconds=45)
    assert isinstance(result.detection_count, int)
    assert isinstance(result.output, str)


def test_scan_file_with_timeout_raises_on_an_unreasonably_short_budget():
    """Forces the timeout path deterministically (rather than depending on
    reproducing the exact multi-second pathological case) by giving a real
    capa call a budget no real analysis - not even a trivially small file -
    could possibly finish within."""
    with pytest.raises(TimeoutError, match="capa analysis timed out after"):
        scan_file_with_timeout(_SMALL_SAMPLE, _CAPA_RULES_DIR, timeout_seconds=0.01)
