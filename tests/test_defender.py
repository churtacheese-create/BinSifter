"""Tests for binsifter.core.defender - the Windows Defender exclusion
helper added 2026-08-08 (see that module's docstring for the real bug this
addresses: Defender's real-time protection racing BinSifter's own worker
pool for extracted archive contents).

This dev sandbox is Linux, so the real Windows-only path (spawning an
elevated powershell.exe, the -EncodedCommand round-trip, Add-MpPreference
itself) can't be exercised here - these tests cover what IS testable from
Linux: the non-Windows guard, and the subprocess-plumbing logic via
monkeypatched subprocess.run so the encoding/exit-code-interpretation logic
is at least exercised, even though the real elevation flow needs a genuine
Windows test before being fully trusted (stated explicitly in the module
docstring too, not just here).
"""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from binsifter.core import defender


def test_non_windows_raises_immediately():
    with patch("binsifter.core.defender.platform.system", return_value="Linux"):
        with pytest.raises(defender.DefenderExclusionError, match="Windows-only"):
            defender.add_exclusion_path("C:\\some\\path")


def _fake_run(returncode, stderr=""):
    def _inner(*args, **kwargs):
        return subprocess.CompletedProcess(args=args, returncode=returncode, stdout="", stderr=stderr)
    return _inner


def test_success_does_not_raise():
    with patch("binsifter.core.defender.platform.system", return_value="Windows"), \
         patch("binsifter.core.defender.subprocess.run", side_effect=_fake_run(0)):
        defender.add_exclusion_path("C:\\Reports\\extracted_archives")  # should not raise


def test_uac_declined_maps_to_1223_specific_message():
    with patch("binsifter.core.defender.platform.system", return_value="Windows"), \
         patch("binsifter.core.defender.subprocess.run", side_effect=_fake_run(1223)):
        with pytest.raises(defender.DefenderExclusionError, match="UAC elevation was declined"):
            defender.add_exclusion_path("C:\\Reports\\extracted_archives")


def test_add_mppreference_failure_surfaces_stderr():
    with patch("binsifter.core.defender.platform.system", return_value="Windows"), \
         patch("binsifter.core.defender.subprocess.run", side_effect=_fake_run(1, stderr="Tamper Protection is enabled")):
        with pytest.raises(defender.DefenderExclusionError, match="Tamper Protection is enabled"):
            defender.add_exclusion_path("C:\\Reports\\extracted_archives")


def test_powershell_not_found_raises_clean_error():
    with patch("binsifter.core.defender.platform.system", return_value="Windows"), \
         patch("binsifter.core.defender.subprocess.run", side_effect=FileNotFoundError()):
        with pytest.raises(defender.DefenderExclusionError, match="powershell.exe was not found"):
            defender.add_exclusion_path("C:\\Reports\\extracted_archives")


def test_timeout_raises_clean_error():
    with patch("binsifter.core.defender.platform.system", return_value="Windows"), \
         patch("binsifter.core.defender.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="powershell.exe", timeout=120)):
        with pytest.raises(defender.DefenderExclusionError, match="Timed out"):
            defender.add_exclusion_path("C:\\Reports\\extracted_archives")
