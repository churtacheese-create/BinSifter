"""Regression tests for binsifter.core.av_detect. subprocess.run is mocked
throughout (this dev sandbox is Linux-only, has no real PowerShell/WMI to
query against) - these test the JSON-parsing/dedup/guidance-lookup logic
around the subprocess call, not the real Windows query itself, same
verification-caveat pattern as defender.py's own module docstring.
"""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from binsifter.core import av_detect


def _fake_run(stdout: str, returncode: int = 0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


# detect_av_products() gates on platform.system() == "Windows" before ever
# touching subprocess - this dev sandbox is Linux, so every test that needs
# to exercise the parsing/dedup logic past that gate has to mock
# platform.system() too, not just subprocess.run. The gate itself is
# covered separately, without mocking platform.system, below.
def test_detect_av_products_parses_single_result_as_bare_string():
    # Get-CimInstance | ConvertTo-Json emits a bare JSON string, not an
    # array, when exactly one object comes back - real PowerShell behavior,
    # not a hypothetical edge case.
    with patch("platform.system", return_value="Windows"), \
         patch("subprocess.run", return_value=_fake_run('"Windows Defender"')):
        products = av_detect.detect_av_products()
    assert [p.name for p in products] == ["Windows Defender"]


def test_detect_av_products_parses_multiple_results_as_array():
    with patch("platform.system", return_value="Windows"), \
         patch("subprocess.run", return_value=_fake_run('["Windows Defender","McAfee Endpoint Security"]')):
        products = av_detect.detect_av_products()
    assert [p.name for p in products] == ["Windows Defender", "McAfee Endpoint Security"]


def test_detect_av_products_dedupes_by_name():
    with patch("platform.system", return_value="Windows"), \
         patch("subprocess.run", return_value=_fake_run('["Windows Defender","Windows Defender"]')):
        products = av_detect.detect_av_products()
    assert [p.name for p in products] == ["Windows Defender"]


def test_detect_av_products_returns_empty_list_for_no_products_not_an_error():
    with patch("platform.system", return_value="Windows"), \
         patch("subprocess.run", return_value=_fake_run("[]")):
        products = av_detect.detect_av_products()
    assert products == []


def test_detect_av_products_returns_empty_list_on_blank_output():
    # The script's catch block emits '[]' on a real failure, but blank
    # stdout (e.g. powershell.exe produced nothing at all) should degrade
    # the same way rather than raising.
    with patch("platform.system", return_value="Windows"), \
         patch("subprocess.run", return_value=_fake_run("")):
        products = av_detect.detect_av_products()
    assert products == []


def test_detect_av_products_returns_empty_list_on_unparseable_output():
    with patch("platform.system", return_value="Windows"), \
         patch("subprocess.run", return_value=_fake_run("not json")):
        products = av_detect.detect_av_products()
    assert products == []


def test_detect_av_products_raises_when_powershell_missing():
    with patch("platform.system", return_value="Windows"), \
         patch("subprocess.run", side_effect=FileNotFoundError()):
        with pytest.raises(av_detect.AvDetectionError):
            av_detect.detect_av_products()


def test_detect_av_products_raises_on_timeout():
    with patch("platform.system", return_value="Windows"), \
         patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="powershell.exe", timeout=30)):
        with pytest.raises(av_detect.AvDetectionError):
            av_detect.detect_av_products()


def test_detect_av_products_raises_on_non_windows():
    with patch("platform.system", return_value="Linux"):
        with pytest.raises(av_detect.AvDetectionError):
            av_detect.detect_av_products()


def test_looks_like_defender_matches_common_names():
    assert av_detect.looks_like_defender("Windows Defender")
    assert av_detect.looks_like_defender("Microsoft Defender Antivirus")
    assert not av_detect.looks_like_defender("McAfee Endpoint Security")


def test_guidance_for_defender_points_at_the_automated_button():
    assert "button below" in av_detect.guidance_for("Windows Defender").lower()


def test_guidance_for_known_vendor_returns_specific_hint():
    hint = av_detect.guidance_for("McAfee Endpoint Security")
    assert "mcafee" in hint.lower() or "McAfee" in hint


def test_guidance_for_unknown_vendor_returns_generic_fallback():
    hint = av_detect.guidance_for("Some Totally Made Up AV Product")
    assert "Some Totally Made Up AV Product" in hint
    assert "no specific guidance" in hint.lower()


def test_guidance_for_centrally_managed_edr_says_so():
    hint = av_detect.guidance_for("CrowdStrike Falcon Sensor")
    assert "centrally" in hint.lower()
