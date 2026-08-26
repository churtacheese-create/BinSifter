"""Regression tests for binsifter.core.av_detect. subprocess.run is mocked
throughout for the Windows path (this dev sandbox is Linux, has no real
PowerShell/WMI to query against) - those tests exercise the JSON-parsing/
dedup/guidance-lookup logic around the subprocess call, not the real
Windows query itself, same verification-caveat pattern as defender.py's
own module docstring.

The Linux path's three signals (_systemd_unit_installed,
_linux_process_names, Path.exists) are mocked individually below instead -
this sandbox genuinely IS Linux, but it has none of the real AV/EDR
products in _LINUX_AV_SIGNATURES installed, so "does the real detection
logic correctly wire up a hit from each of the three signal types" still
needs mocking to exercise deliberately, not because the platform itself
needs faking.
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


def test_detect_av_products_raises_on_unsupported_platform():
    # Only Windows and Linux have a detection mechanism implemented -
    # anything else (macOS here) still raises, same as "non-Windows" used
    # to before Linux support existed.
    with patch("platform.system", return_value="Darwin"):
        with pytest.raises(av_detect.AvDetectionError):
            av_detect.detect_av_products()


# --- Linux detection path -------------------------------------------------
# Real Linux platform (this sandbox), but the three underlying signals are
# mocked individually so each test exercises exactly one hit/no-hit path
# through _detect_linux() without depending on what's actually installed
# on the machine running the test suite.

def test_detect_linux_finds_hit_via_systemd_unit():
    with patch("platform.system", return_value="Linux"), \
         patch("binsifter.core.av_detect._systemd_unit_installed", side_effect=lambda unit: unit == "clamav-daemon.service"), \
         patch("binsifter.core.av_detect._linux_process_names", return_value=set()), \
         patch("pathlib.Path.exists", return_value=False):
        products = av_detect.detect_av_products()
    assert [p.name for p in products] == ["ClamAV"]


def test_detect_linux_finds_hit_via_running_process():
    with patch("platform.system", return_value="Linux"), \
         patch("binsifter.core.av_detect._systemd_unit_installed", return_value=False), \
         patch("binsifter.core.av_detect._linux_process_names", return_value={"falcon-sensor"}), \
         patch("pathlib.Path.exists", return_value=False):
        products = av_detect.detect_av_products()
    assert [p.name for p in products] == ["CrowdStrike Falcon"]


def test_detect_linux_finds_hit_via_install_path():
    # Uses new= (a plain function) rather than side_effect= on a MagicMock -
    # Path.exists is an instance method, and only a real function object
    # gets bound with `self` via the descriptor protocol when patched onto
    # the class; a MagicMock's side_effect would be called with zero args.
    with patch("platform.system", return_value="Linux"), \
         patch("binsifter.core.av_detect._systemd_unit_installed", return_value=False), \
         patch("binsifter.core.av_detect._linux_process_names", return_value=set()), \
         patch("pathlib.Path.exists", new=lambda self: str(self) == "/opt/sophos-spl"):
        products = av_detect.detect_av_products()
    assert [p.name for p in products] == ["Sophos"]


def test_detect_linux_returns_empty_list_when_nothing_matches_not_an_error():
    with patch("platform.system", return_value="Linux"), \
         patch("binsifter.core.av_detect._systemd_unit_installed", return_value=False), \
         patch("binsifter.core.av_detect._linux_process_names", return_value=set()), \
         patch("pathlib.Path.exists", return_value=False):
        products = av_detect.detect_av_products()
    assert products == []


def test_systemd_unit_installed_returns_false_when_systemctl_missing():
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        assert av_detect._systemd_unit_installed("clamav-daemon.service") is False


def test_systemd_unit_installed_returns_true_on_nonblank_output():
    with patch("subprocess.run", return_value=_fake_run("clamav-daemon.service disabled\n")):
        assert av_detect._systemd_unit_installed("clamav-daemon.service") is True


def test_systemd_unit_installed_returns_false_on_blank_output():
    with patch("subprocess.run", return_value=_fake_run("")):
        assert av_detect._systemd_unit_installed("nonexistent.service") is False


def test_linux_process_names_reads_comm_files_from_proc_root(tmp_path):
    pid_dir = tmp_path / "1234"
    pid_dir.mkdir()
    (pid_dir / "comm").write_text("Clamd\n", encoding="utf-8")
    non_pid_dir = tmp_path / "self"
    non_pid_dir.mkdir()
    names = av_detect._linux_process_names(proc_root=tmp_path)
    assert names == {"clamd"}


def test_linux_process_names_returns_empty_set_for_missing_proc_root(tmp_path):
    assert av_detect._linux_process_names(proc_root=tmp_path / "does-not-exist") == set()


def test_guidance_for_linux_defender_for_endpoint_does_not_point_at_windows_button():
    hint = av_detect.guidance_for("Microsoft Defender for Endpoint")
    assert "mdatp" in hint.lower()
    assert "only automates windows defender" in hint.lower()


def test_guidance_for_clamav_returns_linux_specific_hint():
    hint = av_detect.guidance_for("ClamAV")
    assert "clamd.conf" in hint


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
