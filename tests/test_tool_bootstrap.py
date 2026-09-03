"""Tests for binsifter.core.tool_bootstrap - the first-run quick-launch
tool auto-installer (see that module's docstring for the full rationale).

Everything network-facing (urllib, subprocess/pip, venv.create) is
monkeypatched - the point of these tests is to exercise this module's own
decision logic (which asset matches, which tool gets skipped, that nothing
here ever raises out to a caller), not to actually hit GitHub/PyPI or
install real software during a test run. Where a real filesystem
operation is cheap and safe to exercise for real (tar extraction,
chmod'ing a file executable), these tests do so against a tmp_path rather
than mocking it away.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from binsifter.core import tool_bootstrap as tb
from binsifter.core.config import BinSifterConfig


# ---------- check_internet_available ----------

def test_check_internet_available_true_when_first_host_succeeds(monkeypatch):
    monkeypatch.setattr(tb.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(b""))
    assert tb.check_internet_available() is True


def test_check_internet_available_false_when_every_host_fails(monkeypatch):
    def _raise(*_a, **_k):
        raise OSError("no route to host")

    monkeypatch.setattr(tb.urllib.request, "urlopen", _raise)
    assert tb.check_internet_available() is False


def test_check_internet_available_tries_second_host_after_first_fails(monkeypatch):
    calls = []

    def _fake_urlopen(request, timeout):  # noqa: ARG001
        calls.append(request.full_url)
        if len(calls) == 1:
            raise OSError("first host down")
        return io.BytesIO(b"")

    monkeypatch.setattr(tb.urllib.request, "urlopen", _fake_urlopen)
    assert tb.check_internet_available() is True
    assert len(calls) == 2


# ---------- _pick_asset ----------

_RIZIN_ASSETS = [
    {"name": "rizin-v0.9.1-android-aarch64.tar.gz"},
    {"name": "rizin-v0.9.1-android-x86_64.tar.gz"},
    {"name": "rizin-v0.9.1-static-x86_64.tar.xz"},
    {"name": "rizin-windows-static-v0.9.1.zip"},
    {"name": "rizin_installer-v0.9.1-x86_64.exe"},
]

_ANYA_ASSETS = [
    {"name": "Anya-2.0.4-1.x86_64.rpm"},
    {"name": "anya-v2.0.4-universal-apple-darwin.tar.gz"},
    {"name": "anya-v2.0.4-x86_64-pc-windows-msvc.zip"},
    {"name": "anya-v2.0.4-x86_64-unknown-linux-musl.tar.gz"},
    {"name": "Anya_2.0.4_amd64.AppImage"},
]


def test_pick_asset_rizin_avoids_android_x86_64_false_positive():
    """The specific bug this project caught while researching real asset
    names: 'android-x86_64' also contains the 'x86_64' token, so matching
    on 'x86_64' alone would grab the wrong (Android) build. 'static' is
    what actually narrows it to the one real desktop Linux asset."""
    asset = tb._pick_asset(_RIZIN_ASSETS, must_contain=("static", "x86_64"), must_not_contain=("android",))
    assert asset is not None
    assert asset["name"] == "rizin-v0.9.1-static-x86_64.tar.xz"


def test_pick_asset_anya_finds_the_musl_cli_tarball_not_the_gui_appimage():
    asset = tb._pick_asset(_ANYA_ASSETS, must_contain=("linux", "musl", ".tar.gz"))
    assert asset is not None
    assert asset["name"] == "anya-v2.0.4-x86_64-unknown-linux-musl.tar.gz"


def test_pick_asset_returns_none_when_nothing_matches():
    assert tb._pick_asset(_RIZIN_ASSETS, must_contain=("nonexistent-token",)) is None


def test_pick_asset_appimage_matches_case_insensitively():
    assets = [{"name": "PE-bear_0.7.2_qt6_x86_64_linux.AppImage"}]
    asset = tb._pick_asset(assets, must_contain=(".appimage",))
    assert asset is not None


# ---------- run_tool_bootstrap orchestration ----------

def _config_with_all_tools_missing() -> BinSifterConfig:
    return BinSifterConfig()  # every *Exe field defaults to "" per config.py


def test_already_present_tools_are_skipped_with_no_network_check(monkeypatch, tmp_path):
    real_tool = tmp_path / "rizin"
    real_tool.write_text("#!/bin/sh\n")
    config = _config_with_all_tools_missing()
    config.RizinExe = str(real_tool)
    config.PeBearExe = str(real_tool)  # reuse the same fake file for simplicity
    config.AnyaExe = str(real_tool)
    config.DieExe = str(real_tool)
    config.AngrExe = str(real_tool)

    def _fail_if_called(*_a, **_k):
        raise AssertionError("check_internet_available() should never be called when every tool is already present")

    monkeypatch.setattr(tb, "check_internet_available", _fail_if_called)
    results = tb.run_tool_bootstrap(config)
    assert len(results) == 5
    assert all(r.status == "already_present" for r in results)


def test_missing_tool_with_no_internet_reports_no_internet_with_manual_hint(monkeypatch):
    config = _config_with_all_tools_missing()
    monkeypatch.setattr(tb, "check_internet_available", lambda: False)
    results = tb.run_tool_bootstrap(config)
    assert len(results) == 5
    assert all(r.status == "no_internet" for r in results)
    rizin_result = next(r for r in results if r.tool_key == "RizinExe")
    assert "reconnect" in rizin_result.detail.lower() or "internet" in rizin_result.detail.lower()


def test_internet_check_only_happens_once_across_all_missing_tools(monkeypatch):
    config = _config_with_all_tools_missing()
    call_count = {"n": 0}

    def _counted_check():
        call_count["n"] += 1
        return False

    monkeypatch.setattr(tb, "check_internet_available", _counted_check)
    tb.run_tool_bootstrap(config)
    assert call_count["n"] == 1


def test_installer_exception_becomes_a_failed_result_not_a_raise(monkeypatch):
    config = _config_with_all_tools_missing()
    monkeypatch.setattr(tb, "check_internet_available", lambda: True)

    def _broken_installer(_dest_root):
        raise RuntimeError("simulated unexpected failure")

    monkeypatch.setitem(tb._INSTALLERS, "RizinExe", _broken_installer)
    # Every other installer should also just no-op/fail cleanly rather than
    # actually hit the network during this test.
    for key in ("PeBearExe", "AnyaExe", "DieExe", "AngrExe"):
        monkeypatch.setitem(tb._INSTALLERS, key, lambda _d, k=key: tb.ToolBootstrapResult(k, k, "failed", detail="stubbed"))

    results = tb.run_tool_bootstrap(config)
    rizin_result = next(r for r in results if r.tool_key == "RizinExe")
    assert rizin_result.status == "failed"
    assert "simulated unexpected failure" in rizin_result.detail


def test_successful_installer_result_is_passed_through(monkeypatch, tmp_path):
    config = _config_with_all_tools_missing()
    monkeypatch.setattr(tb, "check_internet_available", lambda: True)
    fake_path = str(tmp_path / "rizin")

    for key in tb.TOOL_FILE_NAMES:
        status = "installed" if key == "RizinExe" else "failed"
        path = fake_path if key == "RizinExe" else ""
        monkeypatch.setitem(
            tb._INSTALLERS, key, lambda _d, k=key, s=status, p=path: tb.ToolBootstrapResult(k, k, s, path=p)
        )

    results = tb.run_tool_bootstrap(config)
    rizin_result = next(r for r in results if r.tool_key == "RizinExe")
    assert rizin_result.status == "installed"
    assert rizin_result.path == fake_path


# ---------- per-tool installers (network mocked, real tar/chmod exercised) ----------

def test_install_appimage_tool_downloads_and_makes_executable(monkeypatch, tmp_path):
    monkeypatch.setattr(
        tb, "_latest_release_assets",
        lambda owner, repo, timeout=8.0: [{"name": "PE-bear_0.7.2_qt6_x86_64_linux.AppImage",
                                            "browser_download_url": "https://example.invalid/pe-bear.AppImage"}],
    )

    def _fake_download(url, dest, timeout=180.0):  # noqa: ARG001
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"fake appimage contents")

    monkeypatch.setattr(tb, "_download", _fake_download)
    result = tb._install_pe_bear(tmp_path)
    assert result.status == "installed"
    assert Path(result.path).is_file()
    assert Path(result.path).stat().st_mode & 0o111  # executable bits set


def test_install_appimage_tool_reports_failed_when_no_asset_matches(monkeypatch, tmp_path):
    monkeypatch.setattr(tb, "_latest_release_assets", lambda owner, repo, timeout=8.0: [{"name": "source.tar.gz"}])
    result = tb._install_die(tmp_path)
    assert result.status == "failed"
    assert "no linux appimage" in result.detail.lower()


def test_install_appimage_tool_reports_failed_on_network_error(monkeypatch, tmp_path):
    def _raise(*_a, **_k):
        raise OSError("connection reset")

    monkeypatch.setattr(tb, "_latest_release_assets", _raise)
    result = tb._install_pe_bear(tmp_path)
    assert result.status == "failed"
    assert "connection reset" in result.detail


def _make_tar_gz_with_executable(member_name: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name=member_name)
        payload = b"#!/bin/sh\necho fake\n"
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def test_install_anya_extracts_tarball_and_locates_binary(monkeypatch, tmp_path):
    tarball_bytes = _make_tar_gz_with_executable("anya")
    monkeypatch.setattr(
        tb, "_latest_release_assets",
        lambda owner, repo, timeout=8.0: [{"name": "anya-v2.0.4-x86_64-unknown-linux-musl.tar.gz",
                                            "browser_download_url": "https://example.invalid/anya.tar.gz"}],
    )

    def _fake_download(url, dest, timeout=180.0):  # noqa: ARG001
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(tarball_bytes)

    monkeypatch.setattr(tb, "_download", _fake_download)
    result = tb._install_anya(tmp_path)
    assert result.status == "installed"
    assert Path(result.path).name == "anya"
    assert Path(result.path).is_file()
    assert Path(result.path).stat().st_mode & 0o111


def test_install_rizin_excludes_android_asset(monkeypatch, tmp_path):
    tarball_bytes = _make_tar_gz_with_executable("rizin")
    monkeypatch.setattr(tb, "_latest_release_assets", lambda owner, repo, timeout=8.0: _RIZIN_ASSETS)

    downloaded_urls = []

    def _fake_download(url, dest, timeout=180.0):  # noqa: ARG001
        downloaded_urls.append(url)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(tarball_bytes)

    monkeypatch.setattr(tb, "_download", _fake_download)
    # _RIZIN_ASSETS fixture entries have no browser_download_url - add one
    # to just the expected match so a wrong pick would KeyError instead of
    # silently downloading the wrong (real) asset.
    assets_with_url = [dict(a) for a in _RIZIN_ASSETS]
    for a in assets_with_url:
        if a["name"] == "rizin-v0.9.1-static-x86_64.tar.xz":
            a["browser_download_url"] = "https://example.invalid/rizin-static.tar.xz"
    monkeypatch.setattr(tb, "_latest_release_assets", lambda owner, repo, timeout=8.0: assets_with_url)

    result = tb._install_rizin(tmp_path)
    assert result.status == "installed"
    assert downloaded_urls == ["https://example.invalid/rizin-static.tar.xz"]


def test_install_angr_uses_private_venv_and_checks_for_console_script(monkeypatch, tmp_path):
    created_venvs = []

    def _fake_venv_create(path, with_pip=True, clear=True):  # noqa: ARG001
        created_venvs.append(path)
        bin_dir = path / "bin"
        bin_dir.mkdir(parents=True)
        (bin_dir / "python").write_text("#!/bin/sh\n")
        (bin_dir / "python").chmod(0o755)

    def _fake_pip_install(cmd, **kwargs):  # noqa: ARG001
        # Simulate `pip install angr` succeeding and producing a console
        # script, without actually installing anything.
        bin_dir = Path(cmd[0]).parent
        (bin_dir / "angr").write_text("#!/bin/sh\n")
        (bin_dir / "angr").chmod(0o755)
        return subprocess_completed_process_stub()

    monkeypatch.setattr(tb.venv, "create", _fake_venv_create)
    monkeypatch.setattr(tb.subprocess, "run", _fake_pip_install)

    result = tb._install_angr(tmp_path)
    assert result.status == "installed"
    assert result.path.endswith("/bin/angr")
    assert created_venvs == [tmp_path / "angr-venv"]


def subprocess_completed_process_stub():
    class _Stub:
        returncode = 0
        stdout = ""
        stderr = ""

    return _Stub()


def test_install_angr_reports_failed_when_pip_install_fails(monkeypatch, tmp_path):
    import subprocess as real_subprocess

    def _fake_venv_create(path, with_pip=True, clear=True):  # noqa: ARG001
        (path / "bin").mkdir(parents=True)
        (path / "bin" / "python").write_text("#!/bin/sh\n")

    def _fake_pip_install(cmd, **kwargs):  # noqa: ARG001
        raise real_subprocess.CalledProcessError(1, cmd, output="", stderr="ERROR: could not find a version")

    monkeypatch.setattr(tb.venv, "create", _fake_venv_create)
    monkeypatch.setattr(tb.subprocess, "run", _fake_pip_install)

    result = tb._install_angr(tmp_path)
    assert result.status == "failed"
    assert "could not find a version" in result.detail
