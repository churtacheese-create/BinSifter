"""Tests for binsifter.core.tool_bootstrap - the first-run quick-launch
tool auto-installer (see that module's docstring for the full rationale).

Everything network-facing (urllib, subprocess/pip, venv.create) is
monkeypatched - the point of these tests is to exercise this module's own
decision logic (which asset matches, which tool gets skipped, that nothing
here ever raises out to a caller), not to actually hit GitHub/PyPI or
install real software during a test run. Where a real filesystem
operation is cheap and safe to exercise for real (tar/zip extraction,
chmod'ing a file executable), these tests do so against a tmp_path rather
than mocking it away.

Rizin-specific tests were replaced 2026-09-03 when Rizin was replaced with
Cutter in the quick-launch lineup (see tool_bootstrap.py's module
docstring for why) - the old "avoids the android/x86_64 false positive"
fixture data is kept as a generic _pick_asset exercise since that
must_contain/must_not_contain logic itself is still used by every
AppImage-based installer, even though BinSifter no longer downloads Rizin
itself.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
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

# Kept as real historical asset-name data purely as a generic exercise of
# _pick_asset's must_contain/must_not_contain logic (the android/x86_64
# false-positive risk this caught is a property of substring matching in
# general, not specific to Rizin) - Rizin itself is no longer installed by
# this module.
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

_CUTTER_ASSETS = [
    {"name": "Cutter-v2.3.4-Linux-x86_64.AppImage",
     "browser_download_url": "https://example.invalid/cutter.AppImage"},
    {"name": "Cutter-v2.3.4-Windows-x86_64.zip"},
    {"name": "Cutter-v2.3.4-macOS-x86_64.dmg"},
]


def test_pick_asset_avoids_android_x86_64_false_positive():
    """The specific bug this project caught while researching real asset
    names: 'android-x86_64' also contains the 'x86_64' token, so matching
    on 'x86_64' alone would grab the wrong (Android) build. 'static' is
    what actually narrows it to the one real desktop Linux asset. Generic
    _pick_asset algorithm test - not tied to Rizin specifically."""
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


_ALL_FIELD_NAMES = (*tb.TOOL_FILE_NAMES.keys(), "GhidraHeadlessExe")


def test_already_present_tools_are_skipped_with_no_network_check(monkeypatch, tmp_path):
    real_tool = tmp_path / "cutter"
    real_tool.write_text("#!/bin/sh\n")
    config = _config_with_all_tools_missing()
    for field_name in _ALL_FIELD_NAMES:
        setattr(config, field_name, str(real_tool))  # reuse the same fake file for every field

    monkeypatch.setattr(tb, "_gef_already_configured", lambda: True)

    def _fail_if_called(*_a, **_k):
        raise AssertionError("check_internet_available() should never be called when every tool is already present")

    monkeypatch.setattr(tb, "check_internet_available", _fail_if_called)
    results = tb.run_tool_bootstrap(config)
    assert len(results) == len(_ALL_FIELD_NAMES)
    assert all(r.status == "already_present" for r in results)


def test_missing_tool_with_no_internet_reports_no_internet_with_manual_hint(monkeypatch):
    config = _config_with_all_tools_missing()
    monkeypatch.setattr(tb, "check_internet_available", lambda: False)
    results = tb.run_tool_bootstrap(config)
    assert len(results) == len(_ALL_FIELD_NAMES)
    cutter_result = next(r for r in results if r.tool_key == "CutterExe")
    assert cutter_result.status == "no_internet"
    assert "reconnect" in cutter_result.detail.lower() or "internet" in cutter_result.detail.lower()


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

    monkeypatch.setitem(tb._INSTALLERS, "CutterExe", _broken_installer)
    # Every other installer should also just no-op/fail cleanly rather than
    # actually hit the network during this test.
    for key in ("PeBearExe", "AnyaExe", "DieExe", "AngrExe", "BinwalkExe", "MalwoverviewExe"):
        monkeypatch.setitem(tb._INSTALLERS, key, lambda _d, k=key: tb.ToolBootstrapResult(k, k, "failed", detail="stubbed"))
    monkeypatch.setattr(tb, "_install_gef", lambda _d: tb.ToolBootstrapResult("GdbExe", "GDB + GEF", "failed", detail="stubbed"))
    monkeypatch.setattr(tb, "_install_ghidra", lambda _d: tb.ToolBootstrapResult("GhidraHeadlessExe", "Ghidra", "failed", detail="stubbed"))

    results = tb.run_tool_bootstrap(config)
    cutter_result = next(r for r in results if r.tool_key == "CutterExe")
    assert cutter_result.status == "failed"
    assert "simulated unexpected failure" in cutter_result.detail


def test_successful_installer_result_is_passed_through(monkeypatch, tmp_path):
    config = _config_with_all_tools_missing()
    monkeypatch.setattr(tb, "check_internet_available", lambda: True)
    fake_path = str(tmp_path / "cutter")

    for key in tb.TOOL_FILE_NAMES:
        status = "installed" if key == "CutterExe" else "failed"
        path = fake_path if key == "CutterExe" else ""
        monkeypatch.setitem(
            tb._INSTALLERS, key, lambda _d, k=key, s=status, p=path: tb.ToolBootstrapResult(k, k, s, path=p)
        )
    monkeypatch.setattr(tb, "_install_gef", lambda _d: tb.ToolBootstrapResult("GdbExe", "GDB + GEF", "failed", detail="stubbed"))
    monkeypatch.setattr(tb, "_install_ghidra", lambda _d: tb.ToolBootstrapResult("GhidraHeadlessExe", "Ghidra", "failed", detail="stubbed"))

    results = tb.run_tool_bootstrap(config)
    cutter_result = next(r for r in results if r.tool_key == "CutterExe")
    assert cutter_result.status == "installed"
    assert cutter_result.path == fake_path


# ---------- GdbExe / GEF special-casing ----------

def test_gdb_missing_reports_failed_with_manual_hint_not_no_internet(monkeypatch):
    """GDB itself is never auto-installed (needs a real distro package
    manager) - a missing gdb should be a permanent "failed" with the
    manual-install hint, not "no_internet", since reconnecting alone can't
    fix a missing gdb the way it can for every other tool."""
    config = _config_with_all_tools_missing()

    def _fail_if_called():
        raise AssertionError("check_internet_available() should never be consulted for a missing gdb")

    monkeypatch.setattr(tb, "check_internet_available", _fail_if_called)
    # Isolate GdbExe: every other tool reports already_present so the loop
    # never reaches the shared internet-check path for them either.
    for field_name in tb.TOOL_FILE_NAMES:
        if field_name != "GdbExe":
            setattr(config, field_name, str(Path("/bin/true")))
    config.GhidraHeadlessExe = str(Path("/bin/true"))

    results = tb.run_tool_bootstrap(config)
    gdb_result = next(r for r in results if r.tool_key == "GdbExe")
    assert gdb_result.status == "failed"
    assert "gdb not found on path" in gdb_result.detail.lower()


def test_gdb_present_and_gef_configured_reports_already_present(monkeypatch, tmp_path):
    config = _config_with_all_tools_missing()
    gdb_path = tmp_path / "gdb"
    gdb_path.write_text("#!/bin/sh\n")
    config.GdbExe = str(gdb_path)
    for field_name in tb.TOOL_FILE_NAMES:
        if field_name != "GdbExe":
            setattr(config, field_name, str(gdb_path))
    config.GhidraHeadlessExe = str(gdb_path)

    monkeypatch.setattr(tb, "_gef_already_configured", lambda: True)

    def _fail_if_called(*_a, **_k):
        raise AssertionError("should not need internet when GEF is already configured")

    monkeypatch.setattr(tb, "check_internet_available", _fail_if_called)
    results = tb.run_tool_bootstrap(config)
    gdb_result = next(r for r in results if r.tool_key == "GdbExe")
    assert gdb_result.status == "already_present"


def test_gdb_present_but_gef_missing_runs_gef_installer(monkeypatch, tmp_path):
    config = _config_with_all_tools_missing()
    gdb_path = tmp_path / "gdb"
    gdb_path.write_text("#!/bin/sh\n")
    config.GdbExe = str(gdb_path)
    for field_name in tb.TOOL_FILE_NAMES:
        if field_name != "GdbExe":
            setattr(config, field_name, str(gdb_path))
    config.GhidraHeadlessExe = str(gdb_path)

    monkeypatch.setattr(tb, "_gef_already_configured", lambda: False)
    monkeypatch.setattr(tb, "check_internet_available", lambda: True)
    monkeypatch.setattr(tb, "_install_gef", lambda _d: tb.ToolBootstrapResult("GdbExe", "GDB + GEF", "installed", path=str(gdb_path)))

    results = tb.run_tool_bootstrap(config)
    gdb_result = next(r for r in results if r.tool_key == "GdbExe")
    assert gdb_result.status == "installed"


# ---------- GhidraHeadlessExe special-casing ----------

def test_ghidra_uses_install_ghidra_when_missing(monkeypatch, tmp_path):
    config = _config_with_all_tools_missing()
    real_tool = tmp_path / "cutter"
    real_tool.write_text("#!/bin/sh\n")
    for field_name in tb.TOOL_FILE_NAMES:
        setattr(config, field_name, str(real_tool))
    monkeypatch.setattr(tb, "_gef_already_configured", lambda: True)
    monkeypatch.setattr(tb, "check_internet_available", lambda: True)
    monkeypatch.setattr(tb, "_install_ghidra", lambda _d: tb.ToolBootstrapResult("GhidraHeadlessExe", "Ghidra", "installed", path="/fake/analyzeHeadless"))

    results = tb.run_tool_bootstrap(config)
    ghidra_result = next(r for r in results if r.tool_key == "GhidraHeadlessExe")
    assert ghidra_result.status == "installed"
    assert ghidra_result.path == "/fake/analyzeHeadless"


# ---------- per-tool installers (network mocked, real tar/zip/chmod exercised) ----------

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


def test_install_cutter_downloads_appimage(monkeypatch, tmp_path):
    monkeypatch.setattr(tb, "_latest_release_assets", lambda owner, repo, timeout=8.0: _CUTTER_ASSETS)

    def _fake_download(url, dest, timeout=180.0):  # noqa: ARG001
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"fake cutter appimage")

    monkeypatch.setattr(tb, "_download", _fake_download)
    result = tb._install_cutter(tmp_path)
    assert result.status == "installed"
    assert Path(result.path).is_file()
    assert Path(result.path).stat().st_mode & 0o111


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


def _fake_create_private_venv(path: Path) -> str:
    """Stand-in for tb._create_private_venv() used by every installer test
    below - creates a real bin/python placeholder and reports success (""),
    without touching the real venv module or a real system python3. See
    the dedicated _create_private_venv tests further down for coverage of
    that function's own real/fallback logic."""
    bin_dir = path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    (bin_dir / "python").write_text("#!/bin/sh\n")
    (bin_dir / "python").chmod(0o755)
    return ""


def test_install_angr_uses_private_venv_and_checks_for_console_script(monkeypatch, tmp_path):
    created_venvs = []

    def _fake_create_venv(path):
        created_venvs.append(path)
        return _fake_create_private_venv(path)

    def _fake_pip_install(cmd, **kwargs):  # noqa: ARG001
        # Simulate `pip install --only-binary=:all: angr` succeeding on the
        # first attempt and producing a console script, without actually
        # installing anything.
        bin_dir = Path(cmd[0]).parent
        (bin_dir / "angr").write_text("#!/bin/sh\n")
        (bin_dir / "angr").chmod(0o755)
        return subprocess_completed_process_stub()

    monkeypatch.setattr(tb, "_create_private_venv", _fake_create_venv)
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


def test_install_angr_falls_back_to_source_build_when_no_wheel_available(monkeypatch, tmp_path):
    """HARDENED 2026-09-03: the wheel-only attempt should fall back to a
    normal (possibly source-building) install rather than giving up
    outright the moment no prebuilt wheel matches."""
    import subprocess as real_subprocess

    attempts = []

    def _fake_pip_install(cmd, **kwargs):  # noqa: ARG001
        attempts.append(cmd)
        if "--only-binary=:all:" in cmd:
            raise real_subprocess.CalledProcessError(1, cmd, output="", stderr="ERROR: no matching wheel found")
        bin_dir = Path(cmd[0]).parent
        (bin_dir / "angr").write_text("#!/bin/sh\n")
        (bin_dir / "angr").chmod(0o755)
        return subprocess_completed_process_stub()

    monkeypatch.setattr(tb, "_create_private_venv", _fake_create_private_venv)
    monkeypatch.setattr(tb.subprocess, "run", _fake_pip_install)

    result = tb._install_angr(tmp_path)
    assert result.status == "installed"
    assert len(attempts) == 2


def test_install_angr_reports_failed_when_both_pip_attempts_fail(monkeypatch, tmp_path):
    import subprocess as real_subprocess

    def _fake_pip_install(cmd, **kwargs):  # noqa: ARG001
        raise real_subprocess.CalledProcessError(1, cmd, output="", stderr="ERROR: could not find a version")

    monkeypatch.setattr(tb, "_create_private_venv", _fake_create_private_venv)
    monkeypatch.setattr(tb.subprocess, "run", _fake_pip_install)

    result = tb._install_angr(tmp_path)
    assert result.status == "failed"
    assert "could not find a version" in result.detail


# ---------- Binwalk / Malwoverview (shared _install_pip_venv_tool) ----------

def test_install_binwalk_uses_private_venv_and_checks_for_console_script(monkeypatch, tmp_path):
    def _fake_pip_install(cmd, **kwargs):  # noqa: ARG001
        bin_dir = Path(cmd[0]).parent
        (bin_dir / "binwalk").write_text("#!/bin/sh\n")
        (bin_dir / "binwalk").chmod(0o755)
        return subprocess_completed_process_stub()

    monkeypatch.setattr(tb, "_create_private_venv", _fake_create_private_venv)
    monkeypatch.setattr(tb.subprocess, "run", _fake_pip_install)

    result = tb._install_binwalk(tmp_path)
    assert result.status == "installed"
    assert result.path.endswith("/bin/binwalk")


def test_install_malwoverview_reports_failed_when_pip_install_fails(monkeypatch, tmp_path):
    import subprocess as real_subprocess

    def _fake_pip_install(cmd, **kwargs):  # noqa: ARG001
        raise real_subprocess.CalledProcessError(1, cmd, output="", stderr="ERROR: no matching distribution")

    monkeypatch.setattr(tb, "_create_private_venv", _fake_create_private_venv)
    monkeypatch.setattr(tb.subprocess, "run", _fake_pip_install)

    result = tb._install_malwoverview(tmp_path)
    assert result.status == "failed"
    assert "no matching distribution" in result.detail


# ---------- _create_private_venv itself ----------

def test_create_private_venv_uses_system_python3_when_available(monkeypatch, tmp_path):
    """REGRESSION for the real bug found from a packaged-app user's log
    2026-09-04: venv.create() bases the new venv on sys.executable, which
    is the frozen BinSifter-Winnow binary once packaged, not a real
    interpreter - 'ensurepip' inside that venv then fails outright. This
    confirms the fix actually prefers a real system python3 (via
    shutil.which) over the stdlib venv module when one is on PATH."""
    venv_calls = []

    def _fake_which(name):
        return "/usr/bin/python3" if name == "python3" else None

    def _fake_run(cmd, **kwargs):  # noqa: ARG001
        venv_calls.append(cmd)
        return subprocess_completed_process_stub()

    def _fail_if_called(*_a, **_k):
        raise AssertionError("venv.create() should not be used when a system python3 is available")

    monkeypatch.setattr(tb.shutil, "which", _fake_which)
    monkeypatch.setattr(tb.subprocess, "run", _fake_run)
    monkeypatch.setattr(tb.venv, "create", _fail_if_called)

    venv_dir = tmp_path / "some-venv"
    error = tb._create_private_venv(venv_dir)
    assert error == ""
    assert venv_calls == [["/usr/bin/python3", "-m", "venv", str(venv_dir)]]


def test_create_private_venv_falls_back_to_venv_module_when_no_system_python(monkeypatch, tmp_path):
    monkeypatch.setattr(tb.shutil, "which", lambda name: None)

    fallback_calls = []

    def _fake_venv_create(path, with_pip=True, clear=True):  # noqa: ARG001
        fallback_calls.append(path)

    monkeypatch.setattr(tb.venv, "create", _fake_venv_create)
    venv_dir = tmp_path / "some-venv"
    error = tb._create_private_venv(venv_dir)
    assert error == ""
    assert fallback_calls == [venv_dir]


def test_create_private_venv_reports_error_when_system_python_venv_creation_fails(monkeypatch, tmp_path):
    import subprocess as real_subprocess

    monkeypatch.setattr(tb.shutil, "which", lambda name: "/usr/bin/python3" if name == "python3" else None)

    def _fake_run(cmd, **kwargs):  # noqa: ARG001
        raise real_subprocess.CalledProcessError(1, cmd, output="", stderr="ensurepip is not available")

    monkeypatch.setattr(tb.subprocess, "run", _fake_run)
    error = tb._create_private_venv(tmp_path / "some-venv")
    assert "ensurepip is not available" in error


# ---------- GEF ----------

def test_gef_already_configured_true_when_gdbinit_mentions_gef(monkeypatch, tmp_path):
    (tmp_path / ".gdbinit").write_text("source ~/.gef.py  # GEF\n")
    monkeypatch.setattr(tb.Path, "home", lambda: tmp_path)
    assert tb._gef_already_configured() is True


def test_gef_already_configured_false_when_no_gdbinit(monkeypatch, tmp_path):
    monkeypatch.setattr(tb.Path, "home", lambda: tmp_path)
    assert tb._gef_already_configured() is False


def test_install_gef_fails_when_gdb_not_on_path(monkeypatch, tmp_path):
    monkeypatch.setattr(tb.shutil, "which", lambda name: None)
    result = tb._install_gef(tmp_path)
    assert result.status == "failed"
    assert "gdb" in result.detail.lower()


def test_install_gef_downloads_and_runs_installer_script(monkeypatch, tmp_path):
    monkeypatch.setattr(tb.shutil, "which", lambda name: "/usr/bin/gdb" if name == "gdb" else None)
    monkeypatch.setattr(tb.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(b"# fake gef installer\n"))

    run_calls = []

    def _fake_run(cmd, **kwargs):  # noqa: ARG001
        run_calls.append(cmd)
        return subprocess_completed_process_stub()

    monkeypatch.setattr(tb.subprocess, "run", _fake_run)
    result = tb._install_gef(tmp_path)
    assert result.status == "installed"
    assert result.path == "/usr/bin/gdb"
    assert run_calls and run_calls[0][0] == "/usr/bin/gdb"


def test_install_gef_reports_failed_when_installer_script_fails(monkeypatch, tmp_path):
    import subprocess as real_subprocess

    monkeypatch.setattr(tb.shutil, "which", lambda name: "/usr/bin/gdb" if name == "gdb" else None)
    monkeypatch.setattr(tb.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(b"# fake gef installer\n"))

    def _fake_run(cmd, **kwargs):  # noqa: ARG001
        raise real_subprocess.CalledProcessError(1, cmd, output="", stderr="gdb: syntax error")

    monkeypatch.setattr(tb.subprocess, "run", _fake_run)
    result = tb._install_gef(tmp_path)
    assert result.status == "failed"
    assert "syntax error" in result.detail


# ---------- Ghidra (+ portable JDK) ----------

def _make_zip_with_executable(member_name: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(member_name, "#!/bin/sh\necho fake\n")
    return buf.getvalue()


def test_install_ghidra_downloads_and_extracts_zip_when_java_already_present(monkeypatch, tmp_path):
    zip_bytes = _make_zip_with_executable("ghidra_11.1_PUBLIC/support/analyzeHeadless")
    monkeypatch.setattr(
        tb, "_latest_release_assets",
        lambda owner, repo, timeout=8.0: [{"name": "ghidra_11.1_PUBLIC_20240607.zip",
                                            "browser_download_url": "https://example.invalid/ghidra.zip"}],
    )

    def _fake_download(url, dest, timeout=180.0):  # noqa: ARG001
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(zip_bytes)

    monkeypatch.setattr(tb, "_download", _fake_download)
    monkeypatch.setattr(tb.shutil, "which", lambda name: "/usr/bin/java" if name == "java" else None)

    result = tb._install_ghidra(tmp_path)
    assert result.status == "installed"
    assert Path(result.path).name == "analyzeHeadless"
    assert Path(result.path).is_file()
    assert Path(result.path).stat().st_mode & 0o111


def test_install_ghidra_reports_failed_when_no_zip_asset_matches(monkeypatch, tmp_path):
    monkeypatch.setattr(tb, "_latest_release_assets", lambda owner, repo, timeout=8.0: [{"name": "ghidra_src.zip"}])
    result = tb._install_ghidra(tmp_path)
    assert result.status == "failed"


def test_install_ghidra_reports_failed_when_analyzeheadless_missing_from_archive(monkeypatch, tmp_path):
    zip_bytes = _make_zip_with_executable("ghidra_11.1_PUBLIC/readme.txt")
    monkeypatch.setattr(
        tb, "_latest_release_assets",
        lambda owner, repo, timeout=8.0: [{"name": "ghidra_11.1_PUBLIC_20240607.zip",
                                            "browser_download_url": "https://example.invalid/ghidra.zip"}],
    )

    def _fake_download(url, dest, timeout=180.0):  # noqa: ARG001
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(zip_bytes)

    monkeypatch.setattr(tb, "_download", _fake_download)
    result = tb._install_ghidra(tmp_path)
    assert result.status == "failed"
    assert "analyzeheadless" in result.detail.lower()


def test_install_ghidra_downloads_portable_jdk_when_java_missing(monkeypatch, tmp_path):
    zip_bytes = _make_zip_with_executable("ghidra_11.1_PUBLIC/support/analyzeHeadless")
    monkeypatch.setattr(
        tb, "_latest_release_assets",
        lambda owner, repo, timeout=8.0: [{"name": "ghidra_11.1_PUBLIC_20240607.zip",
                                            "browser_download_url": "https://example.invalid/ghidra.zip"}],
    )

    def _fake_download(url, dest, timeout=180.0):  # noqa: ARG001
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(zip_bytes)

    monkeypatch.setattr(tb, "_download", _fake_download)
    monkeypatch.setattr(tb.shutil, "which", lambda name: None)  # no java on PATH

    fake_jdk_home = tmp_path / "fake-jdk"
    fake_jdk_home.mkdir()
    monkeypatch.setattr(tb, "_install_portable_jdk", lambda _d: fake_jdk_home)

    result = tb._install_ghidra(tmp_path)
    assert result.status == "installed"
    assert Path(result.path).name == "analyzeHeadless-with-bundled-jdk.sh"
    contents = Path(result.path).read_text()
    assert str(fake_jdk_home) in contents
    assert Path(result.path).stat().st_mode & 0o111


def test_install_ghidra_reports_failed_when_no_java_and_portable_jdk_fails(monkeypatch, tmp_path):
    zip_bytes = _make_zip_with_executable("ghidra_11.1_PUBLIC/support/analyzeHeadless")
    monkeypatch.setattr(
        tb, "_latest_release_assets",
        lambda owner, repo, timeout=8.0: [{"name": "ghidra_11.1_PUBLIC_20240607.zip",
                                            "browser_download_url": "https://example.invalid/ghidra.zip"}],
    )

    def _fake_download(url, dest, timeout=180.0):  # noqa: ARG001
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(zip_bytes)

    monkeypatch.setattr(tb, "_download", _fake_download)
    monkeypatch.setattr(tb.shutil, "which", lambda name: None)
    monkeypatch.setattr(tb, "_install_portable_jdk", lambda _d: None)

    result = tb._install_ghidra(tmp_path)
    assert result.status == "failed"
    assert "jdk" in result.detail.lower()


def test_adoptium_architecture_maps_known_architectures(monkeypatch):
    monkeypatch.setattr(tb.platform, "machine", lambda: "x86_64")
    assert tb._adoptium_architecture() == "x64"
    monkeypatch.setattr(tb.platform, "machine", lambda: "aarch64")
    assert tb._adoptium_architecture() == "aarch64"
