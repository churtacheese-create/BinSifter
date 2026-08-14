"""Regression tests for binsifter.core.config's writable-data-root fallback.

2026-08-13: a real installer test crashed Winnow at startup with an
unhandled PermissionError trying to mkdir Reports/ under
'C:\\Program Files\\BinSifter Winnow' - the all-users/admin install path
Winnow.iss offers alongside its default per-user install. get_binsifter_root()
itself is untouched (it still needs to point at the real install directory
for read-only uses like loading the bundled logo PNGs); get_binsifter_data_root()
is the new function build_default_config()/save_settings_cache() use instead,
which probes for real write access and falls back to a per-user location if
the install directory isn't writable.

These tests run on this dev sandbox's Linux permission model (chmod-based),
not Windows ACLs/UAC directly - what's being verified is the fallback LOGIC
(probe, catch, redirect), which is the same regardless of which OS's
permission system triggers the PermissionError.
"""

from binsifter.core import config as config_module


def test_get_binsifter_data_root_returns_root_when_writable(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module, "get_binsifter_root", lambda: tmp_path)
    result = config_module.get_binsifter_data_root()
    assert result == tmp_path


def test_get_binsifter_data_root_falls_back_when_root_not_writable(tmp_path, monkeypatch):
    # Simulate an all-users/Program Files install: the directory exists,
    # but this process has no write access to it - exactly what a normal
    # (non-elevated) launch sees after an admin-mode Winnow install.
    locked_root = tmp_path / "locked_install_dir"
    locked_root.mkdir()
    locked_root.chmod(0o500)  # read + execute only, no write

    fallback_base = tmp_path / "localappdata"
    fallback_base.mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(fallback_base))
    monkeypatch.setattr(config_module, "get_binsifter_root", lambda: locked_root)

    try:
        result = config_module.get_binsifter_data_root()
    finally:
        locked_root.chmod(0o700)  # restore write access so tmp_path cleanup can remove it

    assert result == fallback_base / "BinSifter Winnow"
    assert result.is_dir()


def test_get_binsifter_data_root_falls_back_without_localappdata_set(tmp_path, monkeypatch):
    # Defensive case: LOCALAPPDATA is a Windows-only env var, but nothing
    # here should ever raise just because it's unset (e.g. a non-Windows
    # future Ingot-style build, or a stripped-down environment) - falls
    # back further to the user's home directory instead.
    locked_root = tmp_path / "locked_install_dir"
    locked_root.mkdir()
    locked_root.chmod(0o500)

    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setattr(config_module, "get_binsifter_root", lambda: locked_root)
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(config_module.Path, "home", classmethod(lambda cls: fake_home))

    try:
        result = config_module.get_binsifter_data_root()
    finally:
        locked_root.chmod(0o700)

    assert result == fake_home / "BinSifter Winnow"
    assert result.is_dir()


def test_build_default_config_uses_data_root(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module, "get_binsifter_root", lambda: tmp_path)
    cfg = config_module.build_default_config()
    assert cfg.ReportDirectory == str(tmp_path / "Reports")
    assert (tmp_path / "Reports").is_dir()
    assert (tmp_path / "Attack").is_dir()
    assert (tmp_path / "Blocklist").is_dir()


def test_build_default_config_falls_back_when_root_not_writable(tmp_path, monkeypatch):
    locked_root = tmp_path / "locked_install_dir"
    locked_root.mkdir()
    locked_root.chmod(0o500)

    fallback_base = tmp_path / "localappdata"
    fallback_base.mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(fallback_base))
    monkeypatch.setattr(config_module, "get_binsifter_root", lambda: locked_root)

    try:
        cfg = config_module.build_default_config()
    finally:
        locked_root.chmod(0o700)

    expected_root = fallback_base / "BinSifter Winnow"
    assert cfg.ReportDirectory == str(expected_root / "Reports")
    assert (expected_root / "Reports").is_dir()


def test_save_and_load_settings_cache_round_trip_through_data_root(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module, "get_binsifter_root", lambda: tmp_path)
    cfg = config_module.build_default_config()
    cfg.SrcDir = "C:\\Evidence"
    cfg.YaraRules = "C:\\Rules"
    config_module.save_settings_cache(cfg)

    reloaded = config_module.build_default_config()
    assert reloaded.SrcDir == "C:\\Evidence"
    assert reloaded.YaraRules == "C:\\Rules"


def test_get_bundled_asset_path_falls_back_to_binsifter_root_when_not_frozen(tmp_path, monkeypatch):
    # Normal dev/test case: sys._MEIPASS doesn't exist at all (never frozen).
    monkeypatch.delattr(config_module.sys, "_MEIPASS", raising=False)
    monkeypatch.setattr(config_module, "get_binsifter_root", lambda: tmp_path)
    (tmp_path / "logo.png").write_bytes(b"fake png")

    result = config_module.get_bundled_asset_path("logo.png")
    assert result == tmp_path / "logo.png"


def test_get_bundled_asset_path_prefers_meipass_when_asset_lives_there(tmp_path, monkeypatch):
    # 2026-08-14 bug: PyInstaller 6.0's onedir layout nests datas under
    # _internal/ instead of next to the exe - sys._MEIPASS is the one
    # pointer that's correct regardless of which layout a given
    # PyInstaller version uses, so it must be checked (and preferred).
    meipass_dir = tmp_path / "exe_dir" / "_internal"
    meipass_dir.mkdir(parents=True)
    (meipass_dir / "logo.png").write_bytes(b"real asset, lives under _internal")

    exe_dir = tmp_path / "exe_dir"
    monkeypatch.setattr(config_module.sys, "_MEIPASS", str(meipass_dir), raising=False)
    monkeypatch.setattr(config_module, "get_binsifter_root", lambda: exe_dir)

    result = config_module.get_bundled_asset_path("logo.png")
    assert result == meipass_dir / "logo.png"


def test_get_bundled_asset_path_falls_back_to_exe_dir_when_not_under_meipass(tmp_path, monkeypatch):
    # Defensive case: an older/future PyInstaller puts datas flat next to
    # the exe again (not under _MEIPASS) - still found, not silently lost.
    meipass_dir = tmp_path / "_internal"
    meipass_dir.mkdir()
    exe_dir = tmp_path / "exe_dir"
    exe_dir.mkdir()
    (exe_dir / "logo.png").write_bytes(b"real asset, lives flat next to the exe")

    monkeypatch.setattr(config_module.sys, "_MEIPASS", str(meipass_dir), raising=False)
    monkeypatch.setattr(config_module, "get_binsifter_root", lambda: exe_dir)

    result = config_module.get_bundled_asset_path("logo.png")
    assert result == exe_dir / "logo.png"


def test_get_bundled_asset_path_returns_a_path_even_when_asset_missing_everywhere(tmp_path, monkeypatch):
    # Callers (main_window.py/about.py) already guard with .is_file() -
    # this must never raise, just hand back something they can check.
    monkeypatch.delattr(config_module.sys, "_MEIPASS", raising=False)
    monkeypatch.setattr(config_module, "get_binsifter_root", lambda: tmp_path)

    result = config_module.get_bundled_asset_path("does_not_exist.png")
    assert not result.is_file()
