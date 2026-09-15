"""Tests for binsifter.core.update_check - the Settings-page "Check for
updates" support (see that module's docstring for why it only ever checks
and downloads, never installs).

Everything network-facing (urllib) is monkeypatched - real GitHub calls
have no place in a test run. `check_for_update`'s own tag-filtering logic
(never letting Ingot's `ingot-v*` line leak into Rowan/Winnow's `v*` one)
and the current-version-vs-latest-tag comparison are the parts most worth
covering directly, since a real bug was found by hand here during
development: `_parse_tag` (which requires a `v` prefix, for GitHub tags)
was briefly also used to parse the bare `binsifter.__version__` string
(no `v` prefix), silently failing to match and reporting an update as
always available - `_parse_version` exists specifically to keep these two
string shapes from being parsed by the same function again.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from binsifter.core import update_check as uc


def _release(tag: str, url: str = "x", assets: list[dict] | None = None) -> dict:
    return {"tag_name": tag, "html_url": url, "assets": assets or []}


_FAKE_RELEASES = [
    _release("ingot-v0.5.0"),  # must never match Rowan/Winnow's v* line
    _release(
        "v2.0.8",
        "https://r/v2.0.8",
        [
            {"name": "binsifter-winnow.deb", "browser_download_url": "https://dl/deb-2.0.8"},
        ],
    ),
    _release(
        "v2.0.9",
        "https://r/v2.0.9",
        [
            {"name": "binsifter-winnow.deb", "browser_download_url": "https://dl/deb-2.0.9"},
        ],
    ),
    _release("not-a-tag"),
]


@pytest.fixture(autouse=True)
def _fake_releases(monkeypatch):
    monkeypatch.setattr(uc, "_get_json", lambda url, timeout: _FAKE_RELEASES)


# ---------- tag/version parsing ----------

def test_parse_tag_requires_v_prefix():
    assert uc._parse_tag("v2.0.8") == (2, 0, 8)
    assert uc._parse_tag("2.0.8") is None
    assert uc._parse_tag("ingot-v0.1.0") is None
    assert uc._parse_tag("v2.0") is None


def test_parse_version_rejects_v_prefix():
    assert uc._parse_version("2.0.8") == (2, 0, 8)
    assert uc._parse_version("v2.0.8") is None
    assert uc._parse_version("2.0") is None


# ---------- check_for_update ----------

def test_reports_no_update_when_current_matches_latest_tag():
    result = uc.check_for_update("2.0.9")
    assert result.update_available is False
    assert result.latest_version == "2.0.9"


def test_reports_update_available_and_picks_the_max_not_first_in_list():
    result = uc.check_for_update("2.0.8")
    assert result.update_available is True
    assert result.latest_version == "2.0.9"
    assert result.release_url == "https://r/v2.0.9"
    assert result.assets[0]["name"] == "binsifter-winnow.deb"


def test_never_reports_ingots_tag_line_as_an_update():
    # if this ever regresses, Winnow's Update button would tell a user on
    # 2.0.9 that 0.5.0 (Ingot's line) is "available" - a downgrade
    result = uc.check_for_update("2.0.9")
    assert "0.5.0" not in result.latest_version


def test_current_version_ahead_of_every_tag_reports_no_update():
    result = uc.check_for_update("9.9.9")
    assert result.update_available is False


def test_no_matching_release_reports_no_update_instead_of_raising(monkeypatch):
    monkeypatch.setattr(uc, "_get_json", lambda url, timeout: [_release("ingot-v0.5.0")])
    result = uc.check_for_update("2.0.8")
    assert result.update_available is False
    assert result.latest_version == "2.0.8"


def test_network_failure_raises_update_check_error(monkeypatch):
    def _raise(*_a, **_k):
        raise OSError("no route to host")

    monkeypatch.setattr(uc, "_get_json", _raise)
    with pytest.raises(uc.UpdateCheckError):
        uc.check_for_update("2.0.8")


# ---------- install_command_for ----------

def test_install_command_for_each_manager():
    path = Path("/tmp/binsifter-winnow.deb")
    assert uc.install_command_for("deb", path) == f"sudo apt install {path}"
    assert uc.install_command_for("rpm", path) == f"sudo dnf install {path}"
    assert uc.install_command_for("pacman", path) == f"sudo pacman -U {path}"


# ---------- download_update_asset ----------

def test_download_update_asset_writes_the_matching_asset(monkeypatch, tmp_path):
    result = uc.check_for_update("2.0.8")

    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def read(self):
            return b"FAKE-DEB-BYTES"

    monkeypatch.setattr(uc.urllib.request, "urlopen", lambda *a, **k: _FakeResponse())
    monkeypatch.setattr(uc.Path, "home", staticmethod(lambda: tmp_path / "no-downloads-dir"))
    monkeypatch.setattr(uc, "get_binsifter_data_root", lambda: tmp_path)

    dest = uc.download_update_asset(result, "deb")
    assert dest == tmp_path / "binsifter-winnow.deb"
    assert dest.read_bytes() == b"FAKE-DEB-BYTES"


def test_download_update_asset_raises_for_missing_asset():
    result = uc.check_for_update("2.0.8")
    with pytest.raises(uc.UpdateCheckError):
        uc.download_update_asset(result, "pacman")  # only .deb was published in this fixture


def test_download_update_asset_raises_for_unknown_manager():
    result = uc.check_for_update("2.0.8")
    with pytest.raises(uc.UpdateCheckError):
        uc.download_update_asset(result, "not-a-real-manager")


# ---------- detect_package_manager / is_winnow_running ----------

def test_detect_package_manager_none_when_nothing_on_path(monkeypatch):
    monkeypatch.setattr(uc.shutil, "which", lambda _name: None)
    assert uc.detect_package_manager() is None


def test_detect_package_manager_picks_the_one_that_actually_owns_the_install(monkeypatch):
    monkeypatch.setattr(uc.shutil, "which", lambda name: f"/usr/bin/{name}")

    class _Result:
        def __init__(self, returncode):
            self.returncode = returncode

    def _run(cmd, **_kwargs):
        # only rpm "owns" this fake install, even though dpkg is also on PATH
        return _Result(0 if cmd[0] == "rpm" else 1)

    monkeypatch.setattr(uc.subprocess, "run", _run)
    assert uc.detect_package_manager() == "rpm"


def test_is_winnow_running_false_without_pgrep(monkeypatch):
    monkeypatch.setattr(uc.shutil, "which", lambda _name: None)
    assert uc.is_winnow_running() is False
