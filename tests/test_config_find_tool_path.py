"""Tests for binsifter.core.config's find_tool_path() - specifically the
2026-09-02 PATH-fallback addition (see that function's docstring for the
angr/pipx/AppImage rationale). Uses monkeypatch on shutil.which() rather
than depending on any tool actually being installed on the machine running
the tests - the point is to exercise find_tool_path()'s own fallback logic,
not to require angr/rizin/etc. actually be present in CI.
"""

from __future__ import annotations

from pathlib import Path

from binsifter.core.config import find_tool_path


def test_finds_file_under_directory_without_touching_path(tmp_path, monkeypatch):
    """Directory hit should win without ever consulting PATH."""
    tool = tmp_path / "rizin"
    tool.write_text("#!/bin/sh\n")

    def _fail_if_called(_name):
        raise AssertionError("shutil.which() should not be called when the directory search already hit")

    monkeypatch.setattr("binsifter.core.config.shutil.which", _fail_if_called)
    assert find_tool_path(tmp_path, ("rizin",)) == str(tool)


def test_falls_back_to_path_when_not_under_directory(tmp_path, monkeypatch):
    """A tool absent from `directory` but present on PATH should still resolve."""
    fake_path_binary = "/usr/local/bin/angr"
    monkeypatch.setattr(
        "binsifter.core.config.shutil.which",
        lambda name: fake_path_binary if name == "angr" else None,
    )
    assert find_tool_path(tmp_path, ("angr",)) == fake_path_binary


def test_falls_back_to_path_when_directory_is_none():
    """No ToolsDir configured at all should skip straight to PATH, not return ''
    the way the pre-2026-09-02 behavior did."""
    import shutil

    real_which = shutil.which("ls")
    assert real_which  # sanity check the test environment actually has `ls`
    assert find_tool_path(None, ("ls",)) == real_which


def test_returns_empty_string_when_nothing_found_anywhere(tmp_path, monkeypatch):
    monkeypatch.setattr("binsifter.core.config.shutil.which", lambda name: None)
    assert find_tool_path(tmp_path, ("definitely-not-a-real-tool-xyz",)) == ""


def test_path_hit_on_first_candidate_wins_over_directory_hit_on_second(tmp_path, monkeypatch):
    """Each candidate is checked directory-then-PATH before moving on to the
    next candidate - so a PATH hit on the first candidate ("diec") returns
    immediately, even though the second candidate ("die") exists under
    `directory`. Confirms the search isn't directory-for-all-candidates
    followed by PATH-for-all-candidates."""
    second_candidate_tool = tmp_path / "die"
    second_candidate_tool.write_text("#!/bin/sh\n")
    monkeypatch.setattr(
        "binsifter.core.config.shutil.which",
        lambda name: "/usr/bin/diec" if name == "diec" else None,
    )
    assert find_tool_path(tmp_path, ("diec", "die")) == "/usr/bin/diec"
