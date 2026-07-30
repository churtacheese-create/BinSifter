"""Tests for binsifter.gui.settings_validation - the pure-Python Settings-
Save validation logic (no Qt import, no display needed). Uses real
tmp_path files/directories, not mocks."""

from binsifter.gui.settings_validation import validate_settings


def _make_layout(tmp_path):
    """A directory tree with one of everything Settings needs: a source
    dir, an NSRL text file, a YARA rules file, a capa rules dir, a tools
    dir, and a separate report dir (write-tested but not itself a field)."""
    src_dir = tmp_path / "samples"
    src_dir.mkdir()
    nsrl_path = tmp_path / "nsrl.txt"
    nsrl_path.write_text("hash1\n")
    yara_rules = tmp_path / "rules.yar"
    yara_rules.write_text("rule dummy { condition: true }")
    capa_rules = tmp_path / "capa-rules"
    capa_rules.mkdir()
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    return {
        "src_dir": str(src_dir),
        "nsrl_path": str(nsrl_path),
        "yara_rules": str(yara_rules),
        "capa_rules": str(capa_rules),
        "tools_dir": str(tools_dir),
        "report_dir": str(report_dir),
    }


def test_valid_settings_with_blank_ghidra_dir_succeeds(tmp_path):
    paths = _make_layout(tmp_path)
    values = {
        "SrcDir": paths["src_dir"],
        "NsrlPath": paths["nsrl_path"],
        "YaraRules": paths["yara_rules"],
        "CapaRules": paths["capa_rules"],
        "ToolsDir": paths["tools_dir"],
        "GhidraDir": "",
    }
    result = validate_settings(values, paths["report_dir"])
    assert result.ok
    assert result.candidate["GhidraDir"] == ""
    assert result.candidate["SrcDir"] == str(__import__("pathlib").Path(paths["src_dir"]).resolve())


def test_valid_settings_with_real_ghidra_dir_succeeds(tmp_path):
    paths = _make_layout(tmp_path)
    ghidra_dir = tmp_path / "ghidra"
    ghidra_dir.mkdir()
    values = {
        "SrcDir": paths["src_dir"],
        "NsrlPath": paths["nsrl_path"],
        "YaraRules": paths["yara_rules"],
        "CapaRules": paths["capa_rules"],
        "ToolsDir": paths["tools_dir"],
        "GhidraDir": str(ghidra_dir),
    }
    result = validate_settings(values, paths["report_dir"])
    assert result.ok
    assert result.candidate["GhidraDir"] == str(ghidra_dir.resolve())


def test_missing_required_fields_lists_them_all(tmp_path):
    paths = _make_layout(tmp_path)
    values = {
        "SrcDir": "",
        "NsrlPath": paths["nsrl_path"],
        "YaraRules": "/does/not/exist.yar",
        "CapaRules": paths["capa_rules"],
        "ToolsDir": paths["tools_dir"],
        "GhidraDir": "",
    }
    result = validate_settings(values, paths["report_dir"])
    assert not result.ok
    assert "SrcDir" in result.error_message
    assert "YaraRules" in result.error_message


def test_wrong_path_type_is_invalid(tmp_path):
    """A file where a directory is expected (or vice versa) should be
    rejected, not silently accepted."""
    paths = _make_layout(tmp_path)
    values = {
        "SrcDir": paths["nsrl_path"],  # a file, not a directory
        "NsrlPath": paths["src_dir"],  # a directory, not a file
        "YaraRules": paths["yara_rules"],
        "CapaRules": paths["capa_rules"],
        "ToolsDir": paths["tools_dir"],
        "GhidraDir": "",
    }
    result = validate_settings(values, paths["report_dir"])
    assert not result.ok
    assert "SrcDir" in result.error_message
    assert "NsrlPath" in result.error_message


def test_nonexistent_ghidra_dir_is_invalid_but_others_still_checked(tmp_path):
    paths = _make_layout(tmp_path)
    values = {
        "SrcDir": paths["src_dir"],
        "NsrlPath": paths["nsrl_path"],
        "YaraRules": paths["yara_rules"],
        "CapaRules": paths["capa_rules"],
        "ToolsDir": paths["tools_dir"],
        "GhidraDir": "/does/not/exist",
    }
    result = validate_settings(values, paths["report_dir"])
    assert not result.ok
    assert "GhidraDir" in result.error_message


def test_unwritable_report_directory_blocks_save_even_with_valid_fields(tmp_path, monkeypatch):
    paths = _make_layout(tmp_path)
    values = {
        "SrcDir": paths["src_dir"],
        "NsrlPath": paths["nsrl_path"],
        "YaraRules": paths["yara_rules"],
        "CapaRules": paths["capa_rules"],
        "ToolsDir": paths["tools_dir"],
        "GhidraDir": "",
    }

    from pathlib import Path

    def boom(self, *args, **kwargs):
        raise OSError("disk full (simulated)")

    monkeypatch.setattr(Path, "write_text", boom)

    result = validate_settings(values, paths["report_dir"])
    assert not result.ok
    assert "not writable" in result.error_message


def test_write_succeeding_but_cleanup_failing_still_passes(tmp_path, monkeypatch):
    """Caught for real against this port's sandboxed mount: a directory that
    allows creating a file but not deleting it (Errno 1, Operation not
    permitted, on unlink specifically) must NOT be reported as unwritable -
    only the write itself gates Save, matching the PowerShell version's
    Remove-Item -ErrorAction SilentlyContinue sitting outside its own
    try/catch. Without this, a real, legitimately-writable report directory
    would incorrectly block every Settings save on a filesystem with this
    quirk."""
    paths = _make_layout(tmp_path)
    values = {
        "SrcDir": paths["src_dir"],
        "NsrlPath": paths["nsrl_path"],
        "YaraRules": paths["yara_rules"],
        "CapaRules": paths["capa_rules"],
        "ToolsDir": paths["tools_dir"],
        "GhidraDir": "",
    }

    from pathlib import Path

    def boom(self, *args, **kwargs):
        raise OSError("Operation not permitted (simulated delete failure)")

    monkeypatch.setattr(Path, "unlink", boom)

    result = validate_settings(values, paths["report_dir"])
    assert result.ok
