"""Tests for binsifter.core.disposition - the SHA1|Disposition history file
that lets analyst triage calls survive a re-scan. Uses real tmp_path files,
not mocks, since this is just file I/O."""

from binsifter.core.disposition import load_disposition_history, save_disposition_entry


def test_load_missing_file_returns_empty(tmp_path):
    assert load_disposition_history(str(tmp_path)) == {}


def test_load_blank_report_directory_returns_empty():
    assert load_disposition_history("") == {}


def test_save_then_load_round_trip(tmp_path):
    save_disposition_entry(str(tmp_path), "AABBCC", "Escalated")
    history = load_disposition_history(str(tmp_path))
    assert history == {"aabbcc": "Escalated"}


def test_save_overwrites_existing_entry_case_insensitively(tmp_path):
    save_disposition_entry(str(tmp_path), "aabbcc", "Suspicious")
    save_disposition_entry(str(tmp_path), "AABBCC", "Escalated")
    history = load_disposition_history(str(tmp_path))
    assert history == {"aabbcc": "Escalated"}  # one entry, not two


def test_save_preserves_other_entries(tmp_path):
    save_disposition_entry(str(tmp_path), "sha1one", "Benign")
    save_disposition_entry(str(tmp_path), "sha1two", "Escalated")
    history = load_disposition_history(str(tmp_path))
    assert history == {"sha1one": "Benign", "sha1two": "Escalated"}


def test_save_blank_sha1_or_directory_is_a_no_op(tmp_path):
    save_disposition_entry(str(tmp_path), "", "Escalated")
    save_disposition_entry("", "sha1", "Escalated")
    save_disposition_entry(str(tmp_path / "does-not-exist"), "sha1", "Escalated")
    assert load_disposition_history(str(tmp_path)) == {}


def test_load_skips_blank_lines_and_malformed_entries(tmp_path):
    history_file = tmp_path / ".bsifter-disposition-history.txt"
    history_file.write_text("sha1one|Benign\n\nmalformed-line-no-pipe\nsha1two|Escalated\n", encoding="utf-8")
    history = load_disposition_history(str(tmp_path))
    assert history == {"sha1one": "Benign", "sha1two": "Escalated"}
