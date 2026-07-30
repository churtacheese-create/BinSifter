"""Tests for binsifter.gui.capa_rules_listing - the pure-Python capa rules
directory scan (no Qt import, no display needed). Real tmp_path files."""

from binsifter.gui.capa_rules_listing import list_capa_rule_files


def test_blank_directory_returns_empty():
    assert list_capa_rule_files("") == []


def test_nonexistent_directory_returns_empty(tmp_path):
    assert list_capa_rule_files(str(tmp_path / "does-not-exist")) == []


def test_a_file_not_a_directory_returns_empty(tmp_path):
    f = tmp_path / "not_a_dir.txt"
    f.write_text("x")
    assert list_capa_rule_files(str(f)) == []


def test_empty_directory_returns_empty(tmp_path):
    assert list_capa_rule_files(str(tmp_path)) == []


def test_finds_yml_yaml_and_json_recursively_sorted(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "b.yml").write_text("rule: b")
    (tmp_path / "a.yaml").write_text("rule: a")
    (tmp_path / "sub" / "c.json").write_text("{}")
    (tmp_path / "ignored.txt").write_text("not a rule file")

    result = list_capa_rule_files(str(tmp_path))
    names = [p.split("/")[-1] for p in result]
    assert names == sorted(names)
    assert set(names) == {"a.yaml", "b.yml", "c.json"}


def test_suffix_matching_is_case_insensitive(tmp_path):
    (tmp_path / "upper.YML").write_text("x")
    result = list_capa_rule_files(str(tmp_path))
    assert len(result) == 1
    assert result[0].endswith("upper.YML")
