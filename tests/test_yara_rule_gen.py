"""Regression tests for binsifter.core.yara_rule_gen - the draft-YARA-
rule-per-SSDEEP-cluster generator ported from BinSifter-Rowan.ps1
(lines ~3225-3320).
"""

from binsifter.core.models import FileRecord
from binsifter.core.yara_rule_gen import generate_draft_rules


def _make_member(tmp_path, name: str, content: bytes) -> FileRecord:
    p = tmp_path / name
    p.write_bytes(content)
    return FileRecord(Path=str(p))


def test_cluster_with_shared_strings_generates_rule(tmp_path):
    member_a = _make_member(tmp_path, "a.exe", b"A" * 1000)
    member_b = _make_member(tmp_path, "b.exe", b"B" * 1200)

    static_strings = {
        member_a.Path: ["shared_marker_string_1234", "only_in_a_but_long_enough"],
        member_b.Path: ["shared_marker_string_1234", "only_in_b_but_long_enough"],
    }

    result = generate_draft_rules(
        {0: [member_a, member_b]},
        static_strings,
        str(tmp_path / "reports"),
        ssdeep_cluster_threshold=40,
        timestamp="2026-07-30_120000",
    )

    assert result.rules_written == 1
    rule_files = list((tmp_path / "reports" / "generated_rules").glob("*.yar"))
    assert len(rule_files) == 1

    text = rule_files[0].read_text(encoding="utf-8")
    assert "shared_marker_string_1234" in text
    assert "only_in_a_but_long_enough" not in text  # not common to both members
    assert "(3 of them)" in text
    assert "filesize >=" in text
    assert "AUTO-GENERATED DRAFT" in text


def test_cluster_with_no_floss_data_falls_back_to_skeleton(tmp_path):
    member_a = _make_member(tmp_path, "a.exe", b"A" * 500)
    member_b = _make_member(tmp_path, "b.exe", b"B" * 600)

    result = generate_draft_rules(
        {0: [member_a, member_b]},
        {},  # no FLOSS data for either member
        str(tmp_path / "reports"),
        ssdeep_cluster_threshold=40,
        timestamp="2026-07-30_120000",
    )

    assert result.rules_written == 1
    rule_text = next((tmp_path / "reports" / "generated_rules").glob("*.yar")).read_text()
    assert "TODO: no common strings found" in rule_text
    assert "strings:" not in rule_text
    assert "filesize >=" in rule_text


def test_single_contributing_member_produces_no_common_strings(tmp_path):
    # Only one cluster member has FLOSS data - nothing to intersect against,
    # same as the PowerShell version needing 2+ HashSets to IntersectWith.
    member_a = _make_member(tmp_path, "a.exe", b"A" * 500)
    member_b = _make_member(tmp_path, "b.exe", b"B" * 600)

    result = generate_draft_rules(
        {0: [member_a, member_b]},
        {member_a.Path: ["a_long_enough_string_value"]},
        str(tmp_path / "reports"),
        ssdeep_cluster_threshold=40,
        timestamp="2026-07-30_120000",
    )

    assert result.rules_written == 1
    rule_text = next((tmp_path / "reports" / "generated_rules").glob("*.yar")).read_text()
    assert "TODO: no common strings found" in rule_text


def test_string_length_filter_excludes_too_short_and_too_long(tmp_path):
    member_a = _make_member(tmp_path, "a.exe", b"A" * 500)
    member_b = _make_member(tmp_path, "b.exe", b"B" * 600)

    too_short = "short"  # < 8 chars
    too_long = "x" * 129  # > 128 chars
    just_right = "just_right_length_string"

    static_strings = {
        member_a.Path: [too_short, too_long, just_right],
        member_b.Path: [too_short, too_long, just_right],
    }

    result = generate_draft_rules(
        {0: [member_a, member_b]},
        static_strings,
        str(tmp_path / "reports"),
        ssdeep_cluster_threshold=40,
        timestamp="2026-07-30_120000",
    )

    rule_text = next((tmp_path / "reports" / "generated_rules").glob("*.yar")).read_text()
    assert "just_right_length_string" in rule_text
    assert too_short not in rule_text
    assert too_long not in rule_text


def test_common_strings_capped_at_twelve(tmp_path):
    member_a = _make_member(tmp_path, "a.exe", b"A" * 500)
    member_b = _make_member(tmp_path, "b.exe", b"B" * 600)

    shared = [f"shared_string_number_{i:02d}" for i in range(20)]
    static_strings = {member_a.Path: shared, member_b.Path: shared}

    result = generate_draft_rules(
        {0: [member_a, member_b]},
        static_strings,
        str(tmp_path / "reports"),
        ssdeep_cluster_threshold=40,
        timestamp="2026-07-30_120000",
    )

    rule_text = next((tmp_path / "reports" / "generated_rules").glob("*.yar")).read_text()
    assert rule_text.count("$s") == 12
    assert "Common-string basis: 12 string(s)" in rule_text


def test_cluster_below_min_size_skipped(tmp_path):
    member_a = _make_member(tmp_path, "a.exe", b"A" * 500)

    result = generate_draft_rules(
        {0: [member_a]},  # single-member "cluster" - shouldn't happen upstream, defensive check
        {},
        str(tmp_path / "reports"),
        ssdeep_cluster_threshold=40,
        timestamp="2026-07-30_120000",
    )

    assert result.rules_written == 0


def test_rule_name_sanitized_and_stable(tmp_path):
    member_a = _make_member(tmp_path, "a.exe", b"A" * 500)
    member_b = _make_member(tmp_path, "b.exe", b"B" * 600)

    result = generate_draft_rules(
        {0: [member_a, member_b]},
        {},
        str(tmp_path / "reports"),
        ssdeep_cluster_threshold=40,
        timestamp="2026-07-30_120000",
    )

    rule_files = list((tmp_path / "reports" / "generated_rules").glob("*.yar"))
    # Hyphens in the timestamp aren't in [a-zA-Z0-9_], so the sanitizer
    # (matching the PowerShell version's `-replace '[^a-zA-Z0-9_]', '_'`)
    # replaces them too - not just characters that would be unsafe in a
    # filename.
    assert rule_files[0].name == "bsifter_ssdeep_cluster_0_2026_07_30_120000.yar"


def test_escapes_backslash_and_quote_in_strings(tmp_path):
    member_a = _make_member(tmp_path, "a.exe", b"A" * 500)
    member_b = _make_member(tmp_path, "b.exe", b"B" * 600)

    tricky = r'C:\Windows\System32 "quoted"'
    static_strings = {member_a.Path: [tricky], member_b.Path: [tricky]}

    result = generate_draft_rules(
        {0: [member_a, member_b]},
        static_strings,
        str(tmp_path / "reports"),
        ssdeep_cluster_threshold=40,
        timestamp="2026-07-30_120000",
    )
    assert result.rules_written == 1
    rule_text = next((tmp_path / "reports" / "generated_rules").glob("*.yar")).read_text()
    assert r'C:\\Windows\\System32 \"quoted\"' in rule_text
