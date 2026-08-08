"""Regression tests for binsifter.core.ai_export - the Markdown/JSON export
used by Results' "Export for AI analysis" context-menu action. No Qt import
needed here (ai_export.py is intentionally Qt-free, like dashboard_stats.py),
so these run in any environment PySide6 tests would otherwise need a
display for.

Covers: empty/zero/False/-1 fields get dropped from the compact output
(the whole point - an export with 30 "None"/""/0 lines would be worse than
useless to hand to an AI), long fields get truncated, Markdown/JSON both
render sensibly for a sparse record AND a finding-rich one, and
export_file() actually writes both files with the right naming.
"""

import json

from binsifter.core import ai_export
from binsifter.core.models import FileRecord


def _rec(path: str = "C:\\Evidence\\test.exe", **kwargs) -> FileRecord:
    return FileRecord(Path=path, **kwargs)


def test_compact_record_drops_empty_zero_false_and_negative_one_sentinels():
    record = _rec()  # every field left at its FileRecord default
    compact = ai_export.compact_record(record)

    # Only the always-kept identity fields (plus Disposition, which is a
    # real state - "Untriaged" - not a "not computed" sentinel) should
    # survive a fully-default record.
    assert set(compact.keys()) == {"Path", "MD5", "SHA1", "Disposition"}
    assert compact["Path"] == record.Path
    assert compact["MD5"] is None
    assert compact["SHA1"] is None


def test_compact_record_drops_internal_bookkeeping_fields_even_when_set():
    record = _rec(Status="Completed", Progress=100, YaraHitCount=1)
    compact = ai_export.compact_record(record)

    assert "Status" not in compact
    assert "Progress" not in compact
    assert "Added" not in compact
    assert "SsdeepClusterId" not in compact
    assert "ImphashClusterId" not in compact
    assert compact["YaraHitCount"] == 1


def test_compact_record_keeps_meaningful_zero_free_findings():
    record = _rec(
        SHA1="aaa2",
        YaraHitCount=2,
        YaraMatches="Ransomware_Generic; Suspicious_PackerStub",
        SsdeepClusterSize=4,
        SsdeepHasHighSimilarity=True,
        Entropy=7.9,
        Disposition="Untriaged",  # default value, but should stay - it's
                                   # the real, meaningful default state, not
                                   # a "not computed" sentinel like -1 is.
    )
    compact = ai_export.compact_record(record)

    assert compact["YaraHitCount"] == 2
    assert compact["SsdeepClusterSize"] == 4
    assert compact["SsdeepHasHighSimilarity"] is True
    assert compact["Entropy"] == 7.9
    assert compact["Disposition"] == "Untriaged"


def test_compact_record_truncates_long_strings():
    long_output = "A" * 5000
    record = _rec(CAPAOutput=long_output)
    compact = ai_export.compact_record(record)

    assert len(compact["CAPAOutput"]) < len(long_output)
    assert compact["CAPAOutput"].startswith("A" * 100)
    assert "truncated" in compact["CAPAOutput"]
    assert "5000 chars total" in compact["CAPAOutput"]


def test_compact_record_does_not_truncate_short_strings():
    record = _rec(SignerName="Adobe Systems Incorporated")
    compact = ai_export.compact_record(record)
    assert compact["SignerName"] == "Adobe Systems Incorporated"


def test_build_json_has_meta_disclaimer_and_findings_block():
    record = _rec(YaraHitCount=1, YaraMatches="Some_Rule")
    payload = ai_export.build_json(record)

    assert payload["_meta"]["generated_by"] == "BinSifter"
    assert "no AI analysis has been run" in payload["_meta"]["note"]
    assert "generated_at" in payload["_meta"]
    assert payload["findings"]["YaraMatches"] == "Some_Rule"
    # Must round-trip through json.dumps cleanly - this is the whole point
    # of the export (something a script can feed straight to a local
    # model's API without extra serialization work).
    json.dumps(payload)


def test_build_markdown_sparse_record_stays_readable_and_short():
    record = _rec("C:\\Evidence\\clean_but_unsigned.exe")
    markdown = ai_export.build_markdown(record)

    assert "# BinSifter finding: clean_but_unsigned.exe" in markdown
    assert "C:\\Evidence\\clean_but_unsigned.exe" in markdown
    # No section headers should render for entirely-empty categories.
    assert "## YARA" not in markdown
    assert "## capa" not in markdown
    assert "no AI analysis has been run" in markdown


def test_build_markdown_rich_record_includes_every_populated_section():
    record = _rec(
        "C:\\Evidence\\suspicious.exe",
        MD5="bbb2", SHA1="aaa2", SSDEEP="3:abc:def",
        YaraHitCount=2, YaraMatches="Ransomware_Generic; Suspicious_PackerStub",
        YaraSeverity="High", YaraSeverityScore=85,
        YaraAttackTechniques="T1486 Data Encrypted for Impact [Impact]",
        CapaEligible=True, CapaDetectionCount=12, CAPAOutput="mock capa output",
        SsdeepClusterSize=4, SsdeepHasHighSimilarity=True,
        Imphash="deadbeef", ImphashClusterSize=2,
        SignatureStatus="NotSigned",
        IocCount=2, ExtractedIOCs="http://198.51.100.7/gate.php; C:\\Users\\Public\\note.txt",
        Entropy=7.9, PackerDetected="UPX",
        Disposition="Untriaged",
    )
    markdown = ai_export.build_markdown(record)

    assert "## Signature" in markdown
    assert "## YARA" in markdown
    assert "## capa" in markdown
    assert "### Raw capa output" in markdown
    assert "## Extracted IOCs (2)" in markdown
    assert "http://198.51.100.7/gate.php" in markdown
    assert "## Other" in markdown
    assert "UPX" in markdown


def test_export_file_writes_both_files_named_by_sha1(tmp_path):
    record = _rec("C:\\Evidence\\suspicious.exe", SHA1="aaa2", YaraHitCount=1)
    md_path, json_path = ai_export.export_file(record, tmp_path)

    assert md_path.name == "BinSifter_aaa2.md"
    assert json_path.name == "BinSifter_aaa2.json"
    assert md_path.is_file()
    assert json_path.is_file()
    assert "aaa2" in md_path.read_text(encoding="utf-8")
    json.loads(json_path.read_text(encoding="utf-8"))  # must be valid JSON


def test_export_file_falls_back_to_path_stem_when_sha1_missing(tmp_path):
    # A file that errored before hashing (SHA1 never computed) shouldn't
    # crash the export - same fallback naming _launch_ghidra() already uses.
    record = _rec("C:\\Evidence\\unreadable.exe", SHA1=None, Error="Permission denied")
    md_path, json_path = ai_export.export_file(record, tmp_path)

    assert md_path.name == "BinSifter_unreadable.md"
    assert json_path.name == "BinSifter_unreadable.json"
