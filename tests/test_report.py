"""Regression tests for binsifter.core.report - the CSV report writer
ported from the C# CsvWriter class (BinSifter_v1.3.0-alpha.2.ps1, lines
~431-499). Pins down the exact column set/order and blank-if-default
formatting, since this is a user-facing file format, not an internal data
shape.
"""

import csv

from binsifter.core.models import FileRecord
from binsifter.core.report import COLUMNS, write_all_reports, write_report


def _read_rows(path):
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        return list(csv.reader(fh))


def test_column_header_matches_original_order_exactly():
    assert COLUMNS == [
        "FilePath", "SHA1", "MD5", "SSDEEP", "IsKnownGood", "YaraHitCount",
        "YaraMatches", "YaraSeverity", "YaraSeverityScore", "AttackTechniques",
        "CapaEligible", "PossibleFalseNegative", "CapaDetections", "Status",
        "Error", "Entropy", "CapaShellcodeFormat", "FlossStringCount",
        "SsdeepMatches", "SsdeepClusterId", "SsdeepClusterSize",
        "SsdeepHighSimilarity", "SsdeepPreviouslySeen", "PackerDetected",
        "Compiler", "Imphash", "RichHash", "ImphashClusterId",
        "ImphashClusterSize", "SignatureStatus", "SignerName", "IocCount",
        "ExtractedIOCs", "ReputationStatus", "ReputationSource", "Disposition",
    ]


def test_sentinel_defaults_render_blank_not_negative_one(tmp_path):
    record = FileRecord(Path="C:\\samples\\a.exe", SHA1="abc123")
    # Every -1/0-sentinel field at its default should render as "", not
    # "-1" or "0" - Entropy, FlossStringCount, SsdeepClusterId,
    # ImphashClusterId default to -1; SsdeepClusterSize/ImphashClusterSize/
    # IocCount default to 0.
    out_path = tmp_path / "full.csv"
    write_report(str(out_path), [record], mode="full")

    rows = _read_rows(out_path)
    header, row = rows[0], rows[1]
    as_dict = dict(zip(header, row))

    assert as_dict["Entropy"] == ""
    assert as_dict["FlossStringCount"] == ""
    assert as_dict["SsdeepClusterId"] == ""
    assert as_dict["SsdeepClusterSize"] == ""
    assert as_dict["ImphashClusterId"] == ""
    assert as_dict["ImphashClusterSize"] == ""
    assert as_dict["IocCount"] == ""
    assert as_dict["FilePath"] == "C:\\samples\\a.exe"
    assert as_dict["SHA1"] == "abc123"


def test_entropy_formatted_to_three_decimal_places(tmp_path):
    record = FileRecord(Path="a.exe", Entropy=7.123456)
    out_path = tmp_path / "full.csv"
    write_report(str(out_path), [record], mode="full")

    row = dict(zip(*_read_rows(out_path)))
    assert row["Entropy"] == "7.123"


def test_positive_cluster_ids_render_as_plain_numbers(tmp_path):
    record = FileRecord(
        Path="a.exe",
        SsdeepClusterId=3,
        SsdeepClusterSize=5,
        ImphashClusterId=1,
        ImphashClusterSize=2,
        IocCount=4,
        FlossStringCount=10,
    )
    out_path = tmp_path / "full.csv"
    write_report(str(out_path), [record], mode="full")
    row = dict(zip(*_read_rows(out_path)))

    assert row["SsdeepClusterId"] == "3"
    assert row["SsdeepClusterSize"] == "5"
    assert row["ImphashClusterId"] == "1"
    assert row["ImphashClusterSize"] == "2"
    assert row["IocCount"] == "4"
    assert row["FlossStringCount"] == "10"


def test_suspicious_mode_excludes_nsrl_known_good(tmp_path):
    known_good = FileRecord(Path="good.exe", NsrlMatch=True)
    unknown = FileRecord(Path="unknown.exe", NsrlMatch=False)
    out_path = tmp_path / "suspicious.csv"
    write_report(str(out_path), [known_good, unknown], mode="suspicious")

    rows = _read_rows(out_path)
    paths = [row[0] for row in rows[1:]]
    assert paths == ["unknown.exe"]


def test_yara_mode_excludes_zero_hits(tmp_path):
    hit = FileRecord(Path="hit.exe", YaraHitCount=2)
    no_hit = FileRecord(Path="clean.exe", YaraHitCount=0)
    out_path = tmp_path / "yara.csv"
    write_report(str(out_path), [hit, no_hit], mode="yara")

    rows = _read_rows(out_path)
    paths = [row[0] for row in rows[1:]]
    assert paths == ["hit.exe"]


def test_capa_mode_excludes_ineligible_files(tmp_path):
    eligible = FileRecord(Path="pe.exe", CapaEligible=True)
    ineligible = FileRecord(Path="other.bin", CapaEligible=False)
    out_path = tmp_path / "capa.csv"
    write_report(str(out_path), [eligible, ineligible], mode="capa")

    rows = _read_rows(out_path)
    paths = [row[0] for row in rows[1:]]
    assert paths == ["pe.exe"]


def test_fields_with_commas_are_quoted(tmp_path):
    record = FileRecord(Path="a.exe", YaraMatches="rule_a; rule_b", ExtractedIOCs="1.2.3.4, evil.com")
    out_path = tmp_path / "full.csv"
    write_report(str(out_path), [record], mode="full")

    raw_text = out_path.read_text(encoding="utf-8-sig")
    assert '"1.2.3.4, evil.com"' in raw_text
    # Round-trips correctly through a real CSV parser too.
    row = dict(zip(*_read_rows(out_path)))
    assert row["ExtractedIOCs"] == "1.2.3.4, evil.com"


def test_utf8_bom_present(tmp_path):
    record = FileRecord(Path="a.exe")
    out_path = tmp_path / "full.csv"
    write_report(str(out_path), [record], mode="full")

    raw_bytes = out_path.read_bytes()
    assert raw_bytes.startswith(b"\xef\xbb\xbf")


def test_write_all_reports_creates_four_files_with_timestamp(tmp_path):
    records = [
        FileRecord(Path="known.exe", NsrlMatch=True),
        FileRecord(Path="hit.exe", YaraHitCount=1, CapaEligible=True),
    ]
    paths = write_all_reports(records, str(tmp_path / "Reports"), timestamp="2026-07-30_120000")

    assert paths.full.endswith("BinSifter_Triage_2026-07-30_120000.csv")
    assert paths.suspicious.endswith("suspicious_unknown_2026-07-30_120000.csv")
    assert paths.yara_matches.endswith("yara_matches_2026-07-30_120000.csv")
    assert paths.capa_compatible.endswith("capa_compatible_2026-07-30_120000.csv")

    for p in (paths.full, paths.suspicious, paths.yara_matches, paths.capa_compatible):
        assert (tmp_path / "Reports").exists()
        rows = _read_rows(p)
        assert rows[0] == COLUMNS
