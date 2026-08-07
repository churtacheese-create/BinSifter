"""Regression tests for binsifter.gui.dashboard_stats - the aggregate
Dashboard metrics ported from the PowerShell version's UiTotals/SsdeepMetrics
computation. No Qt import needed here (dashboard_stats.py is intentionally
Qt-free), so these run in any environment PySide6 tests would otherwise
need a display for.
"""

from binsifter.core.models import FileRecord
from binsifter.gui.dashboard_stats import DashboardStats


def _rec(path: str, **kwargs) -> FileRecord:
    return FileRecord(Path=path, **kwargs)


def test_empty_records_all_zero():
    stats = DashboardStats.from_records([])
    assert stats.completed_count == 0
    assert stats.heat_denominator == 1  # max(1, 0)


def test_completed_count_only_counts_completed_status():
    records = [
        _rec("a", Status="Completed"),
        _rec("b", Status="Completed"),
        _rec("c", Status="Error"),
    ]
    stats = DashboardStats.from_records(records)
    assert stats.completed_count == 2


def test_yara_hits_and_capa_sum_not_count():
    records = [
        _rec("a", YaraHitCount=3, CapaDetectionCount=2),
        _rec("b", YaraHitCount=1, CapaDetectionCount=5),
    ]
    stats = DashboardStats.from_records(records)
    assert stats.yara_hits == 4
    assert stats.capa_hits == 7


def test_capa_scans_and_nsrl_matches_count_booleans():
    records = [
        _rec("a", CapaEligible=True, NsrlMatch=True),
        _rec("b", CapaEligible=True, NsrlMatch=False),
        _rec("c", CapaEligible=False, NsrlMatch=True),
    ]
    stats = DashboardStats.from_records(records)
    assert stats.capa_scans == 2
    assert stats.nsrl_matches == 2


def test_signed_only_counts_valid_status():
    # 2026-08-06: went "Unsigned" (one tile) -> "Not Signed"/"Not
    # Verifiable" (two tiles) -> back to one tile reporting the positive
    # "Signed" count instead. Every other status (empty,
    # NotSigned, NotTrusted, HashMismatch, NotSupportedFileFormat,
    # UnknownError) is implicitly "not signed or not verified" and doesn't
    # get counted here.
    records = [
        _rec("a", SignatureStatus="Valid"),
        _rec("b", SignatureStatus="Valid"),
        _rec("c", SignatureStatus=""),
        _rec("d", SignatureStatus="NotSigned"),
        _rec("e", SignatureStatus="NotTrusted"),
        _rec("f", SignatureStatus="UnknownError"),
        _rec("g", SignatureStatus="NotSupportedFileFormat"),
        _rec("h", SignatureStatus="HashMismatch"),
    ]
    stats = DashboardStats.from_records(records)
    assert stats.signed == 2


def test_known_bad_with_iocs_escalated_imphash_clustered():
    records = [
        _rec("a", ReputationStatus="KnownBad"),
        _rec("b", ReputationStatus="Clean"),
        _rec("c", IocCount=2),
        _rec("d", IocCount=0),
        _rec("e", Disposition="Escalated"),
        _rec("f", Disposition="Untriaged"),
        _rec("g", ImphashClusterId=0, ImphashClusterSize=3),
        _rec("h", ImphashClusterId=-1, ImphashClusterSize=0),
    ]
    stats = DashboardStats.from_records(records)
    assert stats.known_bad == 1
    assert stats.with_iocs == 1
    assert stats.escalated == 1
    assert stats.imphash_clustered == 1


def test_severity_bucketed_only_for_files_with_yara_hits():
    records = [
        _rec("a", YaraHitCount=1, YaraSeverity="Critical"),
        _rec("b", YaraHitCount=2, YaraSeverity="Medium"),
        _rec("c", YaraHitCount=0, YaraSeverity="Critical"),  # no hit -> not bucketed
        _rec("d", YaraHitCount=1, YaraSeverity="Bogus"),  # unrecognized -> Unknown
    ]
    stats = DashboardStats.from_records(records)
    assert stats.severity == {"Critical": 1, "High": 0, "Medium": 1, "Low": 0, "Unknown": 1}


def test_ssdeep_cluster_metrics():
    records = [
        _rec("a", SSDEEP="s1", SsdeepClusterId=0, SsdeepClusterSize=3, SsdeepHasHighSimilarity=True, SsdeepMatches="b (90); c (85)"),
        _rec("b", SSDEEP="s2", SsdeepClusterId=0, SsdeepClusterSize=3, SsdeepHasHighSimilarity=True, SsdeepMatches="a (90)"),
        _rec("c", SSDEEP="s3", SsdeepClusterId=0, SsdeepClusterSize=3, SsdeepMatches="a (85)"),
        _rec("d", SSDEEP="s4", SsdeepClusterId=1, SsdeepClusterSize=1),  # singleton
        _rec("e", SSDEEP=None, SsdeepClusterId=-1, SsdeepClusterSize=0),  # never hashed
    ]
    stats = DashboardStats.from_records(records)
    assert stats.total_hashed_files == 4  # e has no SSDEEP
    assert stats.num_clusters == 1  # only cluster 0 has size >= 2
    assert stats.largest_cluster_size == 3
    assert stats.singletons == 1
    assert stats.files_above_85 == 2
    assert stats.avg_score == 87.5  # avg of 90, 85, 90, 85 (each pair counted from both sides)
    assert stats.heat_denominator == 4
    assert stats.largest_cluster_id == 0


def test_largest_cluster_id_ties_go_to_first_encountered():
    # Cluster 1 and cluster 0 both end up size 2, but cluster 0's first
    # member is seen earlier in the records list - it should win the tie,
    # matching the PowerShell version's strictly-greater-than comparison
    # over Dictionary enumeration (insertion) order, not "whichever cluster
    # id happens to be numerically smallest" or similar.
    records = [
        _rec("a", SSDEEP="s1", SsdeepClusterId=1, SsdeepClusterSize=2),
        _rec("b", SSDEEP="s2", SsdeepClusterId=0, SsdeepClusterSize=2),
        _rec("c", SSDEEP="s3", SsdeepClusterId=1, SsdeepClusterSize=2),
        _rec("d", SSDEEP="s4", SsdeepClusterId=0, SsdeepClusterSize=2),
    ]
    stats = DashboardStats.from_records(records)
    assert stats.largest_cluster_id == 1  # cluster 1's member ("a") appears first


def test_largest_cluster_id_is_negative_one_when_no_real_cluster_exists():
    records = [_rec("a", SSDEEP="s1", SsdeepClusterId=-1, SsdeepClusterSize=0)]
    stats = DashboardStats.from_records(records)
    assert stats.largest_cluster_id == -1
    assert stats.largest_cluster_size == 0


def test_previously_seen_clusters_counts_distinct_clusters_not_files():
    records = [
        _rec("a", SsdeepClusterId=0, SsdeepClusterSize=2, SsdeepPreviouslySeen=True),
        _rec("b", SsdeepClusterId=0, SsdeepClusterSize=2, SsdeepPreviouslySeen=False),
        _rec("c", SsdeepClusterId=1, SsdeepClusterSize=2, SsdeepPreviouslySeen=False),
    ]
    stats = DashboardStats.from_records(records)
    # Cluster 0 counts once even though only one of its two members is
    # individually flagged - matches the original counting clusters, not
    # member files.
    assert stats.previously_seen_clusters == 1


def test_no_ssdeep_matches_gives_zero_avg_score_not_error():
    records = [_rec("a", SSDEEP="s1", SsdeepClusterSize=1)]
    stats = DashboardStats.from_records(records)
    assert stats.avg_score == 0.0
