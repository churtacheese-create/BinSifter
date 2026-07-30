"""Locks in the severity-bucketing logic ported from the PowerShell
version's SeverityScorer class - the exact thresholds/priority order
matter (dashboard severity bars key off these bucket names), so these are
regression tests, not just smoke tests.
"""

from binsifter.core.yara_scan import _resolve_severity


def test_score_field_takes_priority_and_buckets_correctly():
    assert _resolve_severity({"score": "95"}) == ("Critical", 95)
    assert _resolve_severity({"score": "70"}) == ("High", 70)
    assert _resolve_severity({"score": "40"}) == ("Medium", 40)
    assert _resolve_severity({"score": "1"}) == ("Low", 1)
    assert _resolve_severity({"score": "0"}) == ("Unknown", 0)


def test_tc_detection_factor_scaled_by_20():
    # factor 5 -> scaled 100 -> Critical
    assert _resolve_severity({"tc_detection_factor": "5"}) == ("Critical", 100)
    # factor 2 -> scaled 40 -> Medium
    assert _resolve_severity({"tc_detection_factor": "2"}) == ("Medium", 40)


def test_severity_word_fallback_when_no_numeric_field():
    assert _resolve_severity({"severity": "high"}) == ("High", -1)
    assert _resolve_severity({"tc_policy_severity": "severe"}) == ("Critical", -1)
    assert _resolve_severity({"importance": "moderate"}) == ("Medium", -1)


def test_score_field_takes_priority_over_word():
    # A rule author who sets both should get the numeric field's answer,
    # not the word - matches the priority order in the original C#.
    assert _resolve_severity({"score": "10", "severity": "critical"}) == ("Low", 10)


def test_unrecognized_or_missing_meta_is_unknown_not_guessed():
    assert _resolve_severity({}) == ("Unknown", -1)
    assert _resolve_severity({"severity": "not-a-real-word"}) == ("Unknown", -1)
