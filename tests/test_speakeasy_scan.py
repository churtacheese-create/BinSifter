"""Regression tests for binsifter.core.speakeasy_scan.

_summarize()/_format_dns()/_format_traffic() are tested against synthetic
report dicts shaped exactly like the real speakeasy 1.5.11 output (verified
directly against the installed library's profiler.py and a real emulation
run against smoketest/samples/calc.exe during development - see the module
docstring) - not against speakeasy's own guessed-wrong-in-the-PowerShell-
version field names. No committed PE fixture is used for the success path
(smoketest/samples/ is real-world binaries, gitignored, not reproducible in
every environment); emulate_file()'s error path is exercised directly
against real bad input instead, which needs no fixture at all.
"""

from binsifter.core.speakeasy_scan import (
    SpeakeasyResult,
    _format_dns,
    _format_traffic,
    _load_config,
    _summarize,
    emulate_file,
)


def test_emulate_file_missing_target_degrades_to_error(tmp_path):
    missing = tmp_path / "does_not_exist.exe"
    result = emulate_file(str(missing))
    assert result.error is not None
    assert result.api_call_count == 0
    assert result.file_operation_count == 0
    assert result.network_indicators == []


def test_emulate_file_non_pe_degrades_to_error(tmp_path):
    garbage = tmp_path / "not_a_pe.bin"
    garbage.write_bytes(b"this is definitely not a PE file")
    result = emulate_file(str(garbage))
    assert result.error is not None
    assert isinstance(result, SpeakeasyResult)


def test_load_config_overrides_timeout_and_scales_max_api_count():
    cfg = _load_config()
    assert cfg["timeout"] == 120
    assert cfg["max_api_count"] == 120 * 500


def test_summarize_empty_entry_points_list():
    result = _summarize({"entry_points": []})
    assert result.api_call_count == 0
    assert result.file_operation_count == 0
    assert result.network_indicators == []
    assert result.raw_report == {"entry_points": []}


def test_summarize_counts_apis_and_file_access_across_entry_points():
    report = {
        "entry_points": [
            {"apis": [{"api_name": "a"}, {"api_name": "b"}], "file_access": [{"path": "x"}]},
            {"apis": [{"api_name": "c"}]},  # no file_access key at all - must not KeyError
        ]
    }
    result = _summarize(report)
    assert result.api_call_count == 3
    assert result.file_operation_count == 1


def test_summarize_missing_optional_keys_does_not_raise():
    # Real speakeasy only adds network_events/file_access/registry_access/
    # process_events/dropped_files when non-empty - an entry point with
    # only "apis" must be handled cleanly.
    report = {"entry_points": [{"apis": []}]}
    result = _summarize(report)
    assert result.api_call_count == 0
    assert result.network_indicators == []


def test_summarize_dns_and_traffic_produce_readable_indicators():
    report = {
        "entry_points": [
            {
                "apis": [],
                "network_events": {
                    "dns": [{"query": "evil.example.com", "response": "203.0.113.5"}],
                    "traffic": [{"server": "203.0.113.5", "port": 443, "proto": "tcp.https"}],
                },
            }
        ]
    }
    result = _summarize(report)
    assert "evil.example.com -> 203.0.113.5" in result.network_indicators
    assert "203.0.113.5:443 (tcp.https)" in result.network_indicators


def test_summarize_dedupes_network_indicators_across_entry_points():
    dup_dns = {"query": "evil.example.com", "response": "203.0.113.5"}
    report = {
        "entry_points": [
            {"apis": [], "network_events": {"dns": [dup_dns], "traffic": []}},
            {"apis": [], "network_events": {"dns": [dup_dns], "traffic": []}},
        ]
    }
    result = _summarize(report)
    assert result.network_indicators.count("evil.example.com -> 203.0.113.5") == 1


def test_format_dns_without_response_omits_arrow():
    assert _format_dns({"query": "example.com", "response": ""}) == "example.com"
    assert _format_dns({"query": "", "response": "1.2.3.4"}) == ""


def test_format_traffic_without_port_or_proto():
    assert _format_traffic({"server": "1.2.3.4"}) == "1.2.3.4"
    assert _format_traffic({"server": "1.2.3.4", "proto": "tcp.http"}) == "1.2.3.4 (tcp.http)"
    assert _format_traffic({"server": "1.2.3.4", "port": 80}) == "1.2.3.4:80"
    assert _format_traffic({}) == ""
