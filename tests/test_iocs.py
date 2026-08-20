"""Regression tests for binsifter.core.iocs - the regex-based IOC mining
ported from BinSifter-Rowan.ps1's v1.3-proto1 IOC extraction step.
Pins down the exact patterns/dedup/cap behavior so this stays a faithful
port, not an "improved" reimplementation - see iocs.py's own docstring for
why some of these quirks (case sensitivity in particular) are intentional.
"""

from binsifter.core.iocs import extract_iocs


def test_no_strings_returns_empty_result():
    result = extract_iocs([])
    assert result.count == 0
    assert result.display == ""


def test_ip_address_extracted():
    result = extract_iocs(["connecting to 203.0.113.42 now"])
    assert result.count == 1
    assert result.display == "203.0.113.42"


def test_url_extracted():
    # The domain regex runs independently over the same string (matching
    # the PowerShell version's behavior of applying all four regexes to
    # every string with no overlap-awareness), so a URL containing a
    # matchable hostname legitimately yields two IOCs here: the full URL
    # and the embedded domain.
    result = extract_iocs(['payload from https://evil.example.com/drop.exe"'])
    assert result.count == 2
    assert "https://evil.example.com/drop.exe" in result.display
    assert "evil.example.com" in result.display


def test_domain_extracted_and_lowercased():
    # Domain matches are explicitly lowercased before dedup/display, same
    # as the PowerShell version's $m.Value.ToLowerInvariant() - but the
    # domain regex itself only matches lowercase input to begin with (see
    # next test), so this exercises a lowercase domain staying lowercase.
    result = extract_iocs(["beacon.evil-domain.xyz"])
    assert result.count == 1
    assert result.display == "beacon.evil-domain.xyz"


def test_uppercase_domain_not_matched_matching_original_quirk():
    # The PowerShell domain regex has no IgnoreCase option and uses [a-z0-9]
    # character classes, so it only ever matches all-lowercase domains -
    # this is a known quirk of the original being ported faithfully, not a
    # bug introduced here. See iocs.py's module docstring.
    result = extract_iocs(["BEACON.EVIL-DOMAIN.XYZ"])
    assert result.count == 0


def test_registry_path_extracted():
    result = extract_iocs([r"persists at HKEY_CURRENT_USER\Software\Evil\Run"])
    assert result.count == 1
    assert result.display == r"HKEY_CURRENT_USER\Software\Evil\Run"


def test_multiple_categories_across_multiple_strings():
    # 4 distinct IOCs: the IP, the URL, its embedded domain (matched
    # separately - see test_url_extracted), and the registry path.
    strings = [
        "reaches out to 198.51.100.7",
        "and http://c2.example.net/beacon",
        "writes HKEY_LOCAL_MACHINE\\Software\\Malware",
    ]
    result = extract_iocs(strings)
    assert result.count == 4


def test_case_insensitive_dedup_keeps_first_seen_casing():
    # Same IP twice - not case-sensitive in the literal sense (IPs have no
    # letters here), but registry paths do, and OrdinalIgnoreCase dedup
    # should collapse two case-variant matches of the "same" value into
    # one entry, keeping the first-seen casing (matches a real .NET
    # HashSet<T>'s behavior: Add() on an existing-ignoring-case value is a
    # no-op, it doesn't overwrite the stored instance).
    strings = [
        r"HKEY_LOCAL_MACHINE\Software\Evil\run",
        r"HKEY_LOCAL_MACHINE\Software\Evil\RUN",
    ]
    result = extract_iocs(strings)
    assert result.count == 1
    assert result.display == r"HKEY_LOCAL_MACHINE\Software\Evil\run"


def test_display_capped_at_fifty_entries():
    # Original caps the CSV column at 50 entries so a pathological string
    # blob can't balloon a report row - see the PowerShell comment at
    # line 2364.
    strings = [f"10.0.0.{i}" for i in range(1, 61)]  # 60 distinct IPs
    result = extract_iocs(strings)
    assert result.count == 60
    assert len(result.display.split("; ")) == 50


def test_non_ioc_strings_produce_no_matches():
    result = extract_iocs(["just a normal debug string", "another one", ""])
    assert result.count == 0
    assert result.display == ""
