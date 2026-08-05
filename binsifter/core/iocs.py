"""IOC extraction from FLOSS string output - regex-mined IP addresses,
URLs, domains, and registry paths.

Direct port of BinSifter-Rowan_v1.3.0-beta.1.ps1, lines ~2329-2365 (the
v1.3-proto1 IOC mining step) - same four regexes, same case-insensitive
dedup, same 50-item display cap, since this is exactly the kind of "match
the original precisely" logic per project convention (see file_type.py's
docstring for the same rationale).

Deliberately NOT "improved" versus the original even where the original's
regexes have quirks:
  - None of the four patterns carry an IgnoreCase option in the PowerShell
    version ($ipRegex/$urlRegex/$domainRegex/$regRegex are all plain
    [regex] literals with no RegexOptions), so matching is case-sensitive
    exactly as written there. In particular the domain pattern's character
    classes are all lowercase ([a-z0-9]), so it only matches all-lowercase
    domains - an UPPERCASE.COM string in a binary would not be flagged.
    This looks like it could be an oversight in the original, but silently
    "fixing" it here would make this port's output diverge from the
    PowerShell version's for the exact same input file, which is worse for
    side-by-side verification than reproducing a known quirk. Flag it to
    Steve before changing it.
  - Similarly, the URL pattern only matches a lowercase "http"/"https"
    scheme literally (no case-insensitivity), so "HTTPS://..." strings
    aren't matched either. Same reasoning - ported as-is.

Runs on the same FLOSS strings already extracted for PossibleFalseNegative
files (see floss_scan.py) - never triggers a second/separate FLOSS
invocation. Best-effort: mirrors the PowerShell version's inner try/catch
around this step (a bad string or regex edge case must never fail the
file's scan) - callers should not need their own try/except around this,
extract_iocs() itself never raises.

Caveat not present in the original: .NET's regex \b (word boundary) and
Python's re \b are not guaranteed to be byte-for-byte identical on exotic
Unicode input (both define "word character" slightly differently at the
edges) - not expected to matter for the ASCII-oriented patterns here, but
noted since exact-match fidelity is the whole point of this module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Same four patterns as the PowerShell version, translated 1:1 - see
# BinSifter-Rowan_v1.3.0-beta.1.ps1 lines 2349-2352. No re.IGNORECASE on any of
# them, matching the original's lack of a RegexOptions.IgnoreCase - see the
# module docstring for why that's deliberate, not an oversight here.
_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
_URL_RE = re.compile(r"""\bhttps?://[^\s"'<>]{4,200}""")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|biz|info|xyz|top|club|online|site|tk|cc)\b"
)
_REGISTRY_RE = re.compile(r"""\bHKEY_[A-Z_]+\\[^\s"']{2,200}""")

# Original caps the CSV column at 50 entries so a pathological string blob
# can't balloon a report row - see the PowerShell version's comment at
# line 2364 ("Capped so a pathological string blob can't balloon the CSV
# row.").
_MAX_DISPLAYED_IOCS = 50


@dataclass
class IocExtractionResult:
    count: int
    # "; "-joined, capped at _MAX_DISPLAYED_IOCS entries - "" if none found.
    display: str


def extract_iocs(strings: list[str]) -> IocExtractionResult:
    """Mines a list of already-extracted FLOSS strings for IOC-shaped
    values (IPs, URLs, domains, registry paths).

    Dedup is case-insensitive, matching the PowerShell version's
    HashSet[string] built with StringComparer.OrdinalIgnoreCase - but the
    first-seen casing is what's kept/displayed (same as a real .NET
    HashSet, which stores the first-inserted instance and just treats a
    later case-variant as "already present"), except domain matches, which
    are explicitly lowercased before insertion, same as the original's
    `$m.Value.ToLowerInvariant()`.

    Insertion order (== first-seen order across IP, then URL, then domain,
    then registry-path regexes, per string, in string-list order) is
    preserved for the first 50 entries used in the display join, mirroring
    a real .NET HashSet<T>'s practical (not contractually guaranteed, but
    consistently observed) enumeration order for a set that's only ever
    added to, never removed from - same assumption the original's
    `Select-Object -First 50` relies on.
    """
    seen: dict[str, str] = {}  # lowercased key -> first-seen-cased display value

    def _add(value: str) -> None:
        key = value.lower()
        if key not in seen:
            seen[key] = value

    for s in strings:
        if not s:
            continue
        for m in _IP_RE.finditer(s):
            _add(m.group(0))
        for m in _URL_RE.finditer(s):
            _add(m.group(0))
        for m in _DOMAIN_RE.finditer(s):
            _add(m.group(0).lower())
        for m in _REGISTRY_RE.finditer(s):
            _add(m.group(0))

    count = len(seen)
    if count == 0:
        return IocExtractionResult(count=0, display="")

    display = "; ".join(list(seen.values())[:_MAX_DISPLAYED_IOCS])
    return IocExtractionResult(count=count, display=display)
