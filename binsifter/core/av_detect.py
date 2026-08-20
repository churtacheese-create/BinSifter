"""Antivirus product detection - a follow-up to defender.py's exclusion
button, since Windows Defender is only one of many antivirus products an
analyst's machine might be running. The existing exclusion button only
ever helps if Defender is the active product; this module answers the
"which AV is actually installed here" question first, so Settings can
point the analyst at the right place even when it isn't Defender.

Uses the same real-world mechanism Windows' own Security app is built on:
the `root/SecurityCenter2` WMI namespace's `AntiVirusProduct` class, which
every registered antivirus product (Defender included) publishes itself
into - this is how Windows Security's "Virus & threat protection" page
itself knows what's installed, not a BinSifter invention. Read via a plain
`Get-CimInstance` call in a non-elevated PowerShell subprocess, same
shell-out approach defender.py already uses (no `wmi`/`pywin32` dependency
needed) - unlike the actual exclusion change, reading this WMI class does
NOT require Administrator rights on any supported Windows version.

Two real caveats worth stating plainly:
- `root/SecurityCenter2` is a client-SKU feature (Windows 10/11 desktop) -
  the underlying Security Center service does not exist on Windows Server,
  so this returns an empty list there rather than raising, and Settings
  shows a message explaining why instead of implying nothing is installed.
- Windows can suppress Defender's own entry from this class once a
  third-party real-time AV registers as active (Defender drops to
  "passive mode" but keeps running signature updates) - so "Defender not
  in this list" does not necessarily mean Defender isn't present at all,
  only that something else is the active real-time scanner. This module
  reports what SecurityCenter2 itself says is active; it does not try to
  second-guess that.

Deliberately does NOT attempt to script an exclusion for anything but
Defender (defender.py's job) - most other vendors either have no
documented, stable local CLI for this at all, or (for enterprise EDR
products especially - CrowdStrike, SentinelOne, Symantec/Broadcom
Endpoint Protection managed via SEP Manager) deliberately block local
self-exclusion by design, since letting a local process silently exempt
itself from EDR scanning is exactly the kind of thing EDR exists to
prevent. `guidance_for()` instead returns a short, honest pointer to where
that vendor's own exclusion settings usually live, verified against each
vendor's own current documentation.
"""

from __future__ import annotations

import json
import logging
import platform
import subprocess
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class AvDetectionError(Exception):
    """Raised only for hard failures (non-Windows, powershell.exe missing,
    the query itself timing out) - a genuinely empty result (no AV
    registered, or SecurityCenter2 unavailable on this SKU) is NOT an
    error, it's a valid `[]` return, so callers can show it as a plain
    status message instead of an error dialog.
    """


@dataclass
class AvProduct:
    name: str


# Substring (lowercased) -> short pointer to that vendor's own exclusion
# settings. Deliberately not step-by-step (menu paths shift between
# versions) - just enough to tell the analyst where to look instead of
# guessing, plus an honest note where local self-exclusion typically isn't
# possible at all (centrally-managed EDR).
_VENDOR_GUIDANCE: tuple[tuple[str, str], ...] = (
    ("windows defender", "Use the button below - BinSifter can add this exclusion automatically."),
    ("microsoft defender", "Use the button below - BinSifter can add this exclusion automatically."),
    ("mcafee", "McAfee: Endpoint Security console > Threat Prevention > Exclusions (or pushed from ePO if centrally managed)."),
    ("eset", "ESET: open the product > Setup > Detection Engine (or Antivirus) > Exclusions."),
    ("sophos", "Sophos: Sophos Endpoint > Exclusions, or Sophos Central > policy Exclusions if centrally managed."),
    ("symantec", "Symantec/Broadcom Endpoint Protection: exclusions are normally pushed from the SEP Manager console - a local client usually can't add its own."),
    ("broadcom", "Broadcom Endpoint Protection: exclusions are normally pushed from the SEP Manager console - a local client usually can't add its own."),
    ("crowdstrike", "CrowdStrike Falcon: exclusions are managed centrally from the Falcon console by design - there is no supported local self-exclusion."),
    ("sentinelone", "SentinelOne: exclusions are managed centrally from the Management Console by design - there is no supported local self-exclusion."),
    ("bitdefender", "Bitdefender: Protection > Antivirus > Settings (gear icon) > Manage Exceptions."),
    ("kaspersky", "Kaspersky: Settings > Threats and Exclusions > Manage Exclusions."),
    ("trend micro", "Trend Micro: open the console/agent's Scan Exclusion List settings."),
    ("malwarebytes", "Malwarebytes: Settings > Exclusions > Add Exclusion."),
    ("avast", "Avast: Menu > Settings > General > Exceptions."),
    ("avg", "AVG: Menu > Settings > General > Exceptions."),
    ("webroot", "Webroot: PC Security > Identity & Privacy Shields > Application/Exclusion list."),
    ("f-secure", "F-Secure: Settings > find the exclusion/exception list for real-time scanning."),
    ("norton", "Norton: Settings > Antivirus > Scans and Risks > Exclusions/Low Risks."),
)


def looks_like_defender(name: str) -> bool:
    lowered = name.lower()
    return "defender" in lowered


def guidance_for(name: str) -> str:
    """Best-effort pointer to where this product's own exclusion settings
    usually live. Falls back to a generic, honest "consult the vendor"
    message for anything not in the table above rather than guessing.
    """
    lowered = name.lower()
    for pattern, hint in _VENDOR_GUIDANCE:
        if pattern in lowered:
            return hint
    return f"No specific guidance available for {name} - check its settings for a scan exclusion/exception list."


def detect_av_products() -> list[AvProduct]:
    """Returns every antivirus product registered in
    `root/SecurityCenter2` on this machine, deduplicated by name. An empty
    list is a normal, valid outcome (Windows Server, Security Center
    service disabled, or genuinely nothing registered) - NOT an error.
    Raises AvDetectionError only for hard failures that mean the query
    itself couldn't run at all.
    """
    if platform.system() != "Windows":
        raise AvDetectionError("Antivirus detection is a Windows-only feature - this machine isn't Windows.")

    # -ErrorAction Stop turns "namespace doesn't exist" (Windows Server, or
    # the Security Center service disabled) into a catchable terminating
    # error instead of a silent empty result mixed in with stderr noise -
    # caught below and mapped to a clean empty list, same "not an error"
    # treatment as genuinely finding nothing installed.
    script = (
        "$ErrorActionPreference = 'Stop'; "
        "try { "
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct "
        "| Select-Object -ExpandProperty displayName | ConvertTo-Json -Compress "
        "} catch { '[]' }"
    )

    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=30,
        )
    except FileNotFoundError as exc:
        raise AvDetectionError("powershell.exe was not found on PATH.") from exc
    except subprocess.TimeoutExpired as exc:
        raise AvDetectionError("Timed out querying installed antivirus products (30s).") from exc

    raw = (result.stdout or "").strip()
    if not raw:
        return []

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Could not parse antivirus product list from PowerShell output: %r", raw)
        return []

    # ConvertTo-Json returns a bare string for exactly one result, a real
    # array for zero or multiple - normalize to a list either way.
    if isinstance(parsed, str):
        names = [parsed]
    elif isinstance(parsed, list):
        names = [n for n in parsed if isinstance(n, str)]
    else:
        names = []

    seen: set[str] = set()
    products: list[AvProduct] = []
    for name in names:
        if name and name not in seen:
            seen.add(name)
            products.append(AvProduct(name=name))
    return products
