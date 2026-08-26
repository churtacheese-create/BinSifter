"""Antivirus product detection - a follow-up to defender.py's exclusion
button, since Windows Defender is only one of many antivirus products an
analyst's machine might be running. The existing exclusion button only
ever helps if Defender is the active product; this module answers the
"which AV is actually installed here" question first, so Settings can
point the analyst at the right place even when it isn't Defender.

Two independent detection mechanisms, one per supported platform - Windows
and Linux have no shared registry of "what antivirus is installed," so
this isn't one implementation with a platform branch, it's two genuinely
different approaches:

**Windows** uses the same real-world mechanism Windows' own Security app
is built on: the `root/SecurityCenter2` WMI namespace's `AntiVirusProduct`
class, which every registered antivirus product (Defender included)
publishes itself into - this is how Windows Security's "Virus & threat
protection" page itself knows what's installed, not a BinSifter
invention. Read via a plain `Get-CimInstance` call in a non-elevated
PowerShell subprocess, same shell-out approach defender.py already uses
(no `wmi`/`pywin32` dependency needed) - unlike the actual exclusion
change, reading this WMI class does NOT require Administrator rights on
any supported Windows version.

Two real caveats worth stating plainly about the Windows path:
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

**Linux** has no equivalent centralized registry at all - there is no
Linux analog to SecurityCenter2 that every AV/EDR vendor publishes itself
into. Instead this checks three independent, non-privileged signals per
known product (a systemd unit file, a running process name under /proc,
and a representative install path) against a curated table
(`_LINUX_AV_SIGNATURES`) built from each vendor's own Linux agent
documentation, and reports a hit if ANY signal matches. This is
deliberately NOT exhaustive - a product not on that table, or one
installed under a renamed/repackaged service, simply won't be found, and
an empty result here means "nothing on the known list was detected," a
weaker guarantee than Windows' "SecurityCenter2 says nothing is
registered." Both are still reported as a normal empty list, not an
error, since neither is a detection failure.

Deliberately does NOT attempt to script an exclusion for anything but
Windows Defender (defender.py's job) - most other vendors either have no
documented, stable local CLI for this at all, or (for enterprise EDR
products especially - CrowdStrike, SentinelOne, Symantec/Broadcom
Endpoint Protection managed via SEP Manager) deliberately block local
self-exclusion by design, since letting a local process silently exempt
itself from EDR scanning is exactly the kind of thing EDR exists to
prevent. `guidance_for()` instead returns a short, honest pointer to where
that vendor's own exclusion settings usually live - checked against
Linux-specific phrasing first (`_LINUX_VENDOR_GUIDANCE`) before falling
back to the original Windows-console-oriented table, since the same
vendor's Linux agent very often exposes an entirely different exclusion
mechanism (a config file or CLI flag instead of a GUI settings page).
"""

from __future__ import annotations

import json
import logging
import platform
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


class AvDetectionError(Exception):
    """Raised only for hard failures - on Windows: powershell.exe missing,
    or the query itself timing out. On any platform other than Windows or
    Linux entirely (macOS, etc.) - detection simply isn't implemented
    there yet. A genuinely empty result (no AV registered/detected) on
    either Windows or Linux is NOT an error, it's a valid `[]` return, so
    callers can show it as a plain status message instead of an error
    dialog.
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

# Linux-specific phrasing, checked BEFORE _VENDOR_GUIDANCE above - the same
# vendor's Linux agent frequently exposes a completely different exclusion
# mechanism (a config file or CLI flag) than its Windows GUI, so reusing
# the Windows-console wording here would actively mislead a Linux analyst.
# Only vendors with a real, documented Linux agent get an entry - anything
# not listed here still falls through to the generic Windows-flavored
# table below rather than making something up.
_LINUX_VENDOR_GUIDANCE: tuple[tuple[str, str], ...] = (
    ("clamav", "ClamAV: add an Exclude/ExcludePath directive to /etc/clamav/clamd.conf (and freshclam.conf if relevant), then restart the clamav-daemon service."),
    ("defender for endpoint", "Microsoft Defender for Endpoint on Linux: run `mdatp exclusion path add --path <folder>`, or set it via your organization's managed configuration profile if enrolled - the button below only automates Windows Defender, not the Linux agent."),
    ("sophos", "Sophos for Linux: check your Sophos Central policy first if centrally managed (local overrides are often blocked by design); otherwise exclusions are set via savsetup/the on-box config."),
    ("bitdefender", "Bitdefender GravityZone (Linux): exclusions are normally pushed from the GravityZone Control Center console, not set locally on the agent."),
    ("trend micro", "Trend Micro Deep Security Agent: exclusions are normally configured from the Deep Security Manager console, not set locally on the agent."),
    ("symantec", "Symantec/Broadcom Endpoint Protection for Linux: exclusions are normally pushed from the SEP Manager console - a local agent usually can't add its own."),
    ("broadcom", "Symantec/Broadcom Endpoint Protection for Linux: exclusions are normally pushed from the SEP Manager console - a local agent usually can't add its own."),
    ("eset", "ESET Endpoint Antivirus for Linux: check /etc/opt/eset/esets/esets.cfg's on-access exclusion list, or the ESET PROTECT console if centrally managed."),
    ("kaspersky", "Kaspersky Endpoint Security for Linux: exclusions are set via the kesl-control CLI, or the centralized management console if enrolled."),
)

# (display name, systemd unit to check, process names to look for under
# /proc, representative install paths) - one entry per known Linux AV/EDR
# agent. A hit on ANY of the three signals counts as "installed", same
# spirit as Windows' SecurityCenter2 not distinguishing "installed" from
# "currently scanning". Curated from each vendor's own Linux agent
# documentation - deliberately not exhaustive, see module docstring.
_LINUX_AV_SIGNATURES: tuple[tuple[str, str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("ClamAV", "clamav-daemon.service", ("clamd", "freshclam"), ("/usr/sbin/clamd", "/usr/bin/clamscan")),
    ("Microsoft Defender for Endpoint", "mdatp.service", ("wdavdaemon", "mdatp"), ("/opt/microsoft/mdatp/sbin/wdavdaemon",)),
    ("CrowdStrike Falcon", "falcon-sensor.service", ("falcon-sensor",), ("/opt/CrowdStrike/falcon-sensor",)),
    ("SentinelOne", "sentinelone.service", ("sentinelctl", "sentineld"), ("/opt/sentinelone/bin/sentinelctl",)),
    ("Sophos", "sophos-spl.service", ("sophos_threat_detector", "savdctl"), ("/opt/sophos-spl",)),
    ("Trend Micro Deep Security Agent", "ds_agent.service", ("ds_agent",), ("/opt/ds_agent/ds_agent",)),
    ("Bitdefender GravityZone", "bd.service", ("bdsec", "epag", "bdredline"), ("/opt/bitdefender-security-tools",)),
    ("Symantec/Broadcom Endpoint Protection", "sisidsdaemon.service", ("rtvscand", "symcfgd"), ("/opt/Symantec/symantec_antivirus",)),
    ("ESET Endpoint Antivirus", "esets.service", ("esets_daemon",), ("/opt/eset/esets/sbin/esets_daemon",)),
    ("Kaspersky Endpoint Security", "kesl.service", ("kesl",), ("/opt/kaspersky/kesl",)),
)


def looks_like_defender(name: str) -> bool:
    lowered = name.lower()
    return "defender" in lowered


def guidance_for(name: str) -> str:
    """Best-effort pointer to where this product's own exclusion settings
    usually live. Checks Linux-specific phrasing first, then falls back to
    the generic Windows-console-oriented table, then a generic, honest
    "consult the vendor" message for anything in neither table rather than
    guessing.
    """
    lowered = name.lower()
    for pattern, hint in _LINUX_VENDOR_GUIDANCE:
        if pattern in lowered:
            return hint
    for pattern, hint in _VENDOR_GUIDANCE:
        if pattern in lowered:
            return hint
    return f"No specific guidance available for {name} - check its settings for a scan exclusion/exception list."


def _systemd_unit_installed(unit: str) -> bool:
    """True if a unit file named `unit` exists on this system, regardless
    of whether it's currently active/enabled - closer to "is this product
    registered" than "is it running right now", matching the same spirit
    as the Windows SecurityCenter2 read. Silently returns False (not an
    error) when systemctl itself isn't present at all - some minimal/non-
    systemd environments (Alpine, certain containers) genuinely have no
    systemd, same "detection just won't find anything there" tradeoff as
    everything else in this table.
    """
    try:
        result = subprocess.run(
            ["systemctl", "list-unit-files", unit, "--no-legend"],
            capture_output=True, text=True, timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return bool((result.stdout or "").strip())


def _linux_process_names(proc_root: str | Path = "/proc") -> set[str]:
    """Lowercased set of every running process's comm name, read directly
    from /proc rather than shelling out to `ps` - pure filesystem access,
    no extra binary dependency, and works identically regardless of which
    `ps` variant (procps vs busybox vs toybox) happens to be installed.
    `proc_root` is overridable purely so tests can point this at a fake
    directory structure instead of the real /proc.
    """
    names: set[str] = set()
    root = Path(proc_root)
    if not root.is_dir():
        return names
    for entry in root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            names.add((entry / "comm").read_text(encoding="utf-8", errors="ignore").strip().lower())
        except OSError:
            continue
    return names


def _detect_linux() -> list[AvProduct]:
    """Checks every entry in _LINUX_AV_SIGNATURES against three signals
    (systemd unit file, running process, install path) and reports a hit
    on any match, deduplicated by display name in table order. See the
    module docstring for why this is a weaker guarantee than the Windows
    SecurityCenter2 path - an empty result means "nothing on the known
    list was found", not "nothing is installed".
    """
    running = _linux_process_names()
    products: list[AvProduct] = []
    for name, unit, process_names, install_paths in _LINUX_AV_SIGNATURES:
        hit = (
            _systemd_unit_installed(unit)
            or any(p in running for p in process_names)
            or any(Path(p).exists() for p in install_paths)
        )
        if hit:
            products.append(AvProduct(name=name))
    return products


def _detect_windows() -> list[AvProduct]:
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


def detect_av_products() -> list[AvProduct]:
    """Returns every antivirus/EDR product this machine's platform-specific
    detection mechanism found, deduplicated by name. An empty list is a
    normal, valid outcome on either supported platform (see module
    docstring for what "empty" means on each) - NOT an error. Raises
    AvDetectionError only for hard failures (Windows query couldn't run at
    all, or a platform other than Windows/Linux with no detection
    mechanism implemented yet).
    """
    system = platform.system()
    if system == "Windows":
        return _detect_windows()
    if system == "Linux":
        return _detect_linux()
    raise AvDetectionError(
        f"Antivirus detection isn't implemented for this platform ({system or 'unknown'}) yet - "
        "only Windows and Linux are currently supported."
    )
