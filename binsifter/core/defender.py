"""Windows Defender exclusion helper - added 2026-08-08 after Steve's real
scan against live Malware Bazaar samples showed Defender's real-time
protection racing BinSifter's own worker pool: files extracted from a
password-protected archive got quarantined/removed between extraction and
BinSifter opening them to hash/scan, surfacing as OSError [Errno 22] mid-scan
(see TODO.md's archive-support entries). This module adds a folder to
Defender's scan-exclusion list so that race can't happen.

Deliberately opt-in only, never triggered automatically by a scan - this is
a real, meaningful security tradeoff (Defender will not automatically flag
anything placed in an excluded folder), so it only ever runs from an
explicit Settings-page button click with its own confirmation dialog
spelling that out, never silently as a side effect of scanning. See
gui/pages/settings.py's _on_add_defender_exclusion_clicked() (Winnow) and
the PS1's equivalent Settings button (Rowan) for the calling side.

Requires Administrator rights, which BinSifter itself does not (and should
not) run under by default - a malware-triage tool that extracts archives,
launches external tools, and reads files off disk has no business running
elevated all the time just so ONE optional feature can work. Instead, this
spawns a SEPARATE elevated PowerShell process via `Start-Process -Verb
RunAs`, so Windows' own UAC consent dialog is what actually elevates -
BinSifter's own process never gains admin rights.

No pure-Python Windows Defender API exists for reading/writing exclusion
preferences - `Add-MpPreference` (part of the ConfigDefender PowerShell
module, bundled with every supported Windows version) is Microsoft's own
supported mechanism for this, so this shells out to it via PowerShell
rather than reimplementing anything at the WMI/COM level.

Verification caveat, stated plainly: this dev sandbox is Linux-only, so the
actual UAC-elevation flow, `-EncodedCommand` round-trip, and `Add-MpPreference`
call have NOT been run against a real Windows machine - only reasoned
through against PowerShell/Windows' own documented behavior (see this
module's own comments for the specific gotchas addressed: Start-Process
-Verb RunAs throwing rather than returning a bad exit code when UAC is
declined, PowerShell's -EncodedCommand requiring UTF-16LE, and
Add-MpPreference's own error behavior needing an explicit try/catch to turn
into a reliable exit code). Steve should test this for real before relying
on it.
"""

from __future__ import annotations

import base64
import logging
import platform
import subprocess

logger = logging.getLogger(__name__)


class DefenderExclusionError(Exception):
    """Raised for any failure - UAC declined, Add-MpPreference itself
    failing (Defender not the active AV product, real-time protection off,
    Tamper Protection blocking preference changes), or powershell.exe not
    being found at all. The message is written to be shown directly in a
    QMessageBox/WinForms MessageBox - callers shouldn't need to inspect
    anything beyond str(exc) to build a decent error dialog.
    """


def add_exclusion_path(path: str) -> None:
    """Adds `path` to Windows Defender's scan-exclusion list, prompting for
    UAC elevation via a separate process. Raises DefenderExclusionError on
    any failure, including the user dismissing the UAC prompt - never lets
    a raw OSError/CalledProcessError/TimeoutExpired escape for the caller
    to translate itself.
    """
    if platform.system() != "Windows":
        raise DefenderExclusionError(
            "Windows Defender exclusions are a Windows-only feature - this machine isn't Windows."
        )

    # Escape embedded single quotes PowerShell's own way (doubling them) -
    # `path` is a real filesystem path BinSifter constructed itself
    # (ReportDirectory/extracted_archives), not raw user text, so this is
    # defensive rather than expected to ever actually fire.
    escaped_path = path.replace("'", "''")

    # This inner script is what actually needs Administrator rights -
    # Add-MpPreference itself throws a terminating error on failure (wrong
    # AV product active, Tamper Protection blocking the change, etc.); the
    # explicit try/catch turns that into a clean 0-or-1 exit code rather
    # than leaving it to PowerShell's own default error-to-exit-code
    # behavior, which isn't reliably 0/nonzero across every failure mode.
    inner_script = (
        f"try {{ Add-MpPreference -ExclusionPath '{escaped_path}'; exit 0 }} "
        "catch { exit 1 }"
    )
    # -EncodedCommand takes base64 of UTF-16LE text - PowerShell's own
    # documented requirement for this parameter, not an arbitrary choice.
    # Used here specifically to avoid the quoting nightmare of nesting a
    # quoted command inside Start-Process's -ArgumentList string, which is
    # itself inside another -Command string one level further out.
    encoded = base64.b64encode(inner_script.encode("utf-16-le")).decode("ascii")

    # $ErrorActionPreference = 'Stop' + the outer try/catch matters here:
    # Start-Process -Verb RunAs does NOT return a Process object with a bad
    # exit code when the user declines the UAC prompt - it throws a
    # terminating error instead, since the elevated process never actually
    # launches at all. Without catching that explicitly, a declined prompt
    # would look like an unhandled PowerShell exception rather than the
    # clean, expected "user said no" outcome this function needs to report.
    # 1223 is the real Win32 ERROR_CANCELLED code, reused here deliberately
    # so both "genuinely got ERROR_CANCELLED from Windows" and "we caught
    # the RunAs failure ourselves" map to the same, correctly-labeled
    # outcome below.
    outer_script = (
        "$ErrorActionPreference = 'Stop'; "
        "try { "
        f"$p = Start-Process powershell.exe -Verb RunAs -Wait -PassThru "
        f"-ArgumentList '-NoProfile -NonInteractive -EncodedCommand {encoded}'; "
        "exit $p.ExitCode "
        "} catch { exit 1223 }"
    )

    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", outer_script],
            capture_output=True, text=True, timeout=120,
        )
    except FileNotFoundError as exc:
        raise DefenderExclusionError("powershell.exe was not found on PATH.") from exc
    except subprocess.TimeoutExpired as exc:
        raise DefenderExclusionError(
            "Timed out waiting for the elevated Add-MpPreference process (120s) - "
            "the UAC prompt may still be waiting for a response on screen."
        ) from exc

    if result.returncode == 1223:
        raise DefenderExclusionError(
            "UAC elevation was declined (or the elevated process could not be started) - "
            "no changes were made."
        )
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise DefenderExclusionError(
            "Add-MpPreference failed. This usually means Windows Defender isn't the active "
            "antivirus product, its real-time protection is off, or Tamper Protection is "
            "blocking preference changes." + (f" Details: {stderr}" if stderr else "")
        )

    logger.info("Added Windows Defender exclusion: %s", path)
