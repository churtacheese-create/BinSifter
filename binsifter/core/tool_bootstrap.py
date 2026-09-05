"""First-run auto-installer for Winnow's quick-launch tools - built
2026-09-03 directly in response to the project owner's request: on
startup, check whether each quick-launch tool is already findable; if not,
try to install it; if that needs the internet and there isn't any, tell the
user to either reconnect and relaunch or install it themselves. In every
case, a missing/failed tool must never block Winnow from loading or from
running a scan - every function in this module is written to fail soft,
never raise out to a caller running on the GUI thread.

Lineup as of 2026-09-03 (revised same day, after a real user's first .deb
install/scan log surfaced two real bugs and prompted a tool-lineup
reconsideration - see git history for the original five-tool version):
PE-bear, Anya, DIE, Cutter (replacing Rizin), Angr, GEF (layered onto
whatever `gdb` find_tool_path() finds on PATH), Binwalk, Malwoverview, and
Ghidra (previously manual-only, now auto-installed on request). Rizin
itself is gone from the auto-install list, not just relabeled: it's a
terminal-native REPL with no window of its own, so launching it via a bare
`subprocess.Popen` from a GUI app with no attached terminal produced no
visible effect at all - confirmed from that same real log
("PE-Bear nor Rizin would work when selected"). Cutter is rizin's own
official Qt GUI front-end (same analysis engine underneath, actual window),
so it replaces Rizin as the quick-launch entry while Rizin itself remains
installable and usable from a real terminal exactly as before.

Design choices worth explaining up front:

- **No root/sudo, ever.** All five tools can be gotten onto a per-user,
  no-elevation-needed path: PE-bear, DIE, and Anya all publish self-
  contained Linux AppImages on their own GitHub Releases (confirmed
  directly against each project's real "latest release" API response, not
  assumed); Rizin publishes a static, dependency-free x86_64 Linux tarball
  the same way (also confirmed against a real release's asset list, not
  just its distro-package story); Angr is a PyPI package with a real
  `angr` console-script entry point (`[project.scripts]` in its own
  pyproject.toml), installable into a private virtualenv with no system
  package manager involved at all. A GUI app silently shelling out to
  `sudo apt install` would need a polkit/pkexec prompt users may not
  expect from a malware-triage tool, so that path was deliberately never
  considered - every tool here is a plain per-user download instead.
- **Installed into get_auto_installed_tools_dir()**, a fixed directory
  separate from the user's own "Path to tools" - config.py's
  set_tool_paths_from_directory() already checks that directory as a
  fallback (see its own docstring), so nothing here needs its own
  persistence logic: once a tool lands in that directory, every future
  startup's normal tool-path resolution finds it the same way it finds
  anything the user staged themselves.
- **No "have we already tried" flag anywhere.** run_tool_bootstrap() is
  meant to be called on every startup, but it only ever does real work
  (network calls, downloads, pip installs) for a tool that ISN'T already
  resolvable - once a tool installs successfully, every later startup's
  cheap find_tool_path() check finds it immediately and skips straight to
  "already_present" with no network touched at all. This naturally matches
  "try again on relaunch" without needing separate persisted state: a
  failed attempt (no internet, a flaky download) just means the next
  launch tries again, for free.
- **GitHub release asset names are hard-matched, not guessed.** Every
  `must_contain` tuple below was checked against a real "latest release"
  API response (or, for Rizin, the real rendered releases page - its API
  endpoint returned nothing usable when checked directly) before being
  written, specifically to avoid the false-positive Rizin was one
  substring away from: `rizin-v0.9.1-android-x86_64.tar.gz` also contains
  "x86_64", so matching on "x86_64" alone would have grabbed an Android
  build; "static" narrows it to the one real desktop-Linux asset,
  `rizin-v0.9.1-static-x86_64.tar.xz`.
"""

from __future__ import annotations

import json
import logging
import platform
import shutil
import stat
import subprocess
import tarfile
import urllib.error
import urllib.request
import venv
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from binsifter.core.config import (
    TOOL_FILE_NAMES,
    BinSifterConfig,
    find_tool_path,
    get_auto_installed_tools_dir,
)

logger = logging.getLogger(__name__)

_USER_AGENT = "BinSifter-Winnow-ToolBootstrap/1.0 (+https://github.com/)"
_NETWORK_TIMEOUT_SECONDS = 8.0
_DOWNLOAD_TIMEOUT_SECONDS = 180.0

# Manual-install fallback text shown when a tool can't be auto-installed
# (no internet) - same commands docs/winnow.md already documents, kept
# here too so the in-app message and the docs never drift apart silently.
_MANUAL_INSTALL_HINTS: dict[str, str] = {
    "PeBearExe": (
        "download the Linux AppImage from https://github.com/hasherezade/pe-bear/releases/latest, "
        "make it executable, and place it somewhere on your PATH or under \"Path to tools\"."
    ),
    "AnyaExe": (
        "run: curl -fsSL https://raw.githubusercontent.com/elementmerc/anya/main/install.sh | bash "
        "(or download the CLI tarball from https://github.com/elementmerc/anya/releases/latest)."
    ),
    "DieExe": (
        "download the Linux AppImage from https://github.com/horsicq/DIE-engine/releases/latest, "
        "make it executable, and place it somewhere on your PATH or under \"Path to tools\"."
    ),
    "CutterExe": (
        "install via your distro's package manager (e.g. \"sudo apt install cutter\", "
        "\"sudo pacman -S cutter\") or download the Linux AppImage from "
        "https://github.com/rizinorg/cutter/releases/latest."
    ),
    "AngrExe": (
        "run: pipx install angr (or pip install angr in a virtualenv of your own)."
    ),
    "GdbExe": (
        "install via your distro's package manager (e.g. \"sudo apt install gdb\", "
        "\"sudo dnf install gdb\", \"sudo pacman -S gdb\") - GDB needs a real package "
        "manager and can't be installed by Winnow itself without root."
    ),
    "BinwalkExe": (
        "run: pipx install binwalk (or pip install binwalk in a virtualenv of your own; "
        "your distro's binwalk package, e.g. \"sudo apt install binwalk\", also works and "
        "additionally pulls in the extraction helper libraries binwalk itself doesn't ship)."
    ),
    "MalwoverviewExe": (
        "run: pipx install malwoverview (or pip install malwoverview in a virtualenv of "
        "your own). Note: malwoverview queries third-party online services (VirusTotal, "
        "Hybrid-Analysis, and similar) with file hashes/IOCs - see its own docs before use."
    ),
    "GhidraHeadlessExe": (
        "download the latest release from "
        "https://github.com/NationalSecurityAgency/ghidra/releases/latest, extract it "
        "anywhere, and point \"Path to Ghidra\" at the extracted folder. Ghidra needs a "
        "JDK 21+ - install one via your distro's package manager "
        "(e.g. \"sudo apt install openjdk-21-jdk\") or from https://adoptium.net/ if you'd "
        "rather not let Winnow download its own copy."
    ),
}

_TOOL_LABELS: dict[str, str] = {
    "PeBearExe": "PE-bear",
    "AnyaExe": "Anya",
    "DieExe": "DIE",
    "CutterExe": "Cutter",
    "AngrExe": "Angr",
    "GdbExe": "GDB + GEF",
    "BinwalkExe": "Binwalk",
    "MalwoverviewExe": "Malwoverview",
    "GhidraHeadlessExe": "Ghidra",
}


@dataclass
class ToolBootstrapResult:
    """One tool's outcome from a single run_tool_bootstrap() pass."""

    tool_key: str
    tool_label: str
    status: str  # "already_present" | "installed" | "no_internet" | "failed"
    path: str = ""
    detail: str = ""


def check_internet_available(timeout: float = _NETWORK_TIMEOUT_SECONDS) -> bool:
    """Cheap connectivity probe - tries a couple of hosts (GitHub, since
    four of the five tools download from there, and PyPI, since Angr's
    install goes through pip) so a single blocked/down host doesn't
    misreport genuine connectivity as absent. Any failure mode (DNS,
    timeout, TLS, refused connection) is treated the same way: no
    internet, try the next host, and if every host fails, report False -
    the caller's job is deciding what to do about it, not this function's.
    """
    for url in ("https://api.github.com", "https://pypi.org"):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT}, method="HEAD")
            with urllib.request.urlopen(request, timeout=timeout):
                return True
        except (urllib.error.URLError, OSError, ValueError) as exc:
            logger.debug("Connectivity probe to %s failed: %s", url, exc)
            continue
    return False


def _get_json(url: str, timeout: float) -> dict:
    request = urllib.request.Request(
        url, headers={"User-Agent": _USER_AGENT, "Accept": "application/vnd.github+json"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _latest_release_assets(owner: str, repo: str, timeout: float = _NETWORK_TIMEOUT_SECONDS) -> list[dict]:
    data = _get_json(f"https://api.github.com/repos/{owner}/{repo}/releases/latest", timeout)
    return data.get("assets", [])


def _pick_asset(
    assets: list[dict], must_contain: tuple[str, ...], must_not_contain: tuple[str, ...] = ()
) -> dict | None:
    """First asset whose (lowercased) name contains every token in
    `must_contain` and none of `must_not_contain`. Substring matching, not
    glob/regex - simple enough to eyeball against a real release's asset
    list, which is exactly how every must_contain tuple below was chosen.
    """
    for asset in assets:
        name = str(asset.get("name", "")).lower()
        if all(token in name for token in must_contain) and not any(token in name for token in must_not_contain):
            return asset
    return None


def _download(url: str, dest: Path, timeout: float = _DOWNLOAD_TIMEOUT_SECONDS) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response, open(dest, "wb") as handle:
        shutil.copyfileobj(response, handle)


def _make_executable(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _install_appimage_tool(
    tool_key: str, owner: str, repo: str, dest_root: Path, saved_filename: str
) -> ToolBootstrapResult:
    """Shared logic for PE-bear and DIE - both publish exactly one Linux
    AppImage asset on their latest release, no extraction needed, just
    download-and-chmod. `saved_filename` deliberately matches one of
    TOOL_FILE_NAMES' own candidates for this tool, purely so a manual
    inspection of the auto-install directory lines up with what a manual
    install would look like - find_tool_path() itself doesn't care what
    the file is named, it searches recursively either way.
    """
    label = _TOOL_LABELS[tool_key]
    try:
        assets = _latest_release_assets(owner, repo)
    except Exception as exc:  # noqa: BLE001 - any urllib/json/network failure mode
        return ToolBootstrapResult(
            tool_key, label, "failed", detail=f"Could not query {owner}/{repo}'s latest release: {exc}"
        )
    asset = _pick_asset(assets, must_contain=(".appimage",))
    if asset is None:
        return ToolBootstrapResult(
            tool_key, label, "failed", detail=f"No Linux AppImage found in {owner}/{repo}'s latest release"
        )
    dest = dest_root / tool_key[: -len("Exe")].lower() / saved_filename
    try:
        _download(asset["browser_download_url"], dest)
        _make_executable(dest)
    except Exception as exc:  # noqa: BLE001
        return ToolBootstrapResult(tool_key, label, "failed", detail=f"Download failed: {exc}")
    return ToolBootstrapResult(
        tool_key, label, "installed", path=str(dest), detail=f"Downloaded {asset['name']} from {owner}/{repo}"
    )


def _install_pe_bear(dest_root: Path) -> ToolBootstrapResult:
    return _install_appimage_tool("PeBearExe", "hasherezade", "pe-bear", dest_root, TOOL_FILE_NAMES["PeBearExe"][0])


def _install_die(dest_root: Path) -> ToolBootstrapResult:
    return _install_appimage_tool("DieExe", "horsicq", "DIE-engine", dest_root, TOOL_FILE_NAMES["DieExe"][1])


def _install_anya(dest_root: Path) -> ToolBootstrapResult:
    """Anya publishes both a GUI AppImage and a static musl CLI binary
    tarball - the tarball is used here, not the AppImage, since its
    documented invocation (`anya --file <path>`) matches how
    _launch_quick_tool builds argv for Anya (see results.py's
    _QUICK_LAUNCH_TOOLS - AnyaExe carries a ("--file",) prefix precisely
    for this), whereas the GUI AppImage's own file-open argument
    convention isn't documented anywhere and would be a guess.
    """
    label = _TOOL_LABELS["AnyaExe"]
    try:
        assets = _latest_release_assets("elementmerc", "anya")
    except Exception as exc:  # noqa: BLE001
        return ToolBootstrapResult(
            "AnyaExe", label, "failed", detail=f"Could not query elementmerc/anya's latest release: {exc}"
        )
    asset = _pick_asset(assets, must_contain=("linux", "musl", ".tar.gz"))
    if asset is None:
        return ToolBootstrapResult(
            "AnyaExe", label, "failed", detail="No Linux musl CLI tarball found in elementmerc/anya's latest release"
        )
    extract_dir = dest_root / "anya"
    archive_path = extract_dir / asset["name"]
    try:
        _download(asset["browser_download_url"], archive_path)
        with tarfile.open(archive_path) as tar:
            tar.extractall(extract_dir)  # noqa: S202 - trusted source (GitHub release we just verified the name of)
        archive_path.unlink(missing_ok=True)
    except Exception as exc:  # noqa: BLE001
        return ToolBootstrapResult("AnyaExe", label, "failed", detail=f"Download/extract failed: {exc}")
    resolved = find_tool_path(extract_dir, TOOL_FILE_NAMES["AnyaExe"])
    if not resolved:
        return ToolBootstrapResult(
            "AnyaExe", label, "failed", detail=f"Extracted {asset['name']} but couldn't locate the anya binary inside"
        )
    _make_executable(Path(resolved))
    return ToolBootstrapResult("AnyaExe", label, "installed", path=resolved, detail=f"Downloaded {asset['name']}")


def _install_cutter(dest_root: Path) -> ToolBootstrapResult:
    """Cutter (rizin's own official Qt GUI front-end) replaces Rizin as the
    quick-launch entry 2026-09-03 - see this module's docstring for why.
    Cutter publishes a Linux AppImage on its GitHub Releases, same shape as
    PE-bear/DIE, so this reuses _install_appimage_tool rather than
    duplicating the old Rizin tarball-extraction logic Cutter doesn't need.
    """
    return _install_appimage_tool("CutterExe", "rizinorg", "cutter", dest_root, TOOL_FILE_NAMES["CutterExe"][1])


# GEF's own documented one-liner installer - a single Python script fetched
# straight into the user's home and sourced from ~/.gdbinit, genuinely
# root-free (no package manager, no venv, nothing outside $HOME) unlike GDB
# itself, which needs a real distro package and is PATH-only here (see
# _MANUAL_INSTALL_HINTS["GdbExe"]).
_GEF_INSTALL_URL = "https://gef.blah.cat/sh"


def _install_gef(dest_root: Path) -> ToolBootstrapResult:
    """GDB itself is never auto-installed (see module docstring) - this
    only ever runs when `gdb` is already found on PATH (see
    run_tool_bootstrap()'s special-cased "GdbExe" handling below), and adds
    GEF on top of that existing GDB by running GEF's own documented
    curl-to-`gdb -x`-based installer, which writes `source ~/.gdb-gef.py`
    (or similar) into ~/.gdbinit itself - nothing for BinSifter to track or
    re-resolve afterward, since the next `gdb` launch picks it up
    automatically via the user's own gdbinit, the same as if the user had
    run GEF's installer by hand.
    """
    label = _TOOL_LABELS["GdbExe"]
    gdb_path = shutil.which("gdb")
    if not gdb_path:
        return ToolBootstrapResult(
            "GdbExe", label, "failed", detail="gdb not found on PATH - GEF needs an existing gdb to attach to"
        )
    try:
        request = urllib.request.Request(_GEF_INSTALL_URL, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(request, timeout=_NETWORK_TIMEOUT_SECONDS) as response:
            installer_script = response.read().decode("utf-8")
    except Exception as exc:  # noqa: BLE001
        return ToolBootstrapResult("GdbExe", label, "failed", detail=f"Could not download GEF's installer: {exc}")

    marker = dest_root / "gef-install.py"
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(installer_script, encoding="utf-8")
        subprocess.run(
            [gdb_path, "-q", "-x", str(marker)],
            check=True,
            capture_output=True,
            text=True,
            timeout=_NETWORK_TIMEOUT_SECONDS * 2,
        )
    except subprocess.CalledProcessError as exc:
        return ToolBootstrapResult(
            "GdbExe", label, "failed", detail=f"GEF install script failed: {(exc.stderr or '').strip()[-500:] or exc}"
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ToolBootstrapResult("GdbExe", label, "failed", detail=f"GEF install script failed: {exc}")

    return ToolBootstrapResult(
        "GdbExe", label, "installed", path=gdb_path, detail="Installed GEF into ~/.gdbinit for the existing gdb on PATH"
    )


def _create_private_venv(venv_dir: Path) -> str:
    """Creates a virtualenv at `venv_dir`, preferring a real system python3
    over the currently-running interpreter. Returns "" on success, or an
    error detail string on failure - never raises.

    REAL BUG FOUND AND FIXED 2026-09-04, from a real user's packaged-app
    log: the stdlib `venv` module's `venv.create()` always bases the new
    environment on `sys.executable` - the CURRENTLY RUNNING interpreter.
    That's a real python3 in this dev sandbox and under `pip install -e .`,
    but once Winnow is frozen by PyInstaller (installer/winnow.spec's whole
    point), `sys.executable` IS the compiled `BinSifter-Winnow` binary
    itself, not a general-purpose python3 executable. `venv.create()`
    still "succeeds" (it copies/symlinks the frozen exe into
    `<venv>/bin/BinSifter-Winnow`), but running
    `<venv>/bin/BinSifter-Winnow -m ensurepip` inside that venv immediately
    fails - confirmed directly from the log: "Could not create a
    virtualenv: Command
    ['.../binwalk-venv/bin/BinSifter-Winnow', '-m', 'ensurepip', ...]
    returned non-zero exit status 255." - since that "python" is actually
    the whole frozen GUI app, not an interpreter that understands `-m`.
    This broke every venv-based installer (Angr, Binwalk, Malwoverview) on
    every real packaged install, every time, not intermittently - it only
    went unnoticed for Angr specifically because that user had already
    installed it manually via pipx before Winnow's own attempt ever ran.

    Fixed by shelling out to a real system python3 (found via
    `shutil.which`, the same PATH-fallback approach every other tool here
    already uses) to create the venv instead of trusting the running
    interpreter - `python3 -m venv <dir>` is a completely ordinary
    invocation on any machine with Python 3 installed at all, which is
    effectively guaranteed on Debian/Ubuntu/Fedora/Arch (all of them
    depend on system Python for their own package managers). Falls back to
    the old `venv.create()` behavior only if no system python3 can be
    found at all - e.g. a from-source/dev environment, where the running
    interpreter genuinely already is the right one to use.
    """
    system_python = shutil.which("python3") or shutil.which("python")
    if system_python:
        try:
            subprocess.run(
                [system_python, "-m", "venv", str(venv_dir)],
                check=True,
                capture_output=True,
                text=True,
                timeout=_NETWORK_TIMEOUT_SECONDS * 4,
            )
            return ""
        except subprocess.CalledProcessError as exc:
            return (exc.stderr or "").strip()[-500:] or str(exc)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return str(exc)
    try:
        venv.create(venv_dir, with_pip=True, clear=True)
        return ""
    except Exception as exc:  # noqa: BLE001
        return str(exc)


def _install_angr(dest_root: Path) -> ToolBootstrapResult:
    """Angr is a PyPI package, not a GitHub-release binary - its own docs
    recommend a dedicated virtualenv rather than a system-wide install
    (several dependencies bundle forked native libraries that can collide
    with system copies), so one is built here specifically for it, kept
    entirely under dest_root and never touching BinSifter's own venv/site-
    packages. Confirmed directly against angr's real pyproject.toml that
    `pip install angr` produces a real `angr` console-script command
    (`[project.scripts] angr = "angr.__main__:main"`) - this isn't a
    library with no CLI to actually launch from the quick-launch menu.
    """
    label = _TOOL_LABELS["AngrExe"]
    venv_dir = dest_root / "angr-venv"
    venv_error = _create_private_venv(venv_dir)
    if venv_error:
        return ToolBootstrapResult("AngrExe", label, "failed", detail=f"Could not create a virtualenv: {venv_error}")

    venv_python = venv_dir / "bin" / "python"
    if not venv_python.is_file():
        return ToolBootstrapResult("AngrExe", label, "failed", detail="Virtualenv creation didn't produce a python binary")

    # HARDENED 2026-09-03: angr's own pyproject.toml requires setuptools-rust
    # and has a [[tool.setuptools-rust.ext-modules]] Cargo-based extension
    # (angr.rustylib) - a bare `pip install angr` on a machine with no Rust
    # toolchain present can fall through to a source build of that
    # extension and fail with a long, generic Cargo/compiler error that
    # gave a real user's log ("Angr could not be installed automatically")
    # no useful detail at all. Try wheel-only first (--only-binary=:all:) -
    # if PyPI has a prebuilt wheel for this platform/Python version, this
    # succeeds fast with no compiler involved; if it doesn't, fall back to
    # a normal install (which may still build from source, exactly like
    # before) so a platform with no wheel isn't worse off than the old
    # behavior. Either way the real pip stderr is captured and returned in
    # `detail` - previously this was captured but never logged anywhere
    # (see run_tool_bootstrap()'s new logging), so a failure's actual cause
    # was invisible outside of a transient popup.
    pip_attempts = (
        ["--only-binary=:all:", "angr"],
        ["angr"],
    )
    last_error = ""
    installed = False
    for pip_args in pip_attempts:
        try:
            subprocess.run(
                [str(venv_python), "-m", "pip", "install", "--quiet", "--disable-pip-version-check", *pip_args],
                check=True,
                capture_output=True,
                text=True,
                timeout=_DOWNLOAD_TIMEOUT_SECONDS * 3,  # angr pulls a real dependency chain - a plain download timeout is too tight
            )
            installed = True
            break
        except subprocess.CalledProcessError as exc:
            last_error = (exc.stderr or "").strip()[-500:] or str(exc)
            continue
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ToolBootstrapResult("AngrExe", label, "failed", detail=f"pip install angr failed: {exc}")

    if not installed:
        return ToolBootstrapResult(
            "AngrExe", label, "failed",
            detail=f"pip install angr failed (tried a prebuilt wheel and a source build): {last_error}",
        )

    angr_exe = venv_dir / "bin" / "angr"
    if not angr_exe.is_file():
        return ToolBootstrapResult(
            "AngrExe", label, "failed", detail="angr installed but no bin/angr console script was produced"
        )
    return ToolBootstrapResult("AngrExe", label, "installed", path=str(angr_exe), detail="Installed into a private virtualenv")


def _install_pip_venv_tool(tool_key: str, package: str, console_script: str, dest_root: Path) -> ToolBootstrapResult:
    """Shared logic for any tool that's a plain PyPI package with a console-
    script entry point and no native/Rust build concerns (unlike angr) -
    Binwalk and Malwoverview both fit this shape. Same private-virtualenv
    approach as _install_angr, minus the wheel-first hardening that only
    angr's build chain needs.
    """
    label = _TOOL_LABELS[tool_key]
    venv_dir = dest_root / f"{package}-venv"
    venv_error = _create_private_venv(venv_dir)
    if venv_error:
        return ToolBootstrapResult(tool_key, label, "failed", detail=f"Could not create a virtualenv: {venv_error}")

    venv_python = venv_dir / "bin" / "python"
    if not venv_python.is_file():
        return ToolBootstrapResult(tool_key, label, "failed", detail="Virtualenv creation didn't produce a python binary")

    try:
        subprocess.run(
            [str(venv_python), "-m", "pip", "install", "--quiet", "--disable-pip-version-check", package],
            check=True,
            capture_output=True,
            text=True,
            timeout=_DOWNLOAD_TIMEOUT_SECONDS * 2,
        )
    except subprocess.CalledProcessError as exc:
        return ToolBootstrapResult(
            tool_key, label, "failed", detail=f"pip install {package} failed: {(exc.stderr or '').strip()[-500:] or exc}"
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ToolBootstrapResult(tool_key, label, "failed", detail=f"pip install {package} failed: {exc}")

    tool_exe = venv_dir / "bin" / console_script
    if not tool_exe.is_file():
        return ToolBootstrapResult(
            tool_key, label, "failed", detail=f"{package} installed but no bin/{console_script} console script was produced"
        )
    return ToolBootstrapResult(tool_key, label, "installed", path=str(tool_exe), detail="Installed into a private virtualenv")


def _install_binwalk(dest_root: Path) -> ToolBootstrapResult:
    """Binwalk's PyPI package (by ReFirmLabs, the project's current
    maintainers) ships a real `binwalk` console-script entry point - the
    pip install here covers signature scanning/carving out of the box;
    some extraction paths (e.g. squashfs) additionally want distro tools
    like sasquatch that only a real package manager provides, same
    "core works, some extras need your distro's package" caveat as
    docs/winnow.md already carries for building Winnow itself from source.
    """
    return _install_pip_venv_tool("BinwalkExe", "binwalk", "binwalk", dest_root)


def _install_malwoverview(dest_root: Path) -> ToolBootstrapResult:
    """Malwoverview's PyPI package ships a `malwoverview` console-script
    entry point. Deliberately installed like any other quick-launch tool
    here - the third-party-service disclosure (VirusTotal/Hybrid-Analysis/
    etc. hash and IOC lookups) is a usage-time concern for whoever runs it,
    not an install-time one, and is already surfaced in
    _MANUAL_INSTALL_HINTS["MalwoverviewExe"] and docs/winnow.md.
    """
    return _install_pip_venv_tool("MalwoverviewExe", "malwoverview", "malwoverview", dest_root)


_ADOPTIUM_JDK_API = "https://api.adoptium.net/v3/assets/latest/21/hotspot"


def _adoptium_architecture() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "x64"
    if machine in ("aarch64", "arm64"):
        return "aarch64"
    return machine  # best-effort passthrough; Adoptium's API just 404s cleanly if this is wrong


def _install_portable_jdk(dest_root: Path) -> Path | None:
    """Downloads a portable, root-free JDK 21 build from Eclipse Temurin
    (via Adoptium's own release API, the same "ask the API, don't hard-code
    a version" approach _latest_release_assets() uses for GitHub) for
    Ghidra to run against, used only when no `java` is already on PATH.
    Returns the extracted JDK's home directory, or None on any failure -
    callers treat that the same as "couldn't get Ghidra a JDK" and report
    Ghidra's own install as failed, never raise.
    """
    arch = _adoptium_architecture()
    url = f"{_ADOPTIUM_JDK_API}?os=linux&architecture={arch}&image_type=jdk"
    try:
        data = _get_json(url, _NETWORK_TIMEOUT_SECONDS)
        asset = data[0]
        download_url = asset["binary"]["package"]["link"]
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not resolve a portable JDK from Adoptium: %s", exc)
        return None

    jdk_root = dest_root / "ghidra-jdk"
    archive_path = jdk_root / "jdk.tar.gz"
    try:
        _download(download_url, archive_path)
        with tarfile.open(archive_path) as tar:
            tar.extractall(jdk_root)  # noqa: S202 - trusted source (Adoptium's own official API response)
        archive_path.unlink(missing_ok=True)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not download/extract the portable JDK: %s", exc)
        return None

    java_matches = sorted(
        (p for p in jdk_root.rglob("java") if p.is_file()), key=lambda p: len(str(p))
    )
    if not java_matches:
        return None
    _make_executable(java_matches[0])
    return java_matches[0].parent.parent  # .../<jdk>/bin/java -> .../<jdk>


def _install_ghidra(dest_root: Path) -> ToolBootstrapResult:
    """Ghidra (NationalSecurityAgency/ghidra on GitHub) publishes a single
    large, platform-independent release zip (Java, not a native binary -
    the same archive works on every OS/architecture with a compatible JDK),
    so unlike every other installer here there's no per-platform asset
    matching - just "the one .zip on the latest release." Previously
    manual-install-only (a multi-hundred-MB download, meaningfully bigger
    and slower than any other tool here) - added to the automatic list
    2026-09-03 per an explicit request ("I want Ghidra to be installed if
    not installed"), same fail-soft/no-internet handling as every other
    tool, just a longer download.
    """
    label = _TOOL_LABELS["GhidraHeadlessExe"]
    try:
        assets = _latest_release_assets("NationalSecurityAgency", "ghidra")
    except Exception as exc:  # noqa: BLE001
        return ToolBootstrapResult(
            "GhidraHeadlessExe", label, "failed",
            detail=f"Could not query NationalSecurityAgency/ghidra's latest release: {exc}",
        )
    asset = _pick_asset(assets, must_contain=("ghidra_", ".zip"), must_not_contain=("src",))
    if asset is None:
        return ToolBootstrapResult(
            "GhidraHeadlessExe", label, "failed", detail="No Ghidra release zip found in the latest release"
        )

    extract_dir = dest_root / "ghidra"
    archive_path = extract_dir / asset["name"]
    try:
        _download(asset["browser_download_url"], archive_path)
        with zipfile.ZipFile(archive_path) as zf:
            zf.extractall(extract_dir)  # noqa: S202 - trusted source (GitHub release we just verified the name of)
        archive_path.unlink(missing_ok=True)
    except Exception as exc:  # noqa: BLE001
        return ToolBootstrapResult("GhidraHeadlessExe", label, "failed", detail=f"Download/extract failed: {exc}")

    resolved = find_tool_path(extract_dir, "analyzeHeadless")
    if not resolved:
        return ToolBootstrapResult(
            "GhidraHeadlessExe", label, "failed",
            detail=f"Extracted {asset['name']} but couldn't locate analyzeHeadless inside",
        )
    _make_executable(Path(resolved))

    if not shutil.which("java"):
        jdk_home = _install_portable_jdk(dest_root)
        if jdk_home is None:
            return ToolBootstrapResult(
                "GhidraHeadlessExe", label, "failed",
                detail=(
                    f"Extracted Ghidra to {extract_dir}, but no JDK 21+ was found on PATH and downloading a "
                    "portable one failed - install a JDK yourself (e.g. \"sudo apt install openjdk-21-jdk\") "
                    "and relaunch Winnow."
                ),
            )
        # Ghidra's own launch support (support/launch.sh) honors JAVA_HOME
        # ahead of searching PATH, so a thin wrapper that exports it before
        # exec'ing the real script is enough - no need to patch Ghidra's own
        # launch scripts, which stay exactly as the zip shipped them.
        wrapper = Path(resolved).parent / "analyzeHeadless-with-bundled-jdk.sh"
        wrapper.write_text(
            f'#!/bin/sh\nexport JAVA_HOME="{jdk_home}"\nexec "{resolved}" "$@"\n', encoding="utf-8"
        )
        _make_executable(wrapper)
        resolved = str(wrapper)

    return ToolBootstrapResult(
        "GhidraHeadlessExe", label, "installed", path=resolved, detail=f"Downloaded {asset['name']}"
    )


_INSTALLERS: dict[str, Callable[[Path], ToolBootstrapResult]] = {
    "PeBearExe": _install_pe_bear,
    "AnyaExe": _install_anya,
    "DieExe": _install_die,
    "CutterExe": _install_cutter,
    "AngrExe": _install_angr,
    "BinwalkExe": _install_binwalk,
    "MalwoverviewExe": _install_malwoverview,
    # GdbExe and GhidraHeadlessExe are deliberately absent here - both need
    # special-cased handling in run_tool_bootstrap() below (GdbExe because
    # GDB itself is PATH-only/never auto-installed and "already present"
    # can't be answered by a single file check the way every other tool's
    # can; GhidraHeadlessExe because it isn't a member of TOOL_FILE_NAMES at
    # all - see config.py's build_default_config() for why Ghidra's own
    # resolution sits outside that shared dict).
}


def _gef_already_configured() -> bool:
    """Best-effort check for whether GEF is already sourced from the
    user's own ~/.gdbinit - there's no separate "GefExe" file BinSifter
    controls the way it does for every other tool (GEF isn't a program,
    it's a gdb extension loaded via gdbinit), so this is the only way to
    avoid re-running GEF's installer, and network probe, on every single
    startup once it's already set up. A false negative here just means
    re-running an idempotent installer - not a hard failure - so this
    stays a simple substring check rather than anything more elaborate.
    """
    gdbinit = Path.home() / ".gdbinit"
    if not gdbinit.is_file():
        return False
    try:
        contents = gdbinit.read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        return False
    return "gef" in contents


def run_tool_bootstrap(config: BinSifterConfig) -> list[ToolBootstrapResult]:
    """Checks each quick-launch tool; for anything not already resolvable,
    attempts an install (network permitting). Safe to call on every
    startup - a tool that's already found costs nothing beyond the
    existing find_tool_path() check, and this never raises: any unexpected
    failure in one tool's installer is caught and reported as that tool's
    own "failed" outcome, so one broken installer can't stop the others or
    bubble up to whatever's calling this (meant to be a background thread,
    per the "must never block startup or a scan" requirement this module
    exists to satisfy).

    Every outcome is also logged here (2026-09-03) - previously
    ToolBootstrapResult.detail (which carries the real pip/download/extract
    error text) was only ever shown in a transient popup and never written
    anywhere persistent, so a real failure (e.g. Angr's pip install failing
    on a user's machine) left no trace at all in the Logs page for later
    diagnosis. "already_present" is logged at debug level (routine, happens
    on every normal startup); "installed" at info; "no_internet"/"failed"
    at warning/error so they're visible in a normal log view without
    needing debug verbosity turned on.
    """
    dest_root = get_auto_installed_tools_dir()
    results: list[ToolBootstrapResult] = []
    internet_checked = False
    internet_available = False

    def _log(result: ToolBootstrapResult) -> None:
        if result.status == "already_present":
            logger.debug("%s already present at %s", result.tool_label, result.path)
        elif result.status == "installed":
            logger.info("%s installed to %s (%s)", result.tool_label, result.path, result.detail)
        elif result.status == "no_internet":
            logger.warning("%s not installed - no internet: %s", result.tool_label, result.detail)
        else:
            logger.error("%s auto-install failed: %s", result.tool_label, result.detail)

    field_names = [*TOOL_FILE_NAMES.keys(), "GhidraHeadlessExe"]
    for field_name in field_names:
        label = _TOOL_LABELS.get(field_name, field_name)
        already = getattr(config, field_name, "") or ""

        if field_name == "GdbExe":
            # GDB itself is never auto-installed (needs a real distro
            # package manager - see module docstring), so "already present"
            # for this entry means "gdb is on PATH AND GEF is already
            # configured for it," and a missing gdb is reported as a
            # permanent "failed" with the manual-install hint rather than
            # "no_internet," since reconnecting the internet alone can't
            # fix a missing gdb the way it can for every other tool.
            if already and Path(already).is_file() and _gef_already_configured():
                result = ToolBootstrapResult(field_name, label, "already_present", path=already)
                results.append(result)
                _log(result)
                continue
            if not already or not Path(already).is_file():
                hint = _MANUAL_INSTALL_HINTS.get(field_name, "install it manually.")
                result = ToolBootstrapResult(
                    field_name, label, "failed", detail=f"gdb not found on PATH - {hint}"
                )
                results.append(result)
                _log(result)
                continue
            # gdb is present but GEF isn't configured yet - falls through
            # to the normal internet-check/installer path below.
        elif already and Path(already).is_file():
            result = ToolBootstrapResult(field_name, label, "already_present", path=already)
            results.append(result)
            _log(result)
            continue

        if not internet_checked:
            internet_available = check_internet_available()
            internet_checked = True

        if not internet_available:
            hint = _MANUAL_INSTALL_HINTS.get(field_name, "install it manually and point \"Path to tools\" at it.")
            result = ToolBootstrapResult(
                field_name, label, "no_internet",
                detail=f"No internet connection - reconnect and relaunch Winnow, or {hint}",
            )
            results.append(result)
            _log(result)
            continue

        installer = _install_gef if field_name == "GdbExe" else _INSTALLERS.get(field_name)
        if field_name == "GhidraHeadlessExe":
            installer = _install_ghidra
        if installer is None:
            continue
        try:
            result = installer(dest_root)
        except Exception as exc:  # noqa: BLE001 - absolute last resort; a per-installer try/except should already catch everything real
            logger.exception("Unexpected error auto-installing %s", label)
            result = ToolBootstrapResult(field_name, label, "failed", detail=f"Unexpected error: {exc}")
        results.append(result)
        _log(result)

    return results
