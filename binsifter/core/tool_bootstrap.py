"""First-run auto-installer for Winnow's quick-launch tools - built
2026-09-03 directly in response to the project owner's request: on
startup, check whether each of the five quick-launch tools (PE-bear, Anya,
DIE, Rizin, Angr) is already findable; if not, try to install it; if that
needs the internet and there isn't any, tell the user to either reconnect
and relaunch or install it themselves. In every case, a missing/failed
tool must never block Winnow from loading or from running a scan - every
function in this module is written to fail soft, never raise out to a
caller running on the GUI thread.

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
import shutil
import stat
import subprocess
import tarfile
import urllib.error
import urllib.request
import venv
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
    "RizinExe": (
        "install via your distro's package manager (e.g. \"sudo apt install rizin\", "
        "\"sudo pacman -S rizin\") or download the static build from "
        "https://github.com/rizinorg/rizin/releases/latest."
    ),
    "AngrExe": (
        "run: pipx install angr (or pip install angr in a virtualenv of your own)."
    ),
}

_TOOL_LABELS: dict[str, str] = {
    "PeBearExe": "PE-bear",
    "AnyaExe": "Anya",
    "DieExe": "DIE",
    "RizinExe": "Rizin",
    "AngrExe": "Angr",
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


def _install_rizin(dest_root: Path) -> ToolBootstrapResult:
    label = _TOOL_LABELS["RizinExe"]
    try:
        assets = _latest_release_assets("rizinorg", "rizin")
    except Exception as exc:  # noqa: BLE001
        return ToolBootstrapResult(
            "RizinExe", label, "failed", detail=f"Could not query rizinorg/rizin's latest release: {exc}"
        )
    # "static" + "x86_64" alone would also match the Android static build
    # (rizin-vX.Y.Z-android-x86_64.tar.gz carries neither token together
    # with "static" in the same asset... but double-check explicitly
    # anyway, since asset naming across releases has changed before -
    # excluding "android" is a cheap, explicit safety net either way.
    asset = _pick_asset(assets, must_contain=("static", "x86_64"), must_not_contain=("android",))
    if asset is None:
        return ToolBootstrapResult(
            "RizinExe", label, "failed", detail="No static x86_64 Linux build found in rizinorg/rizin's latest release"
        )
    extract_dir = dest_root / "rizin"
    archive_path = extract_dir / asset["name"]
    try:
        _download(asset["browser_download_url"], archive_path)
        with tarfile.open(archive_path) as tar:
            tar.extractall(extract_dir)  # noqa: S202 - trusted source (GitHub release we just verified the name of)
        archive_path.unlink(missing_ok=True)
    except Exception as exc:  # noqa: BLE001
        return ToolBootstrapResult("RizinExe", label, "failed", detail=f"Download/extract failed: {exc}")
    resolved = find_tool_path(extract_dir, TOOL_FILE_NAMES["RizinExe"])
    if not resolved:
        return ToolBootstrapResult(
            "RizinExe", label, "failed", detail=f"Extracted {asset['name']} but couldn't locate the rizin binary inside"
        )
    _make_executable(Path(resolved))
    return ToolBootstrapResult("RizinExe", label, "installed", path=resolved, detail=f"Downloaded {asset['name']}")


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
    try:
        venv.create(venv_dir, with_pip=True, clear=True)
    except Exception as exc:  # noqa: BLE001
        return ToolBootstrapResult("AngrExe", label, "failed", detail=f"Could not create a virtualenv: {exc}")

    venv_python = venv_dir / "bin" / "python"
    if not venv_python.is_file():
        return ToolBootstrapResult("AngrExe", label, "failed", detail="Virtualenv creation didn't produce a python binary")

    try:
        subprocess.run(
            [str(venv_python), "-m", "pip", "install", "--quiet", "--disable-pip-version-check", "angr"],
            check=True,
            capture_output=True,
            text=True,
            timeout=_DOWNLOAD_TIMEOUT_SECONDS * 3,  # angr pulls a real dependency chain - a plain download timeout is too tight
        )
    except subprocess.CalledProcessError as exc:
        return ToolBootstrapResult(
            "AngrExe", label, "failed",
            detail=f"pip install angr failed: {(exc.stderr or '').strip()[-500:] or exc}",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ToolBootstrapResult("AngrExe", label, "failed", detail=f"pip install angr failed: {exc}")

    angr_exe = venv_dir / "bin" / "angr"
    if not angr_exe.is_file():
        return ToolBootstrapResult(
            "AngrExe", label, "failed", detail="angr installed but no bin/angr console script was produced"
        )
    return ToolBootstrapResult("AngrExe", label, "installed", path=str(angr_exe), detail="Installed into a private virtualenv")


_INSTALLERS: dict[str, Callable[[Path], ToolBootstrapResult]] = {
    "PeBearExe": _install_pe_bear,
    "AnyaExe": _install_anya,
    "DieExe": _install_die,
    "RizinExe": _install_rizin,
    "AngrExe": _install_angr,
}


def run_tool_bootstrap(config: BinSifterConfig) -> list[ToolBootstrapResult]:
    """Checks each of the five quick-launch tools; for anything not
    already resolvable, attempts an install (network permitting). Safe to
    call on every startup - a tool that's already found costs nothing
    beyond the existing find_tool_path() check, and this never raises: any
    unexpected failure in one tool's installer is caught and reported as
    that tool's own "failed" outcome, so one broken installer can't stop
    the others or bubble up to whatever's calling this (meant to be a
    background thread, per the "must never block startup or a scan"
    requirement this module exists to satisfy).

    Deliberately excludes Ghidra - unlike the other five, it's a multi-
    hundred-MB archive with its own JDK prerequisite, a meaningfully
    bigger and slower download than any of these, and left for the user to
    install manually per docs/winnow.md as before.
    """
    dest_root = get_auto_installed_tools_dir()
    results: list[ToolBootstrapResult] = []
    internet_checked = False
    internet_available = False

    for field_name in TOOL_FILE_NAMES:
        label = _TOOL_LABELS.get(field_name, field_name)
        already = getattr(config, field_name, "") or ""
        if already and Path(already).is_file():
            results.append(ToolBootstrapResult(field_name, label, "already_present", path=already))
            continue

        if not internet_checked:
            internet_available = check_internet_available()
            internet_checked = True

        if not internet_available:
            hint = _MANUAL_INSTALL_HINTS.get(field_name, "install it manually and point \"Path to tools\" at it.")
            results.append(
                ToolBootstrapResult(
                    field_name, label, "no_internet",
                    detail=f"No internet connection - reconnect and relaunch Winnow, or {hint}",
                )
            )
            continue

        installer = _INSTALLERS.get(field_name)
        if installer is None:
            continue
        try:
            results.append(installer(dest_root))
        except Exception as exc:  # noqa: BLE001 - absolute last resort; a per-installer try/except should already catch everything real
            logger.exception("Unexpected error auto-installing %s", label)
            results.append(ToolBootstrapResult(field_name, label, "failed", detail=f"Unexpected error: {exc}"))

    return results
