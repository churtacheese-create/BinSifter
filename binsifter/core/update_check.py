""""Check for updates" support for Winnow's Settings page - added per a
direct request for an Update button on all three BinSifter variants.

Winnow ships **only** as a root-owned Linux system package
(`.deb`/`.rpm`/`.pkg.tar.zst` under `/opt/binsifter-winnow`, installed via
`dpkg`/`rpm`/`pacman`). A GUI app silently rewriting root-owned files
outside its own package manager breaks that manager's integrity tracking
and can corrupt the install - the same failure mode package managers exist
to prevent. So unlike Ingot (a single portable binary with no installer,
where a real self-replace is safe), this module deliberately never installs
or overwrites anything itself: it checks GitHub, downloads the matching
package to an ordinary per-user folder, and hands back the exact command
the user should run through their own package manager.

Rowan and Winnow share one `v*` tag line on the same GitHub repo Ingot also
publishes to (Ingot's own line is the disjoint `ingot-v*`, 0.x) - so this
never calls `/releases/latest` (which would happily return whichever tag is
newest by publish time, regardless of prefix): it fetches the releases list
and filters by tag prefix itself, same approach as Ingot's
`ingot_core::update` module.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from binsifter.core.config import get_binsifter_data_root

logger = logging.getLogger(__name__)

_USER_AGENT = "BinSifter-Winnow-UpdateCheck/1.0 (+https://github.com/)"
_NETWORK_TIMEOUT_SECONDS = 8.0
_DOWNLOAD_TIMEOUT_SECONDS = 120.0
_REPO = "churtacheese-create/BinSifter"
_TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")

# manager key -> the asset filename that release publishes for it
_ASSET_NAMES = {
    "deb": "binsifter-winnow.deb",
    "rpm": "binsifter-winnow.rpm",
    "pacman": "binsifter-winnow.pkg.tar.zst",
}

# manager key -> the real install command, with {path} filled in at call time
_INSTALL_COMMANDS = {
    "deb": "sudo apt install {path}",
    "rpm": "sudo dnf install {path}",
    "pacman": "sudo pacman -U {path}",
}


@dataclass
class UpdateCheckResult:
    current_version: str
    latest_version: str
    update_available: bool
    release_url: str
    # raw GitHub API asset dicts for the matched release - kept here so
    # download_update_asset() doesn't need a second network round-trip for
    # the same two-click flow this exists to serve.
    assets: list[dict] = field(default_factory=list)


class UpdateCheckError(Exception):
    """Raised when the GitHub API can't be reached/parsed - the caller
    shows this message directly, same as av_detect.AvDetectionError."""


def _get_json(url: str, timeout: float) -> object:
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT, "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed https GitHub API host
        return json.loads(response.read().decode("utf-8"))


def _parse_tag(tag: str) -> tuple[int, int, int] | None:
    """Parses a GitHub tag like `v2.0.9` - requires the `v` prefix. Do not
    use this on a bare version string (e.g. `binsifter.__version__`,
    "2.0.9" with no `v`) - it will silently fail to match and return None;
    use `_parse_version` for that instead."""
    m = _TAG_RE.match(tag)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def _parse_version(version: str) -> tuple[int, int, int] | None:
    """Parses a bare `X.Y.Z` version string (no `v` prefix) - what
    `binsifter.__version__` actually looks like."""
    parts = version.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)  # type: ignore[return-value]


def check_for_update(current_version: str) -> UpdateCheckResult:
    """Fetches the releases list and finds the newest `v*` tag (Rowan's and
    Winnow's shared line) - never `/releases/latest`, see module docstring.
    Raises UpdateCheckError on any network/parse failure; never returns a
    partial/guessed result.
    """
    try:
        releases = _get_json(f"https://api.github.com/repos/{_REPO}/releases?per_page=30", _NETWORK_TIMEOUT_SECONDS)
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
        raise UpdateCheckError(f"Could not check for updates: {exc}") from exc

    if not isinstance(releases, list):
        raise UpdateCheckError("Unexpected response from GitHub's releases API.")

    best: tuple[int, int, int] | None = None
    best_release: dict | None = None
    for release in releases:
        if not isinstance(release, dict):
            continue
        version = _parse_tag(str(release.get("tag_name", "")))
        if version is None:
            continue
        if best is None or version > best:
            best, best_release = version, release

    current = _parse_version(current_version) or (0, 0, 0)
    if best is None or best_release is None:
        return UpdateCheckResult(
            current_version=current_version,
            latest_version=current_version,
            update_available=False,
            release_url=f"https://github.com/{_REPO}/releases",
        )

    return UpdateCheckResult(
        current_version=current_version,
        latest_version=".".join(str(n) for n in best),
        update_available=best > current,
        release_url=str(best_release.get("html_url", "")),
        assets=[a for a in best_release.get("assets", []) if isinstance(a, dict)],
    )


def detect_package_manager() -> str | None:
    """Which package manager actually owns *this* Winnow install - checked
    against the real package database (`dpkg -s`/`rpm -q`/`pacman -Qi`),
    not just "is this binary on PATH" (a machine can have more than one
    package manager installed). Returns "deb"/"rpm"/"pacman", or None if
    Winnow isn't installed through any of them (e.g. running from source).
    """
    checks = (
        ("deb", ["dpkg", "-s", "binsifter-winnow"]),
        ("rpm", ["rpm", "-q", "binsifter-winnow"]),
        ("pacman", ["pacman", "-Qi", "binsifter-winnow"]),
    )
    for key, cmd in checks:
        if not shutil.which(cmd[0]):
            continue
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            return key
    return None


def is_winnow_running() -> bool:
    """Best-effort check for another live Winnow process - a courtesy note
    in the install guidance, not a hard gate (package managers handle
    replacing a running binary's file fine on Linux; this is just so the
    user remembers to restart it afterward)."""
    if not shutil.which("pgrep"):
        return False
    try:
        result = subprocess.run(["pgrep", "-f", "binsifter-winnow"], capture_output=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def install_command_for(manager: str, path: Path) -> str:
    return _INSTALL_COMMANDS[manager].format(path=path)


def download_update_asset(result: UpdateCheckResult, manager: str) -> Path:
    """Downloads the asset matching `manager` from `result.assets` into a
    plain per-user folder (Downloads if it exists, else BinSifter's own
    data root) - a pure file write, no privilege needed. Never invokes the
    package manager itself; see module docstring for why."""
    asset_name = _ASSET_NAMES.get(manager)
    if not asset_name:
        raise UpdateCheckError(f"No known asset for package manager '{manager}'.")

    asset = next((a for a in result.assets if a.get("name") == asset_name), None)
    if asset is None:
        raise UpdateCheckError(f"Release {result.latest_version} has no asset named {asset_name}.")
    url = asset.get("browser_download_url")
    if not url:
        raise UpdateCheckError(f"{asset_name} has no download URL.")

    downloads_dir = Path.home() / "Downloads"
    dest_dir = downloads_dir if downloads_dir.is_dir() else get_binsifter_data_root()
    dest = dest_dir / asset_name

    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=_DOWNLOAD_TIMEOUT_SECONDS) as response:  # noqa: S310 - GitHub release asset URL from the API response itself
            dest.write_bytes(response.read())
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise UpdateCheckError(f"Could not download {asset_name}: {exc}") from exc

    return dest
