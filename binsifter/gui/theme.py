"""Color theme - direct port of the PowerShell version's Get-ThemePalette
function (BinSifter-Rowan.ps1, lines ~1339-1377). Same RGB values,
same field names (kept PascalCase to match 1:1, same convention as
models.py's FileRecord) - this is the exact palette the BinSifter_Dash.png
screenshot was rendered with, so matching it precisely is the whole point.

Both palettes are wired up and auto-selected at startup via
detect_os_dark_mode() below, matching whichever theme the OS/desktop is
actually set to - there's no in-app theme-switcher UI, but no manual
config is needed either; it just follows the system.
"""

from __future__ import annotations

import configparser
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtGui import QColor


@dataclass(frozen=True)
class ThemePalette:
    WindowBack: QColor
    SidebarBack: QColor
    SurfaceBack: QColor
    HeaderBack: QColor
    Border: QColor
    Fore: QColor
    MutedFore: QColor
    Accent: QColor
    AccentFore: QColor
    Success: QColor
    Warning: QColor
    Danger: QColor
    NavActive: QColor
    ButtonBack: QColor


DARK = ThemePalette(
    WindowBack=QColor(11, 19, 25),
    SidebarBack=QColor(18, 30, 40),
    SurfaceBack=QColor(14, 25, 32),
    HeaderBack=QColor(9, 16, 22),
    Border=QColor(49, 68, 80),
    Fore=QColor(228, 235, 240),
    MutedFore=QColor(164, 177, 187),
    Accent=QColor(31, 174, 255),
    AccentFore=QColor(255, 255, 255),
    Success=QColor(83, 201, 91),
    Warning=QColor(247, 174, 28),
    Danger=QColor(242, 82, 91),
    NavActive=QColor(30, 52, 70),
    ButtonBack=QColor(25, 39, 49),
)

LIGHT = ThemePalette(
    WindowBack=QColor(244, 245, 247),
    SidebarBack=QColor(255, 255, 255),
    SurfaceBack=QColor(255, 255, 255),
    HeaderBack=QColor(255, 255, 255),
    Border=QColor(220, 222, 226),
    Fore=QColor(30, 32, 36),
    MutedFore=QColor(110, 116, 124),
    Accent=QColor(0, 120, 212),
    AccentFore=QColor(255, 255, 255),
    Success=QColor(30, 160, 90),
    Warning=QColor(210, 140, 20),
    Danger=QColor(200, 60, 60),
    NavActive=QColor(224, 238, 252),
    ButtonBack=QColor(238, 239, 242),
)


def get_theme_palette(is_dark_mode: bool = True) -> ThemePalette:
    return DARK if is_dark_mode else LIGHT


def qcolor_to_css(color: QColor) -> str:
    """"rgba(r, g, b, a)" for embedding in Qt stylesheets."""
    return f"rgba({color.red()}, {color.green()}, {color.blue()}, {color.alpha()})"


def detect_os_dark_mode() -> bool:
    """Port of Test-SystemDarkMode (BinSifter-Rowan.ps1, lines 36-46) for
    Windows, plus real Linux detection added 2026-08-26 once real Ubuntu
    testing showed Winnow always launching in light mode on Linux
    regardless of the desktop's actual theme - this function used to just
    return False (light) unconditionally on any non-Windows platform,
    which was never correct, just unnoticed until Winnow actually ran on a
    real Linux desktop.

    Checked once at startup, not live - changing the OS theme while either
    variant is running requires a relaunch to pick up. Never raises; when
    nothing below can determine a real answer, this falls back to light
    mode, same as the original's behavior for "couldn't tell."
    """
    if sys.platform == "win32":
        return _detect_windows_dark_mode()
    if sys.platform.startswith("linux"):
        result = _detect_linux_dark_mode()
        return False if result is None else result
    return False


def _detect_windows_dark_mode() -> bool:
    """Reads the same registry value Rowan reads
    (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize
    \\AppsUseLightTheme, 0 = dark, nonzero/absent = light) so both variants
    agree on what "the OS theme" means.
    """
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        ) as key:
            value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        return value == 0
    except (ImportError, OSError):
        return False


def _detect_linux_dark_mode() -> bool | None:
    """Tries each Linux theme-detection mechanism in turn, returning as soon
    as one gives a real answer - True/False if determined, None if nothing
    below could tell (caller treats None as light, same "couldn't tell
    means light" convention as the Windows path).

    No single mechanism covers every desktop environment across Debian/Red
    Hat/Arch family distros, since "dark mode" is a desktop-environment
    concept, not a distro one - any of these three families can run GNOME,
    KDE Plasma, XFCE, or something else entirely. Tried in this order:

    1. xdg-desktop-portal's Settings API (org.freedesktop.appearance /
       color-scheme) - the one DE-agnostic mechanism, backed by whichever
       portal backend the running desktop provides (gnome, kde, xfce,
       etc.), so this alone can cover all three families when the portal
       is installed - which it increasingly is by default on GNOME/KDE
       since it's also needed for sandboxed Flatpak/Snap file pickers.
       Queried via `gdbus` (part of glib2/glib2.0, already a near-universal
       transitive dependency of GTK-based desktops) rather than adding a
       new Python dbus dependency just for this one lookup.
    2. GNOME's own gsettings key - covers GNOME itself (Fedora Workstation's
       default, a common Debian/Ubuntu and Arch desktop choice) directly,
       for the case where the portal isn't installed/running.
    3. KDE Plasma's kdeglobals config file - covers Plasma (Fedora KDE
       spin, a common Arch/openSUSE desktop choice) without needing a
       running dbus session at all, just a config file read.
    4. XFCE's xfconf-query - covers XFCE (a common lightweight choice
       across all three families) the same way.

    Each mechanism is wrapped defensively - a missing binary/config file/
    timeout just means "this mechanism had nothing to say," not a crash or
    a hard "light mode" conclusion that would block a later mechanism from
    getting a real answer.
    """
    portal_result = _linux_dark_mode_from_portal()
    if portal_result is not None:
        return portal_result

    gsettings_result = _linux_dark_mode_from_gsettings()
    if gsettings_result is not None:
        return gsettings_result

    kde_result = _linux_dark_mode_from_kdeglobals()
    if kde_result is not None:
        return kde_result

    return _linux_dark_mode_from_xfconf()


def _run_short(args: list[str]) -> str | None:
    """Runs a short-lived CLI probe and returns stripped stdout, or None for
    any failure (binary missing, nonzero exit, or a hung call past the
    2-second timeout - generous for a local IPC/config read, short enough
    to never make startup feel stuck if something's badly misconfigured).
    """
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=2)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def _linux_dark_mode_from_portal() -> bool | None:
    """org.freedesktop.portal.Settings.Read("org.freedesktop.appearance",
    "color-scheme") via gdbus - the reply is a nested variant that prints
    as something like "(<<uint32 1>>,)"; 1 = prefer dark, 2 = prefer light,
    0 = no preference. Only the digit itself is checked for, not an exact
    string match, since gdbus's variant-printing format isn't guaranteed
    stable across glib versions.
    """
    output = _run_short(
        [
            "gdbus", "call", "--session",
            "--dest", "org.freedesktop.portal.Desktop",
            "--object-path", "/org/freedesktop/portal/desktop",
            "--method", "org.freedesktop.portal.Settings.Read",
            "org.freedesktop.appearance", "color-scheme",
        ]
    )
    if output is None:
        return None
    if "uint32 1" in output:
        return True
    if "uint32 2" in output:
        return False
    return None  # "uint32 0" (no preference) or an unrecognized reply shape


def _linux_dark_mode_from_gsettings() -> bool | None:
    """GNOME 42+'s color-scheme key first (the same concept the portal
    exposes, just read directly), falling back to the older gtk-theme
    name for pre-42 GNOME/Cinnamon/other GTK desktops that predate
    color-scheme entirely.
    """
    scheme = _run_short(["gsettings", "get", "org.gnome.desktop.interface", "color-scheme"])
    if scheme is not None:
        if "prefer-dark" in scheme:
            return True
        if "prefer-light" in scheme or "default" in scheme:
            return False
    theme_name = _run_short(["gsettings", "get", "org.gnome.desktop.interface", "gtk-theme"])
    if theme_name:
        return "dark" in theme_name.lower()
    return None


def _linux_dark_mode_from_kdeglobals() -> bool | None:
    """KDE Plasma stores the active color scheme name in ~/.config/kdeglobals
    ([General] ColorScheme=...) - most of KDE's own dark schemes (including
    the default "BreezeDark") have "dark" in the name, same heuristic as
    the GTK-theme-name fallback above rather than trying to maintain an
    exact list of every dark KDE color-scheme name that exists.
    """
    kdeglobals = Path.home() / ".config" / "kdeglobals"
    if not kdeglobals.is_file():
        return None
    try:
        parser = configparser.ConfigParser()
        parser.read(kdeglobals, encoding="utf-8")
        scheme = parser.get("General", "ColorScheme", fallback="")
    except (OSError, configparser.Error):
        return None
    if not scheme:
        return None
    return "dark" in scheme.lower()


def _linux_dark_mode_from_xfconf() -> bool | None:
    """XFCE's active GTK theme name, same "dark" substring heuristic as
    gsettings' gtk-theme fallback above - xfconf-query is XFCE's own CLI
    for reading its settings store, no config file parsing needed.
    """
    theme_name = _run_short(["xfconf-query", "-c", "xsettings", "-p", "/Net/ThemeName"])
    if not theme_name:
        return None
    return "dark" in theme_name.lower()


_LOGO_HORIZONTAL_DARK = "BinSifter-Logo-Horizontal-Dark.png"
_LOGO_HORIZONTAL_LIGHT = "BinSifter-Logo-Horizontal.png"


def logo_horizontal_filename(theme: ThemePalette) -> str:
    """Which of the two horizontal-logo asset files (both already exist in
    the repo root) matches `theme` - port of the bootstrap-time
    `$logoHorizontal = if ($isDarkMode) {...} else {...}` branch
    (BinSifter-Rowan.ps1:6005-6010). `theme is DARK` (identity,
    not equality) is enough to tell them apart since DARK/LIGHT above are
    the only two ThemePalette instances that ever get constructed - callers
    never build their own.
    """
    return _LOGO_HORIZONTAL_DARK if theme is DARK else _LOGO_HORIZONTAL_LIGHT
