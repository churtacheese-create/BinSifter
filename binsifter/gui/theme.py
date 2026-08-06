"""Color theme - direct port of the PowerShell version's Get-ThemePalette
function (BinSifter-Rowan_v1.3.0-beta.1.ps1, lines ~1339-1377). Same RGB values,
same field names (kept PascalCase to match 1:1, same convention as
models.py's FileRecord) - this is the exact palette the BinSifter_Dash.png
screenshot was rendered with, so matching it precisely is the whole point.

Only dark mode is wired up in the GUI for now (matching the reference
screenshot) - the light palette is ported too since it cost nothing extra
and the original supported both, but no theme-switcher UI exists yet.
"""

from __future__ import annotations

from dataclasses import dataclass

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
    """Port of Test-SystemDarkMode (BinSifter-Rowan_v1.3.0-beta.1.ps1, lines
    36-46) - until 2026-08-06 this had no Python equivalent at all, and
    get_theme_palette() above (despite existing since early on) was never
    actually called anywhere: main_window.py hardcoded `self.theme = DARK`
    unconditionally, so Winnow always looked dark regardless of the OS
    setting, unlike Rowan.

    Reads the exact same registry value Rowan reads
    (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize
    \\AppsUseLightTheme, 0 = dark, nonzero/absent = light) so both variants
    agree on what "the OS theme" means, rather than picking some different
    Python-native detection mechanism that could disagree with Rowan on an
    edge case. Checked once at startup, not live - same as Rowan, which
    reads this once before Show-MainWindow and has no in-app theme
    switcher either; changing the OS theme while either variant is already
    running requires a relaunch to pick up.

    Falls back to light mode (matching Test-SystemDarkMode's own `catch {
    return $false }`) if `winreg` isn't importable at all (this code path
    exists for non-Windows platforms - see binsifter/__init__.py's note on
    Winnow's cross-platform goal) or the key/value is missing or
    unreadable for any other reason (older Windows without this key, a
    locked-down environment, etc.) - never raises, same graceful-degrade
    philosophy as the rest of this codebase.
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


_LOGO_HORIZONTAL_DARK = "BinSifter-Logo-Horizontal-Dark.png"
_LOGO_HORIZONTAL_LIGHT = "BinSifter-Logo-Horizontal.png"


def logo_horizontal_filename(theme: ThemePalette) -> str:
    """Which of the two horizontal-logo asset files (both already exist in
    the repo root) matches `theme` - port of the bootstrap-time
    `$logoHorizontal = if ($isDarkMode) {...} else {...}` branch
    (BinSifter-Rowan_v1.3.0-beta.1.ps1:6005-6010). `theme is DARK` (identity,
    not equality) is enough to tell them apart since DARK/LIGHT above are
    the only two ThemePalette instances that ever get constructed - callers
    never build their own.
    """
    return _LOGO_HORIZONTAL_DARK if theme is DARK else _LOGO_HORIZONTAL_LIGHT
