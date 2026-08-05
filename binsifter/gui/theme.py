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
