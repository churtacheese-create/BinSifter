"""About page - port of New-AboutPage (BinSifter-Rowan_v1.3.0-beta.1.ps1, lines
~4933-4971). Logo, version line, short description, integrated-tools line.

Version now comes from binsifter.__version__ (this port's real single
source of truth, following the project's SemVer scheme adopted 2026-07-29)
rather than the PowerShell original's $AppVersion script variable.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from binsifter import __version__
from binsifter.core.config import get_bundled_asset_path
from binsifter.gui.theme import ThemePalette, logo_horizontal_filename, qcolor_to_css
from binsifter.gui.widgets import accent_to_css


class AboutPage(QWidget):
    def __init__(self, theme: ThemePalette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setStyleSheet(f"background-color: {qcolor_to_css(theme.WindowBack)};")

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(0)

        # 2026-08-06: was a hardcoded dark-mode filename, same fix/reasoning
        # as main_window.py's sidebar logo - see theme.logo_horizontal_filename().
        # 2026-08-08: switched from a __file__-relative parent chain to
        # get_binsifter_root(), which resolves correctly under a frozen/
        # installed exe too (see that function's docstring).
        # 2026-08-14: switched again, to get_bundled_asset_path() - see that
        # function's docstring for why get_binsifter_root() alone stopped
        # finding this file under a real installed build.
        logo_path = get_bundled_asset_path(logo_horizontal_filename(theme))
        if logo_path.is_file():
            logo_label = QLabel()
            pixmap = QPixmap(str(logo_path))
            scaled = pixmap.scaledToWidth(320, Qt.TransformationMode.SmoothTransformation)
            logo_label.setPixmap(scaled)
            root.addWidget(logo_label)

        root.addSpacing(16)

        version_label = QLabel(f"BinSifter Winnow {__version__}")
        font = version_label.font()
        font.setFamily("Segoe UI")
        font.setPointSize(12)
        font.setBold(True)
        version_label.setFont(font)
        version_label.setStyleSheet(f"color: {accent_to_css(theme.Fore)}; border: none; background: transparent;")
        root.addWidget(version_label)

        root.addSpacing(14)

        desc_label = QLabel(
            "BinSifter is a bounded-parallel binary triage tool. It hashes each file once "
            "(SHA-1/MD5), filters known-good files against an NSRL hash set, and runs YARA and "
            "capa against the remaining files to surface suspicious matches and identified "
            "capabilities."
        )
        desc_label.setWordWrap(True)
        desc_label.setMaximumWidth(700)
        desc_font = desc_label.font()
        desc_font.setFamily("Segoe UI")
        desc_font.setPointSize(10)
        desc_label.setFont(desc_font)
        desc_label.setStyleSheet(f"color: {accent_to_css(theme.MutedFore)}; border: none; background: transparent;")
        root.addWidget(desc_label)

        root.addSpacing(26)

        tools_label = QLabel("Integrates: YARA, capa, ssdeep (+ post-scan clustering), FLOSS, NSRL RDS, Speakeasy")
        tools_font = tools_label.font()
        tools_font.setFamily("Segoe UI")
        tools_font.setPointSize(10)
        tools_label.setFont(tools_font)
        tools_label.setStyleSheet(f"color: {accent_to_css(theme.MutedFore)}; border: none; background: transparent;")
        root.addWidget(tools_label)

        root.addStretch(1)
