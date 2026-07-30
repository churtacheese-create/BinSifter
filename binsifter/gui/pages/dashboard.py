"""Dashboard page - port of New-DashboardPage (BinSifter_v1.3.0-alpha.2.ps1,
lines ~3514-3920). Visual order top-to-bottom matches the reference
screenshot (BinSifter_Dash.png) exactly: Enrichment Summary (two tile
rows), SSDEEP Cluster Heat Map (one tile row), YARA Severity Breakdown
(bar chart), then the free-text summary line - this is also the actual
source-order in the PowerShell script once WinForms' Dock=Top stacking
(last-added-ends-up-topmost) is accounted for, not a re-invented layout.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QGridLayout, QLabel, QVBoxLayout, QWidget

from binsifter.core.models import FileRecord
from binsifter.gui.dashboard_stats import DashboardStats
from binsifter.gui.theme import ThemePalette
from binsifter.gui.widgets import SeverityBarChart, StatTile, get_heat_color


class DashboardPage(QWidget):
    def __init__(self, theme: ThemePalette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._theme = theme
        self._on_tile_click = None  # set via set_tile_click_handler(), see main_window.py

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ===== Enrichment Summary =====
        root.addWidget(_section_title(theme, "Enrichment Summary", top_margin=0))

        enrichment_row = QGridLayout()
        enrichment_row.setSpacing(16)
        self.tile_imphash = StatTile(theme, "Imphash Clusters", theme.Accent, "layers", compact=True)
        self.tile_unsigned = StatTile(theme, "Unsigned", theme.Warning, "check", compact=True)
        self.tile_known_bad = StatTile(theme, "Known-Bad", theme.Danger, "target", compact=True)
        self.tile_iocs = StatTile(theme, "Files With IOCs", theme.Accent, "document", compact=True)
        self.tile_escalated = StatTile(theme, "Escalated", theme.Danger, "trend", compact=True)
        for i, tile in enumerate(
            (self.tile_imphash, self.tile_unsigned, self.tile_known_bad, self.tile_iocs, self.tile_escalated)
        ):
            tile.setMinimumHeight(120)
            enrichment_row.addWidget(tile, 0, i)
        root.addLayout(_padded(enrichment_row))

        files_row = QGridLayout()
        files_row.setSpacing(16)
        self.tile_files = StatTile(theme, "Files Completed", theme.Accent, "file", "Total files processed")
        self.tile_yara = StatTile(theme, "YARA Hits", theme.Warning, "target", "Matching rules found")
        self.tile_capa_scans = StatTile(theme, "Capa Scans", theme.Accent, "layers", "Files analyzed")
        self.tile_capa = StatTile(theme, "Capa Rule Detections", theme.Accent, "check", "Capabilities identified")
        self.tile_nsrl = StatTile(theme, "NSRL Matches", theme.Accent, "database", "Known file matches")
        for i, tile in enumerate(
            (self.tile_files, self.tile_yara, self.tile_capa_scans, self.tile_capa, self.tile_nsrl)
        ):
            tile.setMinimumHeight(150)
            files_row.addWidget(tile, 0, i)
        margins = _padded(files_row)
        margins.setContentsMargins(28, 16, 28, 0)
        root.addLayout(margins)

        # ===== SSDEEP Cluster Heat Map =====
        root.addWidget(_section_title(theme, "SSDEEP Cluster Heat Map", top_margin=20))

        heat_row = QGridLayout()
        heat_row.setSpacing(16)
        self.heat_clusters = StatTile(theme, "Similarity Clusters", theme.Accent, "cluster", compact=True)
        self.heat_largest = StatTile(theme, "Largest Cluster", theme.Accent, "users", compact=True)
        self.heat_singletons = StatTile(theme, "Singletons", theme.Accent, "user", compact=True)
        self.heat_avg_score = StatTile(theme, "Avg. Similarity", theme.Accent, "percent", compact=True)
        self.heat_above_85 = StatTile(theme, "Files Above 85%", theme.Accent, "trend", compact=True)
        self.heat_previously_seen = StatTile(theme, "Previously Seen Clusters", theme.Accent, "history", compact=True)
        for i, tile in enumerate(
            (
                self.heat_clusters, self.heat_largest, self.heat_singletons,
                self.heat_avg_score, self.heat_above_85, self.heat_previously_seen,
            )
        ):
            tile.setMinimumHeight(120)
            heat_row.addWidget(tile, 0, i)
        root.addLayout(_padded(heat_row))

        # ===== YARA Severity Breakdown =====
        chart_wrap = _padded_widget()
        chart_layout = QVBoxLayout(chart_wrap)
        chart_layout.setContentsMargins(28, 20, 28, 0)
        self.severity_chart = SeverityBarChart(theme)
        chart_layout.addWidget(self.severity_chart)
        root.addWidget(chart_wrap)

        # ===== Summary line =====
        summary_wrap = _padded_widget()
        summary_layout = QVBoxLayout(summary_wrap)
        summary_layout.setContentsMargins(28, 20, 28, 0)
        self.summary_label = QLabel(
            "No scan running. Select a folder and click “Run Scan” to get started."
        )
        self.summary_label.setWordWrap(True)
        self.summary_label.setFont(QFont("Segoe UI", 11))
        self.summary_label.setStyleSheet(f"color: rgb({theme.Fore.red()},{theme.Fore.green()},{theme.Fore.blue()});")
        summary_layout.addWidget(self.summary_label)
        root.addWidget(summary_wrap)

        root.addStretch(1)

        self._all_tiles = {
            "YARA Hits": (self.tile_yara, lambda r: r.YaraHitCount > 0),
            "Capa Scans": (self.tile_capa_scans, lambda r: r.CapaEligible),
            "Capa Rule Detections": (self.tile_capa, lambda r: r.CapaDetectionCount > 0),
            "NSRL Matches": (self.tile_nsrl, lambda r: r.NsrlMatch),
            "Imphash clusters (2+ files)": (self.tile_imphash, lambda r: r.ImphashClusterId >= 0 and r.ImphashClusterSize >= 2),
            "Unsigned / invalid signature": (self.tile_unsigned, lambda r: r.SignatureStatus and r.SignatureStatus != "Valid"),
            "Known-bad (blocklist match)": (self.tile_known_bad, lambda r: r.ReputationStatus == "KnownBad"),
            "Files with extracted IOCs": (self.tile_iocs, lambda r: r.IocCount > 0),
            "Disposition: Escalated": (self.tile_escalated, lambda r: r.Disposition == "Escalated"),
            "SSDEEP clusters (2+ files)": (self.heat_clusters, lambda r: r.SsdeepClusterId >= 0 and r.SsdeepClusterSize >= 2),
            "SSDEEP singletons": (self.heat_singletons, lambda r: r.SsdeepClusterSize == 1),
            "SSDEEP similarity >= 85%": (self.heat_above_85, lambda r: r.SsdeepHasHighSimilarity),
            "Previously-seen SSDEEP clusters": (self.heat_previously_seen, lambda r: r.SsdeepPreviouslySeen),
        }

    def update_from_records(self, records: list[FileRecord]) -> None:
        """Repopulates every tile/chart from a fresh scan's records - the
        Python port's equivalent of the PowerShell version's incremental
        UiTotals refresh, but computed fresh each time rather than
        maintained as a running delta (see dashboard_stats.py's docstring
        for why)."""
        stats = DashboardStats.from_records(records)
        theme = self._theme

        self.tile_files.set_value(stats.completed_count)
        self.tile_yara.set_value(stats.yara_hits)
        self.tile_capa_scans.set_value(stats.capa_scans)
        self.tile_capa.set_value(stats.capa_hits)
        self.tile_nsrl.set_value(stats.nsrl_matches)
        self.tile_imphash.set_value(stats.imphash_clustered)
        self.tile_unsigned.set_value(stats.unsigned)
        self.tile_known_bad.set_value(stats.known_bad)
        self.tile_iocs.set_value(stats.with_iocs)
        self.tile_escalated.set_value(stats.escalated)

        self.severity_chart.set_data(stats.severity)

        denom = stats.heat_denominator
        self.heat_clusters.set_value(stats.num_clusters)
        self.heat_clusters.set_value_color(get_heat_color(theme, stats.num_clusters / denom))
        self.heat_largest.set_value(stats.largest_cluster_size)
        self.heat_largest.set_value_color(get_heat_color(theme, stats.largest_cluster_size / denom))
        self.heat_singletons.set_value(stats.singletons)
        self.heat_singletons.set_value_color(get_heat_color(theme, stats.singletons / denom))
        self.heat_avg_score.set_value(stats.avg_score)
        self.heat_avg_score.set_value_color(get_heat_color(theme, stats.avg_score / 100.0))
        self.heat_above_85.set_value(stats.files_above_85)
        self.heat_above_85.set_value_color(get_heat_color(theme, stats.files_above_85 / denom))
        self.heat_previously_seen.set_value(stats.previously_seen_clusters)
        self.heat_previously_seen.set_value_color(get_heat_color(theme, stats.previously_seen_clusters / denom))

        total = len(records)
        self.summary_label.setText(f"Last scan finished: {stats.completed_count} / {total} files completed.")


def _section_title(theme: ThemePalette, text: str, top_margin: int) -> QWidget:
    wrap = _padded_widget()
    layout = QVBoxLayout(wrap)
    layout.setContentsMargins(28, top_margin + 20 if top_margin else 20, 28, 8)
    label = QLabel(text)
    font = QFont("Segoe UI", 11)
    font.setBold(True)
    label.setFont(font)
    label.setStyleSheet(f"color: rgb({theme.Fore.red()},{theme.Fore.green()},{theme.Fore.blue()});")
    layout.addWidget(label)
    return wrap


def _padded_widget() -> QWidget:
    w = QWidget()
    return w


def _padded(layout: QGridLayout) -> QGridLayout:
    """Wraps a bare QGridLayout with the page's standard 28px left/right
    content margin (matching $content.Padding in the PowerShell version)."""
    layout.setContentsMargins(28, 0, 28, 0)
    return layout
