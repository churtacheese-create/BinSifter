"""Reusable themed widgets - direct ports of the PowerShell version's
New-StatTile, nav-button construction, and severity-chart Paint handler
(BinSifter_v1.3.0-alpha.2.ps1, lines ~3532-3589 for tiles, ~3675-3749 for
the chart, ~5018-5062 for nav buttons, ~1549-1562 for the heat-map color
scale). Coordinates/sizes are copied 1:1 rather than re-derived, and each
tile/chart is built with fixed child positions (setGeometry), matching the
original's absolute Location/Size approach - the point of this pass is
visual fidelity to an existing, approved design, not idiomatic Qt layout
usage.
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QMouseEvent, QPaintEvent, QPainter, QPen
from PySide6.QtWidgets import QFrame, QLabel, QWidget

from binsifter.gui.icons import make_line_icon
from binsifter.gui.theme import ThemePalette


def merge_color(color_a: QColor, color_b: QColor, t: float) -> QColor:
    """Direct port of Merge-Color - linear RGB interpolation, t clamped to
    [0, 1]."""
    t = max(0.0, min(1.0, t))
    r = int(color_a.red() + (color_b.red() - color_a.red()) * t)
    g = int(color_a.green() + (color_b.green() - color_a.green()) * t)
    b = int(color_a.blue() + (color_b.blue() - color_a.blue()) * t)
    return QColor(r, g, b)


def get_heat_color(theme: ThemePalette, intensity: float) -> QColor:
    """Direct port of Get-HeatColor: Success->Warning for the bottom half
    of the 0-1 intensity range, Warning->Danger for the top half - the
    "heat" in the SSDEEP heat map's tile colors."""
    i = max(0.0, min(1.0, intensity))
    if i <= 0.5:
        return merge_color(theme.Success, theme.Warning, i / 0.5)
    return merge_color(theme.Warning, theme.Danger, (i - 0.5) / 0.5)


class StatTile(QFrame):
    """Port of New-StatTile. `compact=True` matches the PowerShell version's
    -Compact switch (smaller icon/font, no subtitle, used for the
    Enrichment Summary's top row and the SSDEEP heat map row); compact=False
    matches the regular tile (used for the Enrichment Summary's bottom row -
    Files Completed/YARA Hits/etc - which carries a subtitle).
    """

    clicked = Signal()

    def __init__(
        self,
        theme: ThemePalette,
        caption: str,
        accent_color: QColor,
        icon_name: str = "file",
        subtitle: str = "",
        compact: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._theme = theme
        self._accent_color = accent_color

        self.setFrameShape(QFrame.Shape.Box)
        self.setLineWidth(1)
        self.setStyleSheet(
            f"StatTile {{ background-color: {accent_to_css(theme.SurfaceBack)}; "
            f"border: 1px solid {accent_to_css(theme.Border)}; }}"
        )
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        caption_label = QLabel(caption, self)
        caption_label.setStyleSheet(f"color: {accent_to_css(theme.MutedFore)}; border: none; background: transparent;")

        icon_label = QLabel(self)
        icon_label.setStyleSheet("background: transparent; border: none;")
        icon_label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

        self._value_label = QLabel("0", self)
        self._value_label.setStyleSheet(
            f"color: {accent_to_css(accent_color)}; border: none; background: transparent;"
        )

        if compact:
            caption_label.setFont(QFont("Segoe UI", 9))
            caption_label.setGeometry(10, 10, 160, 18)
            icon_size = 38
            icon_label.setPixmap(make_line_icon(icon_name, accent_color, size=icon_size))
            icon_label.setGeometry(10, 48, icon_size, icon_size)
            self._value_label.setFont(_semibold_font(23))
            self._value_label.setGeometry(54, 46, 140, 40)
        else:
            caption_label.setFont(QFont("Segoe UI", 10))
            caption_label.setGeometry(18, 14, 220, 20)
            icon_size = 48
            icon_label.setPixmap(make_line_icon(icon_name, accent_color, size=icon_size))
            icon_label.setGeometry(16, 47, icon_size, icon_size)
            self._value_label.setFont(_semibold_font(25))
            self._value_label.setGeometry(70, 44, 160, 44)

            if subtitle:
                subtitle_label = QLabel(subtitle, self)
                subtitle_label.setStyleSheet(
                    f"color: {accent_to_css(theme.MutedFore)}; border: none; background: transparent;"
                )
                subtitle_label.setFont(QFont("Segoe UI", 8))
                subtitle_label.setGeometry(72, 87, 220, 18)

    def set_value(self, value: object) -> None:
        self._value_label.setText(str(value))

    def set_value_color(self, color: QColor) -> None:
        self._value_label.setStyleSheet(f"color: {accent_to_css(color)}; border: none; background: transparent;")

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802 - Qt override
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


def _semibold_font(point_size: int) -> QFont:
    font = QFont("Segoe UI Semibold", point_size)
    font.setWeight(QFont.Weight.DemiBold)
    return font


def accent_to_css(color: QColor) -> str:
    return f"rgba({color.red()}, {color.green()}, {color.blue()}, {color.alpha()})"


# Same 5-bucket order/colors as the PowerShell version's $severityChartOrder/
# $severityChartColors - Medium/Low intentionally reuse the theme's
# Accent/Success colors (not independent hardcoded ones), same as the
# original.
SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Unknown")


def severity_chart_colors(theme: ThemePalette) -> dict[str, QColor]:
    return {
        "Critical": QColor(239, 68, 68),
        "High": QColor(245, 158, 11),
        "Medium": theme.Accent,
        "Low": theme.Success,
        "Unknown": QColor(119, 129, 142),
    }


class SeverityBarChart(QWidget):
    """Port of the severity-chart Paint handler - a small measured bar
    chart with no bundled charting library, same as the original's own
    rationale (no System.Windows.Forms.DataVisualization equivalent
    available, drawn directly instead).
    """

    bar_clicked = Signal(str)

    def __init__(self, theme: ThemePalette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._theme = theme
        self._colors = severity_chart_colors(theme)
        self.data: dict[str, int] = {k: 0 for k in SEVERITY_ORDER}
        self._bar_rects: dict[str, QRectF] = {}
        self.setStyleSheet(
            f"background-color: {accent_to_css(theme.SurfaceBack)}; border: 1px solid {accent_to_css(theme.Border)};"
        )
        self.setMinimumHeight(220)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def set_data(self, data: dict[str, int]) -> None:
        self.data = {k: int(data.get(k, 0)) for k in SEVERITY_ORDER}
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:  # noqa: N802 - Qt override
        theme = self._theme
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        title_font = QFont("Segoe UI", 10)
        value_font = QFont("Segoe UI", 13)
        value_font.setBold(True)
        caption_font = QFont("Segoe UI", 9)
        axis_font = QFont("Segoe UI", 8)

        painter.setFont(title_font)
        painter.setPen(theme.MutedFore)
        painter.drawText(QPointF(18.0, 14.0 + painter.fontMetrics().ascent()), "YARA Severity Breakdown")

        gap = 24
        bar_count = len(SEVERITY_ORDER)
        chart_top = 52
        chart_bottom = self.height() - 34
        chart_height = chart_bottom - chart_top
        chart_left = 48
        chart_right = self.width() - 16
        plot_width = chart_right - chart_left
        bar_width = max(20.0, (plot_width - gap * (bar_count + 1)) / bar_count)

        max_val = 1
        for k in SEVERITY_ORDER:
            if self.data[k] > max_val:
                max_val = self.data[k]
        axis_max = max(10, int(-(-max_val // 10)) * 10)  # ceil(max_val/10)*10

        grid_pen = QPen(theme.Border, 1, Qt.PenStyle.DotLine)
        axis_pen = QPen(theme.MutedFore, 1)
        painter.setFont(axis_font)

        for tick in range(0, 6):
            tick_value = int(axis_max * tick / 5.0)
            tick_y = chart_bottom - (chart_height * tick / 5.0)
            painter.setPen(grid_pen)
            painter.drawLine(QPointF(chart_left, tick_y), QPointF(chart_right, tick_y))
            painter.setPen(axis_pen)
            painter.drawLine(QPointF(chart_left - 5, tick_y), QPointF(chart_left, tick_y))

            tick_text = str(tick_value)
            metrics = painter.fontMetrics()
            text_width = metrics.horizontalAdvance(tick_text)
            painter.setPen(theme.MutedFore)
            painter.drawText(
                QPointF(chart_left - text_width - 8, tick_y + metrics.ascent() / 2 - metrics.descent() / 2),
                tick_text,
            )

        painter.setPen(axis_pen)
        painter.drawLine(QPointF(chart_left, chart_top), QPointF(chart_left, chart_bottom))

        self._bar_rects.clear()
        x = float(chart_left + gap)
        for key in SEVERITY_ORDER:
            val = self.data[key]
            bar_height = (val / axis_max) * chart_height if axis_max else 0.0
            if val > 0 and bar_height < 3:
                bar_height = 3
            y = chart_bottom - bar_height

            painter.fillRect(QRectF(x, y, bar_width, bar_height), self._colors[key])

            painter.setFont(value_font)
            painter.setPen(theme.Fore)
            val_str = str(val)
            val_width = painter.fontMetrics().horizontalAdvance(val_str)
            painter.drawText(
                QPointF(x + (bar_width - val_width) / 2, y - painter.fontMetrics().descent() - 2),
                val_str,
            )

            painter.setFont(caption_font)
            painter.setPen(theme.MutedFore)
            cap_width = painter.fontMetrics().horizontalAdvance(key)
            painter.drawText(
                QPointF(x + (bar_width - cap_width) / 2, chart_bottom + 6 + painter.fontMetrics().ascent()),
                key,
            )

            self._bar_rects[key] = QRectF(x, chart_top, bar_width, chart_bottom - chart_top)
            x += bar_width + gap

        painter.end()

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802 - Qt override
        pos = event.position()
        for key, rect in self._bar_rects.items():
            if rect.contains(pos):
                self.bar_clicked.emit(key)
                return
        super().mousePressEvent(event)


class NavButton(QFrame):
    """Port of the sidebar nav-button construction (icon + label, active-
    state recoloring) - one instance per sidebar entry."""

    clicked = Signal()

    def __init__(self, theme: ThemePalette, icon_name: str, label: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._theme = theme
        self._icon_name = icon_name
        self.setFixedHeight(48)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        self._icon_label = QLabel(self)
        self._icon_label.setGeometry(22, 9, 30, 30)
        self._icon_label.setStyleSheet("background: transparent; border: none;")
        self._icon_label.setScaledContents(True)

        self._text_label = QLabel(label, self)
        self._text_label.setGeometry(72, 0, 210, 48)
        self._text_label.setFont(QFont("Segoe UI", 10.5))
        self._text_label.setStyleSheet("background: transparent; border: none;")
        self._text_label.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)

        self.set_active(False)

    def set_active(self, active: bool) -> None:
        theme = self._theme
        back = theme.NavActive if active else theme.SidebarBack
        fore = theme.Accent if active else theme.Fore
        icon_color = theme.Accent if active else theme.MutedFore

        self.setStyleSheet(f"NavButton {{ background-color: {accent_to_css(back)}; border: none; }}")
        self._text_label.setStyleSheet(f"color: {accent_to_css(fore)}; background: transparent; border: none;")
        self._icon_label.setPixmap(make_line_icon(self._icon_name, icon_color, size=30))

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802 - Qt override
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)
