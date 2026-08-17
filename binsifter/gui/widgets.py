"""Reusable themed widgets - direct ports of the PowerShell version's
New-StatTile, nav-button construction, and severity-chart Paint handler
(BinSifter-Rowan_v1.3.0-beta.1.ps1, lines ~3532-3589 for tiles, ~3675-3749 for
the chart, ~5018-5062 for nav buttons, ~1549-1562 for the heat-map color
scale). Coordinates/sizes are copied 1:1 rather than re-derived, and each
tile/chart is built with fixed child positions (setGeometry), matching the
original's absolute Location/Size approach - the point of this pass is
visual fidelity to an existing, approved design, not idiomatic Qt layout
usage.

2026-08-17: the fixed pixel widths/heights below (copied 1:1 from the
PowerShell version's own absolute Location/Size values, as noted above) are
NOT DPI-safe on their own, unlike WinForms - a real report from a display
scaled above 100% showed dashboard tile and sidebar nav-button text
"skewed and does not fit." Root cause is specific to how these two
frameworks differ, not a simple "DPI scaling is broken" bug: WinForms'
Form.AutoScaleMode = Dpi (see Rowan's own 2026-08-17 fix, added the same
day, in Show-MainWindow) automatically rescales every child control's
Location/Size by the runtime/design DPI ratio, so hardcoded pixel values
there stay proportionally correct at any scale factor with zero extra
work. Qt has no equivalent auto-rescaling of already-fixed
setGeometry() calls - Qt's own High-DPI scaling (on by default in Qt6)
scales rendered fonts and physical pixels together, but a label's fixed
LOGICAL-pixel box does not grow to match whatever width its font happens
to need. At clean integer scale factors (100%/200%) this mostly goes
unnoticed since font and box scale in the same direction; at the
FRACTIONAL scale factors Windows actually recommends by default on most
real laptop/high-res displays (125%/150%/175% - the exact range a
scaled-up display would use), font-metric rounding and logical-pixel
rounding can diverge just enough to clip or crowd text that fit fine at
100%. `_ensure_label_fits()` below is the fix: after a label's real font
and text are both set, it grows (never shrinks below the original design
width/height, so a 100%-scale render looks identical to before) the
label's box to whatever QFontMetrics says the CURRENT font+text actually
needs, with a small margin - correct at any DPI/scale factor, and also
fixes a second, DPI-unrelated latent bug the same way: StatTile's numeric
value label was sized to fit a couple of digits ("0"-"999"), so a tile
showing a much larger real scan count (e.g. "12,483") could already have
clipped even at 100% scaling - set_value() now re-fits the label to its
new text on every update, not just once at construction.
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QFontMetrics, QMouseEvent, QPaintEvent, QPainter, QPen
from PySide6.QtWidgets import QFrame, QLabel, QWidget

from binsifter.gui.icons import make_line_icon
from binsifter.gui.theme import ThemePalette


def _ensure_label_fits(label: QLabel, h_pad: int = 6, v_pad: int = 2) -> None:
    """Grows (never shrinks) `label`'s current geometry so its actual
    current font+text always fits, with a small margin. Call after both
    setFont() and setText() (or setGeometry(), for the original design
    width/height to use as a floor) have already been applied - see this
    module's 2026-08-17 docstring note for why this is needed at all
    (Qt, unlike WinForms, doesn't auto-rescale fixed pixel geometries for
    DPI, and this also covers dynamic text like StatTile's value label
    outgrowing its original design width regardless of DPI).
    """
    metrics = QFontMetrics(label.font())
    needed_width = metrics.horizontalAdvance(label.text()) + h_pad
    needed_height = metrics.height() + v_pad
    geo = label.geometry()
    new_width = max(geo.width(), needed_width)
    new_height = max(geo.height(), needed_height)
    if new_width != geo.width() or new_height != geo.height():
        label.setGeometry(geo.x(), geo.y(), new_width, new_height)


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
            _ensure_label_fits(caption_label)
            icon_size = 38
            icon_label.setPixmap(make_line_icon(icon_name, accent_color, size=icon_size))
            icon_label.setGeometry(10, 48, icon_size, icon_size)
            self._value_label.setFont(_semibold_font(23))
            self._value_label.setGeometry(54, 46, 140, 40)
            _ensure_label_fits(self._value_label)
        else:
            caption_label.setFont(QFont("Segoe UI", 10))
            caption_label.setGeometry(18, 14, 220, 20)
            _ensure_label_fits(caption_label)
            icon_size = 48
            icon_label.setPixmap(make_line_icon(icon_name, accent_color, size=icon_size))
            icon_label.setGeometry(16, 47, icon_size, icon_size)
            self._value_label.setFont(_semibold_font(25))
            self._value_label.setGeometry(70, 44, 160, 44)
            _ensure_label_fits(self._value_label)

            if subtitle:
                subtitle_label = QLabel(subtitle, self)
                subtitle_label.setStyleSheet(
                    f"color: {accent_to_css(theme.MutedFore)}; border: none; background: transparent;"
                )
                subtitle_label.setFont(QFont("Segoe UI", 8))
                subtitle_label.setGeometry(72, 87, 220, 18)
                _ensure_label_fits(subtitle_label)

    def set_value(self, value: object) -> None:
        self._value_label.setText(str(value))
        # Re-fit on every update, not just at construction - a growing scan
        # count (e.g. "12,483") can need more room than the original design
        # width/height, same reasoning as the DPI case this function was
        # added for, just triggered by content instead of scale factor.
        _ensure_label_fits(self._value_label)

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
        _ensure_label_fits(self._text_label, v_pad=0)  # height (48) already has vertical room by design; only width needs to track the font

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
