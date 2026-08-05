"""Procedural line-icon drawing - direct port of the PowerShell version's
New-LineIconBitmap function (BinSifter-Rowan_v1.3.0-beta.1.ps1, lines
~1384-1522). Same 64x64 canvas, same 4px round-cap/round-join pen, same
coordinates for every shape - icons are drawn at runtime rather than
loaded from bundled image files, same self-contained rationale as the
original ("the application stays self-contained and scales cleanly
without relying on font-specific glyph alignment").

Angle-convention note (the one real translation subtlety, not a guess):
GDI+'s Graphics.DrawArc(pen, x, y, w, h, startAngle, sweepAngle) measures
both angles in degrees, 0 at the 3-o'clock position, and sweeps CLOCKWISE
for positive sweepAngle. Qt's QPainter.drawArc(rect, startAngle, spanAngle)
measures in 1/16th-of-a-degree units, also 0 at 3-o'clock, but sweeps
COUNTERCLOCKWISE for positive spanAngle. Since both conventions agree on
where 0 degrees points, only the sweep direction needs flipping - see
_draw_gdi_arc() below, which does that conversion once so every icon's
DrawArc call below can be transcribed with the exact same numbers used in
the PowerShell source instead of hand-converting each one (and risking a
transcription slip on the one icon that actually needs the sign flip
noticed).
"""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QPainter, QPen, QPixmap, QPolygonF

ICON_NAMES = (
    "gauge", "list", "chart", "document", "file", "layers", "database",
    "target", "check", "cluster", "users", "user", "percent", "trend",
    "history",
)

_CANVAS_SIZE = 64
_PEN_WIDTH = 4


def _draw_gdi_arc(painter: QPainter, x: float, y: float, w: float, h: float, start_deg: float, sweep_deg: float) -> None:
    """GDI+ DrawArc(pen, x, y, w, h, startAngle, sweepAngle) equivalent -
    see module docstring for the clockwise/counterclockwise sign flip."""
    painter.drawArc(QRectF(x, y, w, h), int(start_deg * 16), int(-sweep_deg * 16))


def _polyline(points: list[tuple[float, float]]) -> QPolygonF:
    return QPolygonF([QPointF(px, py) for px, py in points])


def _draw_icon(painter: QPainter, name: str) -> None:
    if name == "gauge":
        _draw_gdi_arc(painter, 9, 11, 46, 46, 180, 180)
        painter.drawLine(QPointF(12, 42), QPointF(52, 42))
        painter.drawLine(QPointF(32, 36), QPointF(44, 22))
        painter.drawEllipse(QRectF(29, 33, 6, 6))
        painter.drawLine(QPointF(16, 35), QPointF(19, 31))
        painter.drawLine(QPointF(24, 25), QPointF(26, 22))
        painter.drawLine(QPointF(40, 25), QPointF(38, 22))

    elif name == "list":
        for y in (16, 32, 48):
            painter.drawEllipse(QRectF(9, y - 3, 6, 6))
            painter.drawLine(QPointF(23, y), QPointF(54, y))

    elif name == "chart":
        painter.drawLine(QPointF(10, 53), QPointF(55, 53))
        painter.drawRect(QRectF(14, 34, 8, 19))
        painter.drawRect(QRectF(29, 22, 8, 31))
        painter.drawRect(QRectF(44, 10, 8, 43))

    elif name in ("document", "file"):
        painter.drawRect(QRectF(15, 8, 34, 48))
        painter.drawPolyline(_polyline([(38, 8), (49, 19), (38, 19), (38, 8)]))
        painter.drawLine(QPointF(23, 31), QPointF(41, 31))
        painter.drawLine(QPointF(23, 40), QPointF(41, 40))
        painter.drawLine(QPointF(23, 49), QPointF(35, 49))

    elif name == "layers":
        for offset in (0, 11, 22):
            painter.drawPolygon(_polyline([
                (32, 10 + offset), (52, 21 + offset), (32, 32 + offset), (12, 21 + offset),
            ]))

    elif name == "database":
        painter.drawEllipse(QRectF(13, 9, 38, 16))
        _draw_gdi_arc(painter, 13, 21, 38, 16, 0, 180)
        _draw_gdi_arc(painter, 13, 36, 38, 16, 0, 180)
        painter.drawLine(QPointF(13, 17), QPointF(13, 45))
        painter.drawLine(QPointF(51, 17), QPointF(51, 45))
        _draw_gdi_arc(painter, 13, 37, 38, 16, 0, 180)

    elif name == "target":
        painter.drawEllipse(QRectF(10, 10, 44, 44))
        painter.drawEllipse(QRectF(22, 22, 20, 20))
        painter.drawLine(QPointF(32, 5), QPointF(32, 18))
        painter.drawLine(QPointF(32, 46), QPointF(32, 59))
        painter.drawLine(QPointF(5, 32), QPointF(18, 32))
        painter.drawLine(QPointF(46, 32), QPointF(59, 32))

    elif name == "check":
        painter.drawEllipse(QRectF(9, 9, 46, 46))
        painter.drawPolyline(_polyline([(19, 32), (28, 41), (46, 21)]))

    elif name == "cluster":
        nodes = [(32, 12), (14, 28), (50, 28), (19, 49), (45, 49), (32, 32)]
        hub = nodes[5]
        for idx in (0, 1, 2, 3, 4):
            a = nodes[idx]
            painter.drawLine(QPointF(*a), QPointF(*hub))
        for nx, ny in nodes:
            painter.drawEllipse(QRectF(nx - 4, ny - 4, 8, 8))

    elif name == "users":
        painter.drawEllipse(QRectF(24, 10, 16, 16))
        painter.drawEllipse(QRectF(8, 18, 12, 12))
        painter.drawEllipse(QRectF(44, 18, 12, 12))
        _draw_gdi_arc(painter, 17, 28, 30, 26, 180, 180)
        _draw_gdi_arc(painter, 3, 34, 20, 18, 180, 180)
        _draw_gdi_arc(painter, 41, 34, 20, 18, 180, 180)

    elif name == "user":
        painter.drawEllipse(QRectF(22, 10, 20, 20))
        _draw_gdi_arc(painter, 12, 31, 40, 28, 180, 180)

    elif name == "percent":
        painter.drawEllipse(QRectF(8, 8, 48, 48))
        painter.drawEllipse(QRectF(19, 18, 7, 7))
        painter.drawEllipse(QRectF(38, 39, 7, 7))
        painter.drawLine(QPointF(21, 45), QPointF(44, 18))

    elif name == "trend":
        painter.drawPolyline(_polyline([(8, 48), (22, 32), (33, 41), (53, 17)]))
        painter.drawLine(QPointF(42, 17), QPointF(53, 17))
        painter.drawLine(QPointF(53, 17), QPointF(53, 28))

    elif name == "history":
        _draw_gdi_arc(painter, 10, 10, 44, 44, 45, 300)
        painter.drawPolyline(_polyline([(10, 13), (10, 25), (21, 22)]))
        painter.drawLine(QPointF(32, 21), QPointF(32, 34))
        painter.drawLine(QPointF(32, 34), QPointF(42, 39))

    else:
        raise ValueError(f"Unknown icon name: {name!r} - expected one of {ICON_NAMES}")


def make_line_icon(name: str, color: QColor, size: int = _CANVAS_SIZE) -> QPixmap:
    """Renders icon `name` in `color` onto a size x size transparent
    QPixmap. `size` defaults to the original's fixed 64x64 canvas but can
    be rendered at any size since every coordinate above is scaled by the
    painter's own transform rather than hardcoded per output size.
    """
    if name not in ICON_NAMES:
        raise ValueError(f"Unknown icon name: {name!r} - expected one of {ICON_NAMES}")

    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    try:
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        if size != _CANVAS_SIZE:
            scale = size / _CANVAS_SIZE
            painter.scale(scale, scale)

        pen = QPen(color, _PEN_WIDTH)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)

        _draw_icon(painter, name)
    finally:
        painter.end()

    return pixmap
