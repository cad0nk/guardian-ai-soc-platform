"""Crisp vector icons (24x24 design grid) painted with QPainter.

Used instead of emoji so icons render identically on every Windows build,
scale with DPI, and take the theme color.
"""
from PyQt5.QtCore import Qt, QRectF, QPointF
from PyQt5.QtGui import QPainter, QPen, QPainterPath, QColor, QPolygonF


def _poly(painter, pts, close=False):
    path = QPainterPath(QPointF(*pts[0]))
    for p in pts[1:]:
        path.lineTo(QPointF(*p))
    if close:
        path.closeSubpath()
    painter.drawPath(path)


def _shield(painter):
    p = QPainterPath(QPointF(12, 3))
    p.lineTo(20, 6); p.lineTo(20, 12)
    p.cubicTo(20, 16.5, 16.5, 20, 12, 21.5)
    p.cubicTo(7.5, 20, 4, 16.5, 4, 12)
    p.lineTo(4, 6); p.closeSubpath()
    painter.drawPath(p)


def _dashboard(p):
    for r in ((3, 3, 8, 10), (13, 3, 8, 6), (3, 15, 8, 6), (13, 11, 8, 10)):
        p.drawRoundedRect(QRectF(*r), 1.8, 1.8)


def _cti(p):
    p.drawEllipse(QPointF(12, 12), 9, 9)
    p.drawEllipse(QPointF(12, 12), 4.2, 9)
    _poly(p, [(3, 12), (21, 12)])


def _malware(p):
    p.drawEllipse(QPointF(12, 13.5), 4.6, 6)
    p.drawEllipse(QPointF(12, 6.2), 2.4, 2.4)
    _poly(p, [(12, 8.5), (12, 19.5)])
    for sx in (1, -1):
        x0, x1 = 12 + sx * 4.6, 12 + sx * 8.2
        _poly(p, [(x0, 11), (x1, 9.2)])
        _poly(p, [(x0, 14), (x1, 14)])
        _poly(p, [(x0, 17), (x1, 19)])


def _forensics(p):
    p.drawEllipse(QPointF(10.5, 10.5), 6.5, 6.5)
    _poly(p, [(15.4, 15.4), (21, 21)])


def _ai(p):
    _poly(p, [(12, 3), (14, 9.6), (21, 12), (14, 14.4), (12, 21),
              (10, 14.4), (3, 12), (10, 9.6)], close=True)


def _history(p):
    p.drawEllipse(QPointF(12, 12), 9, 9)
    _poly(p, [(12, 7), (12, 12), (15.8, 14.2)])


def _menu(p):
    for y in (7, 12, 17):
        _poly(p, [(4, y), (20, y)])


def _chev_l(p):
    _poly(p, [(14.5, 6), (8.5, 12), (14.5, 18)])


def _chev_r(p):
    _poly(p, [(9.5, 6), (15.5, 12), (9.5, 18)])


def _shield_ok(p):
    _shield(p)
    _poly(p, [(8.5, 12.2), (11, 14.7), (15.6, 9.6)])


def _shield_alert(p):
    _shield(p)
    _poly(p, [(12, 8.2), (12, 13)])
    p.drawPoint(QPointF(12, 16.2))


def _search(p):
    _forensics(p)


def _send(p):
    _poly(p, [(3.5, 11.5), (20.5, 4), (13, 20.5), (11, 13)], close=True)


def _trash(p):
    _poly(p, [(5, 7), (19, 7)])
    _poly(p, [(7, 7), (8, 20), (16, 20), (17, 7)])
    _poly(p, [(9.5, 7), (9.5, 4), (14.5, 4), (14.5, 7)])


def _refresh(p):
    p.drawArc(QRectF(4, 4, 16, 16), 40 * 16, 270 * 16)
    _poly(p, [(17.5, 3.5), (18.2, 8.2), (13.6, 7.6)])


def _upload(p):
    _poly(p, [(12, 15), (12, 4)])
    _poly(p, [(7.5, 8.5), (12, 4), (16.5, 8.5)])
    _poly(p, [(4, 15), (4, 20), (20, 20), (20, 15)])


def _file(p):
    _poly(p, [(6, 3), (14, 3), (19, 8), (19, 21), (6, 21)], close=True)
    _poly(p, [(14, 3), (14, 8), (19, 8)])


def _copy(p):
    p.drawRoundedRect(QRectF(8, 8, 12, 12), 2, 2)
    _poly(p, [(16, 8), (16, 5), (5, 5), (5, 16), (8, 16)])


def _pdf(p):
    _file(p)
    _poly(p, [(9, 14), (15, 14)]); _poly(p, [(9, 17), (13, 17)])


ICONS = {
    "upload": _upload, "file": _file, "copy": _copy, "pdf": _pdf,
    "dashboard": _dashboard, "cti": _cti, "malware": _malware,
    "forensics": _forensics, "ai": _ai, "history": _history,
    "menu": _menu, "chevron_left": _chev_l, "chevron_right": _chev_r,
    "shield_ok": _shield_ok, "shield_alert": _shield_alert,
    "search": _search, "send": _send, "trash": _trash, "refresh": _refresh,
}


def draw_icon(painter: QPainter, key: str, rect: QRectF, color, stroke: float = 1.7):
    """Paint icon `key` scaled into `rect` using `color`."""
    fn = ICONS.get(key)
    if fn is None:
        return
    painter.save()
    painter.setRenderHint(QPainter.Antialiasing, True)
    painter.translate(rect.topLeft())
    s = min(rect.width(), rect.height()) / 24.0
    painter.scale(s, s)
    pen = QPen(QColor(color), stroke)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.NoBrush)
    fn(painter)
    painter.restore()
