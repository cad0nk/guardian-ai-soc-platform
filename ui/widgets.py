"""Reusable guardian_ai UI components (shared by every module).

Batch 2 set: SidebarButton, SidebarSection, IconButton, IconLabel, HeaderBar,
StatCard, SectionHeader, SeverityBadge, StatusBadge, ModernButton.
"""
from typing import Optional

from PyQt5.QtCore import Qt, QRectF, QSize, QPointF, pyqtSignal
from PyQt5.QtGui import QPainter, QColor, QFont, QFontMetrics, QPen, QPixmap, QIcon, QCursor
from PyQt5.QtWidgets import (QPushButton, QWidget, QLabel, QFrame, QVBoxLayout,
                             QHBoxLayout, QSizePolicy)

from .icons import draw_icon
from .styles import PALETTE as C, TYPE, severity_color
from .styles.colors import tint
from .styles.typography import FONT_MONO_STACK as FONT_MONO
from .styles.components import severity_badge_qss, status_badge_qss

COLLAPSED_BELOW = 120   # a SidebarButton narrower than this paints icon-only


def _qc(hex_or_color, alpha: Optional[int] = None) -> QColor:
    c = QColor(hex_or_color)
    if alpha is not None:
        c.setAlpha(alpha)
    return c


def make_icon(key: str, color: str, size: int = 18, stroke: float = 1.8) -> QIcon:
    """QIcon from a vector icon (for QPushButton.setIcon)."""
    ic = QIcon()
    for scale in (1, 2):
        pm = QPixmap(size * scale, size * scale)
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        draw_icon(p, key, QRectF(0, 0, size * scale, size * scale), color, stroke)
        p.end()
        pm.setDevicePixelRatio(scale)
        ic.addPixmap(pm)
    return ic


class IconLabel(QWidget):
    def __init__(self, key: str, color: str, size: int = 20, parent=None):
        super().__init__(parent)
        self._key, self._color, self._size = key, color, size
        self.setFixedSize(size, size)

    def set_icon(self, key: str, color: str):
        self._key, self._color = key, color
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        draw_icon(p, self._key, QRectF(0, 0, self._size, self._size), self._color)


class IconButton(QPushButton):
    """Icon-only button. Always has a tooltip (set one!) for accessibility."""
    def __init__(self, key: str, tooltip: str, size: int = 36, parent=None):
        super().__init__(parent)
        self._key = key
        self.setToolTip(tooltip)
        self.setAccessibleName(tooltip)
        self.setFixedSize(size, size)
        self.setCursor(QCursor(Qt.PointingHandCursor))
        self.setAttribute(Qt.WA_Hover, True)
        self.setFlat(True)

    def set_key(self, key: str):
        self._key = key
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        if self.isDown():
            p.setPen(Qt.NoPen); p.setBrush(_qc(C["bg_card2"])); p.drawRoundedRect(r, 8, 8)
        elif self.underMouse():
            p.setPen(Qt.NoPen); p.setBrush(_qc(C["bg_card"])); p.drawRoundedRect(r, 8, 8)
        if self.hasFocus() and self.focusPolicy() != Qt.NoFocus:
            p.setPen(QPen(_qc(C["accent"]), 1)); p.setBrush(Qt.NoBrush)
            p.drawRoundedRect(r, 8, 8)
        col = C["text_main"] if self.underMouse() else C["text_label"]
        if not self.isEnabled():
            col = C["text_dim"]
        s = 20
        draw_icon(p, self._key, QRectF((self.width() - s) / 2, (self.height() - s) / 2, s, s), col)


class SidebarButton(QPushButton):
    """Navigation entry painted from tokens: icon + label, hover, active bar,
    keyboard focus ring, optional ON/OFF pill, icon-only when collapsed.

    objectName stays 'btn_sidebar' / 'btn_sidebar_active' (legacy contract)."""
    def __init__(self, icon_key: str, label: str, parent=None):
        super().__init__(parent)
        self.setObjectName("btn_sidebar")
        self._icon_key, self._label = icon_key, label
        self._state: Optional[bool] = None
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setFixedHeight(44)
        self.setCursor(QCursor(Qt.PointingHandCursor))
        self.setAttribute(Qt.WA_Hover, True)
        self.setAccessibleName(label)

    def set_state(self, on: Optional[bool]):
        self._state = on
        self.update()

    def is_active(self) -> bool:
        return self.objectName() == "btn_sidebar_active"

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        inner = QRectF(8, 2, w - 16, h - 4)
        active, hover, down = self.is_active(), self.underMouse(), self.isDown()
        p.setPen(Qt.NoPen)
        if active:
            p.setBrush(_qc(C["accent"], 36)); p.drawRoundedRect(inner, 8, 8)
            p.setBrush(_qc(C["accent"])); p.drawRoundedRect(QRectF(0, 10, 3, h - 20), 1.5, 1.5)
        elif down:
            p.setBrush(_qc(C["bg_card2"])); p.drawRoundedRect(inner, 8, 8)
        elif hover:
            p.setBrush(_qc(C["bg_card"])); p.drawRoundedRect(inner, 8, 8)
        if self.hasFocus() and self.focusPolicy() != Qt.NoFocus and \
                getattr(self, "_kbd_focus", False):
            p.setPen(QPen(_qc(C["accent"]), 1)); p.setBrush(Qt.NoBrush)
            p.drawRoundedRect(inner.adjusted(0.5, 0.5, -0.5, -0.5), 8, 8)

        col = C["accent"] if active else (C["text_main"] if hover else C["text_label"])
        collapsed = w < COLLAPSED_BELOW
        isz = 20
        ix = (w - isz) / 2 if collapsed else 20
        draw_icon(p, self._icon_key, QRectF(ix, (h - isz) / 2, isz, isz), col)

        if collapsed:
            if self._state is not None:
                p.setPen(Qt.NoPen)
                p.setBrush(_qc(C["low"] if self._state else C["text_dim"]))
                p.drawEllipse(QPointF(w / 2 + 11, h / 2 - 9), 3.5, 3.5)
            return

        right = w - 18
        if self._state is not None:
            pw, ph = 36, 18
            pr = QRectF(w - 16 - pw, (h - ph) / 2, pw, ph)
            c = C["low"] if self._state else C["text_dim"]
            p.setPen(QPen(_qc(c, 120), 1)); p.setBrush(_qc(c, 30 if self._state else 0))
            p.drawRoundedRect(pr, 9, 9)
            f = QFont(self.font()); f.setPixelSize(TYPE["helper"] - 1); f.setWeight(QFont.DemiBold)
            p.setFont(f); p.setPen(_qc(c))
            p.drawText(pr, Qt.AlignCenter, "ON" if self._state else "OFF")
            right = pr.left() - 8

        f = QFont(self.font())
        f.setPixelSize(TYPE["body"])
        f.setWeight(QFont.DemiBold if active else QFont.Medium)
        p.setFont(f); p.setPen(_qc(col))
        tr = QRectF(52, 0, max(0, right - 52), h)
        txt = QFontMetrics(f).elidedText(self._label, Qt.ElideRight, int(tr.width()))
        p.drawText(tr, Qt.AlignVCenter | Qt.AlignLeft, txt)

    def keyPressEvent(self, e):
        self._kbd_focus = True
        super().keyPressEvent(e)

    def focusInEvent(self, e):
        self._kbd_focus = e.reason() in (Qt.TabFocusReason, Qt.BacktabFocusReason)
        super().focusInEvent(e)

    def mouseReleaseEvent(self, e):
        self._kbd_focus = False
        super().mouseReleaseEvent(e)


class SidebarSection(QWidget):
    """Section caption (OVERVIEW / SECURITY MODULES / TOOLS); a thin rule when collapsed."""
    def __init__(self, text: str, parent=None):
        super().__init__(parent)
        self._text = text
        self.setFixedHeight(32)

    def paintEvent(self, _):
        p = QPainter(self)
        w, h = self.width(), self.height()
        if w < COLLAPSED_BELOW:
            p.setPen(QPen(_qc(C["border"]), 1)); p.drawLine(16, h // 2, w - 16, h // 2)
            return
        f = QFont(self.font()); f.setPixelSize(TYPE["helper"]); f.setWeight(QFont.DemiBold)
        f.setLetterSpacing(QFont.AbsoluteSpacing, 1.0)
        p.setFont(f); p.setPen(_qc(C["text_dim"]))
        p.drawText(QRectF(20, 8, w - 28, h - 8), Qt.AlignVCenter | Qt.AlignLeft, self._text)


class StatusBadge(QLabel):
    def __init__(self, text: str = "", color: Optional[str] = None, parent=None):
        super().__init__(text, parent)
        self.setAlignment(Qt.AlignCenter)
        self.set_status(text, color)

    def set_status(self, text: str, color: Optional[str] = None):
        self.setText(text)
        self.setStyleSheet(status_badge_qss(color))


class SeverityBadge(QLabel):
    """One badge style for every module — never hand-roll severity chips again."""
    def __init__(self, severity: str = "info", min_width: int = 64, parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignCenter)
        self.setMinimumWidth(min_width)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.set_severity(severity)

    def set_severity(self, severity: str):
        sev = (severity or "info").strip().upper()
        self.setText(sev)
        self.setStyleSheet(severity_badge_qss(sev))


class SectionHeader(QWidget):
    def __init__(self, title: str, subtitle: str = "", parent=None):
        super().__init__(parent)
        lay = QHBoxLayout(self); lay.setContentsMargins(0, 0, 0, 0); lay.setSpacing(12)
        col = QVBoxLayout(); col.setContentsMargins(0, 0, 0, 0); col.setSpacing(2)
        self.title = QLabel(title)
        self.title.setStyleSheet(
            f"color:{C['text_main']};font-size:{TYPE['section_title']}px;font-weight:600;"
            "background:transparent;border:none;")
        col.addWidget(self.title)
        self.subtitle = QLabel(subtitle)
        self.subtitle.setStyleSheet(
            f"color:{C['text_label']};font-size:{TYPE['helper'] + 1}px;"
            "background:transparent;border:none;")
        self.subtitle.setVisible(bool(subtitle))
        col.addWidget(self.subtitle)
        lay.addLayout(col, 1)
        self._lay = lay

    def add_action(self, w: QWidget):
        self._lay.addWidget(w, 0, Qt.AlignRight | Qt.AlignVCenter)


class StatCard(QFrame):
    """label / big number / sublabel with a colored accent edge.
    `emphasis=True` tints the card (used for HIGH RISK)."""
    def __init__(self, label: str, sublabel: str, color: str, emphasis: bool = False, parent=None):
        super().__init__(parent)
        self._color, self._emphasis = color, emphasis
        self.setObjectName("statcard")
        self.setMinimumWidth(150)
        bg = tint(color, 26) if emphasis else C["bg_card"]
        bd = color if emphasis else C["border"]
        self.setStyleSheet(
            f"QFrame#statcard{{background:{bg};border:1px solid {bd};border-radius:12px;}}"
            f"QFrame#statcard:hover{{border-color:{color};}}")
        la = QVBoxLayout(self); la.setContentsMargins(20, 16, 16, 16); la.setSpacing(4)
        self._title = QLabel(label); self._title.setWordWrap(True)
        self._title.setStyleSheet(
            f"color:{C['text_label']};font-size:{TYPE['card_title']}px;font-weight:600;"
            "letter-spacing:0.8px;background:transparent;border:none;")
        la.addWidget(self._title)
        self._num_lbl = QLabel("—")
        self._num_lbl.setStyleSheet(
            f"color:{color if emphasis else C['text_main']};font-size:{TYPE['card_number']}px;"
            "font-weight:700;background:transparent;border:none;")
        la.addWidget(self._num_lbl)
        self._sub = QLabel(sublabel); self._sub.setWordWrap(True)
        self._sub.setStyleSheet(
            f"color:{C['text_dim']};font-size:{TYPE['helper'] + 1}px;"
            "background:transparent;border:none;")
        la.addWidget(self._sub)

    def paintEvent(self, e):
        super().paintEvent(e)
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setPen(Qt.NoPen); p.setBrush(_qc(self._color))
        p.drawRoundedRect(QRectF(0, 14, 4, self.height() - 28), 2, 2)

    def set_value(self, val):
        self._num_lbl.setText(str(val))


class ModernButton(QPushButton):
    """primary | secondary | ghost | danger — normal/hover/pressed/disabled/loading."""
    _QSS = {
        "primary":   ("{a}", "#04121A", "{a}", "#26D6F5", "#009CB8"),
        "secondary": ("{card}", "{t}", "{b}", "{card2}", "{inp}"),
        "ghost":     ("transparent", "{a}", "transparent", "@a31", "@a51"),
        "danger":    ("@c31", "{crit}", "@c102", "@c56", "@c77"),
    }

    def __init__(self, text: str, variant: str = "secondary", icon: Optional[str] = None,
                 tooltip: str = "", parent=None):
        super().__init__(text, parent)
        self._text0, self._variant, self._icon_key = text, variant, icon
        self.setCursor(QCursor(Qt.PointingHandCursor))
        self.setMinimumHeight(34)
        if tooltip:
            self.setToolTip(tooltip)
        self._apply_qss()

    def _apply_qss(self):
        def _res(tok: str) -> str:
            if tok.startswith("@a"):
                return tint(C["accent"], int(tok[2:]))
            if tok.startswith("@c"):
                return tint(C["critical"], int(tok[2:]))
            return tok.format(a=C["accent"], card=C["bg_card"], card2=C["bg_card2"],
                              inp=C["bg_input"], b=C["border2"], t=C["text_main"],
                              crit=C["critical"])
        bg, fg, bd, hov, prs = (_res(t) for t in self._QSS[self._variant])
        self.setStyleSheet(
            f"QPushButton{{background:{bg};color:{fg};border:1px solid {bd};border-radius:8px;"
            f"padding:6px 14px;font-size:{TYPE['body']}px;font-weight:600;}}"
            f"QPushButton:hover{{background:{hov};}}"
            f"QPushButton:pressed{{background:{prs};}}"
            f"QPushButton:focus{{border:1px solid {C['accent']};}}"
            f"QPushButton:disabled{{background:{C['bg_input']};color:{C['text_dim']};"
            f"border:1px solid {C['border']};}}")
        if self._icon_key:
            col = {"primary": "#04121A", "danger": C["critical"]}.get(self._variant, C["accent"])
            self.setIcon(make_icon(self._icon_key, col, 16)); self.setIconSize(QSize(16, 16))

    def set_loading(self, loading: bool, text: str = "Working…"):
        self.setEnabled(not loading)
        self.setText(text if loading else self._text0)


class HeaderBar(QFrame):
    """Top bar: menu toggle, breadcrumb + subtitle, platform status."""
    menu_clicked = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("headerbar")
        self.setFixedHeight(60)
        self.setStyleSheet(
            f"QFrame#headerbar{{background:{C['bg_panel']};border-bottom:1px solid {C['border']};}}")
        lay = QHBoxLayout(self); lay.setContentsMargins(12, 0, 20, 0); lay.setSpacing(12)
        self.menu_btn = IconButton("menu", "Collapse / expand sidebar")
        self.menu_btn.clicked.connect(self.menu_clicked.emit)
        lay.addWidget(self.menu_btn)
        col = QVBoxLayout(); col.setContentsMargins(0, 0, 0, 0); col.setSpacing(1)
        self.crumb = QLabel(); self.crumb.setTextFormat(Qt.RichText)
        self.sub = QLabel()
        self.sub.setStyleSheet(
            f"color:{C['text_label']};font-size:{TYPE['helper'] + 1}px;"
            "background:transparent;border:none;")
        col.addWidget(self.crumb); col.addWidget(self.sub)
        lay.addLayout(col, 1)
        self.status = StatusBadge("SYSTEM STATUS: ONLINE", C["low"])
        lay.addWidget(self.status, 0, Qt.AlignVCenter)

    def set_page(self, title: str, subtitle: str = ""):
        self.crumb.setText(
            f"<span style='color:{C['text_dim']};font-size:{TYPE['section_title']}px;'>guardian_ai"
            f"&nbsp;&nbsp;/&nbsp;&nbsp;</span>"
            f"<span style='color:{C['text_main']};font-size:{TYPE['section_title']}px;"
            f"font-weight:600;'>{title}</span>")
        self.sub.setText(subtitle)

    def set_status(self, text: str, color: str, tooltip: str = ""):
        self.status.set_status(text, color)
        self.status.setToolTip(tooltip)


# ════════════════════════════════════════════════════════════════════════════
#  Batch 3 components
# ════════════════════════════════════════════════════════════════════════════
from PyQt5.QtCore import QTimer, QRect


class RiskMeter(QWidget):
    """Large 0–100 risk gauge: segmented track + marker + score and label."""
    _BANDS = [(0, 20, "info"), (20, 40, "low"), (40, 60, "medium"), (60, 80, "high"), (80, 100, "critical")]

    def __init__(self, score: int = 0, label: str = "", parent=None):
        super().__init__(parent)
        self._score, self._label = 0, label
        self.setMinimumHeight(74)
        self.setMinimumWidth(120)
        self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)
        self.set_score(score, label)

    def set_score(self, score, label: str = ""):
        try:
            self._score = max(0, min(100, int(score)))
        except (TypeError, ValueError):
            self._score = 0
        self._label = label
        self.setAccessibleName(f"Risk score {self._score} of 100 {label}")
        self.update()

    def score_color(self) -> str:
        for lo, hi, sev in self._BANDS:
            if self._score < hi or hi == 100:
                return severity_color(sev)
        return C["text_label"]

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w = self.width()
        col = self.score_color()
        f = QFont(self.font()); f.setPixelSize(TYPE["card_number"] + 6); f.setWeight(QFont.Bold)
        p.setFont(f); p.setPen(_qc(col))
        p.drawText(QRectF(0, 0, 90, 40), Qt.AlignLeft | Qt.AlignVCenter, str(self._score))
        f2 = QFont(self.font()); f2.setPixelSize(TYPE["body"])
        p.setFont(f2); p.setPen(_qc(C["text_label"]))
        p.drawText(QRectF(f.pixelSize() * (len(str(self._score)) * 0.62) + 8, 8, 70, 30),
                   Qt.AlignLeft | Qt.AlignBottom, "/ 100")
        if self._label and w >= 380:
            f3 = QFont(self.font()); f3.setPixelSize(TYPE["card_title"]); f3.setWeight(QFont.DemiBold)
            p.setFont(f3); p.setPen(_qc(col))
            p.drawText(QRectF(w - 220, 0, 220, 40), Qt.AlignRight | Qt.AlignVCenter, self._label.upper())
        # track
        top, h = 48, 10
        seg_gap = 3
        seg_w = (w - seg_gap * 4) / 5.0
        for i, (lo, hi, sev) in enumerate(self._BANDS):
            x = i * (seg_w + seg_gap)
            c = severity_color(sev)
            filled = self._score >= lo
            p.setPen(Qt.NoPen)
            p.setBrush(_qc(c, 255 if filled else 55))
            p.drawRoundedRect(QRectF(x, top, seg_w, h), 4, 4)
        # marker
        mx = max(4, min(w - 4, w * self._score / 100.0))
        p.setBrush(_qc(C["text_main"])); p.setPen(QPen(_qc(C["bg_dark"]), 2))
        p.drawEllipse(QPointF(mx, top + h / 2), 7, 7)


class LoadingIndicator(QWidget):
    """Indeterminate spinner + message. start()/stop() — cheap QTimer, no thread."""
    def __init__(self, text: str = "Working…", parent=None):
        super().__init__(parent)
        self._angle = 0
        self._timer = QTimer(self); self._timer.setInterval(60)
        self._timer.timeout.connect(self._tick)
        lay = QHBoxLayout(self); lay.setContentsMargins(0, 0, 0, 0); lay.setSpacing(10)
        self._spin = QWidget(); self._spin.setFixedSize(18, 18)
        self._spin.paintEvent = self._paint_spin
        self.label = QLabel(text)
        self.label.setStyleSheet(
            f"color:{C['text_label']};font-size:{TYPE['table']}px;background:transparent;border:none;")
        lay.addWidget(self._spin); lay.addWidget(self.label, 1)
        self.setVisible(False)

    def _tick(self):
        self._angle = (self._angle + 30) % 360
        self._spin.update()

    def _paint_spin(self, _):
        p = QPainter(self._spin)
        p.setRenderHint(QPainter.Antialiasing)
        p.translate(9, 9)
        p.rotate(self._angle)
        pen = QPen(_qc(C["accent"]), 2.2); pen.setCapStyle(Qt.RoundCap)
        p.setPen(pen); p.setBrush(Qt.NoBrush)
        p.drawArc(QRectF(-7, -7, 14, 14), 0, 270 * 16)

    def start(self, text: Optional[str] = None):
        if text:
            self.label.setText(text)
        self.setVisible(True)
        self._timer.start()

    def stop(self):
        self._timer.stop()
        self.setVisible(False)

    def hideEvent(self, e):          # never leave a timer running on a hidden page
        self._timer.stop()
        super().hideEvent(e)

    def showEvent(self, e):
        if self.isVisible() and self.label.text():
            pass
        super().showEvent(e)


class AnalysisEmptyState(QFrame):
    """Professional placeholder for EMPTY / ERROR / LOADING-less panels.
    kind: 'empty' | 'error' | 'info'."""
    def __init__(self, icon: str, title: str, body: str = "", kind: str = "empty", parent=None):
        super().__init__(parent)
        self.setObjectName("emptystate")
        self.setMinimumHeight(180)
        self._lay = QVBoxLayout(self)
        self._lay.setContentsMargins(32, 28, 32, 28); self._lay.setSpacing(10)
        self._lay.addStretch(1)
        self._ic = IconLabel(icon, C["accent"], 44)
        self._lay.addWidget(self._ic, 0, Qt.AlignHCenter)
        self._title = QLabel(title); self._title.setAlignment(Qt.AlignCenter); self._title.setWordWrap(True)
        self._body = QLabel(body); self._body.setAlignment(Qt.AlignCenter); self._body.setWordWrap(True)
        self._lay.addWidget(self._title); self._lay.addWidget(self._body)
        self._lay.addStretch(1)
        self.set_content(icon, title, body, kind)

    def set_content(self, icon: str, title: str, body: str = "", kind: str = "empty"):
        col = {"error": C["critical"], "info": C["info"]}.get(kind, C["accent"])
        self._ic.set_icon(icon, col)
        self.setStyleSheet(
            f"QFrame#emptystate{{background:{C['bg_card']};border:1px dashed {C['border2']};border-radius:12px;}}")
        self._title.setText(title); self._body.setText(body)
        self._body.setVisible(bool(body))
        self._title.setStyleSheet(
            f"color:{C['text_main'] if kind != 'error' else col};font-size:{TYPE['section_title']}px;"
            "font-weight:600;background:transparent;border:none;")
        self._body.setStyleSheet(
            f"color:{C['text_label']};font-size:{TYPE['body']}px;background:transparent;border:none;")


class IOCChip(QLabel):
    """Monospace pill for an IOC (hash / IP / domain / URL). Click-to-copy."""
    def __init__(self, text: str, kind: str = "", parent=None):
        super().__init__(parent)
        self._full = text or ""
        self.setText(self._full if len(self._full) <= 64 else self._full[:61] + "…")
        self.setToolTip(f"{kind + ': ' if kind else ''}{self._full}\n(click to copy)")
        self.setCursor(QCursor(Qt.PointingHandCursor))
        self.setTextInteractionFlags(Qt.NoTextInteraction)
        self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)
        self.setStyleSheet(
            f"background:{C['bg_input']};color:{C['text_main']};border:1px solid {C['border2']};"
            f"border-radius:6px;padding:3px 8px;font-family:{FONT_MONO};font-size:{TYPE['table']}px;")

    def mousePressEvent(self, e):
        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText(self._full)
        old = self.text(); self.setText("copied ✓")
        QTimer.singleShot(900, lambda: self.setText(old) if self else None)


class SourceCard(QFrame):
    """One intelligence source: name · status badge · detection/risk line · detail/error.
    state: ok | warn | error | off | pending"""
    _STATE = {"ok": ("OK", "low"), "warn": ("PARTIAL", "medium"), "error": ("ERROR", "critical"),
              "off": ("NOT CONFIGURED", None), "pending": ("PENDING", "info")}

    def __init__(self, name: str, state: str = "pending", headline: str = "", detail: str = "",
                 severity: Optional[str] = None, parent=None):
        super().__init__(parent)
        self.setObjectName("sourcecard")
        self._lay = QVBoxLayout(self)
        self._lay.setContentsMargins(16, 14, 16, 14); self._lay.setSpacing(8)
        top = QHBoxLayout(); top.setSpacing(10)
        self._name = QLabel(name)
        self._name.setStyleSheet(
            f"color:{C['text_main']};font-size:{TYPE['section_title']}px;font-weight:600;"
            "background:transparent;border:none;")
        top.addWidget(self._name, 1)
        self._badge = StatusBadge("", C["info"])
        top.addWidget(self._badge)
        self._lay.addLayout(top)
        self._head = QLabel(); self._head.setWordWrap(True)
        self._det = QLabel(); self._det.setWordWrap(True)
        self._det.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._lay.addWidget(self._head); self._lay.addWidget(self._det)
        self.set_state(state, headline, detail, severity)

    def set_state(self, state: str, headline: str = "", detail: str = "", severity: Optional[str] = None):
        text, sev = self._STATE.get(state, self._STATE["pending"])
        col = severity_color(sev) if sev else C["text_dim"]
        self._badge.set_status(text, col)
        edge = col if state in ("error", "warn") else C["border"]
        self.setStyleSheet(
            f"QFrame#sourcecard{{background:{C['bg_card']};border:1px solid {edge};border-radius:12px;}}")
        hc = severity_color(severity) if severity else C["text_main"]
        self._head.setText(headline); self._head.setVisible(bool(headline))
        self._head.setStyleSheet(
            f"color:{hc};font-size:{TYPE['body'] + 1}px;font-weight:600;background:transparent;border:none;")
        self._det.setText(detail); self._det.setVisible(bool(detail))
        self._det.setStyleSheet(
            f"color:{C['text_label'] if state != 'error' else C['high_text']};"
            f"font-size:{TYPE['table']}px;background:transparent;border:none;")


# ════════════════════════════════════════════════════════════════════════════
#  Batch 4 components
# ════════════════════════════════════════════════════════════════════════════
class TypingIndicator(QFrame):
    """'Analyst is typing' row: three pulsing dots + label. The timer runs only
    while the widget is visible (setVisible(True/False) is all callers need)."""
    def __init__(self, text: str = "AI Analyst is analyzing…", parent=None):
        super().__init__(parent)
        self.setObjectName("typingrow")
        self.setStyleSheet(
            f"QFrame#typingrow{{background:{C['bg_panel']};border-top:1px solid {C['border']};}}")
        self._phase = 0
        self._timer = QTimer(self); self._timer.setInterval(280)
        self._timer.timeout.connect(self._tick)
        lay = QHBoxLayout(self); lay.setContentsMargins(14, 8, 14, 8); lay.setSpacing(10)
        self._dots = QWidget(); self._dots.setFixedSize(34, 12)
        self._dots.paintEvent = self._paint_dots
        self.label = QLabel(text)
        self.label.setStyleSheet(
            f"color:{C['text_label']};font-size:{TYPE['table']}px;background:transparent;border:none;")
        lay.addWidget(self._dots); lay.addWidget(self.label, 1)
        self.setVisible(False)

    def _tick(self):
        self._phase = (self._phase + 1) % 3
        self._dots.update()

    def _paint_dots(self, _):
        p = QPainter(self._dots)
        p.setRenderHint(QPainter.Antialiasing)
        p.setPen(Qt.NoPen)
        for i in range(3):
            p.setBrush(_qc(C["accent"], 255 if i == self._phase else 90))
            p.drawEllipse(QPointF(5 + i * 12, 6), 3.4, 3.4)

    def showEvent(self, e):
        self._timer.start()
        super().showEvent(e)

    def hideEvent(self, e):
        self._timer.stop()
        super().hideEvent(e)
