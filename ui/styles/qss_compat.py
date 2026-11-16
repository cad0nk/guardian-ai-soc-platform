"""Legacy-QSS compatibility shim.

The original code base builds translucent colors as f"{color}22" (RRGGBBAA
intent). Qt interprets 8-digit hex as #AARRGGBB, so those rules render the
wrong color (e.g. a red tint becomes olive). `install()` rewrites such
8-digit literals to the intended rgba() form for every stylesheet set from
Python, so all existing modules are corrected without editing each call site.
"""
import re

_HEX8 = re.compile(r"#([0-9a-fA-F]{6})([0-9a-fA-F]{2})(?![0-9a-fA-F])")


def fix_qss(text: str) -> str:
    if not text or "#" not in text:
        return text

    def _sub(m):
        rgb, aa = m.group(1), int(m.group(2), 16)
        return f"rgba({int(rgb[0:2], 16)},{int(rgb[2:4], 16)},{int(rgb[4:6], 16)},{aa})"
    return _HEX8.sub(_sub, text)


_installed = False


def install():
    """Idempotently patch QWidget/QApplication.setStyleSheet."""
    global _installed
    if _installed:
        return
    from PyQt5.QtWidgets import QWidget, QApplication
    _w, _a = QWidget.setStyleSheet, QApplication.setStyleSheet

    def widget_set(self, qss):
        return _w(self, fix_qss(qss))

    def app_set(self, qss):
        return _a(self, fix_qss(qss))

    QWidget.setStyleSheet = widget_set
    QApplication.setStyleSheet = app_set
    _installed = True
