"""Headless UI audit: clipping / squeeze detection across pages, window sizes and DPI.

Run:  QT_SCALE_FACTOR=1.5 QT_QPA_PLATFORM=offscreen python tools/ui_audit.py
Reports (a) scroll areas whose content needs more width than the viewport and
(b) visible buttons/labels squeezed below their minimum size hint (= clipped text).
"""
import importlib, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
m = importlib.import_module(os.environ.get("GUARDIAN_MODULE", "guardian_ai_v4_fixed"))
from PyQt5.QtWidgets import QApplication, QScrollArea, QPushButton, QLabel, QSizePolicy, QWidget
from PyQt5.QtCore import QSettings, QEvent, Qt

SIZES = [(1920, 1080), (1600, 900), (1366, 768), (1280, 720)]


def pump(app, n=25):
    for _ in range(n):
        app.processEvents(); app.sendPostedEvents(None, QEvent.DeferredDelete); time.sleep(0.015)


def main():
    import tempfile
    QSettings.setDefaultFormat(QSettings.IniFormat)       # never touch the developer's real settings
    QSettings.setPath(QSettings.IniFormat, QSettings.UserScope, tempfile.mkdtemp(prefix="gai_audit_"))
    from PyQt5.QtCore import QCoreApplication
    QCoreApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)   # same as the real app, before QApplication
    QCoreApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication(sys.argv); app.setStyleSheet(m.STYLESHEET)
    w = m.MainWindow(); w.show(); pump(app, 40)
    issues = []
    for (W, H) in SIZES:
        w.resize(W, H); pump(app, 30)
        for idx, name in enumerate(("dashboard", "cti", "malware", "forensics")):
            w._switch(idx); pump(app, 8)
            page = w.pages.currentWidget()
            for sa in page.findChildren(QScrollArea):
                if sa.isVisible() and sa.widget() is not None:
                    need, have = sa.widget().minimumSizeHint().width(), sa.viewport().width()
                    if need > have + 1:
                        issues.append((W, H, name, "scroll-content", need, have))
            for wd in page.findChildren(QWidget):
                if not wd.isVisible() or not isinstance(wd, (QPushButton, QLabel)):
                    continue
                if isinstance(wd, QLabel) and (wd.wordWrap() or wd.pixmap() is not None):
                    continue
                if wd.sizePolicy().horizontalPolicy() == QSizePolicy.Ignored:
                    continue
                if wd.width() + 1 < wd.minimumSizeHint().width():
                    issues.append((W, H, name, f"squeezed {type(wd).__name__}:{(getattr(wd,'text',lambda:'')() or '')[:24]!r}",
                                   wd.minimumSizeHint().width(), wd.width()))
        # side panels (chat + history) at this size
        for pname, panel in (("chat", w._chat_panel), ("history", w._history_panel)):
            if panel.isVisible():
                for wd in panel.findChildren(QPushButton):
                    if wd.isVisible() and wd.width() + 1 < wd.minimumSizeHint().width():
                        issues.append((W, H, pname, f"squeezed button {wd.text()[:20]!r}", wd.minimumSizeHint().width(), wd.width()))
    scale = os.environ.get("QT_SCALE_FACTOR", "1")
    print(f"[scale {scale}] devicePixelRatio={w.devicePixelRatioF():.2f} issues: {len(issues)}")
    for i in issues[:25]:
        print("  ", i)
    w.close()
    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main())
