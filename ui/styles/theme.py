"""Theme entry points. Keep global QSS tokens here, not scattered per widget."""
from .typography import FONT_STACK, TYPE

# 4 / 8 / 12 / 16 / 24 / 32 spacing scale
SPACING = {"micro": 4, "compact": 8, "normal": 12, "component": 16,
           "section": 24, "major": 32}


def base_font_qss() -> str:
    """Root font rule injected into the app-wide stylesheet."""
    return f"font-family: {FONT_STACK};\n    font-size: {TYPE['body']}px;"
