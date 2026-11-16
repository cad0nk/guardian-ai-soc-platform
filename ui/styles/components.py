"""Shared QSS builders so every module renders badges identically."""
from .colors import PALETTE, severity_color, tint
from .typography import TYPE


def severity_badge_qss(sev: str) -> str:
    c = severity_color(sev)
    return (f"color:{c};background:{tint(c, 34)};border:1px solid {tint(c, 102)};"
            f"border-radius:4px;padding:2px 8px;"
            f"font-size:{TYPE['helper']}px;font-weight:700;letter-spacing:0.5px;")


def status_badge_qss(color: str = None) -> str:
    c = color or PALETTE["accent"]
    return (f"color:{c};background:{tint(c, 31)};border:1px solid {tint(c, 85)};"
            f"border-radius:10px;padding:2px 10px;"
            f"font-size:{TYPE['helper']}px;font-weight:600;")
