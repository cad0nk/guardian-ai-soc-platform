"""guardian_ai design system — single source of truth for colors, type and spacing."""
from .colors import PALETTE, SEVERITY, severity_color
from .typography import FONT_STACK, FONT_MONO_STACK, TYPE
from .theme import SPACING, base_font_qss

__all__ = ["PALETTE", "SEVERITY", "severity_color", "FONT_STACK",
           "FONT_MONO_STACK", "TYPE", "SPACING", "base_font_qss"]
