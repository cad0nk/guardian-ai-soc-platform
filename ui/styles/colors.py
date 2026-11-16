"""Global color palette — Premium Enterprise SOC Dashboard (dark).

PALETTE keeps every key the legacy in-file ``P`` dict exposed, so existing
widgets keep working while picking up the new values.
"""

PALETTE = {
    # ── Surfaces ─────────────────────────────────────────────────────────────
    "bg_dark":    "#0B1020",   # MAIN BACKGROUND
    "sidebar_bg": "#0D1424",   # SIDEBAR
    "bg_panel":   "#111B2E",   # CONTENT PANEL
    "bg_input":   "#162239",   # SECONDARY PANEL (inputs, wells)
    "bg_card":    "#17243A",   # CARD
    "bg_card2":   "#1C2B45",   # elevated / hover card
    # ── Accent ───────────────────────────────────────────────────────────────
    "accent":     "#00C8EA",   # ACCENT
    "accent2":    "#3478F6",   # electric blue (brand)
    "accent3":    "#22C55E",
    "accent4":    "#F59E0B",
    # ── Text ─────────────────────────────────────────────────────────────────
    "text_main":  "#E8EEF8",   # PRIMARY TEXT
    "text_label": "#9AABC2",   # SECONDARY TEXT
    "text_dim":   "#7E90AA",   # helper / disabled-ish (still AA on bg_card)
    "text_bright":"#FFFFFF",
    # ── Borders ──────────────────────────────────────────────────────────────
    "border":     "#293A56",   # BORDER
    "border2":    "#34476A",
    "border3":    "#435984",
    # ── Severity ─────────────────────────────────────────────────────────────
    "critical":   "#FF4545",
    "high":       "#F04452",
    "medium":     "#F59E0B",
    "low":        "#22C55E",
    "info":       "#25BCE5",
    "clean":      "#22C55E",
    # ── Severity tints (badges / banners) ────────────────────────────────────
    "critical_bg":"#3A1015",
    "high_bg":    "#37121A",
    "high_border":"#F04452",
    "high_text":  "#FFB3BB",
    "med_bg":     "#3A2907",
    "med_border": "#F59E0B",
    "med_text":   "#FFD699",
    "low_bg":     "#0F2E1D",
    "low_border": "#22C55E",
    "low_text":   "#B7FFCE",
    "info_bg":    "#0B2A3C",
    "info_border":"#25BCE5",
    "info_text":  "#B3ECFF",
}

SEVERITY = {
    "CRITICAL": PALETTE["critical"],
    "HIGH":     PALETTE["high"],
    "MEDIUM":   PALETTE["medium"],
    "LOW":      PALETTE["low"],
    "INFO":     PALETTE["info"],
}


def severity_color(sev: str) -> str:
    """Single lookup used by every badge/meter so severity colors never drift."""
    key = str(sev or "").strip().upper()
    key = {"CLEAN": "LOW", "BENIGN": "LOW", "INFORMATIONAL": "INFO", "INFORMATION": "INFO",
           "SAFE": "LOW", "SUSPICIOUS": "MEDIUM", "MALICIOUS": "CRITICAL"}.get(key, key)
    return SEVERITY.get(key, PALETTE["text_label"])


def tint(color: str, alpha: int) -> str:
    """QSS-safe translucent color. Qt reads 8-digit hex as #AARRGGBB (not
    #RRGGBBAA), so 'f"{c}22"' silently produces a wrong, opaque-ish color.
    Always build translucent colors through this helper."""
    c = color.lstrip("#")
    r, g, b = int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)
    return f"rgba({r},{g},{b},{max(0, min(255, int(alpha)))})"
