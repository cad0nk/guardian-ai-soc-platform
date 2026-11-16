"""Typography tokens. Windows-first: Segoe UI Variable → Segoe UI → Arial."""

FONT_STACK = "'Segoe UI Variable Text', 'Segoe UI Variable', 'Segoe UI', Arial, sans-serif"
# Monospace ONLY for IOC / hash / IP / raw log cells that need alignment.
FONT_MONO_STACK = "'Cascadia Mono', 'Consolas', 'Courier New', monospace"

# px sizes per role (design brief ranges → chosen defaults)
TYPE = {
    "page_title":    24,   # 22–26
    "section_title": 16,   # 15–17
    "card_number":   30,   # 28–34
    "card_title":    12,   # 12–13
    "body":          13,   # 13–14
    "table":         12,   # 12–13
    "helper":        11,   # 11–12
}
WEIGHT = {"regular": 400, "medium": 500, "semibold": 600, "bold": 700}
