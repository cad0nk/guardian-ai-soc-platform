"""Compose the README hero banner (docs/assets/banner.png) from the logo and a screenshot.

    python tools/generate_banner.py
Needs Pillow (requirements-build.txt). Uses Segoe UI / DejaVu Sans when available.
"""
import os
from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "assets", "banner.png")
W, H = 1600, 560
NAVY, NAVY2, CYAN, BLUE, WHITE, MUTED = "#0B1020", "#12204A", "#00D4FF", "#3478F6", "#FFFFFF", "#9AABC2"

FONT_CANDIDATES = {
    "bold": ["C:/Windows/Fonts/segoeuib.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
             "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf"],
    "regular": ["C:/Windows/Fonts/segoeui.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"],
}


def font(kind, size):
    for p in FONT_CANDIDATES[kind]:
        if os.path.isfile(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


def gradient(w, h, c1, c2):
    img = Image.new("RGB", (w, h), c1)
    px = img.load()
    a, b = Image.new("RGB", (1, 1), c1).getpixel((0, 0)), Image.new("RGB", (1, 1), c2).getpixel((0, 0))
    for x in range(w):
        for y in range(h):
            t = min(1.0, (x / w) * 0.7 + (y / h) * 0.3)
            px[x, y] = tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))
    return img


def main():
    bg = gradient(W, H, NAVY, NAVY2).convert("RGBA")
    d = ImageDraw.Draw(bg)
    # soft glow behind the screenshot
    glow = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(glow).ellipse((760, 40, 1700, 640), fill=(0, 212, 255, 40))
    bg.alpha_composite(glow.filter(ImageFilter.GaussianBlur(90)))

    # logo + title block
    logo = Image.open(os.path.join(ROOT, "assets", "icons", "guardian_ai.png")).convert("RGBA").resize((124, 124), Image.LANCZOS)
    bg.alpha_composite(logo, (70, 96))
    d.text((212, 92), "guardian_ai", font=font("bold", 72), fill=WHITE)
    d.text((216, 188), "AI-Powered Security Operations Center", font=font("regular", 26), fill=CYAN)
    d.text((72, 270), "Threat intelligence, malware analysis and", font=font("regular", 25), fill=MUTED)
    d.text((72, 306), "log forensics in one desktop workspace.", font=font("regular", 25), fill=MUTED)

    # feature chips
    x, y = 72, 384
    for label in ("CTI", "Malware Analysis", "Forensics", "AI SOC Analyst"):
        f = font("bold", 19)
        tw = d.textlength(label, font=f)
        d.rounded_rectangle((x, y, x + tw + 32, y + 44), radius=22, outline=BLUE, width=2, fill=(52, 120, 246, 60))
        d.text((x + 16, y + 10), label, font=f, fill=WHITE)
        x += int(tw) + 48
    d.text((72, 468), "Python  ·  PyQt5  ·  SQLite  ·  Windows desktop", font=font("regular", 20), fill=MUTED)

    # screenshot card
    shot = Image.open(os.path.join(ROOT, "docs", "screenshots", "01-dashboard.png")).convert("RGBA")
    sw = 740
    shot = shot.resize((sw, int(shot.height * sw / shot.width)), Image.LANCZOS)
    shot = shot.crop((0, 0, sw, min(shot.height, 450)))
    mask = Image.new("L", shot.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, shot.width, shot.height), radius=18, fill=255)
    shadow = Image.new("RGBA", (shot.width + 80, shot.height + 80), (0, 0, 0, 0))
    ImageDraw.Draw(shadow).rounded_rectangle((40, 50, shot.width + 40, shot.height + 50), radius=18, fill=(0, 0, 0, 170))
    px, py = 810, 56
    bg.alpha_composite(shadow.filter(ImageFilter.GaussianBlur(22)), (px - 40, py - 40))
    bg.paste(shot, (px, py), mask)
    ImageDraw.Draw(bg).rounded_rectangle((px, py, px + shot.width, py + shot.height), radius=18, outline=(0, 212, 255, 110), width=2)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    bg.convert("RGB").save(OUT, optimize=True)
    print("wrote", os.path.relpath(OUT, ROOT))


if __name__ == "__main__":
    main()
