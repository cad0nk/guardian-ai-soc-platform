"""
Generate guardian_ai brand assets (SVG, PNG, multi-size ICO).

Run:  python tools/generate_icons.py

Each ICO size is rendered separately (8x supersampling) and embedded as a PNG
entry, so every size is present in ONE .ico file and small sizes stay crisp
(no single-image downscale).
"""
import os
import struct
import io

from PIL import Image, ImageDraw

NAVY = (11, 16, 32, 255)          # #0B1020
CYAN = (0, 212, 255)              # #00D4FF
BLUE = (52, 120, 246)             # #3478F6
WHITE = (255, 255, 255, 255)

ICO_SIZES = [16, 24, 32, 48, 64, 128, 256]

# Geometry in a 256x256 design space (shared by SVG and raster renderer)
SHIELD_SEGS = [
    ("M", (128, 16)),
    ("L", (216, 48)),
    ("L", (216, 120)),
    ("C", (216, 176), (178, 220), (128, 240)),
    ("C", (78, 220), (40, 176), (40, 120)),
    ("L", (40, 48)),
]
BOLT = [(152, 58), (96, 140), (126, 140), (110, 202), (168, 114), (136, 114)]
INNER_SCALE = 0.80
INNER_SHIFT_Y = 4


def _bezier(p0, p1, p2, p3, n=48):
    pts = []
    for i in range(1, n + 1):
        t = i / n
        u = 1 - t
        x = u**3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t**3 * p3[0]
        y = u**3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t**3 * p3[1]
        pts.append((x, y))
    return pts


def shield_points():
    pts, cur = [], None
    for seg in SHIELD_SEGS:
        if seg[0] in ("M", "L"):
            cur = seg[1]
            pts.append(cur)
        else:
            pts.extend(_bezier(cur, seg[1], seg[2], seg[3]))
            cur = seg[3]
    return pts


def _xform_inner(pt):
    return (128 + (pt[0] - 128) * INNER_SCALE,
            128 + (pt[1] - 128) * INNER_SCALE + INNER_SHIFT_Y)


def render(size: int) -> Image.Image:
    ss = 8
    big = size * ss
    k = big / 256.0

    def S(pts):
        return [(x * k, y * k) for x, y in pts]

    # diagonal cyan -> blue gradient
    grad = Image.new("RGBA", (big, big))
    gd = ImageDraw.Draw(grad)
    for i in range(big * 2):
        t = i / (big * 2 - 1)
        col = tuple(int(CYAN[c] + (BLUE[c] - CYAN[c]) * t) for c in range(3)) + (255,)
        gd.line([(i, 0), (0, i)], fill=col, width=2)

    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).polygon(S(shield_points()), fill=255)

    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    img.paste(grad, (0, 0), mask)

    d = ImageDraw.Draw(img)
    inner = [_xform_inner(p) for p in shield_points()]
    d.polygon(S(inner), fill=NAVY)
    d.polygon(S(BOLT), fill=WHITE)

    return img.resize((size, size), Image.LANCZOS)


def build_svg() -> str:
    def path(segs):
        out = []
        for s in segs:
            if s[0] == "M":
                out.append(f"M{s[1][0]} {s[1][1]}")
            elif s[0] == "L":
                out.append(f"L{s[1][0]} {s[1][1]}")
            else:
                out.append("C" + " ".join(f"{p[0]} {p[1]}" for p in s[1:]))
        return " ".join(out) + " Z"

    bolt = " ".join(f"{x},{y}" for x, y in BOLT)
    ty = 128 + INNER_SHIFT_Y - 128 * INNER_SCALE
    tx = 128 - 128 * INNER_SCALE
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" width="256" height="256" role="img" aria-label="guardian_ai">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#00D4FF"/>
      <stop offset="1" stop-color="#3478F6"/>
    </linearGradient>
  </defs>
  <path d="{path(SHIELD_SEGS)}" fill="url(#g)"/>
  <path d="{path(SHIELD_SEGS)}" fill="#0B1020" transform="translate({tx:.1f} {ty:.1f}) scale({INNER_SCALE})"/>
  <polygon points="{bolt}" fill="#FFFFFF"/>
</svg>
"""


def build_ico(images: dict) -> bytes:
    """Hand-assembled ICO: header + directory + PNG-compressed entries."""
    blobs = []
    for sz in ICO_SIZES:
        buf = io.BytesIO()
        images[sz].save(buf, format="PNG", optimize=True)
        blobs.append((sz, buf.getvalue()))
    header = struct.pack("<HHH", 0, 1, len(blobs))
    offset = 6 + 16 * len(blobs)
    entries, data = b"", b""
    for sz, blob in blobs:
        dim = 0 if sz >= 256 else sz
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(blob), offset)
        data += blob
        offset += len(blob)
    return header + entries + data


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = os.path.join(root, "assets", "icons")
    os.makedirs(out, exist_ok=True)

    images = {sz: render(sz) for sz in sorted(set(ICO_SIZES + [512]))}
    images[256].save(os.path.join(out, "guardian_ai_256.png"))
    images[512].save(os.path.join(out, "guardian_ai.png"))
    with open(os.path.join(out, "guardian_ai.ico"), "wb") as f:
        f.write(build_ico(images))
    with open(os.path.join(out, "guardian_ai.svg"), "w", encoding="utf-8") as f:
        f.write(build_svg())
    print("Assets written to", out)


if __name__ == "__main__":
    main()
