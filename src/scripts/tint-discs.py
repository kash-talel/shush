"""Render the per-vault disc colours from the master disc.png.

Only the red embroidery is recoloured; the white / lavender SHUSH lettering,
the hub and the shading stay exactly as drawn, so every vault keeps the same
logo. Needs only Pillow. Re-run after changing disc.png:

    python src/scripts/tint-discs.py
"""

import colorsys
from pathlib import Path

from PIL import Image

ASSETS = Path(__file__).resolve().parent.parent / "src" / "lib" / "assets"

# name -> (target hue in degrees, saturation multiplier, value multiplier).
# Keep the names in sync with VAULT_COLORS in src-tauri/src/vault/registry.rs.
TINTS = {
    "amber": (38, 1.0, 1.15),
    "teal": (172, 0.9, 1.0),
    "cobalt": (218, 1.0, 1.15),
    "violet": (272, 0.9, 1.2),
    "chrome": (0, 0.0, 1.25),
}


def clamp(x, lo=0.0, hi=1.0):
    return lo if x < lo else hi if x > hi else x


def main():
    src = Image.open(ASSETS / "disc.png").convert("RGBA")
    pixels = list(src.getdata())

    # Precompute HSV and the "red embroidery" weight of every pixel.
    pre = []
    for r, g, b, a in pixels:
        h, s, v = colorsys.rgb_to_hsv(r / 255, g / 255, b / 255)
        hd = h * 360
        signed = hd - 360 if hd > 180 else hd  # -180..180, red at 0
        hue_w = clamp(1 - (abs(signed) - 45) / 20)  # full within +-45 deg, gone by +-65 deg
        sat_w = clamp((s - 0.06) / 0.10)  # shaded stitching is low-saturation; keep near-white lettering
        pre.append((signed, s, v, hue_w * sat_w))

    for name, (hue, sat_k, val_k) in TINTS.items():
        out = []
        for (r, g, b, a), (signed, s, v, w) in zip(pixels, pre):
            if w <= 0:
                out.append((r, g, b, a))
                continue
            nh = ((hue + signed * 0.4) % 360) / 360  # compress hue spread so amber never wraps back to red
            nr, ng, nb = colorsys.hsv_to_rgb(nh, clamp(s * sat_k), clamp(v * val_k))
            out.append(
                (
                    round(r * (1 - w) + nr * 255 * w),
                    round(g * (1 - w) + ng * 255 * w),
                    round(b * (1 - w) + nb * 255 * w),
                    a,
                )
            )
        img = Image.new("RGBA", src.size)
        img.putdata(out)
        img.save(ASSETS / f"disc-{name}.png", optimize=True)
        print("wrote", f"disc-{name}.png")


if __name__ == "__main__":
    main()
