# Usage: python src-tauri/windows/make-installer-sidebar.py src-tauri/windows/installer-sidebar.bmp
# Renders the NSIS welcome/finish sidebar (164x314, 24-bit BMP) in the site palette.
import sys
from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont
R = __import__("pathlib").Path(__file__).resolve().parents[2].as_posix() + "/"
W, H, S = 164, 314, 4                      # draw at 4x, downsample for clean edges
w, h = W * S, H * S
obsidian, crimson, uv, lav, dim, seam = (6, 6, 9), (225, 29, 72), (192, 132, 252), (221, 214, 254), (155, 152, 173), (40, 38, 52)

base = Image.new('RGB', (w, h), obsidian)
glow = Image.new('RGB', (w, h), (0, 0, 0))
g = ImageDraw.Draw(glow)
g.ellipse((-0.55 * w, -0.10 * h, 0.95 * w, 0.50 * h), fill=tuple(int(c * 0.30) for c in crimson))
g.ellipse((0.25 * w, 0.62 * h, 1.60 * w, 1.20 * h), fill=tuple(int(c * 0.20) for c in uv))
glow = glow.filter(ImageFilter.GaussianBlur(70 * S))
base = ImageChops.add(base, glow)

disc = Image.open(R + 'src-tauri/icons/icon.png').convert('RGBA')
d = 128 * S
disc = disc.resize((d, d), Image.LANCZOS)
shadow = Image.new('RGBA', (w, h), (0, 0, 0, 0))
ImageDraw.Draw(shadow).ellipse(((w - d) // 2 + 6 * S, 52 * S + 10 * S, (w + d) // 2 - 6 * S, 52 * S + d + 14 * S), fill=(0, 0, 0, 200))
shadow = shadow.filter(ImageFilter.GaussianBlur(10 * S))
base = Image.alpha_composite(base.convert('RGBA'), shadow)
base.alpha_composite(disc, ((w - d) // 2, 52 * S))

dr = ImageDraw.Draw(base)
y = 52 * S + d + 26 * S
dr.line(((22 * S, y), (w - 22 * S, y)), fill=seam, width=S)
f = ImageFont.truetype('C:/Windows/Fonts/seguisb.ttf', 10 * S)
for i, line in enumerate(['offline-first', 'zero-knowledge', 'password vault']):
    tw = dr.textlength(line, font=f)
    dr.text(((w - tw) / 2, y + (14 + i * 15) * S), line, font=f, fill=lav if i == 2 else dim)

out = base.convert('RGB').resize((W, H), Image.LANCZOS)
out.save(sys.argv[1], format='BMP')

