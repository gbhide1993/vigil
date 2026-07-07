"""Generates tray icons (green/red dot on transparent background) with Pillow.

Run with: python generate_icons.py
Outputs: assets/icon_green.png, assets/icon_red.png (16x16 and 32x32 @2x baked
into a single 32x32 image — Electron/OS scales tray icons as needed).
"""

import os

from PIL import Image, ImageDraw

SIZE = 32
OUT_DIR = os.path.join(os.path.dirname(__file__), "assets")


def make_dot_icon(color, path):
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    margin = 4
    draw.ellipse(
        [margin, margin, SIZE - margin, SIZE - margin],
        fill=color,
    )
    img.save(path)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    make_dot_icon((52, 199, 89, 255), os.path.join(OUT_DIR, "icon_green.png"))
    make_dot_icon((255, 59, 48, 255), os.path.join(OUT_DIR, "icon_red.png"))
    print(f"wrote icons to {OUT_DIR}")


if __name__ == "__main__":
    main()
