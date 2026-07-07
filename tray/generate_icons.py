"""Generates tray icons (dark "V" logo + status badge) with Pillow.

Run with: python generate_icons.py
Outputs: assets/icon_green.png, assets/icon_red.png, assets/icon_amber.png —
32x32 composite icons (dark rounded-square base, white V letterform, small
filled status-circle overlay in the bottom-right corner).
"""

import os

from PIL import Image, ImageDraw

SIZE = 32
OUT_DIR = os.path.join(os.path.dirname(__file__), "assets")

BASE_FILL = (26, 26, 26, 255)  # #1a1a1a
V_COLOR = (255, 255, 255, 255)
V_STROKE_WIDTH = 3
BADGE_DIAMETER = 8

STATUS_COLORS = {
    "green": (34, 197, 94, 255),  # #22c55e
    "red": (239, 68, 68, 255),  # #ef4444
    "amber": (245, 158, 11, 255),  # #f59e0b
}


def draw_base(draw):
    draw.rounded_rectangle([0, 0, SIZE - 1, SIZE - 1], radius=7, fill=BASE_FILL)

    # "V" letterform: two diagonal strokes meeting at a bottom-center point.
    top_y = 8
    bottom_y = 22
    center_x = SIZE / 2
    left_x = 9
    right_x = SIZE - 9

    draw.line([(left_x, top_y), (center_x, bottom_y)], fill=V_COLOR, width=V_STROKE_WIDTH)
    draw.line([(center_x, bottom_y), (right_x, top_y)], fill=V_COLOR, width=V_STROKE_WIDTH)


def draw_badge(draw, color):
    r = BADGE_DIAMETER / 2
    cx = SIZE - r - 2
    cy = SIZE - r - 2
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=color)


def make_icon(status_name, path):
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw_base(draw)
    draw_badge(draw, STATUS_COLORS[status_name])
    img.save(path)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    make_icon("green", os.path.join(OUT_DIR, "icon_green.png"))
    make_icon("red", os.path.join(OUT_DIR, "icon_red.png"))
    make_icon("amber", os.path.join(OUT_DIR, "icon_amber.png"))
    print(f"wrote icons to {OUT_DIR}")


if __name__ == "__main__":
    main()
