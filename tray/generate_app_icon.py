"""Generates the high-resolution V-LAW app icon (no status badge) used for
the packaged Windows executable and the Inno Setup installer.

electron-builder requires a >=256x256 source PNG to build the .exe icon;
the existing assets/icon_*.png tray icons are 32x32 status badges and too
small to reuse directly. This redraws the same "V" wordmark at high
resolution rather than upscaling the small bitmap.

Run with: python generate_app_icon.py
Outputs: assets/app_icon.png (512x512), assets/app_icon.ico (multi-size)
"""

import os

from PIL import Image, ImageDraw

SIZE = 512
OUT_DIR = os.path.join(os.path.dirname(__file__), "assets")

BASE_FILL = (26, 26, 26, 255)  # #1a1a1a
V_COLOR = (255, 255, 255, 255)


def make_app_icon():
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle([0, 0, SIZE - 1, SIZE - 1], radius=112, fill=BASE_FILL)

    top_y = SIZE * 0.25
    bottom_y = SIZE * 0.6875
    center_x = SIZE / 2
    left_x = SIZE * 0.28125
    right_x = SIZE - left_x
    stroke_width = round(SIZE * 0.09375)

    draw.line([(left_x, top_y), (center_x, bottom_y)], fill=V_COLOR, width=stroke_width)
    draw.line([(center_x, bottom_y), (right_x, top_y)], fill=V_COLOR, width=stroke_width)

    png_path = os.path.join(OUT_DIR, "app_icon.png")
    img.save(png_path)

    ico_path = os.path.join(OUT_DIR, "app_icon.ico")
    img.save(ico_path, sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])

    print(f"wrote {png_path} and {ico_path}")


if __name__ == "__main__":
    make_app_icon()
