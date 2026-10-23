from __future__ import annotations

from pathlib import Path

import make_icon
from PIL import Image, ImageDraw, ImageFilter, ImageFont

PROJECT = Path(__file__).resolve().parent.parent
TARGET = PROJECT / "docs" / "social-preview.png"
FONTS = Path("C:/Windows/Fonts")
SIZE = (1280, 640)
BACKGROUND = (8, 8, 10)
RED = (196, 51, 43)
DARK_RED = (142, 27, 27)
TEXT = (236, 233, 230)
MUTED = (155, 152, 160)
FAINT = (109, 106, 114)


def font(name: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONTS / name), size)


def glow() -> Image.Image:
    layer = Image.new("RGB", SIZE, BACKGROUND)
    draw = ImageDraw.Draw(layer)
    draw.ellipse((-120, 40, 640, 640), fill=DARK_RED)
    return layer.filter(ImageFilter.GaussianBlur(170))


def shield_layer(size: int) -> Image.Image:
    return make_icon.draw_icon().resize((size, size), Image.Resampling.LANCZOS)


def build() -> Image.Image:
    image = glow()
    shield = shield_layer(336)
    image.paste(shield, (90, 150), shield)
    draw = ImageDraw.Draw(image)
    title = font("segoeuib.ttf", 92)
    draw.text((470, 205), "Guardia", font=title, fill=TEXT)
    width = draw.textlength("Guardia ", font=title)
    draw.text((470 + width, 205), "MCP", font=title, fill=RED)
    draw.text((474, 330), "Free, offline security shield", font=font("segoeui.ttf", 38), fill=TEXT)
    draw.text((474, 378), "for AI agents that use MCP", font=font("segoeui.ttf", 38), fill=TEXT)
    small = font("segoeui.ttf", 24)
    draw.text((476, 450), "Scanner · Real-time Shield · Signed ledger", font=small, fill=MUTED)
    draw.text((476, 486), "Italiano / English · Apache 2.0", font=small, fill=MUTED)
    draw.text(
        (1190, 590), "by Alexander Puglisi", font=font("segoeui.ttf", 22), fill=FAINT, anchor="ra"
    )
    draw.rectangle((0, SIZE[1] - 3, SIZE[0], SIZE[1]), fill=RED)
    return image


def main() -> int:
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    build().save(TARGET, optimize=True)
    print(TARGET)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
