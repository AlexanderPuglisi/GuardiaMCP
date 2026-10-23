from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

PROJECT = Path(__file__).resolve().parent.parent
TARGET = PROJECT / "src" / "guardia" / "app" / "guardia.ico"
CANVAS = 1024
SCALE = CANVAS / 32
FILL = (29, 29, 35, 255)
RED = (196, 51, 43, 255)
WHITE = (236, 233, 230, 255)
SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
Point = tuple[float, float]


def cubic(start: Point, first: Point, second: Point, end: Point, steps: int = 40) -> list[Point]:
    points = []
    for index in range(1, steps + 1):
        t = index / steps
        u = 1 - t
        points.append(
            (
                u**3 * start[0]
                + 3 * u * u * t * first[0]
                + 3 * u * t * t * second[0]
                + t**3 * end[0],
                u**3 * start[1]
                + 3 * u * u * t * first[1]
                + 3 * u * t * t * second[1]
                + t**3 * end[1],
            )
        )
    return points


def shield() -> list[Point]:
    outline: list[Point] = [(16, 2.5), (4.5, 7), (4.5, 15.2)]
    outline += cubic((4.5, 15.2), (4.5, 22.5), (9.3, 27.7), (16, 29.5))
    outline += cubic((16, 29.5), (22.7, 27.7), (27.5, 22.5), (27.5, 15.2))
    outline += [(27.5, 7)]
    return [(x * SCALE, y * SCALE) for x, y in outline]


def draw_icon() -> Image.Image:
    image = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    outline = shield()
    draw.polygon(outline, fill=FILL)
    draw.line([*outline, outline[0], outline[1]], fill=RED, width=round(2.2 * SCALE), joint="curve")
    check = [(11 * SCALE, 16 * SCALE), (14.6 * SCALE, 19.6 * SCALE), (21.5 * SCALE, 12.7 * SCALE)]
    width = round(2.6 * SCALE)
    draw.line(check, fill=WHITE, width=width, joint="curve")
    radius = width / 2
    for x, y in (check[0], check[-1]):
        draw.ellipse((x - radius, y - radius, x + radius, y + radius), fill=WHITE)
    return image


def main() -> int:
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    draw_icon().save(TARGET, sizes=SIZES)
    print(TARGET)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
