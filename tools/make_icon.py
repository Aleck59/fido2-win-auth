#!/usr/bin/env python3
"""Generate src/gui/app.ico, the application icon.

Same key glyph as the logon tile, drawn at the four sizes Windows asks for,
on a rounded blue plate with transparent corners. Written by hand because the
build toolchain has no image library and an .ico nobody can regenerate is a
binary blob in the tree.
"""
import os
import struct

SIZES = [16, 32, 48, 256]

PLATE = (0x7A, 0x3C, 0x00)  # BGR, Windows accent blue
GLYPH = (0xFF, 0xFF, 0xFF)


def render(size):
    """Returns BGRA rows, top-down, for one icon size."""
    k = size / 128.0
    # Fully transparent outside the plate.
    px = [[(0, 0, 0, 0) for _ in range(size)] for _ in range(size)]

    def opaque(color):
        return (color[0], color[1], color[2], 255)

    # Rounded plate: a square with the corners cut by a circle of radius r.
    r = max(2.0, 22 * k)
    for y in range(size):
        for x in range(size):
            cx = min(max(x + 0.5, r), size - r)
            cy = min(max(y + 0.5, r), size - r)
            if (x + 0.5 - cx) ** 2 + (y + 0.5 - cy) ** 2 <= r * r:
                px[y][x] = opaque(PLATE)

    def disc(ox, oy, rad, color):
        ox, oy, rad = ox * k, oy * k, rad * k
        for y in range(size):
            for x in range(size):
                if (x - ox) ** 2 + (y - oy) ** 2 <= rad * rad:
                    px[y][x] = opaque(color)

    def rect(x0, y0, x1, y1, color):
        x0, y0, x1, y1 = (int(round(v * k)) for v in (x0, y0, x1, y1))
        for y in range(max(0, y0), min(size, y1)):
            for x in range(max(0, x0), min(size, x1)):
                px[y][x] = opaque(color)

    # Key bow with its hole, shaft, two teeth -- the glyph from make_tile.py.
    disc(44, 64, 26, GLYPH)
    disc(44, 64, 11, PLATE)
    rect(62, 58, 104, 70, GLYPH)
    rect(84, 70, 92, 86, GLYPH)
    rect(96, 70, 104, 80, GLYPH)
    return px


def ico_image(size):
    """One BMP-in-ICO entry: BITMAPINFOHEADER, BGRA rows bottom-up, AND mask."""
    px = render(size)

    pixels = bytearray()
    for y in range(size - 1, -1, -1):
        for x in range(size):
            b, g, r, a = px[y][x]
            pixels += bytes((b, g, r, a))

    # The AND mask is unused for 32-bit icons but must still be present and
    # padded to 4 bytes per row.
    mask_row = (size + 31) // 32 * 4
    mask = bytearray(mask_row * size)

    # Height is doubled: the format counts colour rows plus mask rows.
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0,
                         len(pixels) + len(mask), 2835, 2835, 0, 0)
    return header + bytes(pixels) + bytes(mask)


images = [ico_image(s) for s in SIZES]

out = bytearray(struct.pack("<HHH", 0, 1, len(images)))
offset = 6 + 16 * len(images)
for size, data in zip(SIZES, images):
    # 0 means 256 in the directory entry.
    dim = 0 if size >= 256 else size
    out += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
    offset += len(data)
for data in images:
    out += data

path = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "src", "gui", "app.ico"))
with open(path, "wb") as f:
    f.write(bytes(out))
print("wrote", path, len(out), "bytes")
