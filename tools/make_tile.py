#!/usr/bin/env python3
"""Generate the key bitmaps: the provider's logon tile and the GUI's prompt.

Credential provider tile images must be plain 24-bit BMPs, and the GUI prompt
uses the same glyph at a smaller size. Keeping the generator in the tree avoids
committing binaries nobody can edit.
"""
import os
import struct

# (output path relative to the repo root, size in pixels)
OUTPUTS = [
    ("src/provider/tile.bmp", 128),  # credential provider logon tile
    ("src/gui/key.bmp", 64),         # "insert your key" prompt in the GUI
]

BG = (0x7A, 0x3C, 0x00)  # BGR: Windows accent blue
FG = (0xFF, 0xFF, 0xFF)


def render(size):
    """Draws the key glyph at `size` x `size`, returning BMP file bytes."""
    px = [[BG for _ in range(size)] for _ in range(size)]
    # The glyph was drawn for 128px; scale every coordinate from that.
    k = size / 128.0

    def disc(cx, cy, r, color):
        cx, cy, r = cx * k, cy * k, r * k
        for y in range(size):
            for x in range(size):
                if (x - cx) ** 2 + (y - cy) ** 2 <= r * r:
                    px[y][x] = color

    def rect(x0, y0, x1, y1, color):
        x0, y0, x1, y1 = (int(round(v * k)) for v in (x0, y0, x1, y1))
        for y in range(max(0, y0), min(size, y1)):
            for x in range(max(0, x0), min(size, x1)):
                px[y][x] = color

    # Key bow with its hole, shaft to the right, two teeth below the shaft.
    disc(44, 64, 26, FG)
    disc(44, 64, 11, BG)
    rect(62, 58, 104, 70, FG)
    rect(84, 70, 92, 86, FG)
    rect(96, 70, 104, 80, FG)

    # BMP rows are bottom-up and padded to a 4-byte boundary.
    row_pad = (-size * 3) % 4
    pixels = bytearray()
    for y in range(size - 1, -1, -1):
        for x in range(size):
            pixels += bytes(px[y][x])
        pixels += b"\x00" * row_pad

    header = struct.pack("<2sIHHI", b"BM", 14 + 40 + len(pixels), 0, 0, 14 + 40)
    info = struct.pack("<IiiHHIIiiII", 40, size, size, 1, 24, 0, len(pixels),
                       2835, 2835, 0, 0)
    return header + info + bytes(pixels)


root = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
for rel, size in OUTPUTS:
    path = os.path.join(root, rel)
    data = render(size)
    with open(path, "wb") as f:
        f.write(data)
    print("wrote", path, len(data), "bytes")
