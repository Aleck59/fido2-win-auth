#!/usr/bin/env python3
"""Generate src/provider/tile.bmp, the 128x128 tile image for the provider.

Credential provider tile images must be plain 24-bit BMPs; keeping the
generator in the tree avoids committing a binary nobody can edit.
"""
import struct
import os

W = H = 128
BG = (0x7A, 0x3C, 0x00)      # BGR: Windows accent blue
FG = (0xFF, 0xFF, 0xFF)

px = [[BG for _ in range(W)] for _ in range(H)]


def disc(cx, cy, r, color):
    for y in range(H):
        for x in range(W):
            if (x - cx) ** 2 + (y - cy) ** 2 <= r * r:
                px[y][x] = color


def rect(x0, y0, x1, y1, color):
    for y in range(max(0, y0), min(H, y1)):
        for x in range(max(0, x0), min(W, x1)):
            px[y][x] = color


# Key bow with its hole, shaft to the right, two teeth below the shaft.
disc(44, 64, 26, FG)
disc(44, 64, 11, BG)
rect(62, 58, 104, 70, FG)
rect(84, 70, 92, 86, FG)
rect(96, 70, 104, 80, FG)

# BMP rows are bottom-up and padded to a 4-byte boundary (128*3 is already
# aligned, but keep the padding explicit in case the size ever changes).
row_pad = (-W * 3) % 4
pixels = bytearray()
for y in range(H - 1, -1, -1):
    for x in range(W):
        pixels += bytes(px[y][x])
    pixels += b"\x00" * row_pad

header = struct.pack("<2sIHHI", b"BM", 14 + 40 + len(pixels), 0, 0, 14 + 40)
info = struct.pack("<IiiHHIIiiII", 40, W, H, 1, 24, 0, len(pixels),
                   2835, 2835, 0, 0)

out = os.path.join(os.path.dirname(__file__), "..", "src", "provider", "tile.bmp")
with open(os.path.normpath(out), "wb") as f:
    f.write(header + info + bytes(pixels))
print("wrote", os.path.normpath(out), len(header + info + pixels), "bytes")
