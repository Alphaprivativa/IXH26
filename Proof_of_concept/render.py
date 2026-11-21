"""The registered PoC profile: RGGB16, integer interpolation, one 4:4:4 MCU per interval."""

import io
import struct
from dataclasses import astuple, dataclass
from functools import lru_cache

from PIL import Image

from primitives import enc, require


@dataclass(frozen=True)
class Geometry:
    width: int
    height: int
    left: int
    top: int
    crop_width: int
    crop_height: int
    orientation: int

    def __post_init__(self):
        require(2 <= self.width <= 1024 and 2 <= self.height <= 1024, "unsupported sensor size")
        require(0 <= self.left < self.left + self.crop_width <= self.width and
                0 <= self.top < self.top + self.crop_height <= self.height, "invalid crop")
        require(1 <= self.orientation <= 8, "invalid TIFF orientation")

    @property
    def size(self):
        if self.orientation >= 5:
            return self.crop_height, self.crop_width
        return self.crop_width, self.crop_height

    @property
    def count(self):
        w, h = self.size
        return ((w + 7) // 8) * ((h + 7) // 8)

    def wire(self):
        return enc("IXH26/RGGB16-geometry/v1", *astuple(self))

    def source(self, x, y):
        """Inverse TIFF orientation, then crop offset in the original CFA plane."""
        if self.orientation >= 5:
            x, y = y, x
        if self.orientation in (2, 3, 7, 8):
            x = self.crop_width - 1 - x
        if self.orientation in (3, 4, 6, 7):
            y = self.crop_height - 1 - y
        return self.left + x, self.top + y

    def tile(self, i):
        require(0 <= i < self.count, "unexpected MCU index")
        w, h = self.size
        row, col = divmod(i, (w + 7) // 8)
        x, y = 8 * col, 8 * row
        return x, y, min(x + 8, w), min(y + 8, h)

    def bounds(self, i):
        x, y, end_x, end_y = self.tile(i)
        a, b = self.source(x, y)
        c, d = self.source(end_x - 1, end_y - 1)
        return (max(0, min(a, c) - 1), max(0, min(b, d) - 1),
                min(self.width, max(a, c) + 2), min(self.height, max(b, d) + 2))


def fixture(g):
    return b"".join(struct.pack("<H", (x*1901 + y*1201 + ((x//4 ^ y//3) & 1)*30000) % 65536)
                    for y in range(g.height) for x in range(g.width))


def dng_header(g):
    """Single-strip classic TIFF/DNG, CFA and signed crop in the main IFD."""
    entries = []
    def entry(tag, fmt, *values):
        kind = {"B": 1, "H": 3, "I": 4}[fmt]
        entries.append((tag, kind, len(values), struct.pack("<" + fmt * len(values), *values)))

    entry(254, "I", 0)
    entry(256, "I", g.width)
    entry(257, "I", g.height)
    entry(258, "H", 16)
    entry(259, "H", 1)
    entry(262, "H", 32803)
    entry(273, "I", 0)  # strip offset, resolved after the IFD
    entry(274, "H", g.orientation)
    entry(277, "H", 1)
    entry(278, "I", g.height)
    entry(279, "I", 2*g.width*g.height)
    entry(33421, "H", 2, 2)
    entry(33422, "B", 0, 1, 1, 2)
    entry(50706, "B", 1, 4, 0, 0)
    entry(50707, "B", 1, 1, 0, 0)
    entries.append((50708, 2, 12, b"IXH26 RGGB1\0"))
    entry(50717, "I", 65535)
    entry(50719, "H", g.left, g.top)
    entry(50720, "H", g.crop_width, g.crop_height)
    # Identity XYZ-to-camera calibration in signed rationals, D65.
    matrix = b"".join(struct.pack("<ii", int(i % 4 == 0), 1) for i in range(9))
    entries.append((50721, 10, 9, matrix))
    entry(50778, "H", 21)
    base = 14 + 12 * len(entries)
    extra = bytearray()
    rows = bytearray()
    strip_offset = base + sum(len(v) + len(v) % 2 for _, _, _, v in entries if len(v) > 4)
    for tag, kind, count, data in entries:
        if tag == 273:
            data = struct.pack("<I", strip_offset)
        if len(data) > 4:
            offset = base + len(extra)
            extra.extend(data + bytes(len(data) % 2))
            data = struct.pack("<I", offset)
        rows.extend(struct.pack("<HHI4s", tag, kind, count, data))
    return b"II\x2a\x00\x08\x00\x00\x00" + struct.pack("<H", len(entries)) + rows + bytes(4) + extra


def read_plane(dng, g):
    header = dng_header(g)
    require(dng.startswith(header) and len(dng) == len(header) + 2*g.width*g.height,
            "unsupported DNG layout or metadata")
    return dng[len(header):]


def footprint(plane, g, i):
    x, y, end_x, end_y = g.bounds(i)
    return b"".join(plane[2*(row*g.width+x):2*(row*g.width+end_x)] for row in range(y, end_y))


def record(g, i, samples):
    return enc("IXH26/RGGB16le/v1", *g.bounds(i), samples)


def develop(samples, g, bounds, output):
    left, top, end_x, end_y = bounds
    stride = end_x - left
    require(len(samples) == 2 * stride * (end_y - top), "unexpected RAW footprint size")
    x0, y0, x1, y1 = output
    rgb = bytearray()
    for y in range(y0, y1):
        for x in range(x0, x1):
            sx, sy = g.source(x, y)
            totals = [0, 0, 0]
            counts = [0, 0, 0]
            for yy in range(max(0, sy-1), min(g.height, sy+2)):
                for xx in range(max(0, sx-1), min(g.width, sx+2)):
                    color = (xx & 1) + (yy & 1)
                    offset = 2*((yy-top)*stride + xx-left)
                    value = struct.unpack_from("<H", samples, offset)[0]
                    totals[color] += value
                    counts[color] += 1
                    if xx == sx and yy == sy:
                        center = value
            for color in range(3):
                value = center if color == (sx & 1) + (sy & 1) else totals[color] // counts[color]
                rgb.append(value >> 8)
    return Image.frombytes("RGB", (x1-x0, y1-y0), bytes(rgb))


def encode(image):
    output = io.BytesIO()
    image.save(output, "JPEG", quality=95, subsampling=0, optimize=False,
               progressive=False, restart_marker_blocks=1)
    return output.getvalue()


def render_dng(dng, g):
    w, h = g.size
    return encode(develop(read_plane(dng, g), g, (0, 0, g.width, g.height), (0, 0, w, h)))


@lru_cache(maxsize=32)
def header(size):
    data = encode(Image.new("RGB", size))
    pos = 2
    while pos + 4 <= len(data) and data[pos] == 255:
        length = int.from_bytes(data[pos+2:pos+4], "big")
        require(length >= 2, "bad encoder header")
        end = pos + 2 + length
        if data[pos+1] == 0xda:
            return data[:end]
        pos = end
    raise ValueError("encoder produced no SOS")


def intervals(data, size):
    canon = header(size)
    require(data.startswith(canon), "noncanonical JPEG header")
    w, h = size
    count = ((w + 7) // 8) * ((h + 7) // 8)
    start = pos = len(canon)
    result = []
    while len(result) < count:
        pos = data.find(b"\xff", pos)
        require(pos >= 0 and pos+1 < len(data), "truncated JPEG scan")
        marker = data[pos+1]
        if marker == 0:
            pos += 2
            continue
        expected = 0xd9 if len(result) == count-1 else 0xd0 + len(result) % 8
        require(marker == expected and pos > start, "unexpected JPEG boundary")
        result.append(data[start:pos])
        start = pos = pos+2
    require(pos == len(data), "trailing bytes after EOI")
    return result


def render_interval(samples, g, i):
    image = develop(samples, g, g.bounds(i), g.tile(i))
    return intervals(encode(image), image.size)[0]
