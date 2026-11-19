#!/usr/bin/env python3
"""Decode the VietMap dashcam warning-point database (``secrect.bin``).

The file is plain CSV text in which every character was replaced by another
byte (a fixed one-byte substitution). Layout after decoding:

    line 0 : data version, e.g. ``261022``
    line 1 : record in a different encoding (not used, skipped)
    line 2+: ``lon,lat,type,speed_limit,flag,heading``   (CRLF line endings)

VietMap ``type`` (meaning established by matching positions with VietHUD):

    1  speed-limit sign  (speed_limit = km/h)
    2  traffic light
    4  start of residential (urban) zone
    10 no-overtaking sign
    11 traffic camera

Usage: ``python3 vietmap_decode.py secrect.bin [out.csv]``
"""
import struct
import sys
from dataclasses import dataclass

SUBSTITUTION = {
    0x82: "1", 0xA3: ",", 0xCF: "0", 0x64: "2", 0xB4: "5", 0x8B: "6",
    0xB7: "4", 0xA8: "8", 0xD9: "3", 0x91: "9", 0xAF: "7", 0x39: ".",
    0x83: "\r", 0x71: "\n",
}
ENCODE = {v: k for k, v in SUBSTITUTION.items()}

TYPE_SPEED_LIMIT    = 1
TYPE_TRAFFIC_LIGHT  = 2
TYPE_VM_LIGHT_3     = 3
TYPE_URBAN_START    = 4
TYPE_TOLL_BOOTH     = 5
TYPE_VM_LIGHT_6     = 6
TYPE_VM_DANGER_7    = 7
TYPE_VM_TYPE_8      = 8
TYPE_VM_TYPE_9      = 9
TYPE_NO_OVERTAKING  = 10
TYPE_CAMERA         = 11

KNOWN_TYPES = {
    TYPE_SPEED_LIMIT, TYPE_TRAFFIC_LIGHT, TYPE_VM_LIGHT_3,
    TYPE_URBAN_START, TYPE_TOLL_BOOTH, TYPE_VM_LIGHT_6,
    TYPE_VM_DANGER_7, TYPE_VM_TYPE_8, TYPE_VM_TYPE_9,
    TYPE_NO_OVERTAKING, TYPE_CAMERA
}

# Vietnam bounding box (generous) used to reject corrupt rows.
LAT_MIN, LAT_MAX = 8.0, 24.0
LON_MIN, LON_MAX = 102.0, 110.5


@dataclass(frozen=True)
class VietMapPoint:
    lon: float
    lat: float
    type: int
    speed_limit: int
    heading: int


@dataclass
class DecodeResult:
    version: str
    points: list
    skipped: dict


def encode_text(text):
    """Inverse of the substitution (used by tests to build fake files)."""
    return bytes(ENCODE[c] for c in text)


def extract_edogen_bytes(data: bytes) -> bytes:
    """Extract edogen.bin slice from secrect.bin container header (512 bytes)."""
    if data.startswith(b"secrect.bin") or b"edogen.bin" in data[:512]:
        toc: dict[str, int] = {}
        for i in range(0, min(len(data), 512), 68):
            chunk = data[i : i + 68]
            if len(chunk) < 68:
                break
            name = chunk[:64].rstrip(b"\x00").decode("latin1", errors="ignore").strip()
            if name:
                size = struct.unpack("<I", chunk[64:68])[0]
                toc[name] = size

        edogen_size = toc.get("edogen.bin", 2684000)
        return data[512 : 512 + edogen_size]
    return data


def decode_bytes(data):
    raw_data = extract_edogen_bytes(data)
    lines = raw_data.split(b"\x83\x71")
    skipped = {"undecodable": 0, "bad_fields": 0, "out_of_bounds": 0, "unknown_type": 0, "duplicate": 0}
    decoded = []
    version = "Unknown"
    for raw in lines:
        if not raw:
            continue
        if version == "Unknown" and 0xA3 not in raw:
            candidate = "".join(SUBSTITUTION[b] for b in raw if b in SUBSTITUTION).strip()
            if len(candidate) in (6, 8) and candidate.isdigit():
                version = candidate
                continue
        if any(b not in SUBSTITUTION for b in raw):
            decoded.append(None)
        else:
            decoded.append("".join(SUBSTITUTION[b] for b in raw))
    if not decoded:
        raise ValueError("secrect.bin: cannot decode lines")
    points, seen = [], set()
    for text in decoded:
        if text is None:
            skipped["undecodable"] += 1
            continue
        parts = text.split(",")
        try:
            lon, lat = float(parts[0]), float(parts[1])
            ptype, speed, heading = int(parts[2]), int(parts[3]), int(parts[5])
            if len(parts) != 6:
                raise ValueError
        except (ValueError, IndexError):
            skipped["bad_fields"] += 1
            continue
        if not (LAT_MIN <= lat <= LAT_MAX and LON_MIN <= lon <= LON_MAX):
            skipped["out_of_bounds"] += 1
            continue
        if ptype not in KNOWN_TYPES:
            skipped["unknown_type"] += 1
            continue
        key = (ptype, round(lat, 6), round(lon, 6), heading % 360)
        if key in seen:
            skipped["duplicate"] += 1
            continue
        seen.add(key)
        points.append(VietMapPoint(lon, lat, ptype, speed, heading % 360))
    return DecodeResult(version, points, skipped)


def decode_file(path):
    with open(path, "rb") as f:
        return decode_bytes(f.read())


def main():
    if len(sys.argv) not in (2, 3):
        raise SystemExit("usage: vietmap_decode.py <secrect.bin> [out.csv]")
    res = decode_file(sys.argv[1])
    out = open(sys.argv[2], "w", newline="\n") if len(sys.argv) == 3 else sys.stdout
    out.write("lon,lat,type,speed_limit,heading\n")
    for p in res.points:
        out.write(f"{p.lon},{p.lat},{p.type},{p.speed_limit},{p.heading}\n")
    print(f"version {res.version}: {len(res.points)} points, skipped {res.skipped}", file=sys.stderr)


if __name__ == "__main__":
    main()
