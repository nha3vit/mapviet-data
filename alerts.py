#!/usr/bin/env python3
"""Build the MapViet alert pack: VietHUD cameras/signs + VietMap points, de-duplicated.

Usage:
    python3 alerts.py --viethud <dir> --vietmap <secrect.bin> --out <dir> [--skip-verify]

<viethud dir> must contain VietHUD ``manifest.txt``, ``manifest.txt.sig``, ``cameras.bin``
and ``signs.bin`` (from github.com/911273/VietHUD/tree/main/speedmap). The manifest
signature (VietHUD public key) and the size/sha256 of both files are checked first.

Output (<out>): ``cameras.bin`` ``signs.bin`` (same binary formats as VietHUD, so the
app reads them unchanged), ``manifest.txt`` (``version <ver>`` then
``<file> <size> <sha256>``), ``manifest.txt.sig`` when env MAPVIET_SIGNING_KEY_FILE
is set, and ``stats.json``.

Merge rules (VietHUD is the base; VietMap only adds what VietHUD lacks):
  * VietMap type -> VietHUD kind: 1 -> sign 1 (speed limit), 2 -> sign 6 (traffic light),
    4 -> sign 2 subType 0 (urban start), 10 -> sign 3 (no overtaking), 11 -> camera.
  * A VietMap point is a duplicate when a point of the same kind lies within
    MERGE_RADIUS_M and the headings agree (<= SIGN_HEADING_TOL / CAMERA_HEADING_TOL,
    or either heading unknown). Duplicates are dropped; VietHUD's record wins
    (speed-limit disagreements are counted in stats).
  * New points get stable ids derived from their content (signs: 0x80000000 | crc,
    cameras: 1<<62 | crc) so ids do not change between builds. Signs added from
    VietMap carry reserved = SOURCE_VIETMAP.
"""
import argparse
import base64
import collections
import hashlib
import json
import math
import os
import struct
import subprocess
import sys
import tempfile
import time
import zlib

import vietmap_decode as vm

SIGN_HEADER_FMT = "<4sHIHII"
SIGN_POINT_FMT = "<IiiHBBBBH"
CAMERA_FMT = "<QiihH"
SIGN_HEADER_SIZE = struct.calcsize(SIGN_HEADER_FMT)
SIGN_POINT_SIZE = struct.calcsize(SIGN_POINT_FMT)
CAMERA_SIZE = struct.calcsize(CAMERA_FMT)
DIR_ANY = 0xFFFF

MERGE_RADIUS_M = 30.0
SIGN_HEADING_TOL = 45
CAMERA_HEADING_TOL = 60
SOURCE_VIETMAP = 1

SIGN_SPEED, SIGN_URBAN, SIGN_NO_OVERTAKING, SIGN_LIGHT = 1, 2, 3, 6
VIETMAP_TO_KIND = {
    vm.TYPE_SPEED_LIMIT: ("sign", SIGN_SPEED),
    vm.TYPE_TRAFFIC_LIGHT: ("sign", SIGN_LIGHT),
    vm.TYPE_URBAN_START: ("sign", SIGN_URBAN),
    vm.TYPE_NO_OVERTAKING: ("sign", SIGN_NO_OVERTAKING),
    vm.TYPE_CAMERA: ("camera", None),
}

# VietHUD manifest signing key (firmware src/update/DataInstaller.cpp).
VIETHUD_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEln5apjIcBBwLnKzVMOhMFCBVA6rD
7FhcGMXJpIKiMDUBgVvLwKBFiOlI4PqASEINgUEu4aTpkTVdW8iZ9B2WzQ==
-----END PUBLIC KEY-----
"""

CELL_DEG = 0.0005  # ~55 m; a 3x3 neighbourhood always covers MERGE_RADIUS_M


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_viethud(src_dir):
    """Check VietHUD manifest signature + size/sha256 of cameras.bin and signs.bin."""
    manifest = os.path.join(src_dir, "manifest.txt")
    with open(os.path.join(src_dir, "manifest.txt.sig")) as f:
        sig = base64.b64decode(f.read().strip())
    with tempfile.TemporaryDirectory() as tmp:
        pub, sigf = os.path.join(tmp, "pub.pem"), os.path.join(tmp, "sig.der")
        with open(pub, "w") as f:
            f.write(VIETHUD_PUBLIC_KEY_PEM)
        with open(sigf, "wb") as f:
            f.write(sig)
        r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", pub, "-signature", sigf, manifest],
                           capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"VietHUD manifest signature INVALID: {r.stdout.strip()} {r.stderr.strip()}")
    entries = {}
    with open(manifest) as f:
        lines = f.read().splitlines()
    version = lines[0].split(" ", 1)[1] if lines and lines[0].startswith("version ") else "?"
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 3:
            entries[parts[0]] = (int(parts[1]), parts[2].lower())
    for name in ("cameras.bin", "signs.bin"):
        if name not in entries:
            raise SystemExit(f"VietHUD manifest has no {name}")
        p = os.path.join(src_dir, name)
        size, digest = entries[name]
        if os.path.getsize(p) != size or sha256_file(p) != digest:
            raise SystemExit(f"VietHUD {name} does not match its signed manifest")
    return version


def read_cameras(path):
    data = open(path, "rb").read()
    if len(data) % CAMERA_SIZE:
        raise SystemExit("cameras.bin: size is not a multiple of 20")
    return [struct.unpack_from(CAMERA_FMT, data, o) for o in range(0, len(data), CAMERA_SIZE)]


def read_signs(path):
    data = open(path, "rb").read()
    magic, ver, count, _res, crc, ts = struct.unpack_from(SIGN_HEADER_FMT, data, 0)
    if magic != b"VNSG":
        raise SystemExit("signs.bin: bad magic")
    body = data[SIGN_HEADER_SIZE:SIGN_HEADER_SIZE + count * SIGN_POINT_SIZE]
    if len(body) != count * SIGN_POINT_SIZE or (zlib.crc32(body) & 0xFFFFFFFF) != crc:
        raise SystemExit("signs.bin: truncated or bad crc32")
    recs = [struct.unpack_from(SIGN_POINT_FMT, body, i * SIGN_POINT_SIZE) for i in range(count)]
    return ver, ts, recs


def heading_known(d):
    return d != DIR_ANY and 0 <= d < 360


def headings_agree(a, b, tol):
    if not heading_known(a) or not heading_known(b):
        return True
    return abs((a - b + 180) % 360 - 180) <= tol


def distance_m(lat1, lon1, lat2, lon2):
    k = 111_320.0
    return math.hypot((lat1 - lat2) * k, (lon1 - lon2) * k * math.cos(math.radians((lat1 + lat2) / 2)))


class SpatialIndex:
    def __init__(self):
        self.cells = collections.defaultdict(list)

    @staticmethod
    def _cell(lat, lon):
        return int(math.floor(lat / CELL_DEG)), int(math.floor(lon / CELL_DEG))

    def add(self, kind, lat, lon, direction, payload):
        cy, cx = self._cell(lat, lon)
        self.cells[(kind, cy, cx)].append((lat, lon, direction, payload))

    def find(self, kind, lat, lon, direction, radius, tol):
        cy, cx = self._cell(lat, lon)
        best = None
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                for p in self.cells.get((kind, cy + dy, cx + dx), ()):
                    d = distance_m(lat, lon, p[0], p[1])
                    if d <= radius and headings_agree(direction, p[2], tol) and (best is None or d < best[0]):
                        best = (d, p)
        return best


def stable_id(prefix, ptype, lat_e7, lon_e7, heading, used, base, mask):
    seed = f"{prefix}:{ptype}:{lat_e7}:{lon_e7}:{heading}".encode()
    candidate = base | (int.from_bytes(hashlib.sha1(seed).digest()[:8], "big") & mask)
    while candidate in used:
        candidate = base | ((candidate + 1) & mask)
    used.add(candidate)
    return candidate


def merge(vh_cameras, vh_signs, vm_points):
    """Return (cameras, signs, stats). Inputs/outputs are raw struct tuples."""
    index = SpatialIndex()
    for c in vh_cameras:
        index.add("camera", c[1] / 1e7, c[2] / 1e7, c[4], ("vh", c))
    for s in vh_signs:
        index.add(("sign", s[4]), s[1] / 1e7, s[2] / 1e7, s[3], ("vh", s))

    cam_ids = {c[0] for c in vh_cameras}
    sign_ids = {s[0] for s in vh_signs}
    new_cameras, new_signs = [], []
    stats = collections.defaultdict(lambda: collections.Counter())

    for p in vm_points:
        group, sign_type = VIETMAP_TO_KIND[p.type]
        kind = "camera" if group == "camera" else ("sign", sign_type)
        tol = CAMERA_HEADING_TOL if group == "camera" else SIGN_HEADING_TOL
        label = f"vietmap_type_{p.type}"
        hit = index.find(kind, p.lat, p.lon, p.heading, MERGE_RADIUS_M, tol)
        if hit is not None:
            src, rec = hit[1][3]
            stats[label]["duplicate_of_" + src] += 1
            if p.type == vm.TYPE_SPEED_LIMIT and src == "vh" and rec[5] != p.speed_limit:
                stats[label]["speed_conflict_kept_viethud"] += 1
            continue
        lat_e7, lon_e7 = round(p.lat * 1e7), round(p.lon * 1e7)
        if group == "camera":
            cid = stable_id("cam", p.type, lat_e7, lon_e7, p.heading, cam_ids, 1 << 62, (1 << 62) - 1)
            speed = p.speed_limit if p.speed_limit > 0 else -1
            rec = (cid, lat_e7, lon_e7, speed, p.heading)
            new_cameras.append(rec)
        else:
            sid = stable_id("sign", p.type, lat_e7, lon_e7, p.heading, sign_ids, 0x80000000, 0x7FFFFFFF)
            speed = p.speed_limit if sign_type == SIGN_SPEED else 0
            rec = (sid, lat_e7, lon_e7, p.heading, sign_type, speed, 0, 0, SOURCE_VIETMAP)
            new_signs.append(rec)
        index.add(kind, p.lat, p.lon, p.heading, ("vm", rec))
        stats[label]["added"] += 1

    summary = {
        "viethud_cameras": len(vh_cameras),
        "viethud_signs": len(vh_signs),
        "vietmap_points": len(vm_points),
        "added_cameras": len(new_cameras),
        "added_signs": len(new_signs),
        "total_cameras": len(vh_cameras) + len(new_cameras),
        "total_signs": len(vh_signs) + len(new_signs),
        "by_vietmap_type": {k: dict(v) for k, v in sorted(stats.items())},
    }
    return list(vh_cameras) + new_cameras, list(vh_signs) + new_signs, summary


def write_cameras(path, cameras):
    with open(path, "wb") as f:
        for c in cameras:
            f.write(struct.pack(CAMERA_FMT, *c))


def write_signs(path, version, signs, timestamp):
    body = b"".join(struct.pack(SIGN_POINT_FMT, *s) for s in signs)
    header = struct.pack(SIGN_HEADER_FMT, b"VNSG", version, len(signs), 0, zlib.crc32(body) & 0xFFFFFFFF, timestamp)
    with open(path, "wb") as f:
        f.write(header + body)


def write_manifest(out_dir, version):
    lines = [f"version {version}"]
    for name in ("cameras.bin", "signs.bin"):
        p = os.path.join(out_dir, name)
        lines.append(f"{name} {os.path.getsize(p)} {sha256_file(p)}")
    manifest = os.path.join(out_dir, "manifest.txt")
    with open(manifest, "w", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    key = os.environ.get("MAPVIET_SIGNING_KEY_FILE")
    if key:
        der = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key, manifest],
                             check=True, capture_output=True).stdout
        with open(manifest + ".sig", "w") as f:
            f.write(base64.b64encode(der).decode() + "\n")
    return bool(key)


def content_hash(out_dir):
    h = hashlib.sha256()
    for name in ("cameras.bin", "signs.bin"):
        h.update(sha256_file(os.path.join(out_dir, name)).encode())
    return h.hexdigest()


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--viethud", required=True)
    ap.add_argument("--vietmap", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--skip-verify", action="store_true", help="tests only: do not check VietHUD signature")
    args = ap.parse_args(argv)

    vh_version = "unverified" if args.skip_verify else verify_viethud(args.viethud)
    vh_cameras = read_cameras(os.path.join(args.viethud, "cameras.bin"))
    sign_ver, sign_ts, vh_signs = read_signs(os.path.join(args.viethud, "signs.bin"))
    decoded = vm.decode_file(args.vietmap)

    cameras, signs, summary = merge(vh_cameras, vh_signs, decoded.points)
    os.makedirs(args.out, exist_ok=True)
    write_cameras(os.path.join(args.out, "cameras.bin"), cameras)
    # Reuse VietHUD's timestamp so the output is byte-identical when inputs are unchanged.
    write_signs(os.path.join(args.out, "signs.bin"), sign_ver, signs, sign_ts)

    version = os.environ.get("MAPVIET_ALERTS_VERSION") or time.strftime("%Y.%m.%d.%H%M", time.gmtime())
    signed = write_manifest(args.out, version)
    summary.update({
        "version": version,
        "viethud_version": vh_version,
        "vietmap_version": decoded.version,
        "vietmap_skipped": decoded.skipped,
        "content_sha256": content_hash(args.out),
        "signed": signed,
    })
    with open(os.path.join(args.out, "stats.json"), "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    sys.exit(main())
