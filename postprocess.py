#!/usr/bin/env python3
"""Post-process the VietHUD pipeline output into a MapViet road-network pack.

Input  : <src> = output dir of VietHUD synthesize_and_pack.py (OSM-only build)
Output : <dst> = release dir with
           metadata.bin index.bin tiles.bin names.bin seg_names.bin lights.bin
           (each also as <file>.gz), manifest.txt, [manifest.txt.sig]

lights.bin = OSM highway=traffic_signals points (sign type 6) re-packed in the
VNSG signs format, so the app reads it with the existing SignsReader.

manifest.txt:
  version <YYYY.MM.DD.HHMM>
  <file> <size> <sha256> <gz_size>          (size/sha256 of the UNCOMPRESSED file)

Signing (optional): if env MAPVIET_SIGNING_KEY_FILE points to an EC P-256 PEM
private key, manifest.txt.sig = base64(DER ECDSA-SHA256 signature) — same
scheme as VietHUD, verified by the app with the MapViet public key.
"""
import base64
import gzip
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import time
import zlib

NETWORK_FILES = ["metadata.bin", "index.bin", "tiles.bin", "names.bin", "seg_names.bin"]
SIGN_HEADER_FMT = "<4sHIHII"
SIGN_POINT_FMT = "<IiiHBBBBH"
SIGN_TYPE_TRAFFIC_LIGHT = 6


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_lights(signs_path, out_path):
    data = open(signs_path, "rb").read()
    magic, ver, count, _res, _crc, ts = struct.unpack_from(SIGN_HEADER_FMT, data, 0)
    if magic != b"VNSG":
        raise SystemExit("signs.bin: bad magic")
    psize = struct.calcsize(SIGN_POINT_FMT)
    body = bytearray()
    n = 0
    for i in range(count):
        rec = data[20 + i * psize: 20 + (i + 1) * psize]
        if rec[14] == SIGN_TYPE_TRAFFIC_LIGHT:  # type byte
            body += rec
            n += 1
    header = struct.pack(SIGN_HEADER_FMT, b"VNSG", ver, n, 0, zlib.crc32(bytes(body)) & 0xFFFFFFFF, ts)
    with open(out_path, "wb") as f:
        f.write(header + bytes(body))
    return n


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: postprocess.py <pipeline_out_dir> <release_dir>")
    src, dst = sys.argv[1], sys.argv[2]
    os.makedirs(dst, exist_ok=True)
    for f in NETWORK_FILES:
        shutil.copyfile(os.path.join(src, f), os.path.join(dst, f))
    n_lights = extract_lights(os.path.join(src, "signs.bin"), os.path.join(dst, "lights.bin"))

    version = os.environ.get("MAPVIET_NETWORK_VERSION") or time.strftime("%Y.%m.%d.%H%M", time.gmtime())
    lines = [f"version {version}"]
    for f in NETWORK_FILES + ["lights.bin"]:
        p = os.path.join(dst, f)
        with open(p, "rb") as fi, gzip.open(p + ".gz", "wb", compresslevel=9) as fo:
            shutil.copyfileobj(fi, fo, 1 << 20)
        lines.append(f"{f} {os.path.getsize(p)} {sha256(p)} {os.path.getsize(p + '.gz')}")
    manifest = os.path.join(dst, "manifest.txt")
    with open(manifest, "w", newline="\n") as fo:
        fo.write("\n".join(lines) + "\n")

    key = os.environ.get("MAPVIET_SIGNING_KEY_FILE")
    if key:
        der = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key, manifest],
                             check=True, capture_output=True).stdout
        with open(manifest + ".sig", "w") as fo:
            fo.write(base64.b64encode(der).decode() + "\n")
    print(f"pack {version}: {n_lights} OSM traffic lights; signed={bool(key)}")
    print(open(manifest).read())


if __name__ == "__main__":
    main()
