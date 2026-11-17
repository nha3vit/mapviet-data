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
METADATA_FMT = "<4sH16s16sQIIfiihI64sI"
INDEX_ENTRY_FMT = "<IiiiiII"
SEGMENT_FMT = "<IiiiiHBBhBB"
SIGN_HEADER_FMT = "<4sHIHII"
SIGN_POINT_FMT = "<IiiHBBBBH"
SIGN_TYPE_TRAFFIC_LIGHT = 6


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_geom_duplicate(seg_a, seg_b):
    """Kiểm tra 2 segment có cùng hình học (2 đầu mút trùng nhau <= 1m, cùng hoặc ngược chiều)."""
    _, a_s_lat, a_s_lon, a_e_lat, a_e_lon = seg_a[:5]
    _, b_s_lat, b_s_lon, b_e_lat, b_e_lon = seg_b[:5]

    # Trùng toạ độ E7 chính xác (xuôi hoặc ngược)
    if a_s_lat == b_s_lat and a_s_lon == b_s_lon and a_e_lat == b_e_lat and a_e_lon == b_e_lon:
        return True
    if a_s_lat == b_e_lat and a_s_lon == b_e_lon and a_e_lat == b_s_lat and a_e_lon == b_s_lon:
        return True

    # Trùng trong phạm vi <= 1 mét (1m ~= 90 E7 lat, 95 E7 lon tại VN)
    if abs(a_s_lat - b_s_lat) <= 95 and abs(a_s_lon - b_s_lon) <= 105 and \
       abs(a_e_lat - b_e_lat) <= 95 and abs(a_e_lon - b_e_lon) <= 105:
        return True

    if abs(a_s_lat - b_e_lat) <= 95 and abs(a_s_lon - b_e_lon) <= 105 and \
       abs(a_e_lat - b_s_lat) <= 95 and abs(a_e_lon - b_s_lon) <= 105:
        return True

    return False


def deduplicate_tiles(src_dir, dst_dir):
    """Phát hiện và loại bỏ các segment trùng hình học trong cùng tile, giữ lại id nhỏ nhất."""
    index_path = os.path.join(src_dir, "index.bin")
    tiles_path = os.path.join(src_dir, "tiles.bin")
    meta_path = os.path.join(src_dir, "metadata.bin")
    seg_names_path = os.path.join(src_dir, "seg_names.bin")

    if not (os.path.exists(index_path) and os.path.exists(tiles_path) and os.path.exists(meta_path)):
        return 0

    with open(index_path, "rb") as f:
        index_data = f.read()
    with open(tiles_path, "rb") as f:
        tiles_data = f.read()
    with open(meta_path, "rb") as f:
        meta_data = f.read()

    seg_names_data = bytearray()
    if os.path.exists(seg_names_path):
        with open(seg_names_path, "rb") as f:
            seg_names_data = bytearray(f.read())

    index_entry_size = struct.calcsize(INDEX_ENTRY_FMT)
    seg_size = struct.calcsize(SEGMENT_FMT)

    tile_count = len(index_data) // index_entry_size
    new_tiles_data = bytearray()
    new_index_data = bytearray()
    dropped_count = 0
    total_orig_segments = 0

    for i in range(tile_count):
        idx_entry = index_data[i * index_entry_size : (i + 1) * index_entry_size]
        tile_id, min_lat, max_lat, min_lon, max_lon, offset, length = struct.unpack(INDEX_ENTRY_FMT, idx_entry)

        num_segs = length // seg_size
        total_orig_segments += num_segs
        tile_segs = []
        for s in range(num_segs):
            seg_bytes = tiles_data[offset + s * seg_size : offset + (s + 1) * seg_size]
            seg_fields = struct.unpack(SEGMENT_FMT, seg_bytes)
            tile_segs.append((seg_fields, seg_bytes))

        kept_segs = []
        for seg_fields, seg_bytes in tile_segs:
            dup_idx = -1
            for k_idx, (k_fields, _) in enumerate(kept_segs):
                if is_geom_duplicate(k_fields, seg_fields):
                    dup_idx = k_idx
                    break
            if dup_idx == -1:
                kept_segs.append((seg_fields, seg_bytes))
            else:
                k_fields, k_bytes = kept_segs[dup_idx]
                if seg_fields[0] < k_fields[0]:
                    dropped_seg_id = k_fields[0]
                    kept_segs[dup_idx] = (seg_fields, seg_bytes)
                else:
                    dropped_seg_id = seg_fields[0]
                dropped_count += 1
                if seg_names_data and (dropped_seg_id * 4 + 4) <= len(seg_names_data):
                    struct.pack_into("<I", seg_names_data, dropped_seg_id * 4, 0)

        new_tile_offset = len(new_tiles_data)
        new_tile_length = len(kept_segs) * seg_size
        for _, seg_bytes in kept_segs:
            new_tiles_data.extend(seg_bytes)

        new_idx_entry = struct.pack(INDEX_ENTRY_FMT, tile_id, min_lat, max_lat, min_lon, max_lon, new_tile_offset, new_tile_length)
        new_index_data.extend(new_idx_entry)

    with open(os.path.join(dst_dir, "tiles.bin"), "wb") as f:
        f.write(new_tiles_data)
    with open(os.path.join(dst_dir, "index.bin"), "wb") as f:
        f.write(new_index_data)
    if seg_names_data:
        with open(os.path.join(dst_dir, "seg_names.bin"), "wb") as f:
            f.write(seg_names_data)

    meta_fields = list(struct.unpack(METADATA_FMT, meta_data))
    meta_fields[6] = total_orig_segments - dropped_count
    meta_fields[13] = zlib.crc32(bytes(new_index_data)) & 0xFFFFFFFF
    new_meta_data = struct.pack(METADATA_FMT, *meta_fields)
    with open(os.path.join(dst_dir, "metadata.bin"), "wb") as f:
        f.write(new_meta_data)

    print(f"[POSTPROCESS] Đã loại bỏ {dropped_count} segment trùng hình học ({total_orig_segments} -> {total_orig_segments - dropped_count})")
    return dropped_count


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

    # Sao chép names.bin
    names_src = os.path.join(src, "names.bin")
    if os.path.exists(names_src):
        shutil.copyfile(names_src, os.path.join(dst, "names.bin"))

    # Loại bỏ segment trùng hình học và ghi tiles.bin, index.bin, metadata.bin, seg_names.bin vào dst
    deduplicate_tiles(src, dst)

    n_lights = 0
    signs_src = os.path.join(src, "signs.bin")
    if os.path.exists(signs_src):
        n_lights = extract_lights(signs_src, os.path.join(dst, "lights.bin"))

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
