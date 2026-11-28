#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Bản sao từ VietHUD/tools/vietmap_decode.py — nguồn chuẩn là VietHUD/tools; sửa ở đó rồi chép lại
"""
tools/vietmap_decode.py — Giải mã file dữ liệu cảnh báo VietMap SpeedMap M2 / Papago (secrect.bin).

Bản chất file secrect.bin:
  - Header 512 bytes: Chứa chỉ mục phân vùng các sub-file (edogen.bin, citiesen.bin, etc.)
  - Phân vùng edogen.bin: Dữ liệu cảnh báo dạng text được mã hóa bằng bảng thế 1-byte cố định (Substitution Cipher)
  - Phân cách dòng bằng cụm byte: b'\\x83\\x71' (\\r\\n)

Bảng phân loại VietMap type (xem chi tiết và bằng chứng tại docs/DATA_STANDARD.md và AGY_TASK_R5B_PENDING_TYPES.md):
  1  : Biển giới hạn tốc độ (speed_limit = km/h) (đã kiểm chứng)
  2  : R.420 vào khu đông dân cư (đã kiểm chứng)
  3  : R.421 hết khu đông dân cư (đã kiểm chứng)
  4  : Đèn tín hiệu giao thông / nút giao có đèn (độ tin cậy cao - kiểm chứng OSM)
  5  : Bắt đầu đoạn cấm vượt (độ tin cậy trung bình)
  6  : Hết đoạn cấm vượt (độ tin cậy trung bình)
  7  : Cảnh báo khác "Chú ý" (độ tin cậy thấp - app: "Chú ý đoạn đường phía trước")
  8  : Trạm thu phí (đã kiểm chứng)
  9  : Hầm đường bộ (đã kiểm chứng)
  10 : Cảnh báo khác (độ tin cậy thấp - app: chỉ vẽ, không đọc)
  11 : Camera giám sát giao thông / phạt nguội (đã kiểm chứng)

Định dạng dòng sau giải mã:
  lon,lat,type,speed_limit,flag,heading
"""

from __future__ import annotations

import json
import os
import struct
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

SUBSTITUTION = {
    0x82: "1", 0xA3: ",", 0xCF: "0", 0x64: "2", 0xB4: "5", 0x8B: "6",
    0xB7: "4", 0xA8: "8", 0xD9: "3", 0x91: "9", 0xAF: "7", 0x39: ".",
    0x83: "\r", 0x71: "\n",
}

# Reverse lookup dictionary (char -> byte) for testing and encoding
REVERSE_SUBSTITUTION = {v: k for k, v in SUBSTITUTION.items()}

TYPE_SPEED_LIMIT          = 1
TYPE_RESIDENT_ENTER        = 2      # R.420 vào khu đông dân cư   (đã kiểm chứng)
TYPE_RESIDENT_EXIT         = 3      # R.421 hết khu đông dân cư   (đã kiểm chứng)
TYPE_SIGNAL                = 4      # Đèn tín hiệu / nút giao có đèn (độ tin cậy cao)
TYPE_NO_OVERTAKING_START   = 5      # Bắt đầu đoạn cấm vượt       (độ tin cậy trung bình)
TYPE_NO_OVERTAKING_END     = 6      # Hết đoạn cấm vượt           (độ tin cậy trung bình)
TYPE_UNCLEAR_7             = 7      # Cảnh báo khác "Chú ý"       (độ tin cậy thấp)
TYPE_TOLL                  = 8      # Trạm thu phí                (đã kiểm chứng)
TYPE_TUNNEL                = 9      # Hầm đường bộ                (đã kiểm chứng)
TYPE_UNCLEAR_10            = 10     # Cảnh báo khác chỉ vẽ        (độ tin cậy thấp)
TYPE_CAMERA                = 11     # Camera phạt nguội           (đã kiểm chứng)

# Alias R5A và cũ để tương thích ngược tuyệt đối
TYPE_PENDING_4             = TYPE_SIGNAL
TYPE_PENDING_5             = TYPE_NO_OVERTAKING_START
TYPE_PENDING_6             = TYPE_NO_OVERTAKING_END
TYPE_PENDING_7             = TYPE_UNCLEAR_7
TYPE_PENDING_10            = TYPE_UNCLEAR_10
TYPE_TRAFFIC_LIGHT         = TYPE_RESIDENT_ENTER
TYPE_VM_LIGHT_3            = TYPE_RESIDENT_EXIT
TYPE_URBAN_START           = TYPE_SIGNAL
TYPE_TOLL_BOOTH            = TYPE_NO_OVERTAKING_START
TYPE_VM_LIGHT_6            = TYPE_NO_OVERTAKING_END
TYPE_VM_DANGER_7           = TYPE_UNCLEAR_7
TYPE_VM_TYPE_8             = TYPE_TOLL
TYPE_VM_TYPE_9             = TYPE_TUNNEL
TYPE_NO_OVERTAKING         = TYPE_UNCLEAR_10

KNOWN_TYPES = {
    TYPE_SPEED_LIMIT, TYPE_RESIDENT_ENTER, TYPE_RESIDENT_EXIT,
    TYPE_SIGNAL, TYPE_NO_OVERTAKING_START, TYPE_NO_OVERTAKING_END,
    TYPE_UNCLEAR_7, TYPE_TOLL, TYPE_TUNNEL,
    TYPE_UNCLEAR_10, TYPE_CAMERA
}

# Tọa độ bounding box Việt Nam để lọc nhiễu
LAT_MIN, LAT_MAX = 8.0, 24.0
LON_MIN, LON_MAX = 102.0, 110.5


@dataclass(frozen=True)
class VietMapPoint:
    lon: float
    lat: float
    type: int
    speed_limit: int
    heading: int
    raw_flag: int = 0


@dataclass
class DecodeResult:
    version: str
    points: list
    skipped: dict


@dataclass
class TocEntry:
    name: str
    offset: int
    size: int


@dataclass
class RoadPolyline:
    road_id: int
    link_id: int
    name: str
    province_id: int
    district_id: int
    speed_fwd: int
    speed_bwd: int
    coords: list[tuple[float, float]]  # (lat, lon)


# Bảng giải mã 256-byte đầy đủ cho cả 4 phân vùng (edogen, citiesen, districtsen, roadsenz)
# Giữ nguyên SUBSTITUTION / REVERSE_SUBSTITUTION ở trên để tương thích 100% logic & test edogen cũ.
TEXT_CIPHER_BYTE_MAP: dict[int, int] = {
    1: 69, 2: 110, 4: 102, 5: 43, 6: 161, 7: 198, 8: 108, 9: 178,
    11: 172, 12: 195, 14: 121, 15: 181, 17: 80, 18: 101, 22: 67, 23: 155,
    25: 225, 26: 65, 30: 152, 31: 113, 33: 75, 34: 169, 36: 187, 39: 97,
    40: 45, 42: 118, 48: 70, 51: 90, 52: 185, 57: 46, 61: 168, 63: 151,
    64: 173, 65: 109, 66: 146, 67: 160, 68: 77, 70: 239, 73: 9, 74: 182,
    77: 73, 79: 83, 82: 66, 84: 107, 85: 135, 87: 86, 88: 143, 90: 32,
    92: 172, 93: 131, 95: 99, 96: 137, 99: 168, 100: 50, 102: 189, 103: 164,
    107: 117, 108: 176, 109: 186, 111: 170, 113: 10, 115: 85, 119: 87, 121: 139,
    123: 148, 126: 129, 128: 191, 130: 49, 131: 13, 132: 39, 136: 84, 137: 138,
    139: 54, 140: 79, 141: 145, 144: 197, 145: 57, 146: 106, 148: 72, 150: 95,
    151: 162, 153: 147, 157: 182, 159: 158, 160: 163, 161: 88, 162: 183, 163: 44,
    164: 130, 168: 56, 169: 196, 171: 167, 175: 55, 176: 105, 177: 76, 178: 68,
    180: 53, 181: 175, 182: 116, 183: 52, 184: 170, 188: 112, 189: 104, 190: 175,
    195: 81, 198: 89, 200: 103, 202: 100, 205: 98, 207: 48, 210: 74, 212: 133,
    214: 179, 215: 177, 217: 51, 218: 144, 219: 111, 220: 141, 221: 115, 223: 71,
    227: 119, 228: 47, 231: 180, 232: 153, 233: 165, 234: 173, 235: 157, 237: 78,
    239: 114, 244: 82, 248: 121, 250: 122, 251: 141, 255: 154,
}
BYTE_DECODE_LUT: bytes = bytes(TEXT_CIPHER_BYTE_MAP.get(i, i) for i in range(256))


def parse_toc(data: bytes) -> dict[str, TocEntry]:
    """Đọc bảng mục lục 512 bytes đầu file secrect.bin (68 bytes/mục) -> {tên: TocEntry(name, offset, size)}."""
    if len(data) < 512 or (not data.startswith(b"secrect.bin") and b"edogen.bin" not in data[:512]):
        return {}
    entries: dict[str, TocEntry] = {}
    cursor = 512
    for i in range(0, 448, 68):
        chunk = data[i : i + 68]
        if len(chunk) < 68:
            break
        name = chunk[:64].split(b"\x00", 1)[0].decode("latin1", errors="ignore").strip()
        if not name:
            continue
        size = struct.unpack("<I", chunk[64:68])[0]
        if i == 0 and name == "secrect.bin":
            entries[name] = TocEntry(name=name, offset=0, size=size)
        else:
            entries[name] = TocEntry(name=name, offset=cursor, size=size)
            cursor += size
    return entries


def extract_toc_version(data: bytes) -> str | None:
    """Trích chuỗi phiên bản ASCII (vd '2026102820261119') ở cuối header 512 bytes nếu có."""
    if len(data) < 512:
        return None
    tail = data[448:512].strip(b"\x00").decode("ascii", errors="ignore").strip()
    return tail if tail else None


def decode_text_bytes(raw: bytes) -> str:
    """Giải mã mảng byte của citiesen/districtsen/roadsen thành chuỗi UTF-8 thuần."""
    decoded = raw.translate(BYTE_DECODE_LUT)
    return decoded.decode("utf-8", errors="replace").lstrip("\ufeff")


def extract_edogen_bytes(data: bytes) -> bytes:
    """
    Trích xuất đúng phân vùng edogen.bin từ container secrect.bin dựa trên bảng mục lục 512 bytes.
    """
    toc = parse_toc(data)
    if "edogen.bin" in toc:
        ent = toc["edogen.bin"]
        return data[ent.offset : ent.offset + ent.size]
    return data


def decode_bytes(data: bytes, default_version: str | None = None) -> DecodeResult:
    # 1. Trích xuất đúng phân vùng edogen.bin theo bảng mục lục 512 bytes
    raw_data = extract_edogen_bytes(data)
    lines = raw_data.split(b"\x83\x71")

    skipped = {
        "undecodable": 0,
        "bad_fields": 0,
        "out_of_bounds": 0,
        "unknown_type": 0,
        "duplicate": 0,
        "unknown_type_by_type": Counter(),
    }

    points = []
    seen = set()
    detected_version = "Unknown"

    for idx, raw in enumerate(lines):
        if not raw:
            continue

        # Thử nhận version trước khi kiểm tra undecodable:
        # Dòng version không chứa dấu phẩy (0xA3), toàn chữ số dài 6 hoặc 8 ký tự mã thế.
        if detected_version == "Unknown" and 0xA3 not in raw:
            candidate = "".join(SUBSTITUTION[b] for b in raw if b in SUBSTITUTION).strip()
            if len(candidate) in (6, 8) and candidate.isdigit():
                detected_version = candidate
                continue

        # Bỏ qua các dòng chứa byte nằm ngoài bảng mã thế
        if any(b not in SUBSTITUTION for b in raw):
            skipped["undecodable"] += 1
            continue

        text = "".join(SUBSTITUTION[b] for b in raw).strip()
        if not text:
            continue

        # Kiểm tra nếu là dòng version ngày tháng không có byte thừa (e.g. 20261028 hoặc 261022)
        if "," not in text and len(text) in (6, 8) and text.isdigit():
            detected_version = text
            continue

        parts = text.split(",")
        if len(parts) < 5:
            skipped["bad_fields"] += 1
            continue

        try:
            lon = float(parts[0])
            lat = float(parts[1])
            ptype = int(parts[2])
            speed = int(parts[3])

            # Cấu trúc: lon,lat,type,speed,flag,heading (6 cột) hoặc lon,lat,type,speed,heading (5 cột)
            if len(parts) >= 6:
                flag = int(parts[4])
                heading = int(parts[5]) % 360
            else:
                flag = 0
                heading = int(parts[4]) % 360

        except (ValueError, IndexError):
            skipped["bad_fields"] += 1
            continue

        if not (LAT_MIN <= lat <= LAT_MAX and LON_MIN <= lon <= LON_MAX):
            skipped["out_of_bounds"] += 1
            continue

        if ptype not in KNOWN_TYPES:
            skipped["unknown_type"] += 1
            skipped["unknown_type_by_type"][ptype] += 1
            continue

        key = (ptype, round(lat, 6), round(lon, 6), heading)
        if key in seen:
            skipped["duplicate"] += 1
            continue
        seen.add(key)

        points.append(VietMapPoint(lon, lat, ptype, speed, heading, flag))

    if detected_version == "Unknown" and default_version:
        detected_version = default_version

    return DecodeResult(detected_version, points, skipped)


def decode_file(
    path: str | Path,
    default_version: str | None = None,
    manifest_path: str | Path | None = None,
) -> DecodeResult:
    path_obj = Path(path)
    with open(path_obj, "rb") as f:
        res = decode_bytes(f.read(), default_version=default_version)

    # Nếu vẫn chưa tìm thấy version, thử nạp từ manifest
    if res.version == "Unknown":
        mf_candidate = Path(manifest_path) if manifest_path else path_obj.parent / "vietmap_manifest.json"
        if mf_candidate.exists():
            try:
                with open(mf_candidate, "r", encoding="utf-8") as mf:
                    info = json.load(mf)
                    if info.get("version"):
                        res.version = str(info["version"])
            except Exception:
                pass

    return res


def _obits_for(p: int) -> int:
    if p == 0:
        return 0
    if p == 1:
        return 1
    if p == 2:
        return 2
    return (p - 1).bit_length()


def decompress_roadsenz(compressed: bytes, verify_checksum: bool = True) -> bytes:
    """Giải nén phân vùng roadsenz.bin (LZ77 MSB-first + kiểm tra checksum cộng byte từng block).

    Hỗ trợ cả payload đầy đủ (bắt đầu bằng header 32 bytes 'roadsen.bin\\0...')
    lẫn luồng block thô (<u_sz, c_sz, checksum>).
    """
    pos = 32 if compressed.startswith(b"roadsen.bin\x00") else 0
    out_chunks: list[bytes] = []
    n = len(compressed)
    block_idx = 0
    while pos + 12 <= n:
        u_sz, c_sz, chk = struct.unpack_from("<III", compressed, pos)
        pos += 12
        if c_sz == 0 or pos + c_sz > n:
            raise ValueError(f"Block roadsenz #{block_idx} hỏng kích thước: u={u_sz}, c={c_sz}, pos={pos}/{n}")
        inbuf = compressed[pos : pos + c_sz]
        pos += c_sz
        if u_sz == c_sz:
            out_chunks.append(inbuf)
            block_idx += 1
            continue

        outbuf = bytearray(u_sz)
        bit_buf = 0
        bit_cnt = 0
        idx = 0
        p = 0
        while p < u_sz:
            ob = _obits_for(p)
            lb = 4 if p == 0 else 5
            k1 = ob + lb
            while bit_cnt < k1:
                b = inbuf[idx] if idx < c_sz else 0
                idx += 1
                bit_buf = (bit_buf << 8) | b
                bit_cnt += 8
            bit_cnt -= k1
            bv = (bit_buf >> bit_cnt) & ((1 << k1) - 1)
            off = bv >> lb
            ln = bv & ((1 << lb) - 1)
            if off > 0:
                if off > p:
                    raise ValueError(f"Block roadsenz #{block_idx} back-ref lỗi: off={off} > p={p}")
                start = p - off
                for i in range(ln):
                    if p >= u_sz:
                        break
                    outbuf[p] = outbuf[start + i]
                    p += 1
            if p < u_sz:
                while bit_cnt < 8:
                    b = inbuf[idx] if idx < c_sz else 0
                    idx += 1
                    bit_buf = (bit_buf << 8) | b
                    bit_cnt += 8
                bit_cnt -= 8
                outbuf[p] = (bit_buf >> bit_cnt) & 0xFF
                p += 1
        if verify_checksum and (sum(outbuf) & 0xFFFFFFFF) != chk:
            raise ValueError(f"Checksum mismatch block #{block_idx}: {sum(outbuf)} != {chk}")
        out_chunks.append(bytes(outbuf))
        block_idx += 1
    return b"".join(out_chunks)


def decode_cities(secrect_bytes: bytes) -> dict[int, str]:
    """Giải mã bảng tỉnh/thành citiesen.bin -> {province_id: 'TP. Hà Nội', ...}."""
    toc = parse_toc(secrect_bytes)
    ent = toc.get("citiesen.bin")
    if not ent or ent.offset + ent.size > len(secrect_bytes):
        return {}
    raw = secrect_bytes[ent.offset : ent.offset + ent.size]
    out: dict[int, str] = {}
    for chunk in raw.split(b"\x83\x71"):
        line = decode_text_bytes(chunk).strip()
        if "\t" not in line:
            continue
        pid_s, name = line.split("\t", 1)
        try:
            out[int(pid_s.strip())] = name.strip()
        except ValueError:
            continue
    return out


def decode_districts(secrect_bytes: bytes) -> dict[int, tuple[int, str]]:
    """Giải mã bảng xã/phường/huyện districtsen.bin -> {district_id: (province_id, name)}."""
    toc = parse_toc(secrect_bytes)
    ent = toc.get("districtsen.bin")
    if not ent or ent.offset + ent.size > len(secrect_bytes):
        return {}
    raw = secrect_bytes[ent.offset : ent.offset + ent.size]
    out: dict[int, tuple[int, str]] = {}
    for chunk in raw.split(b"\x83\x71"):
        line = decode_text_bytes(chunk).strip()
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        try:
            out[int(parts[0].strip())] = (int(parts[1].strip()), parts[2].strip())
        except ValueError:
            continue
    return out


def has_full_roadsenz(secrect_path: Path) -> bool:
    """Kiểm tra file secrect.bin có chứa phân vùng roadsenz.bin đầy đủ (chưa bị cắt gọn) hay không."""
    if not secrect_path.exists():
        return False
    size = secrect_path.stat().st_size
    if size < 512:
        return False
    with open(secrect_path, "rb") as f:
        hdr = f.read(512)
    toc = parse_toc(hdr)
    ent = toc.get("roadsenz.bin")
    return bool(ent and ent.size > 0 and ent.offset + ent.size <= size)


def _find_compiler() -> str | None:
    import shutil
    for cc in ("cc", "clang", "gcc"):
        if shutil.which(cc):
            return cc
    return None


def _ensure_native_roadsenz_decomp(native_dir: Path | None = None) -> Path | None:
    import subprocess
    nd = native_dir or (Path(__file__).resolve().parent / "native")
    src = nd / "roadsenz_decomp.c"
    if not src.exists():
        return None
    exe = nd / "roadsenz_decomp"
    if exe.exists() and exe.stat().st_mtime >= src.stat().st_mtime:
        return exe
    cc = _find_compiler()
    if not cc:
        return None
    try:
        subprocess.run([cc, "-O3", "-Wall", "-o", str(exe), str(src)], check=True, capture_output=True)
        return exe
    except Exception:
        return None


def extract_roadsenz_tsv(
    secrect_path: Path,
    out_tsv: Path,
    decode_cipher: bool = True,
) -> Path:
    """Giải nén (và giải mã cipher -> UTF-8 TSV) phân vùng roadsenz.bin từ secrect.bin ra ổ đĩa."""
    import subprocess
    with open(secrect_path, "rb") as f:
        hdr = f.read(512)
    toc = parse_toc(hdr)
    ent = toc.get("roadsenz.bin")
    if not ent or ent.size <= 32 or secrect_path.stat().st_size < ent.offset + ent.size:
        raise ValueError(f"File {secrect_path} không chứa phân vùng roadsenz.bin đầy đủ")

    out_tsv.parent.mkdir(parents=True, exist_ok=True)
    native_exe = _ensure_native_roadsenz_decomp()
    if native_exe is not None:
        cmd = [str(native_exe), str(secrect_path), str(ent.offset), str(ent.size), str(out_tsv)]
        if decode_cipher:
            cmd.append("--decode")
        subprocess.run(cmd, check=True)
        return out_tsv

    with open(secrect_path, "rb") as f:
        f.seek(ent.offset)
        comp = f.read(ent.size)
    raw = decompress_roadsenz(comp, verify_checksum=True)
    if decode_cipher:
        raw = raw.translate(BYTE_DECODE_LUT)
    out_tsv.write_bytes(raw)
    return out_tsv


def iter_decoded_roadsen_tsv(tsv_path: Path, min_coords: int = 2):
    """Đọc luồng từng RoadPolyline từ file roadsen_decoded.tsv đã giải mã."""
    with open(tsv_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            ps = line.rstrip("\r\n").split("\t")
            if len(ps) < 11:
                continue
            try:
                rid = int(ps[0])
                lid = int(ps[1]) if ps[1] else 0
                name = ps[2].strip()
                pid = int(ps[3]) if ps[3] else 0
                did = int(ps[4]) if ps[4] else 0
                sfwd = int(ps[5])
                sbwd = int(ps[6])
                raw_coords = ps[7:]
                coords: list[tuple[float, float]] = []
                for i in range(0, len(raw_coords) - 1, 2):
                    lon = float(raw_coords[i])
                    lat = float(raw_coords[i + 1])
                    coords.append((lat, lon))
            except ValueError:
                continue
            if len(coords) >= min_coords:
                yield RoadPolyline(rid, lid, name, pid, did, sfwd, sbwd, coords)


def hydrate_full_secrect_bin(
    vietmap_path: Path | None = None,
    manifest_path: Path | None = None,
    cache_dir: Path | None = None,
) -> Path | None:
    """Đảm bảo có file secrect.bin ĐẦY ĐỦ (kèm roadsenz.bin ~105MB) cho CI & máy local.

    Thứ tự ưu tiên:
    1. Biến môi trường MAPVIET_FULL_SECRECT_BIN (nếu hợp lệ).
    2. File vietmap_path truyền vào nếu đã có phân vùng roadsenz.bin.
    3. File secrect.bin tại cache_dir hoặc /tmp/mapviet_vietmap_cache.
    4. Tải tự động từ vietmap_manifest.json['download_url'], kiểm tra SHA-256 zip (nếu có) và giải nén.
    """
    import hashlib
    import os
    import tempfile
    import urllib.request
    import zipfile

    env_path = os.environ.get("MAPVIET_FULL_SECRECT_BIN")
    if env_path:
        ep = Path(env_path)
        if has_full_roadsenz(ep):
            return ep

    if vietmap_path and has_full_roadsenz(vietmap_path):
        return vietmap_path

    # Thử tìm bản full ngay ở thư mục gốc repo (khi dùng nguồn mặc định, không chỉ định cache/manifest riêng)
    if vietmap_path and cache_dir is None:
        cands = [vietmap_path.parent / "secrect_full.bin"]
        if manifest_path is None:
            cands.append(Path(__file__).resolve().parent.parent / "secrect.bin")
        for cand in cands:
            if cand != vietmap_path and has_full_roadsenz(cand):
                return cand

    mf = manifest_path
    if mf is None and vietmap_path is not None:
        mf = vietmap_path.parent / "vietmap_manifest.json"
    if mf is None or not mf.exists():
        default_mf = Path(__file__).resolve().parent / "sources" / "vietmap" / "vietmap_manifest.json"
        if default_mf.exists():
            mf = default_mf

    if mf is None or not mf.exists():
        return None

    try:
        info = json.loads(mf.read_text(encoding="utf-8"))
    except Exception:
        return None

    url = info.get("download_url")
    if not url:
        return None

    zip_sha = str(info.get("zip_sha256") or "").lower().strip()
    cache_root = cache_dir or (Path(tempfile.gettempdir()) / "mapviet_vietmap_cache")
    tag = zip_sha[:12] if zip_sha else str(info.get("version") or "latest")
    target_bin = cache_root / tag / "secrect.bin"
    if has_full_roadsenz(target_bin):
        return target_bin

    target_bin.parent.mkdir(parents=True, exist_ok=True)
    zip_path = target_bin.parent / "vietmap.zip"
    print(f"[*] Đang tải gói VietMap đầy đủ (kèm roadsen.bin) từ {url}...")
    try:
        urllib.request.urlretrieve(url, zip_path)
        if zip_sha:
            got_sha = hashlib.sha256(zip_path.read_bytes()).hexdigest().lower()
            if got_sha != zip_sha:
                zip_path.unlink(missing_ok=True)
                print(f"[WARN] Sai SHA-256 zip VietMap ({got_sha} != {zip_sha}); bỏ qua")
                return None
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = [n for n in zf.namelist() if Path(n).name.lower() == "secrect.bin"]
            if not names:
                print("[WARN] Không thấy secrect.bin trong file zip VietMap")
                return None
            with zf.open(names[0]) as src, open(target_bin, "wb") as dst:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    dst.write(chunk)
        zip_path.unlink(missing_ok=True)
        if has_full_roadsenz(target_bin):
            print(f"[OK] Đã giải nén secrect.bin đầy đủ tại: {target_bin}")
            return target_bin
    except Exception as exc:
        print(f"[WARN] Không thể tải/giải nén VietMap đầy đủ ({exc}); dùng chế độ không roadsen")
    return None


def main():
    if len(sys.argv) < 2:
        print("Sử dụng: python tools/vietmap_decode.py <secrect.bin> [out.csv]")
        sys.exit(1)

    bin_path = Path(sys.argv[1])
    if not bin_path.exists():
        print(f"[LOI] File không tồn tại: {bin_path}")
        sys.exit(1)

    print(f"[*] Đang giải mã file {bin_path}...")
    res = decode_file(bin_path)

    out_file = sys.argv[2] if len(sys.argv) >= 3 else None
    if out_file:
        with open(out_file, "w", encoding="utf-8") as f:
            f.write("lon,lat,type,speed_limit,heading\n")
            for p in res.points:
                f.write(f"{p.lon:.6f},{p.lat:.6f},{p.type},{p.speed_limit},{p.heading}\n")
        print(f"[OK] Đã ghi {len(res.points):,} điểm giải mã ra file: {out_file}")

    print(f"[OK] Đã giải mã thành công {len(res.points):,} điểm (Version: {res.version})")
    counts = Counter(p.type for p in res.points)
    print("[*] Thống kê điểm theo type:")
    for t in sorted(counts.keys()):
        print(f"    - Type {t}: {counts[t]:,} điểm")

    print(f"[*] Thống kê bỏ qua:")
    for k, v in res.skipped.items():
        if k == "unknown_type_by_type":
            continue
        print(f"    - {k}: {v:,}")

    if res.skipped["unknown_type_by_type"]:
        print("[*] Phân bố loại lạ (unknown_type_by_type):")
        for ut, cnt in sorted(res.skipped["unknown_type_by_type"].items()):
            print(f"    - Loại {ut}: {cnt:,} dòng")


if __name__ == "__main__":
    main()
