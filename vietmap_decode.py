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


def extract_edogen_bytes(data: bytes) -> bytes:
    """
    Trích xuất đúng phân vùng edogen.bin từ container secrect.bin dựa trên bảng mục lục 512 bytes.
    Mỗi mục trong bảng mục lục gồm 68 bytes (64 bytes tên file + 4 bytes kích thước uint32 LE).
    Tránh đọc tràn sang các phân vùng sau (citiesen.bin, districtsen.bin, roadsenz.bin).
    """
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
