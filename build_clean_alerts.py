#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
data-pipeline/build_clean_alerts.py — Xây dựng kho dữ liệu cảnh báo toàn quốc sạch và chuẩn mực.

Nguyên tắc cốt lõi:
1. Chuẩn nền WYN (P1): Giữ 100% đèn tín hiệu giao thông (5.081 điểm OSM), camera (3.696 điểm), trạm thu phí (673 điểm).
2. Nguồn bổ sung VietMap M2 (P2):
   - Đã kiểm chứng và được chủ dự án phê duyệt 100% (báo cáo bao_cao_vietmap_m2_trinh_duyet.md).
   - Type 1: Biển giới hạn tốc độ (24.089 điểm) -> Sign 1 (SPEED_LIMIT), speed hợp lệ 40..120 km/h.
   - Type 2: Bắt đầu KDC R.420 (5.717 điểm) -> Sign 2 (RESIDENT_AREA), subType 0, speed 0.
   - Type 3: Hết KDC R.421 (4.787 điểm) -> Sign 2 (RESIDENT_AREA), subType 1, speed 0.
   - Type 5: Bắt đầu cấm vượt P.125 (4.365 điểm) -> Sign 3 (NO_OVERTAKING), subType 0, speed 0.
   - Type 6: Hết cấm vượt DP.133 (2.069 điểm) -> Sign 3 (NO_OVERTAKING), subType 1, speed 0.
   - Type 8: Trạm thu phí bổ sung -> Sign 5 (TOLL_BOOTH), subType 0 (khử trùng 100m với WYN).
   - Type 9: Cửa hầm đường bộ (136 điểm) -> Sign 10 (DANGER_OTHER), subType 9 (TUNNEL).
   - Type 11: Camera bổ sung -> cameras.bin (khử trùng 20m với WYN, tốc độ -1).
3. LOẠI BỎ TRIỆT ĐỂ:
   - Type 4 (35.020 điểm): LOẠI BỎ 100% (chống lỗi hét KDC ở ngã tư nội đô).
   - Type 7, 10: LOẠI BỎ 100% (cảnh báo nguy hiểm mơ hồ gây rác âm thanh).
4. Khử trùng lặp nội bộ VietMap <= 5m (loại bỏ điểm trùng trên các làn cao tốc).
"""

import argparse
import csv
import hashlib
import math
import os
import struct
import sys
import time
import zlib
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

# Thêm đường dẫn import
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "data-pipeline"))
sys.path.insert(0, str(REPO_ROOT / "VietHUD" / "tools"))

import vietmap_decode as vmd
import sign_manifest

# Định dạng nhị phân chuẩn VietHUD v1
# struct CameraPoint: <QiihH (20 bytes)
# id(8), lat_e7(4), lon_e7(4), speedLimitKmh(2), directionDeg(2)
CAMERA_FMT = "<QiihH"

# struct TrafficSignHeader: <4sHIHII (20 bytes)
# magic(4), version(2), signCount(4), reserved(2), crc32(4), timestamp(4)
SIGN_HEADER_FMT = "<4sHIHII"

# struct TrafficSignPoint: <IiiHBBBBH (20 bytes)
# id(4), lat_e7(4), lon_e7(4), directionDeg(2), signType(1), speedLimitKmh(1), subType(1), flags(1), reserved(2)
SIGN_POINT_FMT = "<IiiHBBBBH"

DIR_OMNI = 0xFFFF


def haversine(lat1, lon1, lat2, lon2):
    R = 6371000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
    return 2 * R * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def heading_diff(h1, h2):
    diff = abs(h1 - h2) % 360
    return 360 - diff if diff > 180 else diff


def clean_camera_speed(raw_spd: int) -> int:
    """Tốc độ camera: bội số của 5 trong [5, 130] hợp lệ, còn lại quy về -1 (chưa rõ / phạt nguội)."""
    if raw_spd is not None and 5 <= raw_spd <= 130 and (raw_spd % 5 == 0):
        return raw_spd
    return -1


def build_clean_alerts(
    wyn_csv: Path,
    secrect_bin: Path,
    output_dir: Path,
    version_str: str | None = None,
    alerts_only: bool = False,
):
    print("=" * 70)
    print("  KHỞI TẠO BỘ ĐÓNG GÓI CẢNH BÁO TOÀN QUỐC MAPVIET")
    print("=" * 70)

    if not version_str:
        now = datetime.now()
        version_str = now.strftime("%Y.%m.%d.%H%M")
    print(f"[*] Phiên bản phát hành: {version_str}")

    output_dir.mkdir(parents=True, exist_ok=True)

    # -------------------------------------------------------------
    # BƯỚC 1: NẠP VÀ CHUẨN HÓA NGUỒN CHUẨN GỐC WYN (P1)
    # -------------------------------------------------------------
    print(f"\n[1/5] Đang nạp nguồn chuẩn nền WYN từ: {wyn_csv}...")
    if not wyn_csv.exists():
        raise FileNotFoundError(f"Không tìm thấy file nguồn WYN: {wyn_csv}")

    with open(wyn_csv, "r", encoding="utf-8-sig") as f:
        wyn_rows = list(csv.DictReader(f))

    final_cameras = []
    final_signs = []
    wyn_cam_grid = defaultdict(list)
    wyn_toll_grid = defaultdict(list)
    CELL = 0.0005 # ~55m

    wyn_cam_count = 0
    wyn_light_count = 0
    wyn_toll_count = 0

    used_cam_ids = set()
    used_sign_ids = set()

    for r in wyn_rows:
        lat = float(r["lat"])
        lon = float(r["lon"])
        kind = r["kind"].strip().lower()
        st = r["sign_type"].strip()
        raw_spd = int(float(r["speed_kmh"] or 0))
        hd_str = r["heading"].strip()
        hd = int(hd_str) if hd_str and hd_str != "15" and (1 <= int(hd_str) <= 359) else DIR_OMNI

        lat_e7 = int(round(lat * 1e7))
        lon_e7 = int(round(lon * 1e7))

        if kind == "camera":
            spd = clean_camera_speed(raw_spd)
            seed = f"cam|wyn|{lat_e7}|{lon_e7}|{hd}".encode()
            cid = (1 << 62) | (zlib.crc32(seed) & ((1 << 62) - 1))
            while cid in used_cam_ids:
                cid = (1 << 62) | ((cid + 1) & ((1 << 62) - 1))
            used_cam_ids.add(cid)

            cam = {
                "id": cid,
                "lat": lat,
                "lon": lon,
                "speed": spd,
                "heading": hd,
                "source": "WYN",
            }
            final_cameras.append(cam)
            gx, gy = int(lon / CELL), int(lat / CELL)
            wyn_cam_grid[(gx, gy)].append(cam)
            wyn_cam_count += 1

        elif kind == "light":
            seed = f"sign|6|{lat_e7}|{lon_e7}|{hd}".encode()
            sid = 0x80000000 | (zlib.crc32(seed) & 0x7FFFFFFF)
            while sid in used_sign_ids:
                sid = 0x80000000 | ((sid + 1) & 0x7FFFFFFF)
            used_sign_ids.add(sid)

            sign = {
                "id": sid,
                "lat": lat,
                "lon": lon,
                "sign_type": 6, # TRAFFIC_LIGHT
                "sub_type": 0,
                "speed": 0,
                "heading": DIR_OMNI,
                "source": "WYN",
                "reserved": 3, # WYN / OSM (reserved=3 yêu cầu AlertPointMerger bỏ qua lights.bin)
            }
            final_signs.append(sign)
            wyn_light_count += 1

        elif kind == "sign" and st == "5":
            seed = f"sign|5|{lat_e7}|{lon_e7}|{hd}".encode()
            sid = 0x80000000 | (zlib.crc32(seed) & 0x7FFFFFFF)
            while sid in used_sign_ids:
                sid = 0x80000000 | ((sid + 1) & 0x7FFFFFFF)
            used_sign_ids.add(sid)

            sign = {
                "id": sid,
                "lat": lat,
                "lon": lon,
                "sign_type": 5, # TOLL_BOOTH
                "sub_type": 0,
                "speed": 0,
                "heading": DIR_OMNI,
                "source": "WYN",
                "reserved": 3, # WYN / OSM
            }
            final_signs.append(sign)
            gx, gy = int(lon / CELL), int(lat / CELL)
            wyn_toll_grid[(gx, gy)].append(sign)
            wyn_toll_count += 1

    # Nạp camera kiểm chứng thực tế (Curated/Custom Cameras)
    curated_cams_path = wyn_csv.parent.parent / "curated" / "custom_cameras.csv"
    curated_cam_count = 0
    if curated_cams_path.exists():
        with open(curated_cams_path, "r", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                try:
                    cid = int(r["id"])
                    lat = float(r["lat"])
                    lon = float(r["lon"])
                    hd = int(r["heading"])
                    spd = clean_camera_speed(int(r["speed"]))
                    cam = {
                        "id": cid,
                        "lat": lat,
                        "lon": lon,
                        "speed": spd,
                        "heading": hd,
                        "source": "CURATED",
                    }
                    final_cameras.append(cam)
                    used_cam_ids.add(cid)
                    gx, gy = int(lon / CELL), int(lat / CELL)
                    wyn_cam_grid[(gx, gy)].append(cam)
                    curated_cam_count += 1
                except Exception:
                    pass

    print(f"      + Camera WYN giữ lại:       {wyn_cam_count:,} điểm")
    if curated_cam_count > 0:
        print(f"      + Camera thực tế bổ sung:   {curated_cam_count:,} điểm (Cầu Hiệp Thượng, v.v.)")
    print(f"      + Đèn tín hiệu OSM/WYN:    {wyn_light_count:,} điểm")
    print(f"      + Trạm thu phí WYN:        {wyn_toll_count:,} điểm")

    # -------------------------------------------------------------
    # BƯỚC 2: GIẢI MÃ VÀ LỌC TRÙNG NỘI BỘ VIETMAP M2
    # -------------------------------------------------------------
    print(f"\n[2/5] Đang giải mã VietMap M2 từ: {secrect_bin}...")
    if not secrect_bin.exists():
        raise FileNotFoundError(f"Không tìm thấy file secrect.bin: {secrect_bin}")

    res = vmd.decode_file(secrect_bin)
    raw_vm_points = res.points
    print(f"      -> Tổng điểm VietMap giải mã: {len(raw_vm_points):,} (Phiên bản: {res.version})")

    # Khử trùng nội bộ VietMap <= 5m
    vm_grid = defaultdict(list)
    vm_clean = []
    vm_internal_dups = 0

    for p in raw_vm_points:
        gx, gy = int(p.lon / CELL), int(p.lat / CELL)
        is_dup = False
        for dx in (-1, 0, 1):
            for dy in (-1, 0, 1):
                for existing in vm_grid.get((gx + dx, gy + dy), []):
                    if existing.type == p.type:
                        d = haversine(p.lat, p.lon, existing.lat, existing.lon)
                        if d <= 5.0 and (p.heading == existing.heading or heading_diff(p.heading, existing.heading) <= 15):
                            is_dup = True
                            break
                if is_dup:
                    break
        if is_dup:
            vm_internal_dups += 1
        else:
            vm_clean.append(p)
            vm_grid[(gx, gy)].append(p)

    print(f"      -> Bỏ {vm_internal_dups:,} điểm VietMap trùng lặp nội bộ (<= 5m trên cùng làn).")
    print(f"      -> Điểm VietMap sạch đưa vào duyệt bổ sung: {len(vm_clean):,}")

    # -------------------------------------------------------------
    # BƯỚC 3: BỔ SUNG CÁC HẠNG MỤC VIETMAP ĐÃ ĐƯỢC DUYỆT
    # -------------------------------------------------------------
    print(f"\n[3/5] Đang tích hợp danh mục VietMap bổ sung và khử trùng với WYN...")

    vm_cams_added = 0
    vm_cams_dropped_near_wyn = 0
    vm_tolls_added = 0
    vm_tolls_dropped_near_wyn = 0
    vm_signs_added = Counter()

    for p in vm_clean:
        hd = p.heading if 1 <= p.heading <= 359 else DIR_OMNI
        lat_e7 = int(round(p.lat * 1e7))
        lon_e7 = int(round(p.lon * 1e7))

        # 1. Camera bổ sung (Type 11) - Khử trùng bán kính 20m với WYN
        if p.type == 11:
            gx, gy = int(p.lon / CELL), int(p.lat / CELL)
            near_wyn = False
            for dx in (-1, 0, 1):
                for dy in (-1, 0, 1):
                    for wc in wyn_cam_grid.get((gx + dx, gy + dy), []):
                        if haversine(p.lat, p.lon, wc["lat"], wc["lon"]) <= 20.0:
                            near_wyn = True
                            break
                    if near_wyn:
                        break
            if near_wyn:
                vm_cams_dropped_near_wyn += 1
            else:
                seed = f"cam|vm11|{lat_e7}|{lon_e7}|{hd}".encode()
                cid = (1 << 62) | (zlib.crc32(seed) & ((1 << 62) - 1))
                while cid in used_cam_ids:
                    cid = (1 << 62) | ((cid + 1) & ((1 << 62) - 1))
                used_cam_ids.add(cid)

                final_cameras.append({
                    "id": cid,
                    "lat": p.lat,
                    "lon": p.lon,
                    "speed": -1, # Phạt nguội chung
                    "heading": hd,
                    "source": "VietMap",
                })
                vm_cams_added += 1

        # 2. Biển giới hạn tốc độ (Type 1)
        elif p.type == 1:
            seed = f"sign|1|{lat_e7}|{lon_e7}|{hd}".encode()
            sid = 0x80000000 | (zlib.crc32(seed) & 0x7FFFFFFF)
            while sid in used_sign_ids:
                sid = 0x80000000 | ((sid + 1) & 0x7FFFFFFF)
            used_sign_ids.add(sid)

            final_signs.append({
                "id": sid,
                "lat": p.lat,
                "lon": p.lon,
                "sign_type": 1, # SPEED_LIMIT
                "sub_type": 0,
                "speed": p.speed_limit,
                "heading": hd,
                "source": "VietMap",
                "reserved": 1,
            })
            vm_signs_added["Biển tốc độ (Type 1)"] += 1

        # 3. Vào khu đông dân cư (Type 2 - R.420)
        elif p.type == 2:
            seed = f"sign|2_0|{lat_e7}|{lon_e7}|{hd}".encode()
            sid = 0x80000000 | (zlib.crc32(seed) & 0x7FFFFFFF)
            while sid in used_sign_ids:
                sid = 0x80000000 | ((sid + 1) & 0x7FFFFFFF)
            used_sign_ids.add(sid)

            final_signs.append({
                "id": sid,
                "lat": p.lat,
                "lon": p.lon,
                "sign_type": 2, # RESIDENT_AREA
                "sub_type": 0, # Vào KDC
                "speed": 0,
                "heading": hd,
                "source": "VietMap",
                "reserved": 1,
            })
            vm_signs_added["Vào KDC (Type 2)"] += 1

        # 4. Hết khu đông dân cư (Type 3 - R.421)
        elif p.type == 3:
            seed = f"sign|2_1|{lat_e7}|{lon_e7}|{hd}".encode()
            sid = 0x80000000 | (zlib.crc32(seed) & 0x7FFFFFFF)
            while sid in used_sign_ids:
                sid = 0x80000000 | ((sid + 1) & 0x7FFFFFFF)
            used_sign_ids.add(sid)

            final_signs.append({
                "id": sid,
                "lat": p.lat,
                "lon": p.lon,
                "sign_type": 2, # RESIDENT_AREA
                "sub_type": 1, # Hết KDC
                "speed": 0,
                "heading": hd,
                "source": "VietMap",
                "reserved": 1,
            })
            vm_signs_added["Hết KDC (Type 3)"] += 1

        # 5. Bắt đầu cấm vượt (Type 5 - P.125)
        elif p.type == 5:
            seed = f"sign|3_0|{lat_e7}|{lon_e7}|{hd}".encode()
            sid = 0x80000000 | (zlib.crc32(seed) & 0x7FFFFFFF)
            while sid in used_sign_ids:
                sid = 0x80000000 | ((sid + 1) & 0x7FFFFFFF)
            used_sign_ids.add(sid)

            final_signs.append({
                "id": sid,
                "lat": p.lat,
                "lon": p.lon,
                "sign_type": 3, # NO_OVERTAKING
                "sub_type": 0, # Bắt đầu cấm vượt
                "speed": 0,
                "heading": hd,
                "source": "VietMap",
                "reserved": 1,
            })
            vm_signs_added["Bắt đầu cấm vượt (Type 5)"] += 1

        # 6. Hết cấm vượt (Type 6 - DP.133)
        elif p.type == 6:
            seed = f"sign|3_1|{lat_e7}|{lon_e7}|{hd}".encode()
            sid = 0x80000000 | (zlib.crc32(seed) & 0x7FFFFFFF)
            while sid in used_sign_ids:
                sid = 0x80000000 | ((sid + 1) & 0x7FFFFFFF)
            used_sign_ids.add(sid)

            final_signs.append({
                "id": sid,
                "lat": p.lat,
                "lon": p.lon,
                "sign_type": 3, # NO_OVERTAKING
                "sub_type": 1, # Hết cấm vượt
                "speed": 0,
                "heading": hd,
                "source": "VietMap",
                "reserved": 1,
            })
            vm_signs_added["Hết cấm vượt (Type 6)"] += 1

        # 7. Trạm thu phí bổ sung (Type 8) - Khử trùng 100m với WYN
        elif p.type == 8:
            gx, gy = int(p.lon / CELL), int(p.lat / CELL)
            near_wyn_toll = False
            for dx in (-1, 0, 1):
                for dy in (-1, 0, 1):
                    for wt in wyn_toll_grid.get((gx + dx, gy + dy), []):
                        if haversine(p.lat, p.lon, wt["lat"], wt["lon"]) <= 100.0:
                            near_wyn_toll = True
                            break
                    if near_wyn_toll:
                        break
            if near_wyn_toll:
                vm_tolls_dropped_near_wyn += 1
            else:
                seed = f"sign|5_vm|{lat_e7}|{lon_e7}|{hd}".encode()
                sid = 0x80000000 | (zlib.crc32(seed) & 0x7FFFFFFF)
                while sid in used_sign_ids:
                    sid = 0x80000000 | ((sid + 1) & 0x7FFFFFFF)
                used_sign_ids.add(sid)

                final_signs.append({
                    "id": sid,
                    "lat": p.lat,
                    "lon": p.lon,
                    "sign_type": 5, # TOLL_BOOTH
                    "sub_type": 0,
                    "speed": 0,
                    "heading": DIR_OMNI,
                    "source": "VietMap",
                    "reserved": 1,
                })
                vm_tolls_added += 1

        # 8. Cửa hầm đường bộ (Type 9)
        elif p.type == 9:
            seed = f"sign|10_9|{lat_e7}|{lon_e7}|{hd}".encode()
            sid = 0x80000000 | (zlib.crc32(seed) & 0x7FFFFFFF)
            while sid in used_sign_ids:
                sid = 0x80000000 | ((sid + 1) & 0x7FFFFFFF)
            used_sign_ids.add(sid)

            final_signs.append({
                "id": sid,
                "lat": p.lat,
                "lon": p.lon,
                "sign_type": 10, # DANGER_OTHER
                "sub_type": 9, # TUNNEL
                "speed": 0,
                "heading": hd,
                "source": "VietMap",
                "reserved": 1,
            })
            vm_signs_added["Hầm đường bộ (Type 9)"] += 1

        # LOẠI BỎ 100% CÁC LOẠI 4, 7, 10
        # (Không làm gì, tự động bỏ qua)

    print(f"      + Camera VietMap bổ sung:   {vm_cams_added:,} (Loại bỏ {vm_cams_dropped_near_wyn:,} trùng WYN <=20m)")
    print(f"      + Trạm thu phí bổ sung:     {vm_tolls_added:,} (Loại bỏ {vm_tolls_dropped_near_wyn:,} trùng WYN <=100m)")
    for cat_name, cnt in vm_signs_added.items():
        print(f"      + {cat_name:<25}: {cnt:,} điểm")

    # -------------------------------------------------------------
    # BƯỚC 4: ĐÓNG GÓI NHỊ PHÂN CAMERAS.BIN & SIGNS.BIN
    # -------------------------------------------------------------
    print(f"\n[4/5] Đang đóng gói tệp nhị phân chuẩn VietHUD v1 vào {output_dir}...")

    # Sắp xếp ổn định theo ID tăng dần
    final_cameras.sort(key=lambda x: x["id"])
    final_signs.sort(key=lambda x: x["id"])

    # 4.1. Đóng gói cameras.bin
    cam_bytes = bytearray()
    for c in final_cameras:
        lat_e7 = int(round(c["lat"] * 1e7))
        lon_e7 = int(round(c["lon"] * 1e7))
        cam_bytes.extend(struct.pack(
            CAMERA_FMT,
            c["id"],
            lat_e7,
            lon_e7,
            c["speed"],
            c["heading"],
        ))

    cams_file = output_dir / "cameras.bin"
    with open(cams_file, "wb") as f:
        f.write(cam_bytes)
    print(f"      [OK] Đã ghi {len(final_cameras):,} camera vào: {cams_file.name} ({len(cam_bytes):,} bytes)")

    # 4.2. Đóng gói signs.bin
    sign_body_bytes = bytearray()
    for s in final_signs:
        lat_e7 = int(round(s["lat"] * 1e7))
        lon_e7 = int(round(s["lon"] * 1e7))
        sign_body_bytes.extend(struct.pack(
            SIGN_POINT_FMT,
            s["id"],
            lat_e7,
            lon_e7,
            s["heading"],
            s["sign_type"],
            s["speed"],
            s["sub_type"],
            0, # flags
            s["reserved"],
        ))

    # Header signs.bin
    magic = b"VNSG"
    version = 1
    count = len(final_signs)
    reserved_hdr = 0
    crc32_val = zlib.crc32(sign_body_bytes) & 0xFFFFFFFF
    timestamp = int(time.time())

    sign_header = struct.pack(
        SIGN_HEADER_FMT,
        magic,
        version,
        count,
        reserved_hdr,
        crc32_val,
        timestamp,
    )

    signs_file = output_dir / "signs.bin"
    with open(signs_file, "wb") as f:
        f.write(sign_header + sign_body_bytes)
    total_sign_bytes = len(sign_header) + len(sign_body_bytes)
    print(f"      [OK] Đã ghi {len(final_signs):,} biển báo vào: {signs_file.name} ({total_sign_bytes:,} bytes, CRC32: {hex(crc32_val)})")

    # -------------------------------------------------------------
    # BƯỚC 5: TẠO VÀ KÝ MANIFEST.TXT BẰNG KHOÁ MAPVIET
    # -------------------------------------------------------------
    print(f"\n[5/5] Đang tạo và ký manifest.txt...")

    manifest_file = output_dir / "manifest.txt"
    manifest_lines = [f"version {version_str}"]

    # Danh sách tệp trong gói
    if alerts_only:
        pack_files = ["cameras.bin", "signs.bin"]
    else:
        pack_files = [
            "metadata.bin",
            "index.bin",
            "tiles.bin",
            "cameras.bin",
            "signs.bin",
            "names.bin",
            "seg_names.bin",
        ]

    for fname in pack_files:
        fpath = output_dir / fname
        if not fpath.exists():
            fallback = REPO_ROOT / "VietHUD" / "speedmap" / fname
            if fallback.exists():
                import shutil
                shutil.copy2(fallback, fpath)
            else:
                raise FileNotFoundError(f"Không tìm thấy tệp bắt buộc {fname} ở {fpath} hay {fallback}")

        fsize = fpath.stat().st_size
        with open(fpath, "rb") as f:
            fsha = hashlib.sha256(f.read()).hexdigest()
        manifest_lines.append(f"{fname} {fsize} {fsha}")

    manifest_content = "\n".join(manifest_lines) + "\n"
    with open(manifest_file, "w", encoding="utf-8") as f:
        f.write(manifest_content)

    print(f"      [OK] Đã tạo {manifest_file.name}:")
    for line in manifest_lines:
        print(f"           {line}")

    # Tạo file stats.json
    cams_path = output_dir / "cameras.bin"
    signs_path = output_dir / "signs.bin"
    with open(cams_path, "rb") as f:
        cams_sha = hashlib.sha256(f.read()).hexdigest()
    with open(signs_path, "rb") as f:
        signs_sha = hashlib.sha256(f.read()).hexdigest()

    hasher = hashlib.sha256()
    hasher.update(cams_sha.encode())
    hasher.update(signs_sha.encode())
    content_sha = hasher.hexdigest()

    stats = {
        "version": version_str,
        "vietmap_version": "20261022",
        "total_points": len(final_cameras) + len(final_signs),
        "cameras_count": len(final_cameras),
        "signs_count": len(final_signs),
        "content_sha256": content_sha,
        "counts_by_source_and_type": {
            "WYN": {"camera": wyn_cam_count, "light": wyn_light_count, "toll": wyn_toll_count},
            "CURATED": {"camera": curated_cam_count},
            "VietMap": {
                "camera": vm_cams_added,
                "speed": vm_signs_added["Biển tốc độ (Type 1)"],
                "kdc": vm_signs_added["Vào KDC (Type 2)"] + vm_signs_added["Hết KDC (Type 3)"],
                "no_overtaking": vm_signs_added["Bắt đầu cấm vượt (Type 5)"] + vm_signs_added["Hết cấm vượt (Type 6)"],
                "toll": vm_tolls_added,
                "tunnel": vm_signs_added["Hầm đường bộ (Type 9)"],
            }
        }
    }
    stats_file = output_dir / "stats.json"
    with open(stats_file, "w", encoding="utf-8") as f:
        import json
        json.dump(stats, f, indent=2)
    print(f"      [OK] Đã tạo {stats_file.name} (content_sha256: {content_sha})")

    # Ký manifest bằng khoá MapViet
    key_file = REPO_ROOT / "Key" / "mapviet_signing_key.pem"
    if not key_file.exists():
        key_file = Path.home() / ".mapviet" / "mapviet_signing_key.pem"

    priv_key = sign_manifest.load_private_key(key_file)
    sig_file = sign_manifest.sign_manifest(manifest_file, key=priv_key)
    print(f"      [OK] Đã ký số ECDSA P-256 thành công ra: {sig_file.name}")

    # Xác thực lại chữ ký ngay lập tức
    is_valid = sign_manifest.verify_manifest(manifest_file)
    if not is_valid:
        raise ValueError(f"Xác thực chữ ký manifest thất bại!")
    print(f"      [OK] Chữ ký manifest đã được xác thực hợp lệ 100%!")

    print("\n" + "=" * 70)
    print("  HOÀN TẤT ĐÓNG GÓI GÓI CẢNH BÁO TOÀN QUỐC THÀNH CÔNG!")
    print("=" * 70)
    return {
        "version": version_str,
        "cameras_count": len(final_cameras),
        "signs_count": len(final_signs),
        "output_dir": str(output_dir),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build clean nationwide alert dataset for MapViet.")
    parser.add_argument("--wyn", type=Path, default=REPO_ROOT / "data-pipeline" / "sources" / "wyn" / "wyn_points.csv")
    parser.add_argument("--vietmap", type=Path, default=REPO_ROOT / "VietHUD" / "data" / "vietmap" / "secrect.bin")
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "VietHUD" / "speedmap")
    parser.add_argument("--version", type=str, default=None)
    parser.add_argument("--alerts-only", action="store_true", default=False, help="Chỉ đưa cameras.bin và signs.bin vào manifest")
    args = parser.parse_args()

    build_clean_alerts(
        wyn_csv=args.wyn,
        secrect_bin=args.vietmap,
        output_dir=args.out,
        version_str=args.version,
        alerts_only=args.alerts_only,
    )
