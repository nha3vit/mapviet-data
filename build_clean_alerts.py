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
   - Type 8: Trạm thu phí bổ sung -> Sign 5 (TOLL_BOOTH), subType 0 (khử trùng 300m với WYN).
   - Type 9: Cửa hầm đường bộ (136 điểm) -> Sign 10 (DANGER_OTHER), subType 9 (TUNNEL).
   - Type 11: Camera bổ sung -> cameras.bin (khử trùng 30m cùng hướng với WYN, tốc độ -1).
   - Type 4: Chỉ cứu camera còn thiếu hướng đối diện khi trùng camera gốc WYN <= 40m (khử trùng 30m cùng hướng); còn lại bỏ qua (Visual-only, không tạo camera đèn đỏ ảo).
   - Type 7, 10: LOẠI BỎ âm thanh / Visual-only (chống rác).
4. Khử trùng lặp nội bộ VietMap <= 5m (loại bỏ điểm trùng trên các làn cao tốc).
"""

from __future__ import annotations

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

# Thêm đường dẫn import (tương thích chạy từ data-pipeline, VietHUD/tools, hoặc mapviet-data)
_SELF_DIR = Path(__file__).resolve().parent
REPO_ROOT = _SELF_DIR.parent
if str(_SELF_DIR) not in sys.path:
    sys.path.insert(0, str(_SELF_DIR))
for _p in (REPO_ROOT / "data-pipeline", REPO_ROOT / "VietHUD" / "tools"):
    if _p.exists() and str(_p) not in sys.path:
        sys.path.append(str(_p))

try:
    from tools import vietmap_decode as vmd
    from tools import sign_manifest
except ImportError:
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

RADIUS_CAM_MATCH_WYN_M = 40.0
RADIUS_CAM_DEDUP_M = 30.0
CAM_SAME_HEADING_DEG = 45
RADIUS_TOLL_DEDUP_M = 300.0
RADIUS_LIGHT_MATCH_M = 40.0


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


def is_same_heading(hd1: int, hd2: int, tol_deg: int = CAM_SAME_HEADING_DEG) -> bool:
    return hd1 == DIR_OMNI or hd2 == DIR_OMNI or heading_diff(hd1, hd2) <= tol_deg


def iter_grid_neighbors(grid, gx: int, gy: int, span: int = 1):
    for dx in range(-span, span + 1):
        for dy in range(-span, span + 1):
            for item in grid.get((gx + dx, gy + dy), ()):
                yield item


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
    curated_dir: Path | None = None,
    osm_gt_path: Path | None = None,
    sign: bool = True,
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
    raw_wyn_cam_grid = defaultdict(list)  # Chỉ chứa camera gốc WYN + CURATED
    all_cam_grid = defaultdict(list)      # Chứa toàn bộ camera đã nhận để khử trùng <= 30m cùng hướng
    wyn_light_grid = defaultdict(list)
    wyn_toll_grid = defaultdict(list)
    CELL = 0.0005  # ~55m

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
            raw_wyn_cam_grid[(gx, gy)].append(cam)
            all_cam_grid[(gx, gy)].append(cam)
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
            gx, gy = int(lon / CELL), int(lat / CELL)
            wyn_light_grid[(gx, gy)].append(sign)
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
    if curated_dir is None:
        curated_candidates = [
            wyn_csv.parent.parent / "curated",
            REPO_ROOT / "data-pipeline" / "sources" / "curated",
            REPO_ROOT / "sources" / "curated",
            Path(__file__).resolve().parent / "sources" / "curated",
        ]
        curated_dir = next((p for p in curated_candidates if p.exists()), wyn_csv.parent.parent / "curated")
    curated_cams_path = curated_dir / "custom_cameras.csv"
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
                    raw_wyn_cam_grid[(gx, gy)].append(cam)
                    all_cam_grid[(gx, gy)].append(cam)
                    curated_cam_count += 1
                except Exception:
                    pass

    # Nạp biển báo / đèn tín hiệu kiểm chứng thực tế (Curated/Custom Signs)
    curated_signs_path = curated_dir / "custom_signs.csv"
    curated_sign_count = 0
    if curated_signs_path.exists():
        with open(curated_signs_path, "r", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                try:
                    sid = int(r["id"])
                    lat = float(r["lat"])
                    lon = float(r["lon"])
                    st = int(r["sign_type"])
                    sub_t = int(r.get("sub_type", 0))
                    spd = int(r.get("speed", 0))
                    hd = int(r.get("heading", DIR_OMNI))
                    sign = {
                        "id": sid,
                        "lat": lat,
                        "lon": lon,
                        "sign_type": st,
                        "sub_type": sub_t,
                        "speed": spd,
                        "heading": hd,
                        "source": "CURATED",
                        "reserved": 3,
                    }
                    final_signs.append(sign)
                    used_sign_ids.add(sid)
                    gx, gy = int(lon / CELL), int(lat / CELL)
                    if st == 6:
                        wyn_light_grid[(gx, gy)].append(sign)
                    elif st == 5:
                        wyn_toll_grid[(gx, gy)].append(sign)
                    curated_sign_count += 1
                except Exception:
                    pass

    # Nạp OSM ground truth (đèn tín hiệu toàn quốc) để đối chiếu và tích hợp
    if osm_gt_path is None:
        osm_gt_candidates = [
            REPO_ROOT / "data-pipeline" / "sources" / "osm" / "osm_ground_truth.json",
            REPO_ROOT / "sources" / "osm" / "osm_ground_truth.json",
            REPO_ROOT / "VietHUD" / "build" / "osm_ground_truth.json",
            Path(__file__).resolve().parent / "sources" / "osm" / "osm_ground_truth.json",
        ]
        osm_gt_path = next((p for p in osm_gt_candidates if p.exists()), None)
    osm_lights = []
    osm_light_grid = defaultdict(list)
    osm_lights_added_count = 0
    if osm_gt_path is not None and osm_gt_path.exists():
        try:
            with open(osm_gt_path, "r", encoding="utf-8") as f:
                import json
                gt = json.load(f)
                osm_lights = gt.get("traffic_signals", [])
                for lat, lon in osm_lights:
                    gx, gy = int(lon / CELL), int(lat / CELL)
                    osm_light_grid[(gx, gy)].append((lat, lon))
            print(f"      + Tọa độ đèn tín hiệu OSM nạp từ ground truth: {len(osm_lights):,} điểm")

            for lat, lon in osm_lights:
                gx, gy = int(lon / CELL), int(lat / CELL)
                # Kiểm tra trùng với WYN / Curated (<= 25m)
                is_dup_wyn = False
                for dx in (-1, 0, 1):
                    for dy in (-1, 0, 1):
                        for ws in wyn_light_grid.get((gx + dx, gy + dy), []):
                            if haversine(lat, lon, ws["lat"], ws["lon"]) <= 25.0:
                                is_dup_wyn = True
                                break
                        if is_dup_wyn:
                            break
                if is_dup_wyn:
                    continue

                # Kiểm tra cụm nhiều cột đèn tại cùng một ngã tư trong OSM (<= 20m)
                is_cluster_dup = False
                for dx in (-1, 0, 1):
                    for dy in (-1, 0, 1):
                        for os in wyn_light_grid.get((gx + dx, gy + dy), []):
                            if os.get("source") == "OSM" and haversine(lat, lon, os["lat"], os["lon"]) <= 20.0:
                                is_cluster_dup = True
                                break
                        if is_cluster_dup:
                            break
                if is_cluster_dup:
                    continue

                lat_e7 = int(round(lat * 1e7))
                lon_e7 = int(round(lon * 1e7))
                seed = f"sign|osm_light|{lat_e7}|{lon_e7}".encode()
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
                    "source": "OSM",
                    "reserved": 3,
                }
                final_signs.append(sign)
                wyn_light_grid[(gx, gy)].append(sign)
                osm_lights_added_count += 1
            print(f"      + Đèn tín hiệu OSM bổ sung sau khử trùng (<=20m/25m): {osm_lights_added_count:,} ngã tư")
        except Exception as e:
            print(f"      [!] Cảnh báo nạp osm_ground_truth.json: {e}")

    print(f"      + Camera WYN giữ lại:       {wyn_cam_count:,} điểm")
    if curated_cam_count > 0:
        print(f"      + Camera thực tế bổ sung:   {curated_cam_count:,} điểm (Cầu Hiệp Thượng, v.v.)")
    print(f"      + Đèn tín hiệu WYN:        {wyn_light_count:,} điểm")
    print(f"      + Đèn tín hiệu OSM bổ sung: {osm_lights_added_count:,} ngã tư")
    if curated_sign_count > 0:
        print(f"      + Biển/đèn thực tế bổ sung: {curated_sign_count:,} điểm (Kinh Môn, v.v.)")
    print(f"      + Tổng đèn tín hiệu chuẩn:  {wyn_light_count + osm_lights_added_count + curated_sign_count:,} điểm")
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
    vm_type11_added = 0
    vm_cams_dropped_near_wyn = 0
    vm_type4_speed_added = 0
    vm_type4_redlight_added = 0
    vm_type4_surveillance_added = 0
    vm_type4_dropped_dup = 0
    vm_type4_skipped_no_wyn = 0
    vm_tolls_added = 0
    vm_tolls_dropped_near_wyn = 0
    vm_signs_added = Counter()
    type4_candidates = []

    for p in vm_clean:
        hd = p.heading if 1 <= p.heading <= 359 else DIR_OMNI
        lat_e7 = int(round(p.lat * 1e7))
        lon_e7 = int(round(p.lon * 1e7))

        # 1. Camera bổ sung (Type 11) - Khử trùng <= 30m cùng hướng với WYN
        if p.type == 11:
            gx, gy = int(p.lon / CELL), int(p.lat / CELL)
            near_wyn = any(
                haversine(p.lat, p.lon, wc["lat"], wc["lon"]) <= RADIUS_CAM_DEDUP_M
                and is_same_heading(hd, wc["heading"])
                for wc in iter_grid_neighbors(raw_wyn_cam_grid, gx, gy)
            )
            if near_wyn:
                vm_cams_dropped_near_wyn += 1
            else:
                seed = f"cam|vm11|{lat_e7}|{lon_e7}|{hd}".encode()
                cid = (1 << 62) | (zlib.crc32(seed) & ((1 << 62) - 1))
                while cid in used_cam_ids:
                    cid = (1 << 62) | ((cid + 1) & ((1 << 62) - 1))
                used_cam_ids.add(cid)

                cam = {
                    "id": cid,
                    "lat": p.lat,
                    "lon": p.lon,
                    "speed": -1, # Phạt nguội chung
                    "heading": hd,
                    "source": "VietMap",
                }
                final_cameras.append(cam)
                all_cam_grid[(gx, gy)].append(cam)
                vm_type11_added += 1
                vm_cams_added += 1

        # 2. Biển giới hạn tốc độ (Type 1)
        elif p.type == 1:
            # Loại bỏ triệt để biển 40 km/h "ma" và các giá trị bất thường
            if p.speed_limit <= 40 or p.speed_limit not in (50, 60, 70, 80, 90, 100, 120):
                continue

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
                "flags": 1, # Flag 1 = Visual-only / Silent (chống rác âm thanh khi chỉ là vạch sơn)
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
                "flags": 1, # Flag 1 = Visual-only / Silent
                "reserved": 1,
            })
            vm_signs_added["Hết cấm vượt (Type 6)"] += 1

        # 7. Trạm thu phí bổ sung (Type 8) - Khử trùng 300m với WYN
        elif p.type == 8:
            gx, gy = int(p.lon / CELL), int(p.lat / CELL)
            near_wyn_toll = any(
                haversine(p.lat, p.lon, wt["lat"], wt["lon"]) <= RADIUS_TOLL_DEDUP_M
                for wt in iter_grid_neighbors(wyn_toll_grid, gx, gy, span=7)
            )
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
                    "flags": 0,
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
                "flags": 0,
                "reserved": 1,
            })
            vm_signs_added["Hầm đường bộ (Type 9)"] += 1

        # 9. Thu thập ứng viên Type 4 để xử lý sau khi đã nạp hết Type 11
        elif p.type == 4:
            type4_candidates.append(p)

        # LOẠI BỎ 100% CÁC LOẠI 7, 10 ĐỂ CHỐNG RÁC
        # (Không làm gì, tự động bỏ qua)

    # 9b. PHỤC HỒI CAMERA CÒN THIẾU HƯỚNG TỪ TYPE 4 (chỉ khi trùng camera WYN/CURATED <= 40m)
    for p in type4_candidates:
        hd = p.heading if 1 <= p.heading <= 359 else DIR_OMNI
        gx, gy = int(p.lon / CELL), int(p.lat / CELL)

        near_speed_cam = None
        near_other_cam = None
        for wc in iter_grid_neighbors(raw_wyn_cam_grid, gx, gy):
            d = haversine(p.lat, p.lon, wc["lat"], wc["lon"])
            if d <= RADIUS_CAM_MATCH_WYN_M:
                if wc["speed"] > 0 and (near_speed_cam is None or d < near_speed_cam[1]):
                    near_speed_cam = (wc, d)
                elif wc["speed"] <= 0 and (near_other_cam is None or d < near_other_cam[1]):
                    near_other_cam = (wc, d)

        if not near_speed_cam and not near_other_cam:
            vm_type4_skipped_no_wyn += 1
            continue

        is_cam_dup = any(
            haversine(p.lat, p.lon, ec["lat"], ec["lon"]) <= RADIUS_CAM_DEDUP_M
            and is_same_heading(hd, ec.get("heading", DIR_OMNI))
            for ec in iter_grid_neighbors(all_cam_grid, gx, gy)
        )
        if is_cam_dup:
            vm_type4_dropped_dup += 1
            continue

        if near_speed_cam:
            cam_speed = near_speed_cam[0]["speed"]
            cam_source = "VietMap4_Speed"
            vm_type4_speed_added += 1
        else:
            cam_speed = -1
            near_light = any(
                haversine(p.lat, p.lon, olat, olon) <= RADIUS_LIGHT_MATCH_M
                for olat, olon in iter_grid_neighbors(osm_light_grid, gx, gy)
            ) or any(
                haversine(p.lat, p.lon, wl["lat"], wl["lon"]) <= RADIUS_LIGHT_MATCH_M
                for wl in iter_grid_neighbors(wyn_light_grid, gx, gy)
            )
            if near_light:
                cam_source = "VietMap4_RedLight"
                vm_type4_redlight_added += 1
            else:
                cam_source = "VietMap4_Surveillance"
                vm_type4_surveillance_added += 1

        lat_e7 = int(round(p.lat * 1e7))
        lon_e7 = int(round(p.lon * 1e7))
        seed = f"cam|vm4|{lat_e7}|{lon_e7}|{hd}".encode()
        cid = (1 << 62) | (zlib.crc32(seed) & ((1 << 62) - 1))
        while cid in used_cam_ids:
            cid = (1 << 62) | ((cid + 1) & ((1 << 62) - 1))
        used_cam_ids.add(cid)

        cam = {
            "id": cid,
            "lat": p.lat,
            "lon": p.lon,
            "speed": cam_speed,
            "heading": hd,
            "source": cam_source,
        }
        final_cameras.append(cam)
        all_cam_grid[(gx, gy)].append(cam)
        vm_cams_added += 1

    print(f"      + Camera VietMap bổ sung:   {vm_cams_added:,} (Type 11: {vm_type11_added:,}, Loại bỏ {vm_cams_dropped_near_wyn:,} trùng WYN <=30m cùng hướng)")
    if vm_type4_speed_added > 0 or vm_type4_redlight_added > 0 or vm_type4_surveillance_added > 0:
        print(
            f"        * Trong đó cứu hướng đối diện từ Type 4: {vm_type4_speed_added:,} tốc độ, "
            f"{vm_type4_redlight_added:,} đèn đỏ, {vm_type4_surveillance_added:,} phạt nguội "
            f"(bỏ {vm_type4_dropped_dup:,} trùng <=30m cùng hướng, {vm_type4_skipped_no_wyn:,} không khớp camera WYN)"
        )
    print(f"      + Trạm thu phí bổ sung:     {vm_tolls_added:,} (Loại bỏ {vm_tolls_dropped_near_wyn:,} trùng WYN <=300m)")
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
            s.get("flags", 0), # flags
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
            "OSM": {"light": osm_lights_added_count},
            "CURATED": {"camera": curated_cam_count, "sign": curated_sign_count},
            "VietMap": {
                "camera_total": vm_cams_added,
                "type4_speed_cam": vm_type4_speed_added,
                "type4_redlight_cam": vm_type4_redlight_added,
                "type4_surveillance_cam": vm_type4_surveillance_added,
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

    if sign:
        # Ký manifest bằng khoá MapViet
        key_file = None
        if (REPO_ROOT / "Key" / "mapviet_signing_key.pem").exists():
            key_file = REPO_ROOT / "Key" / "mapviet_signing_key.pem"
        elif (Path.home() / ".mapviet" / "mapviet_signing_key.pem").exists():
            key_file = Path.home() / ".mapviet" / "mapviet_signing_key.pem"

        priv_key = sign_manifest.load_private_key(key_file)
        sig_file = sign_manifest.sign_manifest(manifest_file, key=priv_key)
        print(f"      [OK] Đã ký số ECDSA P-256 thành công ra: {sig_file.name}")

        # Xác thực lại chữ ký ngay lập tức
        is_valid = sign_manifest.verify_manifest(manifest_file)
        if not is_valid:
            raise ValueError(f"Xác thực chữ ký manifest thất bại!")
        print(f"      [OK] Chữ ký manifest đã được xác thực hợp lệ 100%!")
    else:
        print("      [INFO] Bỏ qua ký số manifest (sign=False)")

    print("\n" + "=" * 70)
    print("  HOÀN TẤT ĐÓNG GÓI GÓI CẢNH BÁO TOÀN QUỐC THÀNH CÔNG!")
    print("=" * 70)
    return {
        "version": version_str,
        "cameras_count": len(final_cameras),
        "signs_count": len(final_signs),
        "output_dir": str(output_dir),
    }


def find_default_wyn() -> Path:
    candidates = [
        REPO_ROOT / "data-pipeline" / "sources" / "wyn" / "wyn_points.csv",
        REPO_ROOT / "VietHUD" / "data" / "wyn" / "wyn_points.csv",
        REPO_ROOT / "sources" / "wyn" / "wyn_points.csv",
        Path(__file__).resolve().parent / "sources" / "wyn" / "wyn_points.csv",
    ]
    return next((p for p in candidates if p.exists()), candidates[0])


def find_default_vietmap() -> Path:
    candidates = [
        REPO_ROOT / "secrect.bin",
        REPO_ROOT / "VietHUD" / "data" / "vietmap" / "secrect.bin",
        REPO_ROOT / "data-pipeline" / "sources" / "vietmap" / "secrect.bin",
        REPO_ROOT / "sources" / "vietmap" / "secrect.bin",
        Path(__file__).resolve().parent / "sources" / "vietmap" / "secrect.bin",
    ]
    return next((p for p in candidates if p.exists()), candidates[0])


def find_default_out() -> Path:
    candidates = [
        REPO_ROOT / "VietHUD" / "speedmap",
        REPO_ROOT / "alerts_out",
        Path(__file__).resolve().parent / "alerts_out",
    ]
    return next((p for p in candidates if p.exists()), candidates[0])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build clean nationwide alert dataset for MapViet.")
    parser.add_argument("--wyn", type=Path, default=find_default_wyn())
    parser.add_argument("--vietmap", type=Path, default=find_default_vietmap())
    parser.add_argument("--out", type=Path, default=find_default_out())
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
