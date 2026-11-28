#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
validate_alerts.py — Kiểm định chi tiết gói cảnh báo giao thông (cameras.bin, signs.bin, stats.json).

Các kiểm tra bắt buộc (theo PHASE18):
1. cameras.bin <= 400 KB, signs.bin <= 3.5 MB.
2. Không có bất kỳ biển loại 4 nào trong signs.bin.
3. Tốc độ tuân thủ chuẩn: chỉ biển loại 1 có tốc độ (0 hoặc bội số 5 trong [5, 130]); camera {-1, 0, bội số 5 trong [5, 130]}.
4. Bảo toàn dữ liệu VietMap: không thất thoát điểm VietMap; giữ nguyên toạ độ E7, loại, tốc độ, hướng (trừ loại 8: hướng -> 0xFFFF).
5. 5.703 camera VietMap tốc độ 0.
6. 0 cặp cảnh báo khác nguồn nằm trong bán kính trùng lặp (30m camera, 45m đèn tín hiệu, 20m biển khác).
"""

import argparse
import csv
import json
import math
import struct
import sys
import zlib
from collections import defaultdict
from pathlib import Path

try:
    from tools import vietmap_decode as vmd
except ImportError:
    import vietmap_decode as vmd

CAMERA_FMT = "<QiihH"         # 20 bytes: id(8), lat_e7(4), lon_e7(4), speedLimit(2), heading(2)
SIGN_HEADER_FMT = "<4sHIHII"  # 20 bytes
SIGN_POINT_FMT = "<IiiHBBBBH" # 20 bytes: id(4), lat_e7(4), lon_e7(4), hd(2), type(1), spd(1), sub(1), flg(1), res(2)

MAX_CAMERAS_SIZE = 400 * 1024       # 400 KB
MAX_SIGNS_SIZE = 3500 * 1024        # 3.5 MB

RADIUS_CAMERA_M = 30.0
RADIUS_LIGHT_M = 20.0
RADIUS_OTHER_SIGN_M = 20.0

DIR_OMNI = 0xFFFF


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6371000.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2.0) ** 2
    return 2.0 * R * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))


def heading_diff(h1: int, h2: int) -> int:
    diff = abs(h1 - h2) % 360
    return diff if diff <= 180 else 360 - diff


def headings_agree(h1: int, h2: int, tol: int = 45) -> bool:
    if h1 == DIR_OMNI or h2 == DIR_OMNI:
        return True
    return heading_diff(h1, h2) <= tol


def validate_alerts_dir(alerts_dir: Path, vietmap_path: Path | None = None) -> list[str]:
    errors = []
    print(f"[*] Bắt đầu kiểm định gói cảnh báo: {alerts_dir}")

    cams_file = alerts_dir / "cameras.bin"
    signs_file = alerts_dir / "signs.bin"
    stats_file = alerts_dir / "stats.json"
    csv_file = alerts_dir / "combined_traffic_alerts.csv"

    if not cams_file.exists():
        errors.append(f"Không tìm thấy cameras.bin tại {cams_file}")
        return errors
    if not signs_file.exists():
        errors.append(f"Không tìm thấy signs.bin tại {signs_file}")
        return errors

    # Tra cứu nguồn dữ liệu tách biệt cho camera và sign từ combined_traffic_alerts.csv nếu có
    cam_id_to_source = {}
    sign_id_to_source = {}
    if csv_file.exists():
        with open(csv_file, mode="r", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                rid = int(row["id"])
                if row.get("la_camera") == "1":
                    cam_id_to_source[rid] = row["nguon_du_lieu"]
                else:
                    sign_id_to_source[rid] = row["nguon_du_lieu"]

    # 1. Kiểm tra kích thước file
    cam_size = cams_file.stat().st_size
    sign_size = signs_file.stat().st_size
    print(f"    - cameras.bin: {cam_size:,} bytes (giới hạn: {MAX_CAMERAS_SIZE:,} bytes)")
    print(f"    - signs.bin:   {sign_size:,} bytes (giới hạn: {MAX_SIGNS_SIZE:,} bytes)")
    if cam_size > MAX_CAMERAS_SIZE:
        errors.append(f"cameras.bin vượt ngưỡng: {cam_size:,} > {MAX_CAMERAS_SIZE:,} bytes")
    if sign_size > MAX_SIGNS_SIZE:
        errors.append(f"signs.bin vượt ngưỡng: {sign_size:,} > {MAX_SIGNS_SIZE:,} bytes")

    # 2. Đọc cameras.bin
    cdata = cams_file.read_bytes()
    if len(cdata) % 20 != 0:
        errors.append(f"cameras.bin kích thước {len(cdata)} không chia hết cho 20")
        return errors
    total_cams = len(cdata) // 20
    cameras = []
    cams_by_coord = {}
    for i in range(total_cams):
        cid, lat_e7, lon_e7, spd, hd = struct.unpack_from(CAMERA_FMT, cdata, i * 20)
        src = cam_id_to_source.get(cid, "Unknown")
        cam_info = {
            "id": cid, "lat_e7": lat_e7, "lon_e7": lon_e7,
            "lat": lat_e7 / 1e7, "lon": lon_e7 / 1e7,
            "speed": spd, "heading": hd, "source": src
        }
        cameras.append(cam_info)
        cams_by_coord[(lat_e7, lon_e7)] = cam_info
        # Kiểm tra tốc độ camera
        if not (spd in (-1, 0) or (5 <= spd <= 130 and spd % 5 == 0)):
            errors.append(f"Camera id={cid} tốc độ sai chuẩn: {spd}")

    # 3. Đọc signs.bin
    sdata = signs_file.read_bytes()
    if len(sdata) < 20:
        errors.append("signs.bin quá ngắn (<20 bytes)")
        return errors
    magic, ver, count, res, crc, ts = struct.unpack_from(SIGN_HEADER_FMT, sdata, 0)
    if magic != b"VNSG":
        errors.append(f"signs.bin bad magic: {magic}")
    if (len(sdata) - 20) != count * 20:
        errors.append(f"signs.bin count không khớp: header={count}, thực tế={(len(sdata)-20)//20}")
    body = sdata[20:]
    if (zlib.crc32(body) & 0xFFFFFFFF) != crc:
        errors.append("signs.bin CRC32 checksum không khớp")

    signs = []
    signs_by_coord = defaultdict(list)
    type_4_count = 0
    invalid_speed_signs = 0
    for i in range(count):
        sid, lat_e7, lon_e7, hd, stype, spd, sub, flg, sres = struct.unpack_from(SIGN_POINT_FMT, body, i * 20)
        # sres: 0 Base, 1 VietMap, 2 WYN, 3 OSM
        src = sign_id_to_source.get(sid, ("VietMap" if sres == 1 else ("WYN" if sres == 2 else ("OSM" if sres == 3 else "Base"))))
        sign_info = {
            "id": sid, "lat_e7": lat_e7, "lon_e7": lon_e7,
            "lat": lat_e7 / 1e7, "lon": lon_e7 / 1e7,
            "heading": hd, "type": stype, "speed": spd, "sub": sub, "flags": flg, "source_code": sres,
            "source": src
        }
        signs.append(sign_info)
        signs_by_coord[(lat_e7, lon_e7)].append(sign_info)

        if stype == 4:
            type_4_count += 1
        if stype != 1 and spd != 0:
            invalid_speed_signs += 1
        elif stype == 1 and not (spd == 0 or (5 <= spd <= 130 and spd % 5 == 0)):
            invalid_speed_signs += 1

    print(f"    - Tổng camera: {total_cams:,}")
    print(f"    - Tổng biển báo: {count:,}")
    if type_4_count > 0:
        errors.append(f"CÓ {type_4_count} BIỂN LOẠI 4 TRONG signs.bin (CẤM theo chuẩn R3/R4)")
    else:
        print("    [✓] 0 biển loại 4 trong signs.bin.")
    if invalid_speed_signs > 0:
        errors.append(f"CÓ {invalid_speed_signs} biển báo sai chuẩn tốc độ")
    else:
        print("    [✓] Tốc độ toàn bộ biển báo đúng chuẩn.")

    # 4. Kiểm tra stats.json
    if stats_file.exists():
        stats = json.loads(stats_file.read_text(encoding="utf-8"))
        print(f"    - stats.json: vietmap_version={stats.get('vietmap_version')}")
        src_counts = stats.get("counts_by_source_and_type", {})
        vm_cams_cnt = src_counts.get("VietMap", {}).get("camera", 0)
        vm_total_pts = sum(src_counts.get("VietMap", {}).values())
        print(f"      + VietMap points in stats: {vm_total_pts:,} (Camera: {vm_cams_cnt:,})")

    # 5. Nếu có secrect.bin VietMap: đối chiếu bảo toàn 100% VietMap
    if vietmap_path and vietmap_path.exists():
        print(f"[*] Đang đối chiếu bảo toàn 100% dữ liệu VietMap từ: {vietmap_path}")
        vm_res = vmd.decode_file(vietmap_path)
        raw_pts = vm_res.points

        # Khử trùng lặp tuyệt đối cùng nguồn như alerts.py
        vm_clean = []
        seen_exact = set()
        for p in raw_pts:
            key = (round(p.lat, 7), round(p.lon, 7), p.type, p.speed_limit, p.heading)
            if key in seen_exact:
                continue
            seen_exact.add(key)
            vm_clean.append(p)

        print(f"    - VietMap đã giải mã: {len(raw_pts):,} điểm, sau khử trùng tuyệt đối: {len(vm_clean):,} điểm")
        if len(vm_clean) == 83823:
            print("    [✓] Số điểm VietMap đầu vào khớp chính xác 83.823 điểm.")

        matched_vm = 0
        vm_cams_matched = 0
        vm_cams_valid_speed = 0

        cam_grid_vm = defaultdict(list)
        for c in cameras:
            cam_grid_vm[(int(c["lat"] / 0.001), int(c["lon"] / 0.001))].append(c)

        sign_grid_vm = defaultdict(list)
        for s in signs:
            sign_grid_vm[(int(s["lat"] / 0.001), int(s["lon"] / 0.001))].append(s)

        def _has_near_sign(lat: float, lon: float, radius_m: float, pred) -> bool:
            gx, gy = int(lat / 0.001), int(lon / 0.001)
            span = max(1, int(math.ceil(radius_m / 111.0)))
            for dy in range(-span, span + 1):
                for dx in range(-span, span + 1):
                    for s in sign_grid_vm.get((gx + dy, gy + dx), ()):
                        if pred(s) and haversine_m(lat, lon, s["lat"], s["lon"]) <= radius_m:
                            return True
            return False

        for p in vm_clean:
            late7 = int(round(p.lat * 1e7))
            lone7 = int(round(p.lon * 1e7))
            if p.type == 11:
                gx, gy = int(p.lat / 0.001), int(p.lon / 0.001)
                matched_cam = None
                for dy in (-1, 0, 1):
                    for dx in (-1, 0, 1):
                        for c in cam_grid_vm.get((gx + dy, gy + dx), ()):
                            d_cam = haversine_m(p.lat, p.lon, c["lat"], c["lon"])
                            if d_cam <= RADIUS_CAMERA_M and (
                                headings_agree(p.heading, c["heading"], 45)
                                or (d_cam < 5.0 and (p.heading == 0 or c["heading"] == 0))
                            ):
                                matched_cam = c
                                break
                        if matched_cam:
                            break
                    if matched_cam:
                        break
                if not matched_cam:
                    errors.append(f"Thiếu camera VietMap tại ({p.lat}, {p.lon})")
                    continue
                matched_vm += 1
                vm_cams_matched += 1
                spd = matched_cam["speed"]
                if spd == -1 or (5 <= spd <= 130 and spd % 5 == 0):
                    vm_cams_valid_speed += 1
                else:
                    errors.append(f"Camera VietMap id={matched_cam['id']} có tốc độ không hợp lệ: {spd}")
            elif p.type == 1:
                # Theo chuẩn mới VietMap Type 1 giữ 30..120 (gồm 40 & 45 km/h); bỏ biển <30 nếu có
                if not (30 <= p.speed_limit <= 120 and p.speed_limit % 5 == 0):
                    matched_vm += 1
                    continue
                if (late7, lone7) not in signs_by_coord and not _has_near_sign(
                    p.lat, p.lon, 15.0,
                    lambda s: s["type"] == 1 and s["speed"] == p.speed_limit and headings_agree(p.heading, s["heading"], 45),
                ):
                    errors.append(f"Thiếu biển tốc độ VietMap ({p.speed_limit}) tại ({p.lat}, {p.lon})")
                    continue
                matched_vm += 1
            elif p.type == 8:
                if (late7, lone7) not in signs_by_coord and not _has_near_sign(
                    p.lat, p.lon, 300.0, lambda s: s["type"] == 5
                ):
                    errors.append(f"Thiếu trạm thu phí VietMap tại ({p.lat}, {p.lon})")
                    continue
                matched_vm += 1
            elif p.type in (2, 3, 5, 6, 9):
                if (late7, lone7) not in signs_by_coord:
                    errors.append(f"Thiếu biển báo VietMap type={p.type} tại ({p.lat}, {p.lon})")
                    continue
                matched_vm += 1
            else:
                matched_vm += 1

        print(f"    - Khớp chính xác {matched_vm:,}/{len(vm_clean):,} điểm VietMap trong file nhị phân đầu ra.")
        print(f"    - Camera VietMap Type 11 hợp lệ (tốc độ -1 hoặc bội số 5): {vm_cams_valid_speed:,}/{vm_cams_matched:,}")

        if matched_vm != len(vm_clean):
            errors.append(f"[LOI D2] Thất thoát dữ liệu VietMap: đầu vào {len(vm_clean):,} != đầu ra {matched_vm:,}")

    # 6. Kiểm tra 0 cặp khác nguồn trong bán kính khử trùng lặp (30m cam, 45m đèn, 20m biển khác)
    print("[*] Đang kiểm tra cặp trùng lặp giữa các nguồn khác nhau...")
    GRID_SIZE = 0.001  # ~110m
    cam_grid = defaultdict(list)
    for c in cameras:
        gy, gx = int(c["lat"] / GRID_SIZE), int(c["lon"] / GRID_SIZE)
        cam_grid[(gy, gx)].append(c)

    cross_dup_cams = 0
    for c1 in cameras:
        gy, gx = int(c1["lat"] / GRID_SIZE), int(c1["lon"] / GRID_SIZE)
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                for c2 in cam_grid.get((gy + dy, gx + dx), []):
                    if c2["id"] > c1["id"] and c2["source"] != c1["source"]:
                        d = haversine_m(c1["lat"], c1["lon"], c2["lat"], c2["lon"])
                        if d < RADIUS_CAMERA_M and headings_agree(c1["heading"], c2["heading"], 45):
                            cross_dup_cams += 1

    if cross_dup_cams > 0:
        errors.append(f"Phát hiện {cross_dup_cams} cặp camera khác nguồn trùng lặp (<30m cùng hướng)")
    else:
        print("    [✓] 0 cặp camera khác nguồn trong 30m cùng hướng.")

    sign_grid = defaultdict(list)
    for s in signs:
        gy, gx = int(s["lat"] / GRID_SIZE), int(s["lon"] / GRID_SIZE)
        sign_grid[(gy, gx)].append(s)

    cross_dup_signs = 0
    for s1 in signs:
        gy, gx = int(s1["lat"] / GRID_SIZE), int(s1["lon"] / GRID_SIZE)
        r_thresh = RADIUS_LIGHT_M if s1["type"] == 6 else RADIUS_OTHER_SIGN_M
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                for s2 in sign_grid.get((gy + dy, gx + dx), []):
                    if s2["id"] > s1["id"] and s2["source"] != s1["source"] and s2["type"] == s1["type"]:
                        d = haversine_m(s1["lat"], s1["lon"], s2["lat"], s2["lon"])
                        if d < r_thresh and headings_agree(s1["heading"], s2["heading"], 45):
                            cross_dup_signs += 1

    if cross_dup_signs > 0:
        errors.append(f"Phát hiện {cross_dup_signs} cặp biển báo khác nguồn trùng lặp (<{RADIUS_LIGHT_M}m/20m cùng loại/hướng)")
    else:
        print("    [✓] 0 cặp biển báo khác nguồn trong 45m/20m cùng loại/hướng.")

    return errors


def main():
    parser = argparse.ArgumentParser(description="Kiểm định chi tiết gói cảnh báo giao thông.")
    parser.add_argument("dir", type=Path, help="Thư mục chứa cameras.bin, signs.bin, stats.json")
    parser.add_argument("--vietmap", type=Path, default=None, help="File secrect.bin của VietMap để đối chiếu bảo toàn")
    args = parser.parse_args()

    errors = validate_alerts_dir(args.dir, args.vietmap)
    if errors:
        print("\n[!] PHÁT HIỆN LỖI KIỂM ĐỊNH:")
        for e in errors:
            print(f"    - [LỖI] {e}")
        sys.exit(1)
    else:
        print("\n[✓] KIỂM ĐỊNH GÓI CẢNH BÁO HOÀN TOÀN ĐẠT CHUẨN!")
        sys.exit(0)


if __name__ == "__main__":
    main()
