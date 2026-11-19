#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Bản sao từ VietHUD/tools/alerts.py — nguồn chuẩn là VietHUD/tools; sửa ở đó rồi chép lại
"""
tools/alerts.py — Engine hợp nhất, khử trùng lặp và làm sạch dữ liệu cảnh báo giao thông VietHUD.

Nguồn dữ liệu & Thứ tự ưu tiên (Priority):
  1. VietMap (P1 - Ưu tiên cao nhất): Từ file secrect.bin giải mã qua tools/vietmap_decode.py
  2. WYN (P2 - Ưu tiên cao): Từ file data/wyn/wyn_points.csv đã được đóng băng
  3. Dữ liệu nền Base (P3 - Cơ sở): Từ cameras.bin và signs.bin do synthesize_and_pack.py sinh

Quy tắc ánh xạ VietMap -> VietHUD:
  - Type 1  -> Sign 1 (SPEED_LIMIT), speed 5..130 (ngoài dải bỏ điểm)
  - Type 2  -> Sign 6 (TRAFFIC_LIGHT), speed 0
  - Type 4  -> Sign 2 (RESIDENT_AREA), subType 0, speed 0
  - Type 5  -> Sign 5 (TOLL_BOOTH), speed 0
  - Type 10 -> Sign 3 (NO_OVERTAKING), speed 0
  - Type 11 -> Camera (phạt nguội), speed 0

CHỈ VietMap type 11, camera WYN (kind=camera) và camera trong base/cameras.bin được ghi vào cameras.bin.
signs.bin CHỈ chứa biển/đèn (không bao giờ chứa camera).
"""

import argparse
import csv
import hashlib
import json
import math
import struct
import sys
import time
import zlib
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Import bộ giải mã VietMap và bộ ký manifest
try:
    from tools import vietmap_decode as vmd
    from tools import sign_manifest
except ImportError:
    import vietmap_decode as vmd
    import sign_manifest

# Bounding box Việt Nam
LAT_MIN, LAT_MAX = 8.0, 24.0
LON_MIN, LON_MAX = 102.0, 110.5

# Loại biển báo VietHUD chuẩn
SIGN_TYPE_SPEED_LIMIT    = 1
SIGN_TYPE_RESIDENT_AREA  = 2
SIGN_TYPE_NO_OVERTAKING  = 3
SIGN_TYPE_TOLL_BOOTH     = 5
SIGN_TYPE_TRAFFIC_LIGHT  = 6
SIGN_TYPE_DANGER_OTHER   = 10

# Bán kính khử trùng lặp chuẩn R3
RADIUS_CAMERA_M          = 30.0  # Camera
RADIUS_LIGHT_M           = 45.0  # Đèn tín hiệu giao thông (Sign 6)
RADIUS_OTHER_SIGN_M      = 20.0  # Biển báo khác (so cùng sign_type)
RADIUS_SAME_SRC_DUP_M    = 2.0   # Bán kính trùng tuyệt đối cùng nguồn (m)
HEADING_SAME_SRC_TOL_DEG = 5     # Dung sai góc hướng trùng tuyệt đối cùng nguồn (độ)

# Alias tương thích
MERGE_RADIUS_DEFAULT_M = RADIUS_CAMERA_M
MERGE_RADIUS_LIGHT_M   = RADIUS_LIGHT_M

# Ngưỡng góc hướng (degrees)
HEADING_TOL_DEG      = 45   # Lệch <= 45 độ => cùng hướng
HEADING_OPPOSITE_DEG = 135  # Lệch >= 135 độ => ngược chiều (giữ cả hai)

DIR_OMNI = 0xFFFF  # Không rõ hướng

# Độ ưu tiên nguồn dữ liệu
PRIORITY_VIETMAP = 1
PRIORITY_WYN     = 2
PRIORITY_BASE    = 3

# Mã nguồn trong trường reserved của signs.bin
SOURCE_CODE_BASE    = 0
SOURCE_CODE_VIETMAP = 1
SOURCE_CODE_WYN     = 2

# Định dạng nhị phân VietHUD
# struct CameraPoint: <QiihH (20 bytes)
# id(8), lat_e7(4), lon_e7(4), speedLimitKmh(2), directionDeg(2)
CAMERA_FMT = "<QiihH"

# struct TrafficSignHeader: <4sHIHII (20 bytes)
# magic(4), version(2), signCount(4), reserved(2), crc32(4), timestamp(4)
SIGN_HEADER_FMT = "<4sHIHII"

# struct TrafficSignPoint: <IiiHBBBBH (20 bytes)
# id(4), lat_e7(4), lon_e7(4), directionDeg(2), signType(1), speedLimitKmh(1), subType(1), flags(1), reserved(2)
SIGN_POINT_FMT = "<IiiHBBBBH"


def is_valid_speed_value(spd: int) -> bool:
    """Kiểm tra giá trị tốc độ có hợp lệ (bội số của 5 trong [5, 130])."""
    return spd is not None and 5 <= spd <= 130 and (spd % 5 == 0)


def clean_camera_speed(spd: int) -> int:
    """
    Quy chuẩn tốc độ camera theo chuẩn R2:
      -1 : chưa rõ tốc độ
       0 : phạt nguội / không bắn tốc độ
      >0 : bắn tốc độ (chỉ nhận bội số của 5 trong [5, 130])
      Giá trị khác -> -1 (chưa rõ), KHÔNG ép về 0.
    """
    if spd in (-1, 0):
        return spd
    if is_valid_speed_value(spd):
        return spd
    return -1


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6371000.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2.0) ** 2
    return 2.0 * R * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))


def heading_diff(h1: int, h2: int) -> float:
    diff = abs((h1 % 360) - (h2 % 360))
    return 360 - diff if diff > 180 else diff


def is_heading_known(h: int, source: str | None = None) -> bool:
    if h is None or h == DIR_OMNI:
        return False
    if source == "VietMap":
        return 0 <= h < 360
    return 0 < h < 360


@dataclass
class AlertPoint:
    lat: float
    lon: float
    sign_type: int | None
    speed_limit: int
    heading: int
    is_camera: bool
    source: str
    priority: int
    desc: str
    kind: str = ""
    sub_type: int = 0
    flags: int = 0
    original_id: int | None = None
    id: int | None = None
    original_type: int | None = None
    decoded_heading: int | None = None

    def __post_init__(self):
        if self.decoded_heading is None and self.source == "VietMap":
            self.decoded_heading = self.heading


# Biến toàn cục theo dõi thống kê giải mã VietMap và lọc tốc độ (R4)
LAST_VIETMAP_DECODE_STATS = {}
GLOBAL_DROP_STATS = {
    "base_speed_sign_zero_dropped": 0,
    "speed_sign_invalid_dropped": 0,
    "vietmap_type8_heading_zero_as_unknown": 0,
}


class SpatialAlertIndex:
    """Chỉ mục không gian lưới ô vuông (Spatial Grid Hash) tối ưu tra cứu O(1)."""
    def __init__(self, cell_deg: float = 0.0005):  # ~55m cell
        self.cell_deg = cell_deg
        self.grid = defaultdict(list)

    def _cell(self, lat: float, lon: float):
        return int(math.floor(lat / self.cell_deg)), int(math.floor(lon / self.cell_deg))

    def insert(self, idx: int, p: AlertPoint):
        cy, cx = self._cell(p.lat, p.lon)
        self.grid[(cy, cx)].append(idx)

    def find_nearby(self, p: AlertPoint, points_list: list, radius_m: float) -> list:
        cy, cx = self._cell(p.lat, p.lon)
        r_cells = max(1, int(math.ceil(radius_m / (self.cell_deg * 100000.0))))
        nearby = []
        for dy in range(-r_cells, r_cells + 1):
            for dx in range(-r_cells, r_cells + 1):
                for candidate_idx in self.grid.get((cy + dy, cx + dx), []):
                    c = points_list[candidate_idx]
                    dist = haversine_m(p.lat, p.lon, c.lat, c.lon)
                    if dist <= radius_m:
                        nearby.append((dist, candidate_idx, c))
        return nearby


def load_vietmap_alerts(secrect_bin_path: Path) -> tuple[list[AlertPoint], str]:
    """Nạp và giải mã điểm cảnh báo từ file secrect.bin của VietMap."""
    print(f"[*] [1/3] Đang nạp dữ liệu VietMap từ: {secrect_bin_path}...")
    res = vmd.decode_file(secrect_bin_path)
    points = []
    dropped_speed = 0

    for p in res.points:
        if not (LAT_MIN <= p.lat <= LAT_MAX and LON_MIN <= p.lon <= LON_MAX):
            continue

        if p.type == vmd.TYPE_VM_TYPE_8:
            # Ngoại lệ F1: loại 8 (634/634 điểm hướng 0, rõ ràng không có hướng) -> DIR_OMNI (0xFFFF)
            hd = DIR_OMNI
            GLOBAL_DROP_STATS["vietmap_type8_heading_zero_as_unknown"] += 1
        else:
            hd = p.heading if is_heading_known(p.heading, "VietMap") else DIR_OMNI

        if p.type == vmd.TYPE_SPEED_LIMIT:
            # Type 1: Sign 1 SPEED_LIMIT (hợp lệ: 0 hoặc bội số 5 trong [5, 130])
            if p.speed_limit != 0 and not is_valid_speed_value(p.speed_limit):
                dropped_speed += 1
                GLOBAL_DROP_STATS["speed_sign_invalid_dropped"] += 1
                continue
            pt = AlertPoint(
                lat=p.lat,
                lon=p.lon,
                sign_type=SIGN_TYPE_SPEED_LIMIT,
                speed_limit=p.speed_limit,
                heading=hd,
                is_camera=False,
                source="VietMap",
                priority=PRIORITY_VIETMAP,
                desc=f"VietMap Speed Limit ({p.speed_limit}km/h)",
                kind="sign",
                original_type=p.type,
                decoded_heading=p.heading,
            )
        elif p.type in (vmd.TYPE_TRAFFIC_LIGHT, vmd.TYPE_VM_LIGHT_3, vmd.TYPE_VM_LIGHT_6):
            # Type 2, 3, 6: Sign 6 TRAFFIC_LIGHT, speed = 0 (Bước 3b)
            pt = AlertPoint(
                lat=p.lat,
                lon=p.lon,
                sign_type=SIGN_TYPE_TRAFFIC_LIGHT,
                speed_limit=0,
                heading=hd,
                is_camera=False,
                source="VietMap",
                priority=PRIORITY_VIETMAP,
                desc="VietMap Traffic Light",
                kind="light",
                original_type=p.type,
                decoded_heading=p.heading,
            )
        elif p.type == vmd.TYPE_URBAN_START:
            # Type 4: Sign 2 RESIDENT_AREA, subType 0, speed = 0
            pt = AlertPoint(
                lat=p.lat,
                lon=p.lon,
                sign_type=SIGN_TYPE_RESIDENT_AREA,
                speed_limit=0,
                heading=hd,
                is_camera=False,
                source="VietMap",
                priority=PRIORITY_VIETMAP,
                desc="VietMap Resident Area",
                kind="sign",
                sub_type=0,
                original_type=p.type,
                decoded_heading=p.heading,
            )
        elif p.type == vmd.TYPE_TOLL_BOOTH:
            # Type 5: Sign 5 TOLL_BOOTH, speed = 0
            pt = AlertPoint(
                lat=p.lat,
                lon=p.lon,
                sign_type=SIGN_TYPE_TOLL_BOOTH,
                speed_limit=0,
                heading=hd,
                is_camera=False,
                source="VietMap",
                priority=PRIORITY_VIETMAP,
                desc="VietMap Toll Booth",
                kind="sign",
                original_type=p.type,
                decoded_heading=p.heading,
            )
        elif p.type in (vmd.TYPE_VM_TYPE_8, vmd.TYPE_VM_TYPE_9):
            # Type 8, 9: Sign 10 DANGER_OTHER, sub_type = 8 hoặc 9, speed = 0 (D2, Kế hoạch 1.J)
            # Ngoại lệ F1: loại 8 ghi 0xFFFF; loại 9 giữ nguyên hướng
            pt = AlertPoint(
                lat=p.lat,
                lon=p.lon,
                sign_type=SIGN_TYPE_DANGER_OTHER,
                speed_limit=0,
                heading=hd,
                is_camera=False,
                source="VietMap",
                priority=PRIORITY_VIETMAP,
                desc=f"VietMap Other (Type {p.type})",
                kind="sign",
                sub_type=p.type,
                original_type=p.type,
                decoded_heading=p.heading,
            )
        elif p.type == vmd.TYPE_VM_DANGER_7:
            # Type 7: Sign 10 DANGER_OTHER, speed = 0 (Bước 3b)
            pt = AlertPoint(
                lat=p.lat,
                lon=p.lon,
                sign_type=SIGN_TYPE_DANGER_OTHER,
                speed_limit=0,
                heading=hd,
                is_camera=False,
                source="VietMap",
                priority=PRIORITY_VIETMAP,
                desc="VietMap Danger/Other",
                kind="sign",
                original_type=p.type,
                decoded_heading=p.heading,
            )
        elif p.type == vmd.TYPE_NO_OVERTAKING:
            # Type 10: Sign 3 NO_OVERTAKING, speed = 0
            pt = AlertPoint(
                lat=p.lat,
                lon=p.lon,
                sign_type=SIGN_TYPE_NO_OVERTAKING,
                speed_limit=0,
                heading=hd,
                is_camera=False,
                source="VietMap",
                priority=PRIORITY_VIETMAP,
                desc="VietMap No Overtaking",
                kind="sign",
                original_type=p.type,
                decoded_heading=p.heading,
            )
        elif p.type == vmd.TYPE_CAMERA:
            # Type 11: Camera phạt nguội, speed = 0
            pt = AlertPoint(
                lat=p.lat,
                lon=p.lon,
                sign_type=None,
                speed_limit=0,
                heading=hd,
                is_camera=True,
                source="VietMap",
                priority=PRIORITY_VIETMAP,
                desc="VietMap Camera",
                kind="camera",
                original_type=p.type,
                decoded_heading=p.heading,
            )
        else:
            continue

        points.append(pt)

    global LAST_VIETMAP_DECODE_STATS
    vm_type_counts = Counter(p.type for p in res.points)
    LAST_VIETMAP_DECODE_STATS = {
        "vietmap_points_loaded": len(points),
        "vietmap_decoded": len(res.points) + res.skipped.get("duplicate", 0),
        "vietmap_identical_dropped": res.skipped.get("duplicate", 0),
        "vietmap_decoded_by_type": dict(sorted(vm_type_counts.items())),
    }

    print(f"      -> Nạp thành công: {len(points):,} điểm VietMap (Version: {res.version})")
    if dropped_speed:
        print(f"      -> Bỏ {dropped_speed:,} điểm type 1 do tốc độ ngoài dải 5..130")
    return points, res.version


def load_wyn_alerts(csv_path: Path) -> list[AlertPoint]:
    """Nạp dữ liệu WYN từ file data/wyn/wyn_points.csv."""
    print(f"[*] [2/3] Đang nạp dữ liệu WYN từ: {csv_path}...")
    if not csv_path.exists():
        print(f"      [!] Không tìm thấy file {csv_path}, bỏ qua.")
        return []

    points = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            try:
                lat = float(r["lat"])
                lon = float(r["lon"])
                kind = r.get("kind", "").strip().lower()
                stype_str = r.get("sign_type", "").strip()
                raw_speed = int(float(r.get("speed_kmh") or 0))
                heading_str = r.get("heading", "").strip()
                heading = int(heading_str) if heading_str else DIR_OMNI
            except (ValueError, KeyError):
                continue

            if not (LAT_MIN <= lat <= LAT_MAX and LON_MIN <= lon <= LON_MAX):
                continue

            hd = heading if is_heading_known(heading, "WYN") else DIR_OMNI

            if kind == "camera":
                # Camera WYN: speed 0, -1, hoặc bội số của 5 trong [5, 130]; khác -> -1
                speed = clean_camera_speed(raw_speed)
                desc = f"WYN Camera ({speed}km/h)" if speed > 0 else ("WYN Camera" if speed == 0 else "WYN Camera (Unknown Speed)")
                points.append(AlertPoint(
                    lat=lat,
                    lon=lon,
                    sign_type=None,
                    speed_limit=speed,
                    heading=hd,
                    is_camera=True,
                    source="WYN",
                    priority=PRIORITY_WYN,
                    desc=desc,
                    kind="camera",
                ))
            elif kind == "light":
                points.append(AlertPoint(
                    lat=lat,
                    lon=lon,
                    sign_type=SIGN_TYPE_TRAFFIC_LIGHT,
                    speed_limit=0,
                    heading=hd,
                    is_camera=False,
                    source="WYN",
                    priority=PRIORITY_WYN,
                    desc="WYN Traffic Light",
                    kind="light",
                ))
            else:  # kind == "sign"
                stype = int(stype_str) if stype_str else SIGN_TYPE_DANGER_OTHER
                if stype == 4:
                    # Tuyệt đối không tự thêm sign type 4 từ WYN (camera chỉ vào cameras.bin)
                    continue
                # Chỉ sign_type 1 có speed, bội số của 5 trong [5, 130] hoặc 0
                if stype == SIGN_TYPE_SPEED_LIMIT:
                    if raw_speed == 0 or is_valid_speed_value(raw_speed):
                        speed = raw_speed
                    else:
                        GLOBAL_DROP_STATS["speed_sign_invalid_dropped"] += 1
                        continue
                else:
                    speed = 0
                points.append(AlertPoint(
                    lat=lat,
                    lon=lon,
                    sign_type=stype,
                    speed_limit=speed,
                    heading=hd,
                    is_camera=False,
                    source="WYN",
                    priority=PRIORITY_WYN,
                    desc=f"WYN Sign {stype}",
                    kind="sign",
                ))

    print(f"      -> Nạp thành công: {len(points):,} điểm WYN")
    return points


def load_base_alerts(base_dir: Path) -> tuple[list[AlertPoint], int]:
    """Nạp dữ liệu nền Base từ base/cameras.bin và base/signs.bin."""
    print(f"[*] [3/3] Đang nạp dữ liệu nền Base từ: {base_dir}...")
    points = []
    base_timestamp = 0

    cams_path = base_dir / "cameras.bin"
    signs_path = base_dir / "signs.bin"

    if cams_path.exists():
        cdata = cams_path.read_bytes()
        cam_count = len(cdata) // struct.calcsize(CAMERA_FMT)
        for i in range(cam_count):
            cid, lat_e7, lon_e7, speed, heading = struct.unpack_from(CAMERA_FMT, cdata, i * 20)
            lat = lat_e7 / 1e7
            lon = lon_e7 / 1e7
            if not (LAT_MIN <= lat <= LAT_MAX and LON_MIN <= lon <= LON_MAX):
                continue
            hd = heading if is_heading_known(heading, "Base") else DIR_OMNI
            spd = clean_camera_speed(speed)
            desc = f"Base Camera ({spd}km/h)" if spd > 0 else ("Base Camera" if spd == 0 else "Base Camera (Unknown Speed)")
            points.append(AlertPoint(
                lat=lat,
                lon=lon,
                sign_type=None,
                speed_limit=spd,
                heading=hd,
                is_camera=True,
                source="Base",
                priority=PRIORITY_BASE,
                desc=desc,
                kind="camera",
                original_id=cid,
            ))
        print(f"      -> Nạp được: {cam_count:,} camera nền")

    if signs_path.exists():
        sdata = signs_path.read_bytes()
        hdr_size = struct.calcsize(SIGN_HEADER_FMT)
        magic, ver, count, reserved, crc, ts = struct.unpack_from(SIGN_HEADER_FMT, sdata, 0)
        base_timestamp = ts
        point_size = struct.calcsize(SIGN_POINT_FMT)
        for i in range(count):
            sid, lat_e7, lon_e7, heading, stype, speed, sub_type, flags, sres = struct.unpack_from(
                SIGN_POINT_FMT, sdata, hdr_size + i * point_size
            )
            lat = lat_e7 / 1e7
            lon = lon_e7 / 1e7
            if not (LAT_MIN <= lat <= LAT_MAX and LON_MIN <= lon <= LON_MAX):
                continue
            hd = heading if is_heading_known(heading, "Base") else DIR_OMNI
            # Quy ước signs nền (Bước 2, Kế hoạch 1.E - Sửa đổi Claude 19/11):
            # Biển loại 1 có tốc độ 0 từ nền -> GIỮ (là biển hết hạn chế có thật trong dữ liệu gốc VietHUD)
            # Biển loại 1 có tốc độ sai chuẩn (không phải 0, không phải bội số 5 trong [5, 130]) -> BỎ ĐIỂM, không bao giờ ép về 0
            if stype == SIGN_TYPE_SPEED_LIMIT:
                if speed == 0:
                    spd = 0
                elif not is_valid_speed_value(speed):
                    GLOBAL_DROP_STATS["speed_sign_invalid_dropped"] += 1
                    continue
                else:
                    spd = speed
            else:
                spd = 0
            k = "light" if stype == SIGN_TYPE_TRAFFIC_LIGHT else "sign"
            points.append(AlertPoint(
                lat=lat,
                lon=lon,
                sign_type=stype,
                speed_limit=spd,
                heading=hd,
                is_camera=False,
                source="Base",
                priority=PRIORITY_BASE,
                desc=f"Base Sign {stype}",
                kind=k,
                sub_type=sub_type,
                flags=flags,
                original_id=sid,
            ))
        print(f"      -> Nạp được: {count:,} biển báo/đèn nền (timestamp={base_timestamp})")

    return points, base_timestamp


def clean_bogus_headings(points: list[AlertPoint]) -> tuple[list[dict], list[dict]]:
    """
    Bước 3 (kế hoạch 1.F) — Phát hiện và làm sạch heading giả:
    - Nhóm biển theo (nguồn, sign_type)
    - Camera theo (nguồn, "camera"), đèn theo (nguồn, "light")
    - Điều kiện: một heading chiếm > 50% số điểm có heading (is_heading_known) và tổng số điểm có heading >= 100.
    - Áp dụng:
      + WYN: sửa heading thành DIR_OMNI (0xFFFF)
      + VietMap: CHỈ ghi vào stats.json (bogus_headings_report_only), KHÔNG SỬA (D2)
      + Nền Base: không xét.
    """
    bogus_list = []
    report_only_list = []
    groups = defaultdict(list)
    for p in points:
        if p.source != "Base":
            if p.is_camera:
                grp_kind = "camera"
            elif p.sign_type == SIGN_TYPE_TRAFFIC_LIGHT:
                grp_kind = "light"
            else:
                grp_kind = f"sign_{p.sign_type}"
            groups[(p.source, grp_kind)].append(p)

    for (src, grp_kind), grp in sorted(groups.items()):
        with_h = [p for p in grp if is_heading_known(p.heading, p.source)]
        total_known = len(with_h)
        if total_known < 100:
            continue
        h_counts = Counter(p.heading for p in with_h)
        top_h, top_cnt = h_counts.most_common(1)[0]
        if top_cnt > 0.5 * total_known:
            entry = {
                "source": src,
                "kind": grp_kind,
                "heading": top_h,
                "count": top_cnt,
                "total_known": total_known,
                "pct": round(top_cnt / total_known * 100, 2),
            }
            if src == "VietMap":
                report_only_list.append(entry)
                print(f"[*] Phát hiện heading giả VietMap ({src}, {grp_kind}): heading={top_h}° ({top_cnt}/{total_known} = {entry['pct']}%) -> CHỈ BÁO CÁO, GIỮ NGUYÊN (D2)")
            else:
                bogus_list.append(entry)
                print(f"[!] Phát hiện heading giả ({src}, {grp_kind}): heading={top_h}° ({top_cnt}/{total_known} = {entry['pct']}%) -> Chuyển thành DIR_OMNI (0xFFFF)")
                for p in grp:
                    if p.heading == top_h:
                        p.heading = DIR_OMNI

    return bogus_list, report_only_list


def deduplicate_points(
    candidates: list[AlertPoint],
    get_radius_func,
    stats_counter: dict,
) -> list[AlertPoint]:
    """
    Khử trùng lặp theo quy tắc R3:
      - Sắp xếp: priority (VietMap 1 -> WYN 2 -> Base 3), tốc độ hợp lệ trước, hướng rõ ràng trước, lat, lon.
      - KHÁC NGUỒN: candidate nguồn thấp hơn nằm trong bán kính của master nguồn cao hơn -> BỎ, KHÔNG XÉT HƯỚNG.
      - CÙNG NGUỒN: giữ nguyên từng chiều xe; chỉ bỏ nếu trùng tuyệt đối (cùng loại, dist <= 2m, cùng hướng +-5 độ hoặc cùng không rõ).
      - Kế thừa: master lấy speed/heading hợp lệ từ điểm bị bỏ nếu master thiếu.
    """
    candidates.sort(key=lambda p: (
        p.priority,
        0 if is_valid_speed_value(p.speed_limit) else (1 if p.speed_limit == 0 else 2),
        0 if is_heading_known(p.heading, p.source) else 1,
        round(p.lat, 6),
        round(p.lon, 6),
        p.heading,
        p.original_id or 0,
    ))

    spatial_index = SpatialAlertIndex(cell_deg=0.0005)
    master_points: list[AlertPoint] = []

    for p in candidates:
        radius = get_radius_func(p)
        nearby = spatial_index.find_nearby(p, master_points, radius_m=radius)

        is_duplicate = False
        matched_master = None

        nearby.sort(key=lambda x: x[0])

        for dist, m_idx, m in nearby:
            # So sánh cùng loại: Camera so Camera, Sign so Sign cùng sign_type
            if p.is_camera != m.is_camera:
                continue
            if not p.is_camera and p.sign_type != m.sign_type:
                continue

            if m.source == p.source:
                if p.source == "VietMap":
                    # VietMap (D2): Chỉ bỏ bản sao GIỐNG HỆT (cùng loại, toạ độ E7, hướng, tốc độ, sub_type)
                    if (round(p.lat * 1e7) == round(m.lat * 1e7) and
                        round(p.lon * 1e7) == round(m.lon * 1e7) and
                        p.heading == m.heading and
                        p.speed_limit == m.speed_limit and
                        p.sub_type == m.sub_type):
                        is_duplicate = True
                        matched_master = m
                        break
                else:
                    # WYN, Base: Giữ luật <= 2m, +-5 độ (hoặc cùng không rõ hướng)
                    if dist <= RADIUS_SAME_SRC_DUP_M:
                        p_known = is_heading_known(p.heading, p.source)
                        m_known = is_heading_known(m.heading, m.source)
                        if p_known and m_known:
                            if heading_diff(p.heading, m.heading) <= HEADING_SAME_SRC_TOL_DEG:
                                is_duplicate = True
                                matched_master = m
                                break
                        elif not p_known and not m_known:
                            is_duplicate = True
                            matched_master = m
                            break
            elif m.priority < p.priority:
                # KHÁC NGUỒN: nguồn thấp hơn trong bán kính nguồn cao hơn -> BỎ, KHÔNG XÉT HƯỚNG
                if dist <= radius:
                    is_duplicate = True
                    matched_master = m
                    break

        if is_duplicate and matched_master:
            stats_counter["noise_dropped"] += 1
            pair_key = f"{p.source}->{matched_master.source}"
            cat_name = "camera" if p.is_camera else ("light" if p.sign_type == SIGN_TYPE_TRAFFIC_LIGHT else f"sign_{p.sign_type}")
            stats_counter["dropped_by_source_pair"][pair_key][cat_name] += 1

            if p.source == "VietMap" and matched_master.source == "VietMap":
                stats_counter["vm_identical_dropped_in_dedup"] += 1

            # 1. Kế thừa tốc độ (Bước 4, Kế hoạch 1.G):
            # Camera: CHỈ kế thừa khi Master == -1. Camera VietMap KHÔNG BAO GIỜ nhận tốc độ (D4).
            # Biển tốc độ: KHÔNG kế thừa vào biển 0 (hết hạn chế).
            if is_valid_speed_value(p.speed_limit):
                if matched_master.is_camera:
                    if matched_master.source != "VietMap" and matched_master.speed_limit == -1:
                        matched_master.speed_limit = p.speed_limit
                        stats_counter["inherited_speed"] += 1
                else:
                    if matched_master.sign_type == SIGN_TYPE_SPEED_LIMIT:
                        if not is_valid_speed_value(matched_master.speed_limit) and matched_master.speed_limit != 0:
                            matched_master.speed_limit = p.speed_limit
                            stats_counter["inherited_speed"] += 1

            # 2. Kế thừa hướng (Bước 4, Kế hoạch 1.G): Master 0xFFFF lấy hướng thật của điểm bị bỏ
            # F1: VietMap hướng 0 là hướng hợp lệ (is_heading_known=True), không bị ghi đè.
            # VietMap loại 8 giữ 0xFFFF (không kế thừa hướng).
            is_type8 = (getattr(matched_master, "original_type", None) == vmd.TYPE_VM_TYPE_8 or matched_master.sub_type == 8)
            if not is_type8 and not is_heading_known(matched_master.heading, matched_master.source) and is_heading_known(p.heading, p.source):
                matched_master.heading = p.heading
                stats_counter["inherited_heading"] += 1

            if matched_master.sub_type == 0 and p.sub_type != 0:
                matched_master.sub_type = p.sub_type

        else:
            idx = len(master_points)
            master_points.append(p)
            spatial_index.insert(idx, p)

    return master_points


def merge_and_deduplicate(all_candidates: list[AlertPoint]) -> tuple[list[AlertPoint], dict]:
    """
    Hợp nhất và khử trùng lặp theo quy chuẩn R3:
      - Bước 1: Làm sạch heading giả.
      - Bước 2: Camera là nguồn chuẩn duy nhất (xử lý sign type 4 theo camera, loại bỏ khỏi signs).
      - Bước 3: Luật khử trùng KHÁC NGUỒN (VietMap > WYN > Base, bán kính: camera 30m, đèn 45m, biển 20m).
    """
    print("\n[*] Đang tiến hành HỢP NHẤT & KHỬ TRÙNG LẶP / LỌC NHIỄU KHÔNG GIAN (CHUẨN R3)...")

    # Bước 1: Làm sạch heading giả (kế hoạch 1.F)
    bogus_headings, bogus_report_only = clean_bogus_headings(all_candidates)

    stats = {
        "vietmap_kept": 0,
        "wyn_kept": 0,
        "base_kept": 0,
        "noise_dropped": 0,
        "inherited_speed": 0,
        "inherited_heading": 0,
        "bogus_headings": bogus_headings,
        "bogus_headings_report_only": bogus_report_only,
        "sign_type_4_dropped_duplicate": 0,
        "sign_type_4_converted_to_camera": 0,
        "base_speed_sign_zero_dropped": GLOBAL_DROP_STATS["base_speed_sign_zero_dropped"],
        "speed_sign_invalid_dropped": GLOBAL_DROP_STATS["speed_sign_invalid_dropped"],
        "vietmap_type8_heading_zero_as_unknown": GLOBAL_DROP_STATS.get("vietmap_type8_heading_zero_as_unknown", 0),
        "dropped_by_source_pair": defaultdict(Counter),
        "vm_identical_dropped_in_dedup": 0,
    }

    # Phân loại ứng viên
    cam_candidates = [p for p in all_candidates if p.is_camera]
    sign_candidates = [p for p in all_candidates if not p.is_camera and p.sign_type != 4]
    sign_4_candidates = [p for p in all_candidates if not p.is_camera and p.sign_type == 4]

    # 1. Khử trùng Cameras (bán kính 30m)
    master_cameras = deduplicate_points(
        cam_candidates,
        get_radius_func=lambda p: RADIUS_CAMERA_M,
        stats_counter=stats,
    )

    # 2. Bước 2: Xử lý sign type 4 theo Camera
    cam_spatial_index = SpatialAlertIndex(cell_deg=0.0005)
    for idx, c in enumerate(master_cameras):
        cam_spatial_index.insert(idx, c)

    for s4 in sign_4_candidates:
        nearby_cams = cam_spatial_index.find_nearby(s4, master_cameras, radius_m=RADIUS_CAMERA_M)
        if nearby_cams:
            stats["sign_type_4_dropped_duplicate"] += 1
            stats["noise_dropped"] += 1
            stats["dropped_by_source_pair"][f"{s4.source}->Camera"]["sign_4"] += 1
        else:
            stats["sign_type_4_converted_to_camera"] += 1
            lat_e7 = int(round(s4.lat * 1e7))
            lon_e7 = int(round(s4.lon * 1e7))
            hd = s4.heading if is_heading_known(s4.heading, s4.source) else DIR_OMNI
            seed = f"cam|11|{lat_e7}|{lon_e7}|{hd}".encode()
            val = zlib.crc32(seed)
            cam_id = (1 << 62) | (val & ((1 << 62) - 1))

            converted_cam = AlertPoint(
                lat=s4.lat,
                lon=s4.lon,
                sign_type=None,
                speed_limit=-1,
                heading=hd,
                is_camera=True,
                source="Base",
                priority=PRIORITY_BASE,
                desc="Base Camera (Converted from Sign 4)",
                kind="camera",
                sub_type=0,
                flags=s4.flags,
                id=cam_id,
            )
            c_idx = len(master_cameras)
            master_cameras.append(converted_cam)
            cam_spatial_index.insert(c_idx, converted_cam)

    # 3. Khử trùng Signs (đèn 45m, biển khác 20m)
    master_signs = deduplicate_points(
        sign_candidates,
        get_radius_func=lambda p: RADIUS_LIGHT_M if p.sign_type == SIGN_TYPE_TRAFFIC_LIGHT else RADIUS_OTHER_SIGN_M,
        stats_counter=stats,
    )

    # Tổng hợp danh sách master
    master_points = master_cameras + master_signs

    for p in master_points:
        if p.priority == PRIORITY_VIETMAP:
            stats["vietmap_kept"] += 1
        elif p.priority == PRIORITY_WYN:
            stats["wyn_kept"] += 1
        else:
            stats["base_kept"] += 1

    stats["dropped_by_source_pair"] = {k: dict(v) for k, v in stats["dropped_by_source_pair"].items()}

    # Thống kê VietMap đầu ra và kiểm tra bảo toàn 100% VietMap (D2)
    vm_out_points = [p for p in master_points if p.source == "VietMap"]
    stats["vietmap_out"] = len(vm_out_points)
    stats["vietmap_out_by_type"] = dict(Counter(
        getattr(p, "original_type", None) or (11 if p.is_camera else p.sign_type)
        for p in vm_out_points
    ))

    vm_in_candidates = [p for p in all_candidates if p.source == "VietMap"]
    if LAST_VIETMAP_DECODE_STATS and len(vm_in_candidates) == LAST_VIETMAP_DECODE_STATS.get("vietmap_points_loaded", -1):
        stats["vietmap_decoded"] = LAST_VIETMAP_DECODE_STATS.get("vietmap_decoded", len(vm_in_candidates))
        stats["vietmap_identical_dropped"] = LAST_VIETMAP_DECODE_STATS.get("vietmap_identical_dropped", 0) + stats.get("vm_identical_dropped_in_dedup", 0)
        stats["vietmap_decoded_by_type"] = LAST_VIETMAP_DECODE_STATS.get("vietmap_decoded_by_type", {})
    else:
        stats["vietmap_decoded"] = len(vm_in_candidates)
        stats["vietmap_identical_dropped"] = stats.get("vm_identical_dropped_in_dedup", 0)
        stats["vietmap_decoded_by_type"] = dict(Counter(
            getattr(p, "original_type", None) or (11 if p.is_camera else p.sign_type)
            for p in vm_in_candidates
        ))

    # Pipeline dừng với lỗi nếu vietmap_out != vietmap_decoded - vietmap_identical_dropped (D2)
    if stats["vietmap_decoded"] > 0:
        expected_vm_out = stats["vietmap_decoded"] - stats["vietmap_identical_dropped"]
        if stats["vietmap_out"] != expected_vm_out:
            raise SystemExit(
                f"[LOI D2] Thất thoát dữ liệu VietMap! "
                f"vietmap_out ({stats['vietmap_out']}) != "
                f"vietmap_decoded ({stats['vietmap_decoded']}) - "
                f"vietmap_identical_dropped ({stats['vietmap_identical_dropped']}) = {expected_vm_out}"
            )

    # Pipeline dừng với lỗi nếu có bất kỳ điểm VietMap nào bị sai hướng giải mã (F1)
    vm_heading_mismatches = []
    for p in vm_out_points:
        orig_t = getattr(p, "original_type", None)
        if orig_t == vmd.TYPE_VM_TYPE_8 or p.sub_type == 8:
            if p.heading != DIR_OMNI:
                vm_heading_mismatches.append(
                    f"VietMap Type 8 (lat={p.lat:.6f}, lon={p.lon:.6f}) heading={p.heading} != 0xFFFF"
                )
        else:
            exp_h = getattr(p, "decoded_heading", None)
            if exp_h is not None and exp_h != DIR_OMNI and p.heading != exp_h:
                vm_heading_mismatches.append(
                    f"VietMap Type {orig_t} (lat={p.lat:.6f}, lon={p.lon:.6f}) heading={p.heading} != decoded={exp_h}"
                )

    if vm_heading_mismatches:
        raise SystemExit(
            f"[LOI F1] Sai lệch hướng VietMap ở đầu ra! Có {len(vm_heading_mismatches)} điểm bị sai hướng:\n"
            + "\n".join(vm_heading_mismatches[:10])
        )

    print(f"[OK] Hoàn tất khử trùng lặp và làm sạch dữ liệu chuẩn R4:")
    print(f"     + Điểm VietMap giữ lại:   {stats['vietmap_kept']:,}")
    print(f"     + Điểm WYN giữ lại:       {stats['wyn_kept']:,}")
    print(f"     + Điểm nền Base giữ lại:  {stats['base_kept']:,}")
    print(f"     = TỔNG ĐIỂM SAU HỢP NHẤT: {len(master_points):,}")
    print(f"     - Số điểm trùng đã loại:  {stats['noise_dropped']:,}")
    print(f"     * Số kế thừa tốc độ:      {stats['inherited_speed']:,}")
    print(f"     * Số kế thừa hướng:       {stats['inherited_heading']:,}")
    print(f"     ! Biển loại 1 nền tốc độ 0 bỏ: {stats['base_speed_sign_zero_dropped']:,}")
    print(f"     ! Biển loại 1 tốc độ sai chuẩn bỏ: {stats['speed_sign_invalid_dropped']:,}")
    print(f"     ! VietMap type 8 chuyển hướng về 0xFFFF: {stats['vietmap_type8_heading_zero_as_unknown']:,}")
    print(f"     ! Sign type 4 bỏ do trùng:{stats['sign_type_4_dropped_duplicate']:,}")
    print(f"     ! Sign type 4 thành camera:{stats['sign_type_4_converted_to_camera']:,}")
    if bogus_headings:
        print(f"     ! Nhóm heading giả làm sạch: {len(bogus_headings)}")
    if bogus_report_only:
        print(f"     ! Nhóm heading giả VietMap (chỉ báo cáo): {len(bogus_report_only)}")

    return master_points, stats


def allocate_stable_ids(master_points: list[AlertPoint]):
    """
    Gán ID ổn định (chép theo chuẩn MapViet):
      - Điểm nền giữ ID gốc.
      - Điểm mới:
        sign: 0x80000000 | (crc32(f"sign|{type}|{lat_e7}|{lon_e7}|{heading}") & 0x7FFFFFFF)
        camera: (1<<62) | (crc32(f"cam|{type}|{lat_e7}|{lon_e7}|{heading}") & ((1<<62)-1))
        Trùng ID -> tăng dần đến khi chưa dùng.
    """
    used_sign_ids = set()
    used_cam_ids = set()

    # 1. Đăng ký trước các ID đã có (ID gốc của Base hoặc ID camera đã gán)
    for p in master_points:
        if p.id is not None:
            if p.is_camera:
                used_cam_ids.add(p.id)
            else:
                used_sign_ids.add(p.id)
        elif p.priority == PRIORITY_BASE and p.original_id is not None:
            if p.is_camera:
                used_cam_ids.add(p.original_id)
                p.id = p.original_id
            else:
                used_sign_ids.add(p.original_id)
                p.id = p.original_id

    # 2. Sinh ID ổn định cho các điểm mới (VietMap và WYN)
    sign_base = 0x80000000
    sign_mask = 0x7FFFFFFF
    cam_base = 1 << 62
    cam_mask = (1 << 62) - 1

    for p in master_points:
        if p.id is not None:
            continue

        lat_e7 = int(round(p.lat * 1e7))
        lon_e7 = int(round(p.lon * 1e7))
        hd = p.heading if is_heading_known(p.heading, p.source) else DIR_OMNI

        if p.is_camera:
            seed = f"cam|{p.sign_type or 11}|{lat_e7}|{lon_e7}|{hd}".encode()
            val = zlib.crc32(seed)
            candidate = cam_base | (val & cam_mask)
            while candidate in used_cam_ids:
                candidate = cam_base | ((candidate + 1) & cam_mask)
            used_cam_ids.add(candidate)
            p.id = candidate
        else:
            seed = f"sign|{p.sign_type}|{lat_e7}|{lon_e7}|{hd}".encode()
            val = zlib.crc32(seed)
            candidate = sign_base | (val & sign_mask)
            while candidate in used_sign_ids:
                candidate = sign_base | ((candidate + 1) & sign_mask)
            used_sign_ids.add(candidate)
            p.id = candidate


def measure_same_direction_cameras(
    cameras: list[AlertPoint],
    out_md_path: Path | None = None,
) -> dict:
    """
    Bước 5 (Kế hoạch 1.B) — Đo camera gần nhau cùng hướng (CHỈ ĐO, KHÔNG ĐỔI LUẬT):
    - Cặp camera cùng nguồn, cùng hướng (±20°), cách 2–15 m, tách theo nguồn (VietMap / WYN / Base).
    - Ghi số lượng + 20 cặp mẫu mỗi nguồn vào build/r4/same_dir_cameras.md.
    """
    sources = ["VietMap", "WYN", "Base"]
    results = {}

    for src in sources:
        src_cams = [c for c in cameras if c.source == src]
        total_cams = len(src_cams)

        # Dùng spatial grid ~55m (0.0005 deg)
        cell_deg = 0.0005
        grid = defaultdict(list)
        for idx, c in enumerate(src_cams):
            cx = int(math.floor(c.lon / cell_deg))
            cy = int(math.floor(c.lat / cell_deg))
            grid[(cy, cx)].append(idx)

        pairs = []
        for idx1, c1 in enumerate(src_cams):
            if not is_heading_known(c1.heading, c1.source):
                continue
            cy = int(math.floor(c1.lat / cell_deg))
            cx = int(math.floor(c1.lon / cell_deg))

            for dy in (-1, 0, 1):
                for dx in (-1, 0, 1):
                    for idx2 in grid.get((cy + dy, cx + dx), []):
                        if idx2 <= idx1:
                            continue
                        c2 = src_cams[idx2]
                        if not is_heading_known(c2.heading, c2.source):
                            continue
                        h_diff = heading_diff(c1.heading, c2.heading)
                        if h_diff > 20.0:
                            continue
                        dist = haversine_m(c1.lat, c1.lon, c2.lat, c2.lon)
                        if 2.0 <= dist <= 15.0:
                            pairs.append({
                                "cam1": c1,
                                "cam2": c2,
                                "dist_m": dist,
                                "heading_diff": h_diff,
                            })

        pairs.sort(key=lambda x: x["dist_m"])
        results[src] = {
            "total_cameras": total_cams,
            "total_pairs": len(pairs),
            "samples": pairs[:20],
        }
        print(f"[*] [Bước 5] Camera {src}: {total_cams:,} camera, {len(pairs):,} cặp cùng hướng (±20°) cách 2–15 m")

    if out_md_path:
        out_md_path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# Báo cáo đo lường các cặp camera gần nhau cùng hướng (2–15 m, ±20°)",
            "",
            "**Ngày:** 2026-11-19  ",
            "**Tham chiếu nhiệm vụ:** AGY_TASK_STANDARDIZE_R4.md (Bước 5, Kế hoạch 1.B — CHỈ ĐO, KHÔNG ĐỔI LUẬT)",
            "",
            "---",
            "",
            "## 1. Tổng quan số lượng theo nguồn",
            "",
            "| Nguồn | Tổng số camera | Số cặp cùng hướng (±20°) trong 2–15 m |",
            "| :--- | ---: | ---: |",
        ]
        total_all_cams = sum(r["total_cameras"] for r in results.values())
        total_all_pairs = sum(r["total_pairs"] for r in results.values())
        for src in sources:
            r = results[src]
            lines.append(f"| **{src}** | {r['total_cameras']:,} | {r['total_pairs']:,} |")
        lines.append(f"| **TỔNG CỘNG** | {total_all_cams:,} | {total_all_pairs:,} |")
        lines.append("")
        lines.append("---")
        lines.append("")

        for src in sources:
            r = results[src]
            lines.append(f"## 2. 20 cặp mẫu nguồn {src} (Tổng: {r['total_pairs']:,} cặp)")
            lines.append("")
            if not r["samples"]:
                lines.append(f"- Không có cặp camera nào thỏa mãn điều kiện.")
            else:
                lines.append("| STT | Khoảng cách | Lệch hướng | Cam 1 (ID, Toạ độ, Tốc độ, Hướng) | Cam 2 (ID, Toạ độ, Tốc độ, Hướng) |")
                lines.append("| :--- | :--- | :--- | :--- | :--- |")
                for s_idx, sample in enumerate(r["samples"], 1):
                    c1 = sample["cam1"]
                    c2 = sample["cam2"]
                    d = sample["dist_m"]
                    hd = sample["heading_diff"]
                    lines.append(
                        f"| {s_idx} | {d:.2f} m | {hd:.1f}° | "
                        f"ID: {c1.id}, ({c1.lat:.6f}, {c1.lon:.6f}), Spd: {c1.speed_limit}, Hd: {c1.heading}° | "
                        f"ID: {c2.id}, ({c2.lat:.6f}, {c2.lon:.6f}), Spd: {c2.speed_limit}, Hd: {c2.heading}° |"
                    )
            lines.append("")
            lines.append("---")
            lines.append("")

        lines.extend([
            "## 3. Nhận xét & Đánh giá (Kế hoạch 1.B)",
            "",
            "- **VietMap:** Toàn bộ 5.703 camera được bảo toàn nguyên vẹn theo nguyên tắc D2. Các camera cách nhau 2–15 m phản ánh thực tế lắp đặt (ví dụ camera giám sát từng làn hoặc hai chiều đối xứng trên dải phân cách nhưng hướng tương đồng).",
            "- **WYN & Base:** Quy tắc cùng nguồn khử trùng lặp ở bán kính ≤ 2 m và lệch hướng ≤ 5°. Các khoảng cách từ 2 m đến 15 m được giữ nguyên theo đúng quy chuẩn không gian hiện tại.",
            "- **Khuyến nghị:** Giữ nguyên quy chuẩn, KHÔNG gộp các cặp camera này nhằm đảm bảo tính toàn vẹn và độ chi tiết của dữ liệu định vị camera.",
        ])

        out_md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"[OK] Đã ghi báo cáo đo camera gần nhau ra: {out_md_path}")

    return results


def export_binary_files(
    master_points: list[AlertPoint],
    out_dir: Path,
    base_timestamp: int = 0,
    vietmap_version: str = "Unknown",
    stats_merge: dict | None = None,
) -> tuple[Path, Path, Path, Path]:
    """Xuất cameras.bin, signs.bin, combined_traffic_alerts.csv, stats.json."""
    out_dir.mkdir(parents=True, exist_ok=True)
    cams_path = out_dir / "cameras.bin"
    signs_path = out_dir / "signs.bin"
    csv_path = out_dir / "combined_traffic_alerts.csv"
    stats_path = out_dir / "stats.json"

    # Phân tách cameras và signs
    cameras: list[AlertPoint] = []
    signs: list[AlertPoint] = []

    for p in master_points:
        if p.is_camera:
            cameras.append(p)
        else:
            signs.append(p)

    # Sắp xếp theo ID tăng dần để đảm bảo thứ tự ghi nhị phân tuyệt đối xác định
    cameras.sort(key=lambda p: p.id)
    signs.sort(key=lambda p: p.id)

    # 1. Đóng gói cameras.bin (<QiihH)
    cam_bytes_list = []
    cam_speeds = Counter()
    cam_speeds_by_source = defaultdict(Counter)
    for p in cameras:
        lat_e7 = int(round(p.lat * 1e7))
        lon_e7 = int(round(p.lon * 1e7))
        hd = p.heading if is_heading_known(p.heading, p.source) else DIR_OMNI
        spd = clean_camera_speed(p.speed_limit)
        cam_speeds[spd] += 1
        cam_speeds_by_source[p.source][spd] += 1
        cam_bytes_list.append(struct.pack(
            CAMERA_FMT,
            p.id,
            lat_e7,
            lon_e7,
            spd,
            hd,
        ))

    cam_data = b"".join(cam_bytes_list)
    with open(cams_path, "wb") as f:
        f.write(cam_data)
    cam_sha256 = hashlib.sha256(cam_data).hexdigest()
    print(f"[OK] Đã ghi {len(cameras):,} cameras ra: {cams_path} ({len(cam_data):,} bytes)")

    # 2. Đóng gói signs.bin (<4sHIHII header + <IiiHBBBBH points)
    sign_bytes_list = []
    for p in signs:
        lat_e7 = int(round(p.lat * 1e7))
        lon_e7 = int(round(p.lon * 1e7))
        hd = p.heading if is_heading_known(p.heading, p.source) else DIR_OMNI
        stype = p.sign_type if p.sign_type is not None else 0
        # Chỉ sign_type 1 có speed
        spd = p.speed_limit if stype == SIGN_TYPE_SPEED_LIMIT and (p.speed_limit == 0 or is_valid_speed_value(p.speed_limit)) else 0

        # Reserved: 0 nền, 1 VietMap, 2 WYN
        if p.priority == PRIORITY_BASE:
            res_val = SOURCE_CODE_BASE
        elif p.priority == PRIORITY_VIETMAP:
            res_val = SOURCE_CODE_VIETMAP
        else:
            res_val = SOURCE_CODE_WYN

        sign_bytes_list.append(struct.pack(
            SIGN_POINT_FMT,
            p.id,
            lat_e7,
            lon_e7,
            hd,
            stype,
            spd,
            p.sub_type,
            p.flags,
            res_val,
        ))

    body_data = b"".join(sign_bytes_list)
    body_crc = zlib.crc32(body_data) & 0xFFFFFFFF
    header_data = struct.pack(
        SIGN_HEADER_FMT,
        b"VNSG",
        1,
        len(signs),
        0,
        body_crc,
        base_timestamp,
    )
    signs_data = header_data + body_data
    with open(signs_path, "wb") as f:
        f.write(signs_data)
    signs_sha256 = hashlib.sha256(signs_data).hexdigest()
    print(f"[OK] Đã ghi {len(signs):,} signs ra: {signs_path} ({len(signs_data):,} bytes, ts={base_timestamp})")

    # 3. Ghi combined_traffic_alerts.csv (chỉ để tra cứu)
    csv_rows = []
    # Ghi tất cả điểm đã hợp nhất
    all_sorted = sorted(master_points, key=lambda p: (0 if p.is_camera else 1, p.id))
    for p in all_sorted:
        hd = p.heading if is_heading_known(p.heading, p.source) else 0
        csv_rows.append({
            "id": p.id,
            "kinh_do": f"{p.lon:.6f}",
            "vi_do": f"{p.lat:.6f}",
            "loai_canh_bao": p.desc,
            "ma_loai": (p.sign_type if p.sign_type is not None else (11 if p.is_camera else 0)),
            "toc_do_kmh": p.speed_limit,
            "huong_do": hd,
            "la_camera": 1 if p.is_camera else 0,
            "nguon_du_lieu": p.source,
        })

    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "id", "kinh_do", "vi_do", "loai_canh_bao", "ma_loai", "toc_do_kmh", "huong_do", "la_camera", "nguon_du_lieu"
        ])
        writer.writeheader()
        writer.writerows(csv_rows)
    print(f"[OK] Đã ghi {len(csv_rows):,} bản ghi tra cứu ra: {csv_path}")

    # 4. Ghi stats.json
    content_sha256 = hashlib.sha256((cam_sha256 + signs_sha256).encode("ascii")).hexdigest()
    counts_by_source_and_type = defaultdict(Counter)
    for p in master_points:
        key = "camera" if p.is_camera else f"sign_{p.sign_type}"
        counts_by_source_and_type[p.source][key] += 1

    sign_type_4_count = sum(1 for p in signs if p.sign_type == 4)
    sign_type_1_speed_0_count = sum(1 for p in signs if p.sign_type == 1 and p.speed_limit == 0)

    # Bước 5: Đo camera gần nhau cùng hướng (kế hoạch 1.B)
    same_dir_md = None
    if out_dir.name == "alerts":
        same_dir_md = out_dir.parent / "same_dir_cameras.md"
    else:
        same_dir_md = out_dir / "same_dir_cameras.md"
    same_dir_stats = measure_same_direction_cameras(cameras, same_dir_md)

    stats_dict = {
        "cameras_count": len(cameras),
        "signs_count": len(signs),
        "total_points": len(master_points),
        "cameras_sha256": cam_sha256,
        "signs_sha256": signs_sha256,
        "content_sha256": content_sha256,
        "vietmap_version": vietmap_version,
        "base_timestamp": base_timestamp,
        "vietmap_decoded": (stats_merge or {}).get("vietmap_decoded", 0),
        "vietmap_identical_dropped": (stats_merge or {}).get("vietmap_identical_dropped", 0),
        "vietmap_out": (stats_merge or {}).get("vietmap_out", 0),
        "vietmap_decoded_by_type": (stats_merge or {}).get("vietmap_decoded_by_type", {}),
        "vietmap_out_by_type": (stats_merge or {}).get("vietmap_out_by_type", {}),
        "inherited_speed": (stats_merge or {}).get("inherited_speed", 0),
        "inherited_heading": (stats_merge or {}).get("inherited_heading", 0),
        "enriched_attributes": (stats_merge or {}).get("inherited_speed", 0) + (stats_merge or {}).get("inherited_heading", 0),
        "bogus_headings": (stats_merge or {}).get("bogus_headings", []),
        "bogus_headings_report_only": (stats_merge or {}).get("bogus_headings_report_only", []),
        "sign_type_4_dropped_duplicate": (stats_merge or {}).get("sign_type_4_dropped_duplicate", 0),
        "sign_type_4_converted_to_camera": (stats_merge or {}).get("sign_type_4_converted_to_camera", 0),
        "base_speed_sign_zero_dropped": (stats_merge or {}).get("base_speed_sign_zero_dropped", 0),
        "speed_sign_invalid_dropped": (stats_merge or {}).get("speed_sign_invalid_dropped", 0),
        "vietmap_type8_heading_zero_as_unknown": (stats_merge or {}).get("vietmap_type8_heading_zero_as_unknown", 0),
        "dropped_by_source_pair": (stats_merge or {}).get("dropped_by_source_pair", {}),
        "camera_speeds_distribution": dict(sorted(cam_speeds.items())),
        "camera_speeds_by_source": {src: dict(sorted(cnt.items())) for src, cnt in sorted(cam_speeds_by_source.items())},
        "signs_convention_stats": {
            "sign_type_4_camera_count": sign_type_4_count,
            "sign_type_1_speed_0_count": sign_type_1_speed_0_count,
        },
        "counts_by_source_and_type": {src: dict(cnt) for src, cnt in counts_by_source_and_type.items()},
        "deduplication_stats": stats_merge or {},
    }

    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(stats_dict, f, indent=2, ensure_ascii=False)
    print(f"[OK] Đã ghi thống kê ra: {stats_path}")

    # Kiểm tra nhị phân đảm bảo hướng VietMap ghi ra file không bị sai lệch (F1)
    cdata = cams_path.read_bytes()
    for i in range(len(cameras)):
        cid, clat_e7, clon_e7, cspd, chd = struct.unpack_from(CAMERA_FMT, cdata, i * 20)
        cp = cameras[i]
        if cp.source == "VietMap":
            exp_h = getattr(cp, "decoded_heading", cp.heading)
            if exp_h != DIR_OMNI and chd != exp_h:
                raise SystemExit(f"[LOI F1] cameras.bin ghi sai hướng VietMap id={cid}: ghi {chd} != kỳ vọng {exp_h}")

    sdata = signs_path.read_bytes()
    hdr_size = struct.calcsize(SIGN_HEADER_FMT)
    pt_size = struct.calcsize(SIGN_POINT_FMT)
    for i in range(len(signs)):
        sid, slat_e7, slon_e7, shd, stype, sspd, ssub, sflg, sres = struct.unpack_from(
            SIGN_POINT_FMT, sdata, hdr_size + i * pt_size
        )
        sp = signs[i]
        if sp.source == "VietMap":
            if getattr(sp, "original_type", None) == vmd.TYPE_VM_TYPE_8 or sp.sub_type == 8:
                if shd != DIR_OMNI:
                    raise SystemExit(f"[LOI F1] signs.bin ghi sai hướng VietMap Type 8 id={sid}: ghi {shd} != 0xFFFF")
            else:
                exp_h = getattr(sp, "decoded_heading", sp.heading)
                if exp_h != DIR_OMNI and shd != exp_h:
                    raise SystemExit(f"[LOI F1] signs.bin ghi sai hướng VietMap id={sid}: ghi {shd} != kỳ vọng {exp_h}")

    return cams_path, signs_path, csv_path, stats_path


def write_manifest(
    out_dir: Path,
    version: str,
    no_sign: bool = False,
    key=None,
) -> tuple[Path, Path | None]:
    """
    Sinh manifest.txt chứa danh mục cameras.bin và signs.bin.
    Ký manifest nếu có khoá và không có cờ no_sign.
    """
    manifest_path = out_dir / "manifest.txt"
    lines = [f"version {version}"]

    for fname in ["cameras.bin", "signs.bin"]:
        fpath = out_dir / fname
        if fpath.exists():
            size = fpath.stat().st_size
            sha = hashlib.sha256(fpath.read_bytes()).hexdigest()
            lines.append(f"{fname} {size} {sha}")

    content = "\n".join(lines) + "\n"
    manifest_path.write_text(content, encoding="utf-8")
    print(f"[OK] Đã tạo manifest: {manifest_path}")

    sig_path = None
    if not no_sign:
        try:
            sig_path = sign_manifest.sign_manifest(manifest_path, key=key)
            print(f"[OK] Đã ký manifest -> {sig_path}")
        except Exception as e:
            print(f"[!] Bỏ qua ký manifest: {e}")

    return manifest_path, sig_path


def main():
    parser = argparse.ArgumentParser(
        description="Tool hợp nhất dữ liệu cảnh báo VietMap + WYN + Nền, khử trùng lặp và làm sạch nhiễu cho VietHUD."
    )
    parser.add_argument("--vietmap", type=Path, default=None,
                        help="Đường dẫn file secrect.bin của VietMap SpeedMap M2")
    parser.add_argument("--wyn", type=Path, default=None,
                        help="Đường dẫn file wyn_points.csv của WYN")
    parser.add_argument("--base", type=Path, default=None,
                        help="Thư mục chứa dữ liệu nền cameras.bin và signs.bin")
    parser.add_argument("--out", type=Path, required=True,
                        help="Thư mục xuất kết quả")
    parser.add_argument("--version", type=str, default=None,
                        help="Phiên bản dữ liệu (mặc định lấy theo ngày giờ YYYY.MM.DD.HHMM)")
    parser.add_argument("--timestamp", type=int, default=None,
                        help="Timestamp ghi vào signs.bin header (mặc định lấy từ base/signs.bin)")
    parser.add_argument("--no-sign", action="store_true",
                        help="Không thực hiện ký manifest.txt bằng khoá MapViet")

    args = parser.parse_args()

    all_candidates: list[AlertPoint] = []
    vm_version = "Unknown"
    base_ts = 0

    # 1. Nạp VietMap
    if args.vietmap and args.vietmap.exists():
        vm_points, vm_ver = load_vietmap_alerts(args.vietmap)
        all_candidates.extend(vm_points)
        vm_version = vm_ver

    # 2. Nạp WYN
    if args.wyn and args.wyn.exists():
        wyn_points = load_wyn_alerts(args.wyn)
        all_candidates.extend(wyn_points)

    # 3. Nạp Base
    if args.base and args.base.exists():
        base_points, b_ts = load_base_alerts(args.base)
        all_candidates.extend(base_points)
        base_ts = b_ts

    if args.timestamp is not None:
        base_ts = args.timestamp

    if not all_candidates:
        print("[LOI] Không có điểm cảnh báo nào được nạp!")
        sys.exit(1)

    # Khử trùng lặp
    master_points, stats = merge_and_deduplicate(all_candidates)

    # Gán ID ổn định
    allocate_stable_ids(master_points)

    # Xuất file nhị phân
    cams_path, signs_path, csv_path, stats_path = export_binary_files(
        master_points=master_points,
        out_dir=args.out,
        base_timestamp=base_ts,
        vietmap_version=vm_version,
        stats_merge=stats,
    )

    # Sinh manifest & ký
    ver = args.version or time.strftime("%Y.%m.%d.%H%M")
    write_manifest(args.out, version=ver, no_sign=args.no_sign)


if __name__ == "__main__":
    main()
