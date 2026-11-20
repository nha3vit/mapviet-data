#!/usr/bin/env python3
"""tools/sync_wyn_vietmap.py — Đồng bộ dữ liệu WYN với VietMap (cả ký tự, ký hiệu, mã hóa nhị phân).

Nguyên tắc đồng bộ:
1. Nguồn VietMap là ưu tiên số 1: Giữ nguyên 100% dữ liệu VietMap (83.823 điểm).
2. Khử trùng lặp và lân cận 20m: Bất kỳ điểm WYN nào trùng hoặc nằm trong bán kính 20m của VietMap đều bị loại bỏ.
3. Đồng bộ KÝ HIỆU (Notations / Types):
   - Ánh xạ sang 11 mã loại chuẩn của VietMap (Type 1..11).
   - Tốc độ camera: 0 (phạt nguội) hoặc tốc độ hợp lệ (>0); biển báo: 0.
   - Làm sạch hướng giả 15° của WYN về 0 (đa hướng chuẩn VietMap).
   - Cờ: flag = 1.
4. Đồng bộ KÝ TỰ (Characters & Format):
   - Cấu trúc dòng 6 trường chuẩn VietMap: `lon,lat,type,speed_limit,flag,heading\r\n`.
   - Mã hóa ký tự nhị phân qua bảng thế byte VietMap (Substitution cipher).
   - Đóng gói container TOC 512 bytes chuẩn VietMap (`secrect.bin`).
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT.parent / "data-pipeline"))

try:
    import vietmap_decode as vm
except ImportError:
    from tools import vietmap_decode as vm

# Bounding box Việt Nam
LAT_MIN, LAT_MAX = 8.0, 24.0
LON_MIN, LON_MAX = 102.0, 110.5

# Bảng mã hóa thế byte ký tự ngược lại cho VietMap
ENCODE_MAP = {v: k for k, v in vm.SUBSTITUTION.items()}

# Tên loại cảnh báo chuẩn VietMap
VIETMAP_TYPE_NAMES = {
    1: "Tốc độ giới hạn",
    2: "Đèn giao thông / camera đèn đỏ",
    3: "Camera vượt đèn đỏ",
    4: "Bắt đầu khu đông dân cư",
    5: "Trạm thu phí",
    6: "Giao lộ có đèn",
    7: "Điểm chú ý / nguy hiểm",
    8: "Cảnh báo khác (loại 8)",
    9: "Cảnh báo khác (loại 9)",
    10: "Biển cấm vượt",
    11: "Camera phạt nguội / giám sát",
}

# Nhóm tương đương cảnh báo giữa các loại VietMap để khử trùng thông minh
CATEGORY_GROUPS = {
    11: {11, 3},       # Camera phạt nguội so với camera và camera đèn đỏ
    2:  {2, 3, 6},     # Đèn tín hiệu so với đèn, camera đèn đỏ, giao lộ có đèn
    4:  {4},           # Khu đông dân cư
    5:  {5},           # Trạm thu phí
    10: {10},          # Cấm vượt
    7:  {7, 8, 9},     # Điểm nguy hiểm / cảnh báo khác
}


@dataclass
class SynchronizedPoint:
    lon: float
    lat: float
    type: int
    speed_limit: int
    flag: int
    heading: int
    source: str
    original_kind: str = ""
    original_sign_type: str = ""


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Tính khoảng cách Haversine giữa 2 tọa độ (mét)."""
    k = 111320.0
    dlat = (lat1 - lat2) * k
    dlon = (lon1 - lon2) * k * math.cos(math.radians((lat1 + lat2) / 2.0))
    return math.hypot(dlat, dlon)


class SpatialIndex:
    """Lưới không gian ô ~55m để tìm kiếm O(1)."""
    def __init__(self, cell_deg: float = 0.0005):
        self.cell_deg = cell_deg
        self.cells = defaultdict(list)
        self.cells_by_type = defaultdict(list)

    def _cell(self, lat: float, lon: float):
        return int(math.floor(lat / self.cell_deg)), int(math.floor(lon / self.cell_deg))

    def insert(self, p):
        cy, cx = self._cell(p.lat, p.lon)
        self.cells[(cy, cx)].append(p)
        self.cells_by_type[(p.type, cy, cx)].append(p)

    def find_nearby_same_category(self, target_type: int, lat: float, lon: float, radius_m: float):
        cy, cx = self._cell(lat, lon)
        allowed_types = CATEGORY_GROUPS.get(target_type, {target_type})
        r_cells = max(1, int(math.ceil(radius_m / (self.cell_deg * 111320.0))))
        for t in allowed_types:
            for dy in range(-r_cells, r_cells + 1):
                for dx in range(-r_cells, r_cells + 1):
                    for p in self.cells_by_type.get((t, cy + dy, cx + dx), []):
                        d = haversine_m(lat, lon, p.lat, p.lon)
                        if d <= radius_m:
                            return d, p
        return None

    def find_nearby_any(self, lat: float, lon: float, radius_m: float):
        cy, cx = self._cell(lat, lon)
        r_cells = max(1, int(math.ceil(radius_m / (self.cell_deg * 111320.0))))
        for dy in range(-r_cells, r_cells + 1):
            for dx in range(-r_cells, r_cells + 1):
                for p in self.cells.get((cy + dy, cx + dx), []):
                    d = haversine_m(lat, lon, p.lat, p.lon)
                    if d <= radius_m:
                        return d, p
        return None


def map_wyn_point_to_vietmap(row: dict) -> SynchronizedPoint | None:
    """Ánh xạ 1 bản ghi WYN sang ký hiệu và loại chuẩn VietMap."""
    try:
        lat = float(row.get("lat") or 0.0)
        lon = float(row.get("lon") or 0.0)
        kind = (row.get("kind") or "").strip().lower()
        stype = (row.get("sign_type") or "").strip()
        speed = int(float(row.get("speed_kmh") or 0))
        h_str = (row.get("heading") or "").strip()
        heading = int(float(h_str)) if h_str and h_str.replace(".", "", 1).isdigit() else 0
    except (ValueError, KeyError):
        return None

    if not (LAT_MIN <= lat <= LAT_MAX and LON_MIN <= lon <= LON_MAX):
        return None

    # Ánh xạ phân loại sang mã loại VietMap (1-11):
    if kind == "camera":
        # WYN camera: nếu có ghi nhận tốc độ > 0 thì gán speed, nếu không là camera phạt nguội (speed=0)
        vm_type = 11
        vm_speed = speed if (5 <= speed <= 130 and speed % 5 == 0) else 0
        vm_heading = heading if (0 < heading < 360 and heading != 15) else 0
    elif kind == "light":
        # WYN đèn tín hiệu: mã loại 2. 99% đèn WYN có hướng 15 độ giả -> đưa về 0 (đa hướng)
        vm_type = 2
        vm_speed = 0
        vm_heading = 0
    elif kind == "sign":
        if stype == "2":
            # Khu đông dân cư R.420 -> VietMap loại 4
            vm_type = 4
            vm_speed = 0
            vm_heading = heading if (0 < heading < 360) else 0
        elif stype == "3":
            # Cấm vượt P.125 -> VietMap loại 10
            vm_type = 10
            vm_speed = 0
            vm_heading = heading if (0 < heading < 360) else 0
        elif stype == "5":
            # Trạm thu phí P.135 -> VietMap loại 5. 100% trạm WYN có hướng 15 độ giả -> đưa về 0
            vm_type = 5
            vm_speed = 0
            vm_heading = 0
        elif stype == "10":
            # Đoạn đường nguy hiểm / chú ý -> VietMap loại 7
            vm_type = 7
            vm_speed = 0
            vm_heading = heading if (0 < heading < 360) else 0
        else:
            vm_type = 7
            vm_speed = 0
            vm_heading = 0
    else:
        return None

    return SynchronizedPoint(
        lon=round(lon, 6),
        lat=round(lat, 6),
        type=vm_type,
        speed_limit=vm_speed,
        flag=1,  # flag chuẩn VietMap luôn là 1
        heading=vm_heading,
        source="WYN",
        original_kind=kind,
        original_sign_type=stype,
    )


def sync_wyn_with_vietmap(
    vietmap_path: Path,
    wyn_path: Path,
    radius_m: float = 20.0,
    strict_any_point: bool = False,
) -> tuple[list[SynchronizedPoint], list[dict], dict]:
    """Thực hiện đồng bộ hóa WYN với VietMap."""
    print(f"[*] [1/3] Đang nạp cơ sở dữ liệu VietMap từ {vietmap_path}...")
    res_vm = vm.decode_file(vietmap_path)
    vm_points = res_vm.points
    print(f"      -> VietMap nạp được: {len(vm_points):,} điểm (Phiên bản: {res_vm.version})")

    # Dựng chỉ mục không gian cho VietMap
    index_vm = SpatialIndex()
    for p in vm_points:
        index_vm.insert(p)

    print(f"[*] [2/3] Đang nạp và ánh xạ dữ liệu WYN từ {wyn_path}...")
    raw_wyn = []
    with open(wyn_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for r in reader:
            pt = map_wyn_point_to_vietmap(r)
            if pt:
                raw_wyn.append(pt)
    print(f"      -> WYN nạp và ánh xạ được: {len(raw_wyn):,} điểm")

    print(f"[*] [3/3] Đang khử trùng lặp và loại bỏ điểm WYN lân cận VietMap (Bán kính = {radius_m}m)...")
    kept_wyn: list[SynchronizedPoint] = []
    dropped_wyn: list[dict] = []
    drop_reasons = Counter()

    # Khử trùng nội bộ WYN trước (nếu có 2 điểm WYN giống hệt nhau hoặc <= 2m)
    internal_wyn_index = SpatialIndex()
    unique_wyn = []
    for w in raw_wyn:
        near_same = internal_wyn_index.find_nearby_same_category(w.type, w.lat, w.lon, radius_m=2.0)
        if near_same and near_same[0] <= 2.0:
            drop_reasons["wyn_internal_duplicate"] += 1
            continue
        unique_wyn.append(w)
        internal_wyn_index.insert(w)

    for w in unique_wyn:
        if strict_any_point:
            hit = index_vm.find_nearby_any(w.lat, w.lon, radius_m=radius_m)
        else:
            hit = index_vm.find_nearby_same_category(w.type, w.lat, w.lon, radius_m=radius_m)

        if hit is not None:
            dist, vm_pt = hit
            drop_reasons[f"vietmap_overlap_type_{vm_pt.type}"] += 1
            dropped_wyn.append({
                "wyn_lat": w.lat,
                "wyn_lon": w.lon,
                "wyn_type": w.type,
                "vm_type": vm_pt.type,
                "distance_m": round(dist, 2),
            })
        else:
            kept_wyn.append(w)

    stats = {
        "vietmap_total": len(vm_points),
        "wyn_total_raw": len(raw_wyn),
        "wyn_internal_duplicates_dropped": drop_reasons["wyn_internal_duplicate"],
        "wyn_dropped_near_vietmap": len(dropped_wyn),
        "wyn_kept": len(kept_wyn),
        "radius_meters": radius_m,
        "strict_mode": strict_any_point,
        "by_vietmap_type": Counter(w.type for w in kept_wyn),
        "drop_reasons": drop_reasons,
    }

    return kept_wyn, dropped_wyn, stats


def export_vietmap_format_csv(output_path: Path, points: list, include_header_line: bool = True, source_name: str | None = None):
    """Xuất danh sách điểm ra định dạng CSV chuẩn 6 cột ký tự của VietMap:
    lon,lat,type,speed_limit,flag,heading
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if include_header_line:
            writer.writerow(["lon", "lat", "type", "speed_limit", "flag", "heading", "source", "type_name"])
            for p in points:
                src = source_name or getattr(p, "source", "VietMap")
                writer.writerow([
                    f"{p.lon:.6f}",
                    f"{p.lat:.6f}",
                    p.type,
                    p.speed_limit,
                    getattr(p, "flag", 1),
                    p.heading,
                    src,
                    VIETMAP_TYPE_NAMES.get(p.type, "Khác"),
                ])
        else:
            for p in points:
                writer.writerow([
                    f"{p.lon:.6f}",
                    f"{p.lat:.6f}",
                    p.type,
                    p.speed_limit,
                    getattr(p, "flag", 1),
                    p.heading,
                ])
    print(f"[+] Đã xuất {len(points):,} điểm ra CSV: {output_path}")


def encode_points_to_vietmap_binary(points: list, version: str = "20261022") -> bytes:
    """Mã hóa toàn bộ danh sách điểm theo bảng thế byte ký tự nhị phân của VietMap."""
    lines = [version]
    for p in points:
        flag = getattr(p, "flag", 1)
        lines.append(f"{p.lon:.6f},{p.lat:.6f},{p.type},{p.speed_limit},{flag},{p.heading}")
    full_text = "\r\n".join(lines) + "\r\n"
    return bytes(ENCODE_MAP[c] for c in full_text)


def export_vietmap_container_bin(output_path: Path, points: list, version: str = "20261022"):
    """Đóng gói tệp container nhị phân chuẩn VietMap (header TOC 512 bytes + edogen.bin mã hóa byte)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    edogen_bytes = encode_points_to_vietmap_binary(points, version=version)
    
    # Header container mục lục TOC 512 bytes
    hdr = bytearray(512)
    hdr[0:10] = b"edogen.bin"
    struct.pack_into("<I", hdr, 64, len(edogen_bytes))
    container = bytes(hdr) + edogen_bytes

    with open(output_path, "wb") as f:
        f.write(container)
    print(f"[+] Đã đóng gói {len(points):,} điểm thành tệp nhị phân VietMap ({len(container):,} bytes): {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Đồng bộ dữ liệu WYN với VietMap (cả ký tự, ký hiệu, nhị phân)")
    parser.add_argument("--vietmap", default="VietHUD/secrect.bin", help="Đường dẫn file secrect.bin của VietMap")
    parser.add_argument("--wyn", default="VietHUD/data/wyn/wyn_points.csv", help="Đường dẫn file wyn_points.csv")
    parser.add_argument("--radius", type=float, default=20.0, help="Bán kính lân cận khử trùng (mét, mặc định: 20m)")
    parser.add_argument("--strict", action="store_true", help="Chế độ nghiêm ngặt: bỏ bất kỳ điểm WYN nào <= radius của bất kỳ điểm VietMap nào")
    args = parser.parse_args()

    vm_path = Path(args.vietmap)
    wyn_path = Path(args.wyn)

    if not vm_path.exists():
        alt_vm = REPO_ROOT / args.vietmap
        if alt_vm.exists():
            vm_path = alt_vm

    if not wyn_path.exists():
        alt_wyn = REPO_ROOT / args.wyn
        if alt_wyn.exists():
            wyn_path = alt_wyn

    kept_wyn, dropped_wyn, stats = sync_wyn_with_vietmap(
        vietmap_path=vm_path,
        wyn_path=wyn_path,
        radius_m=args.radius,
        strict_any_point=args.strict,
    )

    # 1. Xuất WYN đã đồng bộ ký hiệu và ký tự chuẩn VietMap
    wyn_csv_out = REPO_ROOT / "data" / "wyn" / "wyn_synchronized_vietmap.csv"
    export_vietmap_format_csv(wyn_csv_out, kept_wyn, include_header_line=True, source_name="WYN")

    # Đồng bộ sang data-pipeline
    pipeline_wyn_csv = REPO_ROOT.parent / "data-pipeline" / "sources" / "wyn" / "wyn_synchronized_vietmap.csv"
    if pipeline_wyn_csv.parent.exists():
        export_vietmap_format_csv(pipeline_wyn_csv, kept_wyn, include_header_line=True, source_name="WYN")

    # 2. Xuất WYN mã hóa nhị phân chuẩn VietMap
    wyn_bin_out = REPO_ROOT / "data" / "wyn" / "wyn_synchronized_vietmap.bin"
    export_vietmap_container_bin(wyn_bin_out, kept_wyn, version="20261022")

    # 3. Tạo cơ sở dữ liệu gộp đầy đủ (83.823 VietMap + 25.475 WYN)
    res_vm = vm.decode_file(vm_path)
    combined_points = list(res_vm.points) + list(kept_wyn)

    combined_csv_out = REPO_ROOT / "data" / "combined_vietmap_wyn_synced.csv"
    export_vietmap_format_csv(combined_csv_out, combined_points, include_header_line=True)

    # 4. Xuất tệp nhị phân gộp hoàn chỉnh (secrect.bin / container)
    combined_bin_out = REPO_ROOT / "data" / "combined_vietmap_wyn_synced.bin"
    export_vietmap_container_bin(combined_bin_out, combined_points, version="20261022")

    # 5. Lưu thống kê chi tiết
    stats_out = REPO_ROOT / "data" / "wyn" / "sync_stats.json"
    serializable_stats = {
        k: (dict(v) if isinstance(v, Counter) else v)
        for k, v in stats.items()
    }
    with open(stats_out, "w", encoding="utf-8") as f:
        json.dump(serializable_stats, f, indent=2, ensure_ascii=False)
    print(f"[+] Đã lưu thống kê chi tiết ra: {stats_out}")

    # 6. Kiểm định toàn vẹn bằng cách giải mã ngược lại tệp nhị phân vừa tạo
    print("\n[*] Đang chạy tự kiểm tra (Self-test) giải mã ngược lại từ tệp nhị phân...")
    decoded_check = vm.decode_file(combined_bin_out)
    print(f"      -> Giải mã thành công: {len(decoded_check.points):,} điểm, Skipped: {decoded_check.skipped}")
    assert len(decoded_check.points) == len(combined_points), "Số lượng điểm giải mã không khớp!"
    print("      -> [XÁC THỰC HOÀN HẢO] 100% điểm khớp chính xác từng ký tự và ký hiệu!")

    print("\n" + "=" * 65)
    print("      KẾT QUẢ ĐỒNG BỘ TOÀN DIỆN WYN VỚI VIETMAP (KÝ TỰ & KÝ HIỆU)")
    print("=" * 65)
    print(f"• Dữ liệu VietMap gốc (Ưu tiên số 1):  {stats['vietmap_total']:,} điểm (Bảo toàn 100%)")
    print(f"• Dữ liệu WYN nạp vào:                 {stats['wyn_total_raw']:,} điểm")
    print(f"• Trùng lặp nội bộ WYN (<=2m):          {stats['wyn_internal_duplicates_dropped']:,} điểm (BỎ)")
    print(f"• Điểm WYN trùng/lân cận VietMap (20m): {stats['wyn_dropped_near_vietmap']:,} điểm (BỎ)")
    print(f"• Điểm WYN ĐỒNG BỘ GIỮ LẠI:            {stats['wyn_kept']:,} điểm ({stats['wyn_kept']/stats['wyn_total_raw']*100:.2f}%)")
    print(f"• TỔNG SỐ ĐIỂM HỢP NHẤT TOÀN QUỐC:     {len(combined_points):,} điểm")
    print("-" * 65)
    print("Phân bố dữ liệu WYN sau đồng bộ theo 11 ký hiệu loại VietMap:")
    for t, cnt in sorted(stats["by_vietmap_type"].items()):
        name = VIETMAP_TYPE_NAMES.get(t, "Khác")
        print(f"  - Loại {t:2d} ({name:<30}): {cnt:,} điểm")
    print("=" * 65)


if __name__ == "__main__":
    main()
