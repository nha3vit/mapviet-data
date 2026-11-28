#!/usr/bin/env python3
"""
build_clean_alerts.py — Hợp nhất 5 nguồn dữ liệu (VietMap edogen + VietMap roadsen +
WYN + existing_cameras + OSM) thành cameras.bin & signs.bin chuẩn cho Map Việt.

Quy chuẩn đã kiểm chứng chéo toàn quốc:
1. Camera 5 tầng (cameras.bin, struct <QiihH>, speed=-1 hoặc 30..120 bội số 5):
   - Tầng 0: custom_cameras.csv (điểm thực địa hiệu chỉnh tay).
   - Tầng 1: VietMap Type 11 (5.703 camera chuẩn hướng) -> kế thừa tốc độ nếu khớp WYN/ex_cam <= 40m cùng hướng, else -1.
   - Tầng 2: WYN kind='camera' -> sửa hướng lỗi (hd=15/0xFFFF hoặc lệch >50° qua roadsen, bảo vệ đường đôi >=135°) & khử trùng 30m.
   - Tầng 3: WYN sign_type=2 CHỈ KHI kiểm chứng chéo khớp VM Type 4 hoặc existing_cameras <= 40m -> đưa vào cameras.bin.
   - Tầng 4: existing_cameras.csv (7.753 điểm chuẩn hướng/tốc độ) -> bổ sung & nâng cấp tốc độ cho camera chưa rõ tốc độ.
   - Tầng 5: OSM highway=speed_camera (nếu có .osm.pbf).
   - Tầng 6: VM Type 4 cứu hướng đối diện cho camera WYN/ex_cam cùng trục đường <= 40m (không kế thừa tốc độ <= 40 km/h từ nhánh rẽ).
2. Đèn tín hiệu giao thông (signType=6):
   - Gộp WYN (khử hd=15 -> 0xFFFF, dedup 25m) + OSM traffic_signals ngoài 20m (bảo vệ hai chiều đại lộ > 20m).
3. Biển báo (signs.bin VNSG v1, 20 bytes/record):
   - VM Type 1 (30..120 bội số 5, bao gồm cả 40 & 45 km/h theo chuẩn VietMap) -> signType=1.
   - VM Type 2/3 -> signType=2 subType=0/1 (KDC R.420/R.421).
   - VM Type 5/6 -> signType=3 subType=0/1 flags=1 (Cấm vượt hiển thị HUD, không đọc TTS).
   - Trạm thu phí: WYN st=5 + VM Type 8 ngoài 300m + OSM ngoài 300m -> signType=5.
   - Hầm đường bộ: VM Type 9 -> signType=10 subType=9.
   - Giao cắt đường sắt / cầu nguy hiểm: VM Type 7 & Type 10 khớp OSM railway=level_crossing|rail
     hoặc bridge=* / FLAG_BRIDGE trong <= 50m -> signType=10 subType=7 (AlertType.DANGER).
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import math
import os
import struct
import sys
import tempfile
import time
import zlib
from collections import Counter, defaultdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

try:
    from tools import sign_manifest
    from tools import vietmap_decode as vmd
except ImportError:
    import sign_manifest
    import vietmap_decode as vmd

CAMERA_FMT = "<QiihH"
SIGN_HEADER_FMT = "<4sHIHII"
SIGN_POINT_FMT = "<IiiHBBBBH"
TILE_SEGMENT_FMT = "<IiiiiHBBhBB"
FLAG_BRIDGE = 0x04

DIR_OMNI = 0xFFFF
RADIUS_CAM_MATCH_WYN_M = 40.0
RADIUS_CAM_DEDUP_M = 30.0
RADIUS_TOLL_DEDUP_M = 300.0
RADIUS_LIGHT_MATCH_M = 40.0
RADIUS_DANGER_MATCH_M = 50.0
CAM_SAME_HEADING_DEG = 45
SIGN_GRID_SIZE = 0.002


def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2.0) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2.0) ** 2
    return 2.0 * r * math.atan2(math.sqrt(a), math.sqrt(max(0.0, 1.0 - a)))


def heading_diff(h1: int | float, h2: int | float) -> float:
    d = abs((float(h1) % 360.0) - (float(h2) % 360.0))
    return 360.0 - d if d > 180.0 else d


def is_same_heading(hd1: int, hd2: int, tol_deg: int = CAM_SAME_HEADING_DEG) -> bool:
    if hd1 == DIR_OMNI or hd2 == DIR_OMNI:
        return True
    return heading_diff(hd1, hd2) <= tol_deg


def is_collinear_or_opposite(hd1: int, hd2: int, tol_deg: int = CAM_SAME_HEADING_DEG) -> bool:
    if hd1 == DIR_OMNI or hd2 == DIR_OMNI:
        return True
    d = heading_diff(hd1, hd2)
    return d <= tol_deg or d >= (180.0 - tol_deg)


def iter_grid_neighbors(grid: dict, gx: int, gy: int, span: int = 1):
    for dx in range(-span, span + 1):
        for dy in range(-span, span + 1):
            for item in grid.get((gx + dx, gy + dy), ()):
                yield item


def clean_camera_speed(raw_spd: int | None) -> int:
    """Tốc độ camera: bội số của 5 trong [5, 130] hợp lệ, còn lại quy về -1 (chưa rõ / phạt nguội)."""
    if raw_spd is not None and 5 <= raw_spd <= 130 and (raw_spd % 5 == 0):
        return int(raw_spd)
    return -1


def valid_sign_speed(raw_spd: int | None) -> bool:
    """Chuẩn biển tốc độ VietMap Type 1: 30..120 km/h bội số của 5 (gồm cả 40 & 45 km/h)."""
    return raw_spd is not None and 30 <= raw_spd <= 120 and (raw_spd % 5 == 0)


def _pt_seg_dist_and_hd(
    pla: float, plo: float, la1: float, lo1: float, la2: float, lo2: float
) -> tuple[float, float]:
    c = math.cos(math.radians(pla))
    ax, ay = (lo1 - plo) * 111320.0 * c, (la1 - pla) * 111320.0
    bx, by = (lo2 - plo) * 111320.0 * c, (la2 - pla) * 111320.0
    dx, dy = bx - ax, by - ay
    l2 = dx * dx + dy * dy
    u = 0.0 if l2 == 0.0 else max(0.0, min(1.0, -(ax * dx + ay * dy) / l2))
    px, py = ax + u * dx, ay + u * dy
    hd = (math.degrees(math.atan2(dx, dy)) + 360.0) % 360.0
    return math.hypot(px, py), hd


class _SpatialGrid:
    def __init__(self, cell_deg: float = 0.002):
        self.cell = cell_deg
        self.buckets: dict[tuple[int, int], list] = defaultdict(list)

    def add(self, lat: float, lon: float, item) -> None:
        self.buckets[(int(lat / self.cell), int(lon / self.cell))].append((lat, lon, item))

    def query(self, lat: float, lon: float, max_m: float) -> list[tuple[float, object]]:
        gx, gy = int(lat / self.cell), int(lon / self.cell)
        step = max(1, int(math.ceil(max_m / (self.cell * 111320.0))))
        out = []
        for dx in range(-step, step + 1):
            for dy in range(-step, step + 1):
                for pla, plo, item in self.buckets.get((gx + dx, gy + dy), ()):
                    d = haversine(lat, lon, pla, plo)
                    if d <= max_m:
                        out.append((d, item))
        out.sort(key=lambda x: x[0])
        return out


class _RoadsenSnapper:
    """Bắt hướng (snap heading) từ VietMap roadsen.bin với cơ chế bảo vệ đường đôi."""

    def __init__(self, roadsen_tsv: Path | None):
        self.grid = _SpatialGrid(cell_deg=0.004)
        self.enabled = False
        if not roadsen_tsv or not roadsen_tsv.exists():
            return
        cnt = 0
        for rp in vmd.iter_decoded_roadsen_tsv(roadsen_tsv):
            for k in range(len(rp.coords) - 1):
                la1, lo1 = rp.coords[k]
                la2, lo2 = rp.coords[k + 1]
                self.grid.add((la1 + la2) * 0.5, (lo1 + lo2) * 0.5, (la1, lo1, la2, lo2, rp.speed_fwd, rp.speed_bwd))
                cnt += 1
        self.enabled = cnt > 0

    def snap(self, lat: float, lon: float, raw_hd: int | None, max_m: float = 30.0):
        if not self.enabled:
            return None, None, False
        cands = self.grid.query(lat, lon, max_m=max_m + 30.0)
        best = None
        best_score = 1e9
        best_any = None
        best_any_d = 1e9
        has_close_match = False
        for _, (la1, lo1, la2, lo2, sa, sb) in cands:
            d, seg_hd = _pt_seg_dist_and_hd(lat, lon, la1, lo1, la2, lo2)
            if d > max_m:
                continue
            if d < best_any_d:
                best_any_d = d
                best_any = (seg_hd, sa, sb, d)
            if raw_hd is None or raw_hd == DIR_OMNI:
                continue
            valid_dirs = []
            if sa > 0:
                valid_dirs.append((seg_hd, sa))
            if sb > 0:
                valid_dirs.append(((seg_hd + 180.0) % 360.0, sb))
            if not valid_dirs:
                valid_dirs.append((seg_hd, 0))
                valid_dirs.append(((seg_hd + 180.0) % 360.0, 0))
            for vhd, vspd in valid_dirs:
                df = heading_diff(raw_hd, vhd)
                score = d + df * 0.5
                if score < best_score:
                    best_score = score
                    best = (vhd, vspd, df, d)
                if df <= 35.0 and d <= max_m:
                    has_close_match = True
        return best, best_any, has_close_match

    def fix_heading(self, lat: float, lon: float, raw_hd: int, from_omni_fallback: bool = True) -> tuple[int, bool]:
        if not self.enabled:
            return (DIR_OMNI if raw_hd in (15, DIR_OMNI) or not (0 <= raw_hd < 360) else raw_hd), False
        is_omni = raw_hd in (15, DIR_OMNI) or not (0 <= raw_hd < 360)
        snapped, any_rd, has_match = self.snap(lat, lon, None if is_omni else raw_hd, max_m=35.0)
        if is_omni:
            if from_omni_fallback and any_rd:
                return int(round(any_rd[0])) % 360, True
            return DIR_OMNI, False
        if not has_match and snapped and snapped[2] > 50.0 and snapped[3] <= 35.0:
            # Bảo vệ làn đối diện trên đường đôi (>135° trừ khi đoạn roadsen hỗ trợ cả 2 chiều)
            if snapped[2] < 135.0 or not any_rd or (any_rd[1] > 0 and any_rd[2] > 0):
                return int(round(snapped[0])) % 360, True
        return raw_hd, False


def _parse_osm_dir(val: str | None) -> int | None:
    if not val:
        return None
    s = val.strip()
    try:
        return int(round(float(s))) % 360
    except ValueError:
        return None


def _is_wyn_hd_speed_artifact(spd: int, hd: int) -> bool:
    """Tránh coi nhầm góc hướng bị gán nhầm vào trường speed_kmh của WYN."""
    if spd <= 0:
        return True
    if spd in (40, 50, 60, 70, 80, 90, 100, 120):
        return False
    return hd not in (DIR_OMNI, 15) and abs(spd - hd) <= 5


def _load_danger_refs(
    osm_pbf_path: Path | None,
    osm_danger_refs_path: Path | None,
    tiles_bin_path: Path | None,
):
    """Nạp index không gian cho đường sắt (railway) và cầu (bridge) từ OSM PBF / JSON / tiles.bin."""
    rail_grid = _SpatialGrid(cell_deg=0.004)
    bridge_grid = _SpatialGrid(cell_deg=0.004)
    has_rail = False
    has_bridge = False

    def _add_poly_to_grid(grid: _SpatialGrid, pts: list):
        for k in range(len(pts) - 1):
            la1, lo1 = float(pts[k][0]), float(pts[k][1])
            la2, lo2 = float(pts[k + 1][0]), float(pts[k + 1][1])
            grid.add((la1 + la2) * 0.5, (lo1 + lo2) * 0.5, (la1, lo1, la2, lo2))

    if osm_danger_refs_path is not None and osm_danger_refs_path.exists():
        raw = osm_danger_refs_path.read_bytes()
        if str(osm_danger_refs_path).endswith(".gz"):
            raw = gzip.decompress(raw)
        data = json.loads(raw.decode("utf-8"))
        for la, lo in data.get("rail_nodes", []):
            rail_grid.add(float(la), float(lo), (float(la), float(lo), float(la), float(lo)))
            has_rail = True
        for poly in data.get("rail_ways", []):
            if len(poly) >= 2:
                _add_poly_to_grid(rail_grid, poly)
                has_rail = True
        for poly in data.get("bridge_ways", []):
            if len(poly) >= 2:
                _add_poly_to_grid(bridge_grid, poly)
                has_bridge = True

    if osm_pbf_path is not None and osm_pbf_path.exists() and (not has_rail or not has_bridge):
        import osmium

        class DangerHandler(osmium.SimpleHandler):
            def node(self, n):
                if not n.location.valid() or len(n.tags) == 0:
                    return
                if n.tags.get("railway") in ("level_crossing", "crossing"):
                    la, lo = n.location.lat, n.location.lon
                    rail_grid.add(la, lo, (la, lo, la, lo))

            def way(self, w):
                if len(w.tags) == 0 or len(w.nodes) < 2:
                    return
                rw = w.tags.get("railway")
                br = w.tags.get("bridge")
                hw = w.tags.get("highway")
                is_rail = rw in ("rail", "narrow_gauge", "light_rail", "tram", "subway")
                is_br = bool(hw and br and br.lower() not in ("no", "false", "0"))
                if not (is_rail or is_br):
                    return
                pts = [(nd.location.lat, nd.location.lon) for nd in w.nodes if nd.location.valid()]
                if len(pts) < 2:
                    return
                if is_rail:
                    _add_poly_to_grid(rail_grid, pts)
                if is_br:
                    _add_poly_to_grid(bridge_grid, pts)

        DangerHandler().apply_file(str(osm_pbf_path), locations=True)
        has_rail = bool(rail_grid.buckets)
        has_bridge = bool(bridge_grid.buckets)

    if not has_bridge and tiles_bin_path is not None and tiles_bin_path.exists():
        raw_t = tiles_bin_path.read_bytes()
        sz = struct.calcsize(TILE_SEGMENT_FMT)
        for off in range(0, len(raw_t) - (len(raw_t) % sz), sz):
            _, s_la, s_lo, e_la, e_lo, _, _, _, _, _, flg = struct.unpack_from(TILE_SEGMENT_FMT, raw_t, off)
            if flg & FLAG_BRIDGE:
                la1, lo1 = s_la * 1e-7, s_lo * 1e-7
                la2, lo2 = e_la * 1e-7, e_lo * 1e-7
                bridge_grid.add((la1 + la2) * 0.5, (lo1 + lo2) * 0.5, (la1, lo1, la2, lo2))
                has_bridge = True

    def matches_danger(lat: float, lon: float, radius_m: float = RADIUS_DANGER_MATCH_M) -> bool:
        for grid in (rail_grid, bridge_grid):
            if not grid.buckets:
                continue
            for _, seg in grid.query(lat, lon, max_m=radius_m + 150.0):
                la1, lo1, la2, lo2 = seg
                if la1 == la2 and lo1 == lo2:
                    if haversine(lat, lon, la1, lo1) <= radius_m:
                        return True
                else:
                    d, _ = _pt_seg_dist_and_hd(lat, lon, la1, lo1, la2, lo2)
                    if d <= radius_m:
                        return True
        return False

    return (has_rail or has_bridge), matches_danger


def build_clean_alerts(
    wyn_csv: Path,
    secrect_bin: Path,
    output_dir: Path,
    version_str: str | None = None,
    alerts_only: bool = False,
    curated_dir: Path | None = None,
    osm_gt_path: Path | None = None,
    osm_signs_path: Path | None = None,
    sign_output: bool = True,
    existing_cameras_path: Path | None = None,
    roadsen_tsv_path: Path | None = None,
    osm_pbf_path: Path | None = None,
    osm_danger_refs_path: Path | None = None,
    tiles_bin_path: Path | None = None,
    vietmap_manifest_path: Path | None = None,
) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    if not version_str:
        version_str = os.environ.get("MAPVIET_ALERTS_VERSION") or time.strftime("%Y.%m.%d.%H%M")

    # 1. Nạp VietMap edogen
    print(f"[1/5] Đang giải mã VietMap từ {secrect_bin}...")
    vm_res = vmd.decode_file(secrect_bin)
    vm_points = vm_res.points
    print(f"      + VietMap version={vm_res.version}, tổng điểm={len(vm_points):,}")

    # Tự động nạp roadsen khi có file TSV chỉ định hoặc secrect.bin đầy đủ / bản sản xuất thật
    tmp_roadsen_ctx = None
    effective_roadsen_tsv = roadsen_tsv_path
    if effective_roadsen_tsv is None:
        if vmd.has_full_roadsenz(secrect_bin):
            tmp_roadsen_ctx = tempfile.TemporaryDirectory(prefix="alerts_roadsen_")
            effective_roadsen_tsv = vmd.extract_roadsenz_tsv(secrect_bin, Path(tmp_roadsen_ctx.name) / "roadsen.tsv")
        elif vietmap_manifest_path is not None and vietmap_manifest_path.exists():
            full_bin = vmd.hydrate_full_secrect_bin(secrect_bin, manifest_path=vietmap_manifest_path)
            if full_bin is not None:
                tmp_roadsen_ctx = tempfile.TemporaryDirectory(prefix="alerts_roadsen_")
                effective_roadsen_tsv = vmd.extract_roadsenz_tsv(full_bin, Path(tmp_roadsen_ctx.name) / "roadsen.tsv")
        elif len(vm_points) >= 1000:
            default_mf = secrect_bin.parent / "vietmap_manifest.json"
            if default_mf.exists():
                full_bin = vmd.hydrate_full_secrect_bin(secrect_bin, manifest_path=default_mf)
                if full_bin is not None:
                    tmp_roadsen_ctx = tempfile.TemporaryDirectory(prefix="alerts_roadsen_")
                    effective_roadsen_tsv = vmd.extract_roadsenz_tsv(
                        full_bin, Path(tmp_roadsen_ctx.name) / "roadsen.tsv"
                    )

    snapper = _RoadsenSnapper(effective_roadsen_tsv)
    if snapper.enabled:
        print("      + Đã kích hoạt bộ bắt hướng roadsen.bin")

    try:
        # 2. Nạp WYN
        print(f"[2/5] Đang đọc dữ liệu WYN từ {wyn_csv}...")
        wyn_cameras: list[dict] = []
        wyn_st2_candidates: list[dict] = []
        wyn_raw_lights: list[dict] = []
        wyn_tolls: list[dict] = []
        with open(wyn_csv, "r", encoding="utf-8-sig") as f:
            for r in csv.DictReader(f):
                lat = float(r["lat"])
                lon = float(r["lon"])
                kind = (r.get("kind") or "").strip()
                st = (r.get("sign_type") or "").strip()
                raw_spd = int(float(r["speed_kmh"] or 0))
                raw_hd_str = (r.get("heading") or "").strip()
                hd = (int(float(raw_hd_str)) % 360) if raw_spd is not None and raw_hd_str != "" else DIR_OMNI

                if kind == "camera":
                    spd = -1 if _is_wyn_hd_speed_artifact(raw_spd, hd) else clean_camera_speed(raw_spd)
                    wyn_cameras.append({"lat": lat, "lon": lon, "speed": spd, "heading": hd})
                elif kind == "light":
                    wyn_raw_lights.append({"lat": lat, "lon": lon, "heading": hd})
                elif st == "2":
                    wyn_st2_candidates.append({"lat": lat, "lon": lon, "speed": clean_camera_speed(raw_spd), "heading": hd})
                elif st == "5":
                    wyn_tolls.append({"lat": lat, "lon": lon})
                # Các WYN st=3, 10 hoặc st khác đều bị loại trừ chống nhiễu

        # 3. Nạp nguồn tùy chỉnh + existing_cameras + OSM
        if curated_dir is None:
            curated_candidates = [
                wyn_csv.parent.parent / "curated",
                REPO_ROOT / "data-pipeline" / "sources" / "curated",
                REPO_ROOT / "sources" / "curated",
                SCRIPT_DIR / "sources" / "curated",
            ]
            curated_dir = next((p for p in curated_candidates if p.exists()), wyn_csv.parent.parent / "curated")

        curated_cams: list[dict] = []
        curated_cams_path = curated_dir / "custom_cameras.csv"
        if curated_cams_path.exists():
            with open(curated_cams_path, "r", encoding="utf-8") as f:
                for r in csv.DictReader(f):
                    if not (r.get("lat") or "").strip():
                        continue
                    curated_cams.append({
                        "lat": float(r["lat"]),
                        "lon": float(r["lon"]),
                        "speed": clean_camera_speed(int(float(r.get("speed") or 0))),
                        "heading": int(float(r["heading"])) % 360 if (r.get("heading") or "").strip() else DIR_OMNI,
                    })

        curated_signs: list[dict] = []
        curated_signs_path = curated_dir / "custom_signs.csv"
        if curated_signs_path.exists():
            with open(curated_signs_path, "r", encoding="utf-8") as f:
                for r in csv.DictReader(f):
                    if not (r.get("lat") or "").strip():
                        continue
                    curated_signs.append({
                        "lat": float(r["lat"]),
                        "lon": float(r["lon"]),
                        "heading": int(float(r["heading"])) % 360 if (r.get("heading") or "").strip() else DIR_OMNI,
                        "sign_type": int(r["sign_type"]),
                        "sub_type": int(r.get("sub_type") or 0),
                        "speed": int(r.get("speed") or 0),
                    })

        ex_cams: list[dict] = []
        ex_path = existing_cameras_path
        if ex_path is None:
            cand = curated_dir / "existing_cameras.csv"
            if cand.exists():
                ex_path = cand
        if ex_path is not None and ex_path.exists():
            with open(ex_path, "r", encoding="utf-8-sig") as f:
                for r in csv.DictReader(f):
                    if not (r.get("lat") or "").strip():
                        continue
                    spd = clean_camera_speed(int(float(r["speed_limit"]))) if (r.get("speed_limit") or "").strip() else -1
                    hd = int(float(r["heading"])) % 360 if (r.get("heading") or "").strip() else DIR_OMNI
                    ex_cams.append({"lat": float(r["lat"]), "lon": float(r["lon"]), "speed": spd, "heading": hd})
            print(f"      + Đã nạp {len(ex_cams):,} camera từ {ex_path.name}")

        osm_lights: list[tuple[float, float, int]] = []
        osm_tolls: list[tuple[float, float]] = []
        osm_cams: list[tuple[float, float, int, int]] = []

        if osm_pbf_path is not None and osm_pbf_path.exists():
            import osmium

            class OsmNodeHandler(osmium.SimpleHandler):
                def node(self, n):
                    if len(n.tags) == 0 or not n.location.valid():
                        return
                    hw = n.tags.get("highway")
                    br = n.tags.get("barrier")
                    la, lo = n.location.lat, n.location.lon
                    if hw == "traffic_signals":
                        hd_val = _parse_osm_dir(n.tags.get("traffic_signals:direction") or n.tags.get("direction"))
                        osm_lights.append((la, lo, hd_val if hd_val is not None else DIR_OMNI))
                    elif br == "toll_booth" or hw == "toll_gantry":
                        osm_tolls.append((la, lo))
                    elif hw == "speed_camera":
                        spd_raw = n.tags.get("maxspeed", "")
                        spd = clean_camera_speed(int(round(float(spd_raw)))) if spd_raw.replace(".", "", 1).isdigit() else -1
                        osm_cams.append((la, lo, spd, DIR_OMNI))

            OsmNodeHandler().apply_file(str(osm_pbf_path), locations=True)
            print(f"      + OSM PBF nodes: lights={len(osm_lights):,}, tolls={len(osm_tolls):,}, cams={len(osm_cams):,}")
        else:
            if osm_gt_path is not None and osm_gt_path.exists():
                gt = json.loads(osm_gt_path.read_text(encoding="utf-8"))
                for item in gt.get("traffic_signals", []):
                    osm_lights.append((float(item[0]), float(item[1]), DIR_OMNI))
                for item in gt.get("toll_booths", []):
                    osm_tolls.append((float(item[0]), float(item[1])))
            elif osm_signs_path is not None and osm_signs_path.exists():
                sdata = osm_signs_path.read_bytes()
                if len(sdata) > 20:
                    for off in range(20, len(sdata) - (len(sdata) - 20) % 20, 20):
                        _, la_e7, lo_e7, hd_v, stype, _, _, _, _ = struct.unpack_from(SIGN_POINT_FMT, sdata, off)
                        if stype == 6:
                            osm_lights.append((la_e7 / 1e7, lo_e7 / 1e7, hd_v))
                        elif stype == 5:
                            osm_tolls.append((la_e7 / 1e7, lo_e7 / 1e7))

        # 4. Trộn đèn tín hiệu WYN + OSM (khử hd=15 -> 0xFFFF; OSM ngoài 20m giữ đường đôi)
        print("[3/5] Hợp nhất đèn tín hiệu giao thông & 5 tầng camera...")
        final_signs: list[dict] = []
        light_grid = _SpatialGrid(cell_deg=0.001)
        wyn_light_count = 0
        for wl in wyn_raw_lights:
            la, lo, hd = wl["lat"], wl["lon"], wl["heading"]
            if light_grid.query(la, lo, 25.0):
                continue
            fixed_hd = DIR_OMNI if (hd == 15 or hd < 0 or hd >= 360) else hd
            rec = {
                "lat": la,
                "lon": lo,
                "heading": fixed_hd,
                "sign_type": 6,
                "sub_type": 0,
                "speed": 0,
                "flags": 0,
                "source_code": 2,
                "source_name": "WYN",
                "desc": "Đèn tín hiệu giao thông",
                "is_wyn": True,
            }
            light_grid.add(la, lo, rec)
            final_signs.append(rec)
            wyn_light_count += 1

        osm_lights_added_count = 0
        for la, lo, hd in osm_lights:
            fixed_hd = hd if 0 <= hd < 360 else DIR_OMNI
            dups = light_grid.query(la, lo, 20.0)
            if any(
                l["is_wyn"] or (fixed_hd == DIR_OMNI or l["heading"] == DIR_OMNI or heading_diff(fixed_hd, l["heading"]) <= 45)
                for _, l in dups
            ):
                continue
            rec = {
                "lat": la,
                "lon": lo,
                "heading": fixed_hd,
                "sign_type": 6,
                "sub_type": 0,
                "speed": 0,
                "flags": 0,
                "source_code": 3,
                "source_name": "OSM",
                "desc": "Đèn tín hiệu giao thông",
                "is_wyn": False,
            }
            light_grid.add(la, lo, rec)
            final_signs.append(rec)
            osm_lights_added_count += 1

        # Bổ sung custom_signs
        for cs in curated_signs:
            final_signs.append({
                "lat": cs["lat"],
                "lon": cs["lon"],
                "heading": cs["heading"],
                "sign_type": cs["sign_type"],
                "sub_type": cs["sub_type"],
                "speed": cs["speed"],
                "flags": 0,
                "source_code": 0,
                "source_name": "CURATED",
                "desc": f"Biển hiệu chỉnh ({cs['sign_type']})",
            })

        # Tiền chỉ mục VietMap theo type + các grid đối chiếu chéo
        vm_type11 = [p for p in vm_points if p.type == 11]
        vm_type4 = [p for p in vm_points if p.type == 4]

        vm4_grid = _SpatialGrid(cell_deg=0.001)
        for p in vm_type4:
            vm4_grid.add(p.lat, p.lon, p)

        wcam_grid = _SpatialGrid(cell_deg=0.001)
        for wc in wyn_cameras:
            wcam_grid.add(wc["lat"], wc["lon"], wc)

        excam_grid = _SpatialGrid(cell_deg=0.001)
        for ec in ex_cams:
            excam_grid.add(ec["lat"], ec["lon"], ec)

        # Hợp nhất Camera 6 tầng
        final_cameras: list[dict] = []
        cam_grid = _SpatialGrid(cell_deg=0.001)
        cam_stats = Counter()

        def find_dup_and_promote(lat: float, lon: float, hd: int, spd_cand: int, rad_m: float = RADIUS_CAM_DEDUP_M):
            for d, c in cam_grid.query(lat, lon, rad_m):
                same_dir = (
                    is_same_heading(hd, c["heading"], CAM_SAME_HEADING_DEG)
                    or (d < 5.0 and (hd == 0 or c["heading"] == 0))
                )
                if same_dir:
                    if c["speed"] <= 0 and spd_cand > 0:
                        c["speed"] = spd_cand
                        cam_stats["spd_promoted_on_merge"] += 1
                    return c
            return None

        # Tầng 0: CURATED cameras
        for cc in curated_cams:
            if find_dup_and_promote(cc["lat"], cc["lon"], cc["heading"], cc["speed"], RADIUS_CAM_DEDUP_M):
                continue
            rec = {
                "lat": cc["lat"],
                "lon": cc["lon"],
                "speed": cc["speed"],
                "heading": cc["heading"],
                "source_code": 0,
                "source_name": "CURATED",
                "desc": f"Camera thực tế ({cc['speed']} km/h)" if cc["speed"] > 0 else "Camera thực tế",
            }
            cam_grid.add(cc["lat"], cc["lon"], rec)
            final_cameras.append(rec)
            cam_stats["curated_added"] += 1

        # Tầng 1: WYN kind='camera' (sửa hướng lỗi qua roadsen & khử trùng 30m)
        for wc in wyn_cameras:
            fixed_hd, was_fixed = snapper.fix_heading(wc["lat"], wc["lon"], wc["heading"], from_omni_fallback=True)
            if was_fixed:
                cam_stats["wcam_hd_fixed"] += 1
            if find_dup_and_promote(wc["lat"], wc["lon"], fixed_hd, wc["speed"], RADIUS_CAM_DEDUP_M):
                cam_stats["wcam_merged_dup"] += 1
                continue
            rec = {
                "lat": wc["lat"],
                "lon": wc["lon"],
                "speed": wc["speed"],
                "heading": fixed_hd,
                "source_code": 2,
                "source_name": "WYN",
                "desc": f"Camera tốc độ {wc['speed']} km/h" if wc["speed"] > 0 else "Camera phạt nguội (WYN)",
            }
            cam_grid.add(wc["lat"], wc["lon"], rec)
            final_cameras.append(rec)
            cam_stats["wcam_added"] += 1

        # Tầng 2: VietMap Type 11 (chuẩn hướng; bổ sung ngoài 30m cùng hướng WYN, kế thừa tốc độ từ ex_cam <= 40m)
        for p in vm_type11:
            if find_dup_and_promote(p.lat, p.lon, p.heading, -1, RADIUS_CAM_DEDUP_M):
                cam_stats["vm11_internal_dup"] += 1
                continue
            spd = -1
            for _, wc in wcam_grid.query(p.lat, p.lon, RADIUS_CAM_MATCH_WYN_M):
                if wc["speed"] > 0 and is_same_heading(p.heading, wc["heading"], CAM_SAME_HEADING_DEG):
                    spd = wc["speed"]
                    break
            if spd < 0:
                for _, ec in excam_grid.query(p.lat, p.lon, RADIUS_CAM_MATCH_WYN_M):
                    if ec["speed"] > 0 and is_same_heading(p.heading, ec["heading"], CAM_SAME_HEADING_DEG):
                        spd = ec["speed"]
                        break
            rec = {
                "lat": p.lat,
                "lon": p.lon,
                "speed": spd,
                "heading": p.heading,
                "source_code": 1,
                "source_name": "VietMap",
                "desc": "Camera theo dõi tốc độ" if spd > 0 else "Camera phạt nguội (VietMap Type 11)",
            }
            cam_grid.add(p.lat, p.lon, rec)
            final_cameras.append(rec)
            cam_stats["vm11_added"] += 1

        # Tầng 3: WYN sign_type=2 kiểm chứng chéo với VM Type 4 hoặc existing_cameras <= 40m
        for wst in wyn_st2_candidates:
            has_vm4 = bool(vm4_grid.query(wst["lat"], wst["lon"], RADIUS_CAM_MATCH_WYN_M))
            has_ex = bool(excam_grid.query(wst["lat"], wst["lon"], RADIUS_CAM_MATCH_WYN_M))
            if not (has_vm4 or has_ex):
                cam_stats["wst2_unverified_skipped"] += 1
                continue
            fixed_hd, was_fixed = snapper.fix_heading(wst["lat"], wst["lon"], wst["heading"], from_omni_fallback=False)
            if was_fixed:
                cam_stats["wst2_hd_fixed"] += 1
            if find_dup_and_promote(wst["lat"], wst["lon"], fixed_hd, -1, RADIUS_CAM_DEDUP_M):
                cam_stats["wst2_merged_dup"] += 1
                continue
            spd = -1
            for _, ec in excam_grid.query(wst["lat"], wst["lon"], RADIUS_CAM_MATCH_WYN_M):
                if ec["speed"] > 0 and is_same_heading(fixed_hd, ec["heading"], CAM_SAME_HEADING_DEG):
                    spd = ec["speed"]
                    break
            rec = {
                "lat": wst["lat"],
                "lon": wst["lon"],
                "speed": spd,
                "heading": fixed_hd,
                "source_code": 2,
                "source_name": "WYN_ST2_VERIFIED",
                "desc": f"Camera tốc độ {spd} km/h (WYN st=2)" if spd > 0 else "Camera kiểm chứng chéo (WYN st=2)",
            }
            cam_grid.add(wst["lat"], wst["lon"], rec)
            final_cameras.append(rec)
            cam_stats["wst2_added"] += 1

        # Tầng 4: existing_cameras.csv
        for ec in ex_cams:
            fixed_hd, was_fixed = snapper.fix_heading(ec["lat"], ec["lon"], ec["heading"], from_omni_fallback=True)
            if was_fixed:
                cam_stats["excam_hd_fixed"] += 1
            if find_dup_and_promote(ec["lat"], ec["lon"], fixed_hd, ec["speed"], RADIUS_CAM_DEDUP_M):
                cam_stats["excam_merged_dup"] += 1
                continue
            rec = {
                "lat": ec["lat"],
                "lon": ec["lon"],
                "speed": ec["speed"],
                "heading": fixed_hd,
                "source_code": 0,
                "source_name": "CURATED_EXISTING",
                "desc": f"Camera tốc độ {ec['speed']} km/h" if ec["speed"] > 0 else "Camera phạt nguội",
            }
            cam_grid.add(ec["lat"], ec["lon"], rec)
            final_cameras.append(rec)
            cam_stats["excam_added"] += 1

        # Tầng 5: OSM highway=speed_camera
        for la, lo, spd, _ in osm_cams:
            fixed_hd, _ = snapper.fix_heading(la, lo, DIR_OMNI, from_omni_fallback=True)
            if find_dup_and_promote(la, lo, fixed_hd, spd, RADIUS_CAM_DEDUP_M):
                cam_stats["osmcam_merged_dup"] += 1
                continue
            rec = {
                "lat": la,
                "lon": lo,
                "speed": spd,
                "heading": fixed_hd,
                "source_code": 3,
                "source_name": "OSM",
                "desc": "Camera tốc độ (OSM)",
            }
            cam_grid.add(la, lo, rec)
            final_cameras.append(rec)
            cam_stats["osmcam_added"] += 1

        # Tầng 6: Cứu hướng đối diện VM Type 4 khi khớp camera WYN/ex_cam cùng trục <= 40m
        # Quy tắc an toàn: KHÔNG khớp đường cắt vuông góc và KHÔNG kế thừa tốc độ <= 40 km/h (nhánh rẽ)
        ref_cams = wyn_cameras + ex_cams
        ref_cam_grid = _SpatialGrid(cell_deg=0.001)
        for rc in ref_cams:
            ref_cam_grid.add(rc["lat"], rc["lon"], rc)

        vm_type4_speed_added = 0
        vm_type4_redlight_added = 0
        vm_type4_surveillance_added = 0
        vm_type4_dropped_dup = 0
        vm_type4_skipped_no_ref = 0

        for p in vm_type4:
            matches = [
                (d, rc)
                for d, rc in ref_cam_grid.query(p.lat, p.lon, RADIUS_CAM_MATCH_WYN_M)
                if is_collinear_or_opposite(p.heading, rc["heading"], CAM_SAME_HEADING_DEG)
            ]
            if not matches:
                vm_type4_skipped_no_ref += 1
                continue
            # Chỉ cứu các hướng chưa được bao phủ trong 30m cùng hướng
            if find_dup_and_promote(p.lat, p.lon, p.heading, -1, RADIUS_CAM_DEDUP_M):
                vm_type4_dropped_dup += 1
                continue
            # Chỉ kế thừa tốc độ > 40 km/h (chặn lây tốc độ <= 40 km/h từ nhánh rẽ sang làn chính)
            _, rc_best = matches[0]
            spd = rc_best["speed"] if rc_best["speed"] > 40 else -1
            near_signal = bool(light_grid.query(p.lat, p.lon, RADIUS_LIGHT_MATCH_M))
            if spd > 0:
                vm_type4_speed_added += 1
                desc = f"Camera tốc độ {spd} km/h (VM Type 4)"
            elif near_signal:
                vm_type4_redlight_added += 1
                desc = "Camera vượt đèn đỏ (VM Type 4)"
            else:
                vm_type4_surveillance_added += 1
                desc = "Camera đối hướng (VM Type 4)"
            rec = {
                "lat": p.lat,
                "lon": p.lon,
                "speed": spd,
                "heading": p.heading,
                "source_code": 1,
                "source_name": "VietMap",
                "desc": desc,
            }
            cam_grid.add(p.lat, p.lon, rec)
            final_cameras.append(rec)

        # 5. Xử lý Biển báo (signs.bin)
        print("[4/5] Đang phân loại và đóng gói biển báo chuẩn Map Việt...")
        has_danger_refs, matches_danger = _load_danger_refs(osm_pbf_path, osm_danger_refs_path, tiles_bin_path)
        if has_danger_refs:
            print("      + Đã bật bộ lọc đường sắt/cầu OSM cho VM Type 7 & Type 10")

        vm_signs_added = Counter()
        vm_type1_grid = _SpatialGrid(cell_deg=0.001)
        vm_danger_grid = _SpatialGrid(cell_deg=0.001)
        toll_grid = _SpatialGrid(cell_deg=0.005)

        # Trạm thu phí ưu tiên WYN st=5 (khử 200m), sau đó VM Type 8 & OSM ngoài 300m
        for wt in wyn_tolls:
            if toll_grid.query(wt["lat"], wt["lon"], 200.0):
                continue
            toll_grid.add(wt["lat"], wt["lon"], True)
            final_signs.append({
                "lat": wt["lat"],
                "lon": wt["lon"],
                "heading": DIR_OMNI,
                "sign_type": 5,
                "sub_type": 0,
                "speed": 0,
                "flags": 0,
                "source_code": 2,
                "source_name": "WYN",
                "desc": "Trạm thu phí BOT",
            })

        vm_toll_dropped = 0
        for p in vm_points:
            if p.type == 1:
                if not valid_sign_speed(p.speed_limit):
                    continue
                if any(
                    s["speed"] == p.speed_limit and is_same_heading(p.heading, s["heading"], 45)
                    for _, s in vm_type1_grid.query(p.lat, p.lon, 15.0)
                ):
                    continue
                rec = {
                    "lat": p.lat,
                    "lon": p.lon,
                    "heading": p.heading,
                    "sign_type": 1,
                    "sub_type": 0,
                    "speed": p.speed_limit,
                    "flags": 0,
                    "source_code": 1,
                    "source_name": "VietMap",
                    "desc": f"Giới hạn {p.speed_limit} km/h",
                }
                vm_type1_grid.add(p.lat, p.lon, rec)
                final_signs.append(rec)
                vm_signs_added["speed"] += 1
            elif p.type == 2:
                final_signs.append({
                    "lat": p.lat, "lon": p.lon, "heading": p.heading,
                    "sign_type": 2, "sub_type": 0, "speed": 0, "flags": 0,
                    "source_code": 1, "source_name": "VietMap", "desc": "Vào khu đông dân cư (R.420)",
                })
                vm_signs_added["kdc_enter"] += 1
            elif p.type == 3:
                final_signs.append({
                    "lat": p.lat, "lon": p.lon, "heading": p.heading,
                    "sign_type": 2, "sub_type": 1, "speed": 0, "flags": 0,
                    "source_code": 1, "source_name": "VietMap", "desc": "Hết khu đông dân cư (R.421)",
                })
                vm_signs_added["kdc_exit"] += 1
            elif p.type == 5:
                final_signs.append({
                    "lat": p.lat, "lon": p.lon, "heading": p.heading,
                    "sign_type": 3, "sub_type": 0, "speed": 0, "flags": 1,
                    "source_code": 1, "source_name": "VietMap", "desc": "Bắt đầu cấm vượt",
                })
                vm_signs_added["no_overtake_start"] += 1
            elif p.type == 6:
                final_signs.append({
                    "lat": p.lat, "lon": p.lon, "heading": p.heading,
                    "sign_type": 3, "sub_type": 1, "speed": 0, "flags": 1,
                    "source_code": 1, "source_name": "VietMap", "desc": "Hết cấm vượt",
                })
                vm_signs_added["no_overtake_end"] += 1
            elif p.type == 8:
                if toll_grid.query(p.lat, p.lon, RADIUS_TOLL_DEDUP_M):
                    vm_toll_dropped += 1
                    continue
                toll_grid.add(p.lat, p.lon, True)
                final_signs.append({
                    "lat": p.lat, "lon": p.lon, "heading": DIR_OMNI,
                    "sign_type": 5, "sub_type": 0, "speed": 0, "flags": 0,
                    "source_code": 1, "source_name": "VietMap", "desc": "Trạm thu phí BOT",
                })
                vm_signs_added["toll"] += 1
            elif p.type == 9:
                final_signs.append({
                    "lat": p.lat, "lon": p.lon, "heading": p.heading,
                    "sign_type": 10, "sub_type": 9, "speed": 0, "flags": 0,
                    "source_code": 1, "source_name": "VietMap", "desc": "Hầm đường bộ",
                })
                vm_signs_added["tunnel"] += 1
            elif p.type in (7, 10) and has_danger_refs:
                if matches_danger(p.lat, p.lon, RADIUS_DANGER_MATCH_M):
                    if any(is_same_heading(p.heading, d["heading"], 45) for _, d in vm_danger_grid.query(p.lat, p.lon, 25.0)):
                        continue
                    rec = {
                        "lat": p.lat, "lon": p.lon, "heading": p.heading,
                        "sign_type": 10, "sub_type": 7, "speed": 0, "flags": 0,
                        "source_code": 1, "source_name": "VietMap",
                        "desc": "Cảnh báo đường sắt / cầu (VM Type 7/10 + OSM)",
                    }
                    vm_danger_grid.add(p.lat, p.lon, rec)
                    final_signs.append(rec)
                    vm_signs_added["danger_rail_bridge"] += 1

        for la, lo in osm_tolls:
            if toll_grid.query(la, lo, RADIUS_TOLL_DEDUP_M):
                continue
            toll_grid.add(la, lo, True)
            final_signs.append({
                "lat": la, "lon": lo, "heading": DIR_OMNI,
                "sign_type": 5, "sub_type": 0, "speed": 0, "flags": 0,
                "source_code": 3, "source_name": "OSM", "desc": "Trạm thu phí (OSM)",
            })
            vm_signs_added["osm_toll_added"] += 1

        # 6. Ghi tệp nhị phân cameras.bin, signs.bin, combined_traffic_alerts.csv, stats.json, manifest.txt
        cams_out_path = output_dir / "cameras.bin"
        signs_out_path = output_dir / "signs.bin"

        cam_buf = bytearray()
        for cid, c in enumerate(final_cameras, start=1):
            c["id"] = cid
            cam_buf += struct.pack(
                CAMERA_FMT,
                cid,
                int(round(c["lat"] * 1e7)),
                int(round(c["lon"] * 1e7)),
                int(c["speed"]),
                int(c["heading"]) if 0 <= int(c["heading"]) < 360 else DIR_OMNI,
            )
        cams_out_path.write_bytes(bytes(cam_buf))

        sign_body = bytearray()
        for sid, s in enumerate(final_signs, start=1):
            s["id"] = sid
            sign_body += struct.pack(
                SIGN_POINT_FMT,
                sid,
                int(round(s["lat"] * 1e7)),
                int(round(s["lon"] * 1e7)),
                int(s["heading"]) if 0 <= int(s["heading"]) < 360 else DIR_OMNI,
                int(s["sign_type"]),
                int(s["speed"]),
                int(s["sub_type"]),
                int(s["flags"]),
                int(s["source_code"]),
            )
        crc = zlib.crc32(bytes(sign_body)) & 0xFFFFFFFF
        sign_hdr = struct.pack(SIGN_HEADER_FMT, b"VNSG", 1, len(final_signs), 0, crc, int(time.time()))
        signs_out_path.write_bytes(sign_hdr + bytes(sign_body))

        csv_path = output_dir / "combined_traffic_alerts.csv"
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["id", "lat", "lon", "la_camera", "sign_type", "sub_type", "speed", "heading", "flags", "nguon_du_lieu", "mo_ta"])
            for c in final_cameras:
                writer.writerow([c["id"], f"{c['lat']:.7f}", f"{c['lon']:.7f}", 1, 0, 0, c["speed"], c["heading"], 0, c["source_name"], c["desc"]])
            for s in final_signs:
                writer.writerow([s["id"], f"{s['lat']:.7f}", f"{s['lon']:.7f}", 0, s["sign_type"], s["sub_type"], s["speed"], s["heading"], s["flags"], s["source_name"], s["desc"]])

        # manifest.txt + ECDSA signature
        print("[5/5] Đang tạo và ký manifest.txt...")
        manifest_files = ["cameras.bin", "signs.bin"]
        if not alerts_only:
            for extra in ("metadata.bin", "index.bin", "tiles.bin", "names.bin", "seg_names.bin"):
                if (output_dir / extra).exists():
                    manifest_files.insert(0, extra)

        manifest_lines = [f"version {version_str}"]
        for fname in manifest_files:
            fp = output_dir / fname
            if fp.exists():
                fsha = hashlib.sha256(fp.read_bytes()).hexdigest()
                manifest_lines.append(f"{fname} {fp.stat().st_size} {fsha}")
        manifest_file = output_dir / "manifest.txt"
        manifest_file.write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")

        content_sha = hashlib.sha256(cams_out_path.read_bytes() + signs_out_path.read_bytes()).hexdigest()
        vm_cam_total = cam_stats["vm11_added"] + vm_type4_speed_added + vm_type4_redlight_added + vm_type4_surveillance_added
        stats = {
            "version": version_str,
            "vietmap_version": vm_res.version,
            "content_sha256": content_sha,
            "total_points": len(final_cameras) + len(final_signs),
            "cameras_count": len(final_cameras),
            "signs_count": len(final_signs),
            "total_cameras": len(final_cameras),
            "total_signs": len(final_signs),
            "camera_fusion": dict(cam_stats),
            "counts_by_source_and_type": {
                "VietMap": {
                    "camera_total": vm_cam_total,
                    "camera_type11": cam_stats["vm11_added"],
                    "type4_speed_cam": vm_type4_speed_added,
                    "type4_redlight_cam": vm_type4_redlight_added,
                    "type4_surveillance_cam": vm_type4_surveillance_added,
                    "type4_dropped_dup": vm_type4_dropped_dup,
                    "type4_skipped_no_wyn": vm_type4_skipped_no_ref,
                    "speed": vm_signs_added["speed"],
                    "kdc_enter": vm_signs_added["kdc_enter"],
                    "kdc_exit": vm_signs_added["kdc_exit"],
                    "no_overtake_start": vm_signs_added["no_overtake_start"],
                    "no_overtake_end": vm_signs_added["no_overtake_end"],
                    "toll": vm_signs_added["toll"],
                    "toll_dropped_300m": vm_toll_dropped,
                    "tunnel": vm_signs_added["tunnel"],
                    "danger_rail_bridge": vm_signs_added["danger_rail_bridge"],
                },
                "WYN": {
                    "camera": cam_stats["wcam_added"] + cam_stats["wst2_added"],
                    "camera_st2_verified": cam_stats["wst2_added"],
                    "traffic_light": wyn_light_count,
                    "toll": sum(1 for s in final_signs if s["sign_type"] == 5 and s["source_name"] == "WYN"),
                },
                "OSM": {
                    "traffic_light": osm_lights_added_count,
                    "camera": cam_stats["osmcam_added"],
                    "toll": vm_signs_added["osm_toll_added"],
                },
                "CURATED": {
                    "camera": cam_stats["curated_added"] + cam_stats["excam_added"],
                    "existing_cameras": cam_stats["excam_added"],
                    "sign": len(curated_signs),
                },
            },
        }
        (output_dir / "stats.json").write_text(json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8")

        if sign_output:
            key_file = (
                os.environ.get("SIGN_KEY")
                or os.environ.get("MAPVIET_SIGNING_KEY_FILE")
                or str(SCRIPT_DIR / "keys" / "mapviet_signing_key.pem")
            )
            if Path(key_file).exists():
                priv_key = sign_manifest.load_private_key(Path(key_file))
                sign_manifest.sign_manifest(manifest_file, key=priv_key)
                if not sign_manifest.verify_manifest(manifest_file):
                    raise ValueError("Xác thực chữ ký manifest thất bại!")
                print("      [OK] Đã ký số và xác thực manifest.txt.sig thành công!")
            else:
                print(f"      [WARN] Không tìm thấy khóa ký số tại {key_file}; bỏ qua ký số")

        print(f"[OK] Hoàn tất build_clean_alerts: cameras={len(final_cameras):,}, signs={len(final_signs):,}")
        return stats
    finally:
        if tmp_roadsen_ctx is not None:
            tmp_roadsen_ctx.cleanup()


def find_default_wyn() -> Path:
    for p in [SCRIPT_DIR / "sources" / "wyn" / "wyn_points.csv", REPO_ROOT / "VietHUD" / "data" / "wyn" / "wyn_points.csv"]:
        if p.exists():
            return p
    return SCRIPT_DIR / "sources" / "wyn" / "wyn_points.csv"


def find_default_vietmap() -> Path:
    for p in [REPO_ROOT / "secrect.bin", SCRIPT_DIR / "sources" / "vietmap" / "secrect.bin"]:
        if p.exists():
            return p
    return SCRIPT_DIR / "sources" / "vietmap" / "secrect.bin"


def find_default_out() -> Path:
    return REPO_ROOT / "VietHUD" / "speedmap"


def main():
    parser = argparse.ArgumentParser(description="Hợp nhất đa nguồn VietMap + WYN + existing_cameras + OSM -> Map Việt.")
    parser.add_argument("--wyn", type=Path, default=find_default_wyn())
    parser.add_argument("--vietmap", type=Path, default=find_default_vietmap())
    parser.add_argument("--vietmap-manifest", type=Path, default=None)
    parser.add_argument("--roadsen-tsv", type=Path, default=None)
    parser.add_argument("--existing-cameras", type=Path, default=None)
    parser.add_argument("--curated-dir", type=Path, default=None)
    parser.add_argument("--osm-gt", type=Path, default=None)
    parser.add_argument("--osm-signs", type=Path, default=None)
    parser.add_argument("--osm-pbf", type=Path, default=None)
    parser.add_argument("--osm-danger-refs", type=Path, default=None)
    parser.add_argument("--tiles", type=Path, default=None, help="tiles.bin để lấy fallback cờ BRIDGE 0x04")
    parser.add_argument("--out", type=Path, default=find_default_out())
    parser.add_argument("--version", type=str, default=None)
    parser.add_argument("--alerts-only", action="store_true", default=False)
    parser.add_argument("--no-sign", action="store_true", default=False)
    args = parser.parse_args()

    build_clean_alerts(
        wyn_csv=args.wyn,
        secrect_bin=args.vietmap,
        output_dir=args.out,
        version_str=args.version,
        alerts_only=args.alerts_only,
        curated_dir=args.curated_dir,
        osm_gt_path=args.osm_gt,
        osm_signs_path=args.osm_signs,
        sign_output=not args.no_sign,
        existing_cameras_path=args.existing_cameras,
        roadsen_tsv_path=args.roadsen_tsv,
        osm_pbf_path=args.osm_pbf,
        osm_danger_refs_path=args.osm_danger_refs,
        tiles_bin_path=args.tiles,
        vietmap_manifest_path=args.vietmap_manifest,
    )


if __name__ == "__main__":
    main()
