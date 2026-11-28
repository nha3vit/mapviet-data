#!/usr/bin/env python3
"""
enrich_network.py — Làm giàu tốc độ giới hạn & tên đường cho tiles.bin từ VietMap roadsen.bin.

Đọc 1.88M tuyến đường đã giải nén/giải mã từ phân vùng roadsenz.bin của VietMap SpeedMap M2:
  1. Cập nhật speedSrc=0 (UNKNOWN / speedLimit=-1) -> tốc độ thực tế theo chiều lưu thông.
  2. Thay thế speedSrc=4 (DEFAULT theo Thông tư 31 suy đoán) -> tốc độ thực tế VietMap (speedSrc=1).
  3. Bảo toàn speedSrc in {1,2,3} khi speedLimit <= 40 km/h (biển nội bộ sân bay/cầu yếu/khu dân cư hẹp);
     cập nhật các đoạn OSM speedLimit >= 50 km/h bị cũ/lệch theo giá trị thực tế VietMap.
  4. Bổ sung tên đường còn thiếu (seg_names[segId] == 0) từ tên đường roadsen trong <= 12m,
     cập nhật names.bin (VNNM v2) và seg_names.bin mà vẫn giữ nguyên 100% segId & index.bin cho dẫn đường.

Tự động biên dịch native/enrich_tiles.c (-O3) để chạy trong ~3 giây trên toàn quốc (8.85M đoạn),
có fallback Python thuần cho môi trường không có trình biên dịch C hoặc kiểm thử unit test.
"""

from __future__ import annotations

import json
import math
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

try:
    from tools import vietmap_decode as vmd
except ImportError:
    import vietmap_decode as vmd


SEGMENT_STRUCT = struct.Struct("<IiiiiHBBhBB")
NAME_HEADER_STRUCT = struct.Struct("<4sHIIH")
FLAG_NO_VEHICLE = 0x20


def _haversine_m(la1: float, lo1: float, la2: float, lo2: float) -> float:
    r = 6371000.0
    p1, p2 = math.radians(la1), math.radians(la2)
    dp = math.radians(la2 - la1)
    dl = math.radians(lo2 - lo1)
    a = math.sin(dp / 2.0) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2.0) ** 2
    return 2.0 * r * math.atan2(math.sqrt(a), math.sqrt(max(0.0, 1.0 - a)))


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


def _angle_diff(a: float, b: float) -> float:
    d = abs((a % 360.0) - (b % 360.0))
    return 360.0 - d if d > 180.0 else d


def _ensure_native_enricher() -> Path | None:
    nd = Path(__file__).resolve().parent / "native"
    src = nd / "enrich_tiles.c"
    if not src.exists():
        return None
    exe = nd / "enrich_tiles"
    if exe.exists() and exe.stat().st_mtime >= src.stat().st_mtime:
        return exe
    cc = vmd._find_compiler()
    if not cc:
        return None
    try:
        subprocess.run([cc, "-O3", "-Wall", "-o", str(exe), str(src), "-lm"], check=True, capture_output=True)
        return exe
    except Exception:
        return None


def _enrich_tiles_python(src_dir: Path, roadsen_tsv: Path, dst_dir: Path) -> dict:
    """Fallback Python thuần — thực hiện đúng logic của enrich_tiles.c."""
    dst_dir.mkdir(parents=True, exist_ok=True)
    names_raw = (src_dir / "names.bin").read_bytes()
    magic, ver, cnt, pool_bytes, _ = NAME_HEADER_STRUCT.unpack_from(names_raw, 0)
    if magic != b"VNNM":
        raise ValueError(f"names.bin magic không hợp lệ: {magic!r}")
    offs = struct.unpack_from(f"<{cnt}I", names_raw, NAME_HEADER_STRUCT.size) if cnt else ()
    pool = names_raw[NAME_HEADER_STRUCT.size + cnt * 4 :]

    ordered_names: list[str] = []
    name_to_id: dict[str, int] = {}
    for off in offs:
        end = pool.find(b"\x00", off)
        s = (pool[off:end] if end != -1 else pool[off:]).decode("utf-8", errors="replace")
        ordered_names.append(s)
        if s and s not in name_to_id:
            name_to_id[s] = len(ordered_names)

    def intern_name(s: str) -> int:
        if not s:
            return 0
        existing = name_to_id.get(s)
        if existing:
            return existing
        ordered_names.append(s)
        nid = len(ordered_names)
        name_to_id[s] = nid
        return nid

    seg_names_bytes = bytearray((src_dir / "seg_names.bin").read_bytes())
    n_seg_names = len(seg_names_bytes) // 4
    seg_names = list(struct.unpack(f"<{n_seg_names}I", seg_names_bytes)) if n_seg_names else []

    tiles_buf = bytearray((src_dir / "tiles.bin").read_bytes())
    n_segs = len(tiles_buf) // SEGMENT_STRUCT.size

    cell_size = 0.005
    rgrid: dict[tuple[int, int], list[tuple[float, float, float, float, int, int, str]]] = {}
    rlines = 0
    nsub = 0
    for rp in vmd.iter_decoded_roadsen_tsv(roadsen_tsv):
        rlines += 1
        for k in range(len(rp.coords) - 1):
            la1, lo1 = rp.coords[k]
            la2, lo2 = rp.coords[k + 1]
            cx = int(((la1 + la2) * 0.5 - 8.0) / cell_size)
            cy = int(((lo1 + lo2) * 0.5 - 102.0) / cell_size)
            rgrid.setdefault((cx, cy), []).append((la1, lo1, la2, lo2, rp.speed_fwd, rp.speed_bwd, rp.name))
            nsub += 1

    cnt_unk_filled = cnt_def_updated = cnt_def_same = cnt_osm_kept_low = cnt_osm_updated = cnt_name_added = cnt_unmatched = 0
    for i in range(n_segs):
        off = i * SEGMENT_STRUCT.size
        seg_id, s_lat_e7, s_lon_e7, e_lat_e7, e_lon_e7, hd_deg, rcls, direction, spd, spd_src, flg = (
            SEGMENT_STRUCT.unpack_from(tiles_buf, off)
        )
        if rcls > 3 or (flg & FLAG_NO_VEHICLE):
            continue
        midla = (s_lat_e7 + e_lat_e7) * 0.5e-7
        midlo = (s_lon_e7 + e_lon_e7) * 0.5e-7
        c0 = int((midla - 8.0) / cell_size)
        c1 = int((midlo - 102.0) / cell_size)

        best_score = 1e9
        best = None
        for dr in (-1, 0, 1):
            for dc in (-1, 0, 1):
                for la1, lo1, la2, lo2, sa, sb, rname in rgrid.get((c0 + dr, c1 + dc), ()):
                    d, rhd = _pt_seg_dist_and_hd(midla, midlo, la1, lo1, la2, lo2)
                    if d > 15.0:
                        continue
                    df = _angle_diff(float(hd_deg), rhd)
                    axis_df = df if df <= 30.0 else (180.0 - df if df >= 150.0 else 999.0)
                    if axis_df <= 30.0:
                        score = d + axis_df * 0.3
                        if score < best_score:
                            best_score = score
                            best = (d, rhd, sa, sb, rname)
        if best is None:
            cnt_unmatched += 1
            continue

        best_d, best_rhd, sa, sb, rname = best
        is_fwd = _angle_diff(float(hd_deg), best_rhd) <= 30.0
        if direction == 1:
            vm_spd = sa if is_fwd else sb
            if vm_spd == 0:
                vm_spd = sa if sa > 0 else sb
        elif direction == 2:
            vm_spd = sb if is_fwd else sa
            if vm_spd == 0:
                vm_spd = sa if sa > 0 else sb
        else:
            s_match = sa if is_fwd else sb
            s_opp = sb if is_fwd else sa
            if s_match > 0 and s_opp > 0:
                vm_spd = min(s_match, s_opp)
            else:
                vm_spd = s_match if s_match > 0 else s_opp

        new_spd, new_src = spd, spd_src
        if 20 <= vm_spd <= 120:
            if spd_src == 0 or spd == -1:
                new_spd, new_src = vm_spd, 1
                cnt_unk_filled += 1
            elif spd_src == 4:
                if spd != vm_spd:
                    cnt_def_updated += 1
                else:
                    cnt_def_same += 1
                new_spd, new_src = vm_spd, 1
            elif 1 <= spd_src <= 3:
                if spd <= 40:
                    cnt_osm_kept_low += 1
                elif spd != vm_spd:
                    new_spd = vm_spd
                    cnt_osm_updated += 1

        if new_spd != spd or new_src != spd_src:
            SEGMENT_STRUCT.pack_into(
                tiles_buf, off,
                seg_id, s_lat_e7, s_lon_e7, e_lat_e7, e_lon_e7, hd_deg, rcls, direction, new_spd, new_src, flg
            )

        if rname and best_d <= 12.0 and seg_id < n_seg_names and seg_names[seg_id] == 0:
            nid = intern_name(rname)
            if nid > 0:
                seg_names[seg_id] = nid
                cnt_name_added += 1

    (dst_dir / "tiles.bin").write_bytes(bytes(tiles_buf))

    new_offs: list[int] = []
    new_pool = bytearray()
    for nm in ordered_names:
        new_offs.append(len(new_pool))
        new_pool += nm.encode("utf-8") + b"\x00"
    new_cnt = len(ordered_names)
    out_names = bytearray(NAME_HEADER_STRUCT.pack(b"VNNM", 2, new_cnt, len(new_pool), 0))
    if new_cnt:
        out_names += struct.pack(f"<{new_cnt}I", *new_offs)
    out_names += new_pool
    (dst_dir / "names.bin").write_bytes(bytes(out_names))
    if n_seg_names:
        (dst_dir / "seg_names.bin").write_bytes(struct.pack(f"<{n_seg_names}I", *seg_names))
    else:
        (dst_dir / "seg_names.bin").write_bytes(b"")

    return {
        "polylines": rlines,
        "subsegments": nsub,
        "total_segs": n_segs,
        "unmatched": cnt_unmatched,
        "unknown_filled": cnt_unk_filled,
        "default_changed": cnt_def_updated,
        "default_confirmed": cnt_def_same,
        "osm_kept_low": cnt_osm_kept_low,
        "osm_updated": cnt_osm_updated,
        "names_added": cnt_name_added,
        "unique_names_before": cnt,
        "unique_names_after": new_cnt,
    }


def enrich_speedmap_network(
    src_dir: Path,
    dst_dir: Path | None = None,
    vietmap_path: Path | None = None,
    manifest_path: Path | None = None,
    roadsen_tsv: Path | None = None,
    prefer_native: bool = True,
) -> dict:
    """Làm giàu mạng đường tiles.bin / names.bin / seg_names.bin từ VietMap roadsen."""
    src_dir = Path(src_dir)
    dst = Path(dst_dir) if dst_dir else src_dir
    dst.mkdir(parents=True, exist_ok=True)

    # Nếu dst_dir != src_dir, sao chép trước các file đồng hành (index.bin, metadata.bin, v.v.)
    if dst.resolve() != src_dir.resolve():
        for fn in ("index.bin", "metadata.bin", "cameras.bin", "signs.bin"):
            sp = src_dir / fn
            if sp.exists():
                shutil.copy2(sp, dst / fn)

    with tempfile.TemporaryDirectory(prefix="enrich_roadsen_") as tmp_s:
        tmp_dir = Path(tmp_s)
        tsv_path = Path(roadsen_tsv) if roadsen_tsv else None
        if tsv_path is None or not tsv_path.exists():
            full_bin = vmd.hydrate_full_secrect_bin(vietmap_path=vietmap_path, manifest_path=manifest_path)
            if full_bin is None:
                print("[WARN] Không có secrect.bin đầy đủ (kèm roadsen.bin); giữ nguyên mạng đường gốc.")
                if dst.resolve() != src_dir.resolve():
                    for fn in ("tiles.bin", "names.bin", "seg_names.bin"):
                        sp = src_dir / fn
                        if sp.exists():
                            shutil.copy2(sp, dst / fn)
                return {"status": "skipped", "reason": "missing_roadsenz"}
            tsv_path = tmp_dir / "roadsen_decoded.tsv"
            vmd.extract_roadsenz_tsv(full_bin, tsv_path, decode_cipher=True)

        native_exe = _ensure_native_enricher() if prefer_native else None
        if native_exe is not None:
            proc = subprocess.run(
                [str(native_exe), str(src_dir), str(tsv_path), str(dst)],
                check=True,
                capture_output=True,
                text=True,
            )
            stats = json.loads(proc.stdout.strip().splitlines()[-1])
            stats["engine"] = "native_c"
        else:
            stats = _enrich_tiles_python(src_dir, tsv_path, dst)
            stats["engine"] = "python"

        stats["status"] = "ok"
        return stats


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Làm giàu tốc độ & tên đường tiles.bin từ VietMap roadsen.bin")
    parser.add_argument("src_dir", type=Path, help="Thư mục chứa tiles.bin, names.bin, seg_names.bin")
    parser.add_argument("--dst", type=Path, default=None, help="Thư mục đầu ra (mặc định ghi đè ngay src_dir)")
    parser.add_argument("--vietmap", type=Path, default=None, help="Đường dẫn secrect.bin (bản đầy đủ hoặc cắt gọn)")
    parser.add_argument("--manifest", type=Path, default=None, help="Đường dẫn vietmap_manifest.json để tự tải roadsen nếu cần")
    parser.add_argument("--roadsen-tsv", type=Path, default=None, help="File roadsen_decoded.tsv đã giải mã sẵn")
    parser.add_argument("--python-only", action="store_true", help="Ép dùng engine Python thay vì native C")
    args = parser.parse_args()

    stats = enrich_speedmap_network(
        src_dir=args.src_dir,
        dst_dir=args.dst or args.src_dir,
        vietmap_path=args.vietmap,
        manifest_path=args.manifest,
        roadsen_tsv=args.roadsen_tsv,
        prefer_native=not args.python_only,
    )
    print(json.dumps(stats, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
