#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Bản sao từ VietHUD/tools/validate_speedmap.py — nguồn chuẩn là VietHUD/tools; sửa ở đó rồi chép lại
"""
tools/validate_speedmap.py — Bộ kiểm định chuẩn bộ dữ liệu SpeedMap VietHUD.

CLI:
  validate_speedmap.py <dir> [--pub <pem>] [--json out.json]

Thoát mã:
  0 nếu tất cả các kiểm tra đều ĐẠT (Passed).
  1 nếu có bất kỳ lỗi (Error) nào. (Cảnh báo Warning không làm trượt).

Các hạng mục kiểm định:
  1. manifest: Dòng 1 version YYYY.MM.DD.HHMM; mỗi file tồn tại, đúng size + sha256;
     nếu có .sig và --pub -> xác thực chữ ký ECDSA P-256.
  2. metadata: Magic 'SLMP', version 2, tileCount = len(index)/28, segmentCount,
     crc32(index) khớp chính xác.
  3. index: tileId tăng dần, offset liền mạch, offset cuối = size tiles.bin, bbox hợp lệ.
  4. tiles: Mẫu ngẫu nhiên 5.000 segment: toạ độ trong bbox tile ± 0.02°, heading 0..359,
     roadClass 1..3, speed == -1 hoặc 5..130.
  5. cameras: ID duy nhất, toạ độ VN, speed in {-1, 0} U {5..130 bội số của 5},
     heading 0..359 hoặc 0xFFFF.
  6. signs: Magic 'VNSG', count khớp size, crc32 khớp, ID duy nhất,
     type in {1, 2, 3, 4, 5, 6, 10}, speed chỉ có ở type 1.
  7. names/seg_names: Header names v2 (VNNM, ver=2), seg_names đủ (maxSegId+1)*4 bytes.
  8. trùng lặp gần: Số cặp camera cùng hướng cách nhau < 5m (Cảnh báo, không phải lỗi).
"""

import argparse
import hashlib
import json
import math
import os
import random
import re
import struct
import sys
import zlib
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from tools import sign_manifest
except ImportError:
    import sign_manifest

# Bounding box chuẩn Việt Nam
LAT_MIN, LAT_MAX = 8.0, 24.0
LON_MIN, LON_MAX = 102.0, 110.5

METADATA_FMT = "<4sH16s16sQIIfiihI64sI"  # 140 bytes
INDEX_ENTRY_FMT = "<IiiiiII"             # 28 bytes
SEGMENT_FMT = "<IiiiiHBBhBB"             # 28 bytes
CAMERA_FMT = "<QiihH"                    # 20 bytes
SIGN_HEADER_FMT = "<4sHIHII"             # 20 bytes
SIGN_POINT_FMT = "<IiiHBBBBH"            # 20 bytes
NAME_HEADER_FMT = "<4sHIIH"              # 16 bytes


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


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class SpeedMapValidator:
    def __init__(self, target_dir: Path, pub_key_path: Path | None = None, sample_size: int = 5000, seed: int = 42, sounds_ref_dir: Path | None = None, prev_dir: Path | None = None):
        self.target_dir = Path(target_dir)
        self.pub_key_path = Path(pub_key_path) if pub_key_path else None
        self.sample_size = sample_size
        self.seed = seed
        self.sounds_ref_dir = Path(sounds_ref_dir) if sounds_ref_dir else None
        self.prev_dir = Path(prev_dir) if prev_dir else None

        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.section_results: dict[str, dict] = {}
        self.max_seg_id = 0
        self.metadata_seg_count = 0

    def add_error(self, section: str, msg: str):
        self.errors.append(f"[{section}] {msg}")
        self.section_results[section]["errors"].append(msg)
        self.section_results[section]["status"] = "FAILED"

    def add_warning(self, section: str, msg: str):
        self.warnings.append(f"[{section}] {msg}")
        self.section_results[section]["warnings"].append(msg)

    def _init_section(self, name: str):
        self.section_results[name] = {
            "status": "PASSED",
            "errors": [],
            "warnings": [],
            "details": {},
        }

    # -------------------------------------------------------------------------
    # 1. Manifest
    # -------------------------------------------------------------------------
    def validate_manifest(self):
        sec = "manifest"
        self._init_section(sec)
        mf_path = self.target_dir / "manifest.txt"
        if not mf_path.exists():
            self.add_error(sec, f"Không tìm thấy file {mf_path.name}")
            return

        lines = mf_path.read_text(encoding="utf-8").strip().splitlines()
        if not lines:
            self.add_error(sec, "manifest.txt rỗng")
            return

        header = lines[0].strip()
        self.section_results[sec]["details"]["header"] = header
        m = re.match(r"^version (\d{4}\.\d{2}\.\d{2}\.\d{4})$", header)
        if not m:
            self.add_error(sec, f"Dòng 1 không đúng định dạng 'version YYYY.MM.DD.HHMM' (nhận được: '{header}')")

        verified_files = 0
        for idx, line in enumerate(lines[1:], start=2):
            parts = line.strip().split()
            if len(parts) != 3:
                self.add_error(sec, f"Dòng {idx} sai cấu trúc (kỳ vọng: <file> <size> <sha256>): '{line}'")
                continue
            fname, size_str, exp_hash = parts
            fpath = self.target_dir / fname
            if not fpath.exists():
                self.add_error(sec, f"File liệt kê trong manifest không tồn tại: {fname}")
                continue

            try:
                exp_size = int(size_str)
            except ValueError:
                self.add_error(sec, f"Kích thước không hợp lệ cho {fname}: {size_str}")
                continue

            act_size = fpath.stat().st_size
            if act_size != exp_size:
                self.add_error(sec, f"{fname} sai kích thước: kỳ vọng {exp_size}, thực tế {act_size}")

            act_hash = sha256_file(fpath)
            if act_hash.lower() != exp_hash.lower():
                self.add_error(sec, f"{fname} sai SHA-256: kỳ vọng {exp_hash}, thực tế {act_hash}")

            verified_files += 1

        self.section_results[sec]["details"]["verified_files_count"] = verified_files

        # Kiểm tra chữ ký .sig nếu có
        sig_path = self.target_dir / "manifest.txt.sig"
        if sig_path.exists():
            self.section_results[sec]["details"]["has_signature"] = True
            if self.pub_key_path:
                try:
                    pub = sign_manifest.load_public_key(self.pub_key_path)
                    valid_sig = sign_manifest.verify_manifest(mf_path, pub_key=pub)
                    if valid_sig:
                        self.section_results[sec]["details"]["signature_verified"] = True
                    else:
                        self.add_error(sec, "Chữ ký manifest.txt.sig không hợp lệ với public key cung cấp")
                except Exception as e:
                    self.add_error(sec, f"Lỗi xác thực chữ ký: {e}")
            else:
                self.add_warning(sec, "Có manifest.txt.sig nhưng không cung cấp --pub để kiểm tra chữ ký")
        else:
            self.section_results[sec]["details"]["has_signature"] = False

    # -------------------------------------------------------------------------
    # 2. Metadata
    # -------------------------------------------------------------------------
    def validate_metadata(self):
        sec = "metadata"
        self._init_section(sec)
        meta_path = self.target_dir / "metadata.bin"
        if not meta_path.exists():
            self.add_error(sec, f"Không tìm thấy {meta_path.name}")
            return

        data = meta_path.read_bytes()
        if len(data) != 140:
            self.add_error(sec, f"metadata.bin sai kích thước: kỳ vọng 140 bytes, nhận được {len(data)}")
            return

        magic, ver, reg, mver, ts, tile_cnt, seg_cnt, tsize, tlat, tlon, thd, trid, attr, idx_crc = struct.unpack(
            METADATA_FMT, data
        )

        self.metadata_seg_count = seg_cnt
        self.section_results[sec]["details"] = {
            "magic": magic.decode("ascii", errors="replace"),
            "version": ver,
            "region": reg.decode("ascii", errors="replace").strip("\x00"),
            "map_version": mver.decode("ascii", errors="replace").strip("\x00"),
            "tileCount": tile_cnt,
            "segmentCount": seg_cnt,
            "index_crc32": f"0x{idx_crc:08X}",
        }

        if magic != b"SLMP":
            self.add_error(sec, f"Magic không phải 'SLMP': nhận được {magic}")
        if ver != 2:
            self.add_error(sec, f"Version không phải 2: nhận được {ver}")

        idx_path = self.target_dir / "index.bin"
        if idx_path.exists():
            idx_data = idx_path.read_bytes()
            actual_tiles = len(idx_data) // 28
            if tile_cnt != actual_tiles:
                self.add_error(sec, f"tileCount ({tile_cnt}) không khớp số entry index.bin ({actual_tiles})")

            act_crc = zlib.crc32(idx_data) & 0xFFFFFFFF
            if idx_crc != act_crc:
                self.add_error(sec, f"CRC32 index.bin không khớp: metadata=0x{idx_crc:08X}, thực tế=0x{act_crc:08X}")
        else:
            self.add_error(sec, "Không tìm thấy index.bin để đối chiếu metadata")

    # -------------------------------------------------------------------------
    # 3. Index
    # -------------------------------------------------------------------------
    def validate_index(self):
        sec = "index"
        self._init_section(sec)
        idx_path = self.target_dir / "index.bin"
        tiles_path = self.target_dir / "tiles.bin"

        if not idx_path.exists():
            self.add_error(sec, "Không tìm thấy index.bin")
            return
        if not tiles_path.exists():
            self.add_error(sec, "Không tìm thấy tiles.bin")
            return

        idx_data = idx_path.read_bytes()
        if len(idx_data) % 28 != 0:
            self.add_error(sec, f"index.bin kích thước {len(idx_data)} không chia hết cho 28")

        tiles_size = tiles_path.stat().st_size
        entry_count = len(idx_data) // 28
        self.section_results[sec]["details"]["entry_count"] = entry_count

        prev_tid = -1
        expected_offset = 0
        bad_tid_order = 0
        bad_offsets = 0
        bad_bboxes = 0

        for i in range(entry_count):
            tid, minLat, maxLat, minLon, maxLon, off, sz = struct.unpack_from(INDEX_ENTRY_FMT, idx_data, i * 28)

            if tid <= prev_tid:
                bad_tid_order += 1
            prev_tid = tid

            if off != expected_offset:
                bad_offsets += 1
            expected_offset = off + sz

            min_lat_deg, max_lat_deg = minLat / 1e7, maxLat / 1e7
            min_lon_deg, max_lon_deg = minLon / 1e7, maxLon / 1e7

            if not (min_lat_deg <= max_lat_deg and min_lon_deg <= max_lon_deg):
                bad_bboxes += 1
            elif not (0.0 <= min_lat_deg <= 35.0 and 95.0 <= min_lon_deg <= 125.0):
                bad_bboxes += 1

        if bad_tid_order > 0:
            self.add_error(sec, f"Có {bad_tid_order} tileId không tăng dần nghiêm ngặt")
        if bad_offsets > 0:
            self.add_error(sec, f"Có {bad_offsets} vị trí offset không liền mạch trong index.bin")
        if expected_offset != tiles_size:
            self.add_error(sec, f"Offset cuối ({expected_offset}) không khớp kích thước tiles.bin ({tiles_size})")
        if bad_bboxes > 0:
            self.add_error(sec, f"Có {bad_bboxes} tile có bounding box không hợp lệ")

    # -------------------------------------------------------------------------
    # 4. Tiles
    # -------------------------------------------------------------------------
    def validate_tiles(self):
        sec = "tiles"
        self._init_section(sec)
        idx_path = self.target_dir / "index.bin"
        tiles_path = self.target_dir / "tiles.bin"

        if not idx_path.exists() or not tiles_path.exists():
            self.add_error(sec, "Thiếu index.bin hoặc tiles.bin")
            return

        idx_data = idx_path.read_bytes()
        entry_count = len(idx_data) // 28
        if entry_count == 0:
            self.add_error(sec, "index.bin không có tile nào")
            return

        rng = random.Random(self.seed)
        # Thu thập các tile để lấy mẫu segment
        tile_indices = list(range(entry_count))
        rng.shuffle(tile_indices)

        sampled_segments = 0
        bad_bbox_coords = 0
        bad_heading = 0
        bad_road_class = 0
        bad_speed = 0
        scanned_max_sid = 0

        with open(tiles_path, "rb") as tf:
            for t_idx in tile_indices:
                tid, minLat, maxLat, minLon, maxLon, off, sz = struct.unpack_from(
                    INDEX_ENTRY_FMT, idx_data, t_idx * 28
                )
                t_min_lat = (minLat / 1e7) - 0.02
                t_max_lat = (maxLat / 1e7) + 0.02
                t_min_lon = (minLon / 1e7) - 0.02
                t_max_lon = (maxLon / 1e7) + 0.02

                tf.seek(off)
                tbytes = tf.read(sz)
                n_segs = sz // 28

                for s_i in range(n_segs):
                    sid, la1, lo1, la2, lo2, hd, rclass, rdir, spd, src, flg = struct.unpack_from(
                        SEGMENT_FMT, tbytes, s_i * 28
                    )
                    if sid > scanned_max_sid:
                        scanned_max_sid = sid

                    # Kiểm tra mẫu segment
                    if sampled_segments < self.sample_size or n_segs <= 1:
                        sampled_segments += 1
                        lat1, lon1 = la1 / 1e7, lo1 / 1e7
                        lat2, lon2 = la2 / 1e7, lo2 / 1e7

                        if not (t_min_lat <= lat1 <= t_max_lat and t_min_lon <= lon1 <= t_max_lon and
                                t_min_lat <= lat2 <= t_max_lat and t_min_lon <= lon2 <= t_max_lon):
                            bad_bbox_coords += 1

                        if not (0 <= hd <= 359):
                            bad_heading += 1

                        if not (1 <= rclass <= 3):
                            bad_road_class += 1

                        if not (spd == -1 or (5 <= spd <= 130)):
                            bad_speed += 1

                if sampled_segments >= self.sample_size and t_idx > 500:
                    # Đã đủ mẫu đại diện và đã duyệt một số tile
                    break

        self.max_seg_id = scanned_max_sid
        self.section_results[sec]["details"] = {
            "sampled_segments": sampled_segments,
            "max_sampled_seg_id": scanned_max_sid,
        }

        if bad_bbox_coords > 0:
            self.add_error(sec, f"Có {bad_bbox_coords} segment toạ độ lệch ngoài tile bbox ±0.02°")
        if bad_heading > 0:
            self.add_error(sec, f"Có {bad_heading} segment heading ngoài dải 0..359")
        if bad_road_class > 0:
            self.add_error(sec, f"Có {bad_road_class} segment roadClass ngoài dải 1..3")
        if bad_speed > 0:
            self.add_error(sec, f"Có {bad_speed} segment speed không hợp lệ (không phải -1 hoặc 5..130)")

    # -------------------------------------------------------------------------
    # 5. Cameras
    # -------------------------------------------------------------------------
    def validate_cameras(self):
        sec = "cameras"
        self._init_section(sec)
        cam_path = self.target_dir / "cameras.bin"
        if not cam_path.exists():
            self.add_warning(sec, "Không tìm thấy cameras.bin")
            return

        data = cam_path.read_bytes()
        if len(data) % 20 != 0:
            self.add_error(sec, f"cameras.bin kích thước {len(data)} không chia hết cho 20")
            return

        total_cams = len(data) // 20
        self.section_results[sec]["details"]["total_cameras"] = total_cams

        seen_ids = set()
        dup_ids = 0
        bad_pos = 0
        bad_speed = 0
        bad_heading = 0

        for i in range(total_cams):
            cid, lat_e7, lon_e7, spd, hd = struct.unpack_from(CAMERA_FMT, data, i * 20)
            if cid in seen_ids:
                dup_ids += 1
            seen_ids.add(cid)

            lat = lat_e7 / 1e7
            lon = lon_e7 / 1e7
            if not (LAT_MIN <= lat <= LAT_MAX and LON_MIN <= lon <= LON_MAX):
                bad_pos += 1

            if not (spd in (-1, 0) or (5 <= spd <= 130 and spd % 5 == 0)):
                bad_speed += 1

            if not (0 <= hd <= 359 or hd == 0xFFFF):
                bad_heading += 1

        if dup_ids > 0:
            self.add_error(sec, f"Có {dup_ids} camera bị trùng ID")
        if bad_pos > 0:
            self.add_error(sec, f"Có {bad_pos} camera toạ độ ngoài lãnh thổ Việt Nam")
        if bad_speed > 0:
            self.add_error(sec, f"Có {bad_speed} camera tốc độ sai chuẩn (phải là -1, 0 hoặc bội số của 5 trong [5, 130])")
        if bad_heading > 0:
            self.add_error(sec, f"Có {bad_heading} camera heading ngoài dải 0..359 và 0xFFFF")

    # -------------------------------------------------------------------------
    # 6. Signs
    # -------------------------------------------------------------------------
    def validate_signs(self):
        sec = "signs"
        self._init_section(sec)
        signs_path = self.target_dir / "signs.bin"
        if not signs_path.exists():
            self.add_warning(sec, "Không tìm thấy signs.bin")
            return

        data = signs_path.read_bytes()
        if len(data) < 20:
            self.add_error(sec, f"signs.bin quá ngắn ({len(data)} bytes)")
            return

        magic, ver, count, reserved, header_crc, ts = struct.unpack_from(SIGN_HEADER_FMT, data, 0)
        self.section_results[sec]["details"] = {
            "magic": magic.decode("ascii", errors="replace"),
            "version": ver,
            "signCount": count,
            "timestamp": ts,
        }

        if magic != b"VNSG":
            self.add_error(sec, f"Magic signs.bin không phải 'VNSG': nhận được {magic}")

        expected_size = 20 + count * 20
        if len(data) != expected_size:
            self.add_error(sec, f"Kích thước signs.bin không khớp signCount: kỳ vọng {expected_size}, thực tế {len(data)}")

        body = data[20:]
        act_crc = zlib.crc32(body) & 0xFFFFFFFF
        if header_crc != act_crc:
            self.add_error(sec, f"CRC32 signs.bin không khớp: header=0x{header_crc:08X}, thực tế=0x{act_crc:08X}")

        seen_ids = set()
        dup_ids = 0
        bad_types = 0
        bad_speeds = 0
        total_sign_1 = 0
        speed_0_sign_1 = 0
        allowed_types = {1, 2, 3, 5, 6, 10}

        actual_points = len(body) // 20
        for i in range(actual_points):
            sid, lat_e7, lon_e7, hd, stype, spd, sub, flg, sres = struct.unpack_from(SIGN_POINT_FMT, body, i * 20)
            if sid in seen_ids:
                dup_ids += 1
            seen_ids.add(sid)

            if stype not in allowed_types:
                bad_types += 1

            if stype != 1 and spd != 0:
                bad_speeds += 1
            elif stype == 1:
                total_sign_1 += 1
                if spd == 0:
                    speed_0_sign_1 += 1
                if not (spd == 0 or (5 <= spd <= 130 and spd % 5 == 0)):
                    bad_speeds += 1

        if dup_ids > 0:
            self.add_error(sec, f"Có {dup_ids} biển báo bị trùng ID")
        if bad_types > 0:
            self.add_error(sec, f"Có {bad_types} biển báo có sign_type không thuộc {{1,2,3,5,6,10}} (sign_type 4 cấm trong signs.bin theo chuẩn R3)")
        if bad_speeds > 0:
            self.add_error(sec, f"Có {bad_speeds} biển báo sai tốc độ (speed chỉ cho phép ở type 1)")
        if total_sign_1 > 0:
            ratio_0 = speed_0_sign_1 / total_sign_1
            self.section_results[sec]["details"]["speed_0_sign_1_ratio"] = round(ratio_0, 4)
            self.section_results[sec]["details"]["speed_0_sign_1_count"] = speed_0_sign_1
            self.section_results[sec]["details"]["total_sign_1_count"] = total_sign_1

            if self.prev_dir:
                prev_signs_path = self.prev_dir / "signs.bin"
                if prev_signs_path.exists():
                    pdata = prev_signs_path.read_bytes()
                    pbody = pdata[20:] if len(pdata) >= 20 else b""
                    p_pts = len(pbody) // 20
                    p_tot_1 = 0
                    p_sp0_1 = 0
                    for pi in range(p_pts):
                        _, _, _, _, pstype, pspd, _, _, _ = struct.unpack_from(SIGN_POINT_FMT, pbody, pi * 20)
                        if pstype == 1:
                            p_tot_1 += 1
                            if pspd == 0:
                                p_sp0_1 += 1
                    if p_tot_1 > 0:
                        prev_ratio_0 = p_sp0_1 / p_tot_1
                        delta_pp = (ratio_0 - prev_ratio_0) * 100.0
                        self.section_results[sec]["details"]["prev_speed_0_sign_1_ratio"] = round(prev_ratio_0, 4)
                        self.section_results[sec]["details"]["speed_0_sign_1_delta_pp"] = round(delta_pp, 2)
                        if abs(delta_pp) > 5.0:
                            self.add_warning(
                                sec,
                                f"Tỷ lệ biển loại 1 tốc độ 0 ({ratio_0*100:.2f}%) thay đổi quá ±5 điểm % so với bản trước ({prev_ratio_0*100:.2f}%, delta={delta_pp:+.2f}%)"
                            )
                        else:
                            print(f"[INFO] [{sec}] Tỷ lệ biển loại 1 tốc độ 0: {ratio_0*100:.2f}% ({speed_0_sign_1}/{total_sign_1}), bản trước: {prev_ratio_0*100:.2f}% (delta={delta_pp:+.2f}%, trong ngưỡng ±5 điểm %)")
                    else:
                        print(f"[INFO] [{sec}] Bản trước không có biển loại 1 để so sánh.")
                else:
                    print(f"[INFO] [{sec}] Không tìm thấy signs.bin trong thư mục bản trước: {self.prev_dir}")
            else:
                print(f"[INFO] [{sec}] Tỷ lệ biển loại 1 tốc độ 0: {ratio_0*100:.2f}% ({speed_0_sign_1}/{total_sign_1}) (không có --prev nên không so sánh cảnh báo)")

    # -------------------------------------------------------------------------
    # 7. Names & Seg_names
    # -------------------------------------------------------------------------
    def validate_names_and_seg_names(self):
        sec = "names_and_seg_names"
        self._init_section(sec)
        names_path = self.target_dir / "names.bin"
        seg_names_path = self.target_dir / "seg_names.bin"

        if not names_path.exists():
            self.add_error(sec, "Không tìm thấy names.bin")
            return
        if not seg_names_path.exists():
            self.add_error(sec, "Không tìm thấy seg_names.bin")
            return

        # 1. Kiểm tra names.bin
        ndata = names_path.read_bytes()
        if len(ndata) < 16:
            self.add_error(sec, f"names.bin quá ngắn ({len(ndata)} bytes)")
            return

        magic, ver, count, pool_bytes, res = struct.unpack(NAME_HEADER_FMT, ndata[:16])
        self.section_results[sec]["details"]["names_count"] = count
        self.section_results[sec]["details"]["names_version"] = ver

        if magic != b"VNNM":
            self.add_error(sec, f"names.bin magic không phải 'VNNM': nhận được {magic}")
        if ver != 2:
            self.add_error(sec, f"names.bin version không phải 2 (V2): nhận được {ver}")

        expected_names_len = 16 + count * 4 + pool_bytes
        if len(ndata) != expected_names_len:
            self.add_error(sec, f"Kích thước names.bin không khớp header: kỳ vọng {expected_names_len}, thực tế {len(ndata)}")

        # 2. Kiểm tra seg_names.bin
        sdata = seg_names_path.read_bytes()
        if len(sdata) % 4 != 0:
            self.add_error(sec, f"seg_names.bin kích thước {len(sdata)} không chia hết cho 4")

        seg_names_count = len(sdata) // 4
        self.section_results[sec]["details"]["seg_names_entries"] = seg_names_count

        # Kiểm tra đủ (maxSegId + 1) * 4
        target_max_sid = max(self.max_seg_id, self.metadata_seg_count)
        if target_max_sid > 0:
            expected_seg_names_len = (target_max_sid + 1) * 4
            if len(sdata) < expected_seg_names_len:
                self.add_error(
                    sec,
                    f"seg_names.bin thiếu kích thước cho maxSegId={target_max_sid}: "
                    f"kỳ vọng ít nhất {expected_seg_names_len} bytes, thực tế {len(sdata)} bytes"
                )

    # -------------------------------------------------------------------------
    # 8. Near duplicate cameras (Warning)
    # -------------------------------------------------------------------------
    def validate_near_duplicates(self, distance_threshold_m: float = 5.0):
        sec = "near_duplicates"
        self._init_section(sec)
        cam_path = self.target_dir / "cameras.bin"
        if not cam_path.exists():
            return

        cdata = cam_path.read_bytes()
        total_cams = len(cdata) // 20
        if total_cams == 0:
            return

        GRID_DEG = 0.0001  # ~11m cell
        grid = defaultdict(list)
        cams = []

        for i in range(total_cams):
            cid, lat_e7, lon_e7, spd, hd = struct.unpack_from(CAMERA_FMT, cdata, i * 20)
            lat = lat_e7 / 1e7
            lon = lon_e7 / 1e7
            cams.append((cid, lat, lon, spd, hd))
            gy = int(lat / GRID_DEG)
            gx = int(lon / GRID_DEG)
            grid[(gy, gx)].append(i)

        near_dup_pairs = 0
        for i in range(total_cams):
            cid1, lat1, lon1, spd1, hd1 = cams[i]
            gy = int(lat1 / GRID_DEG)
            gx = int(lon1 / GRID_DEG)

            for dy in (-1, 0, 1):
                for dx in (-1, 0, 1):
                    for j in grid.get((gy + dy, gx + dx), []):
                        if j > i:
                            cid2, lat2, lon2, spd2, hd2 = cams[j]
                            d = haversine_m(lat1, lon1, lat2, lon2)
                            if d < distance_threshold_m:
                                # Cùng hướng: nếu một bên omni hoặc lệch <= 45°
                                if hd1 in (0, 0xFFFF) or hd2 in (0, 0xFFFF) or heading_diff(hd1, hd2) <= 45:
                                    near_dup_pairs += 1

        self.section_results[sec]["details"]["near_duplicate_camera_pairs"] = near_dup_pairs
        if near_dup_pairs > 0:
            self.add_warning(sec, f"Phát hiện {near_dup_pairs:,} cặp camera cùng hướng cách nhau < {distance_threshold_m}m")

    # -------------------------------------------------------------------------
    # 9. Sounds (so khớp với thư mục tham chiếu --sounds-ref)
    # -------------------------------------------------------------------------
    def validate_sounds(self):
        sec = "sounds"
        self._init_section(sec)
        if not self.sounds_ref_dir:
            return
        if not self.sounds_ref_dir.exists():
            self.add_error(sec, f"Thư mục tham chiếu âm thanh không tồn tại: {self.sounds_ref_dir}")
            return

        target_sounds = self.target_dir / "sounds"
        if not target_sounds.exists():
            self.add_error(sec, f"Không tìm thấy thư mục sounds trong bản build: {target_sounds}")
            return

        ref_files = [p for p in self.sounds_ref_dir.rglob("*") if p.is_file() and not p.name.startswith(".")]
        missing = []
        for rf in ref_files:
            rel = rf.relative_to(self.sounds_ref_dir)
            tf = target_sounds / rel
            if not tf.exists():
                missing.append(str(rel))

        self.section_results[sec]["details"] = {
            "ref_files_total": len(ref_files),
            "missing_count": len(missing),
        }

        if missing:
            sample_missing = missing[:5]
            msg = f"Thiếu {len(missing)} file âm thanh so với tham chiếu ({', '.join(sample_missing)}"
            if len(missing) > 5:
                msg += f" ...và {len(missing) - 5} file khác"
            msg += ")"
            self.add_error(sec, msg)

    # -------------------------------------------------------------------------
    # Chạy toàn bộ
    # -------------------------------------------------------------------------
    def run_alerts_only(self) -> bool:
        self.validate_manifest()
        self.validate_cameras()
        self.validate_signs()
        self.validate_near_duplicates()
        return len(self.errors) == 0

    def run_all(self) -> bool:
        self.validate_manifest()
        self.validate_metadata()
        self.validate_index()
        self.validate_tiles()
        self.validate_cameras()
        self.validate_signs()
        self.validate_names_and_seg_names()
        self.validate_near_duplicates()
        if self.sounds_ref_dir:
            self.validate_sounds()
        return len(self.errors) == 0

    def print_summary(self):
        print("\n" + "=" * 80)
        print(f"       BÁO CÁO KIỂM ĐỊNH TẬP DỮ LIỆU SPEEDMAP: {self.target_dir}")
        print("=" * 80)

        for sec, data in self.section_results.items():
            status = data["status"]
            icon = "✓ [ĐẠT]" if status == "PASSED" else "✗ [LỖI]"
            print(f"{icon:<10} Mục: {sec:<22}")
            if data["details"]:
                det_str = ", ".join(f"{k}={v}" for k, v in list(data["details"].items())[:4])
                print(f"           Chi tiết: {det_str}")
            if data["warnings"]:
                for w in data["warnings"]:
                    print(f"           [CẢNH BÁO] {w}")
            if data["errors"]:
                for e in data["errors"]:
                    print(f"           [LỖI] {e}")

        print("-" * 80)
        total_errors = len(self.errors)
        total_warnings = len(self.warnings)
        if total_errors == 0:
            print(f"[KẾT LUẬN] TỔNG THỂ: ĐẠT CHUẨN (0 lỗi, {total_warnings} cảnh báo)")
        else:
            print(f"[KẾT LUẬN] TỔNG THỂ: KHÔNG ĐẠT ({total_errors} lỗi, {total_warnings} cảnh báo)")
        print("=" * 80 + "\n")

    def to_dict(self) -> dict:
        return {
            "target_dir": str(self.target_dir),
            "passed": len(self.errors) == 0,
            "total_errors": len(self.errors),
            "total_warnings": len(self.warnings),
            "errors": self.errors,
            "warnings": self.warnings,
            "sections": self.section_results,
        }


def main():
    parser = argparse.ArgumentParser(description="Bộ kiểm định chuẩn bộ dữ liệu SpeedMap VietHUD.")
    parser.add_argument("dir", type=Path, help="Thư mục speedmap cần kiểm tra")
    parser.add_argument("--pub", type=Path, default=None, help="File public key PEM dùng xác thực manifest.txt.sig")
    parser.add_argument("--json", type=Path, default=None, dest="out_json", help="Đường dẫn xuất file JSON chi tiết")
    parser.add_argument("--sample-size", type=int, default=5000, help="Số segment mẫu kiểm tra trong tiles.bin")
    parser.add_argument("--sounds-ref", type=Path, default=None, help="Thư mục tham chiếu âm thanh gốc (ví dụ: speedmap/sounds)")
    parser.add_argument("--prev", type=Path, default=None, help="Thư mục speedmap của bản trước để so sánh tỷ lệ biển tốc độ 0")
    parser.add_argument("--alerts-only", action="store_true", help="Chỉ kiểm định cameras.bin và signs.bin (dành cho gói alerts)")

    args = parser.parse_args()

    if not args.dir.exists():
        print(f"[LOI] Thư mục không tồn tại: {args.dir}")
        sys.exit(1)

    validator = SpeedMapValidator(
        args.dir,
        pub_key_path=args.pub,
        sample_size=args.sample_size,
        sounds_ref_dir=args.sounds_ref,
        prev_dir=args.prev,
    )
    if args.alerts_only:
        passed = validator.run_alerts_only()
    else:
        passed = validator.run_all()
    validator.print_summary()

    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump(validator.to_dict(), f, indent=2, ensure_ascii=False)
        print(f"[OK] Đã ghi kết quả JSON chi tiết ra: {args.out_json}")

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
