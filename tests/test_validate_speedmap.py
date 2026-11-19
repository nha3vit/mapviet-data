#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Bản sao từ VietHUD/tools/tests/test_validate_speedmap.py — nguồn chuẩn là VietHUD/tools; sửa ở đó rồi chép lại
"""
tools/tests/test_validate_speedmap.py — Unit test cho bộ kiểm định tools/validate_speedmap.py.
"""

import sys
from pathlib import Path
_REPO_DIR = Path(__file__).resolve().parent.parent
if str(_REPO_DIR) not in sys.path:
    sys.path.insert(0, str(_REPO_DIR))

import hashlib
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

try:
    from tools import validate_speedmap as vsm
except ImportError:
    import validate_speedmap as vsm


def make_valid_speedmap_dataset(dir_path: Path, version_str: str = "2026.11.18.1200"):
    """Tạo bộ dữ liệu SpeedMap tổng hợp hoàn toàn hợp lệ trong thư mục chỉ định."""
    dir_path.mkdir(parents=True, exist_ok=True)

    # 1. tiles.bin: 1 segment (28 bytes)
    # <IiiiiHBBhBB: segId=1, lat1=21.0, lon1=105.8, lat2=21.01, lon2=105.81, hd=45, rclass=1, rdir=1, spd=60, src=1, flg=0
    seg_bytes = struct.pack(
        vsm.SEGMENT_FMT,
        1,
        int(21.0 * 1e7),
        int(105.8 * 1e7),
        int(21.01 * 1e7),
        int(105.81 * 1e7),
        45,
        1,
        1,
        60,
        1,
        0,
    )
    (dir_path / "tiles.bin").write_bytes(seg_bytes)

    # 2. index.bin: 1 entry (28 bytes)
    # <IiiiiII: tid=100, minLat, maxLat, minLon, maxLon, offset=0, size=28
    idx_bytes = struct.pack(
        vsm.INDEX_ENTRY_FMT,
        100,
        int(20.99 * 1e7),
        int(21.02 * 1e7),
        int(105.79 * 1e7),
        int(105.82 * 1e7),
        0,
        len(seg_bytes),
    )
    (dir_path / "index.bin").write_bytes(idx_bytes)
    idx_crc = zlib.crc32(idx_bytes) & 0xFFFFFFFF

    # 3. metadata.bin: 140 bytes
    meta_bytes = struct.pack(
        vsm.METADATA_FMT,
        b"SLMP",
        2,
        b"VN\x00" + b"\x00" * 13,
        b"20261118\x00" + b"\x00" * 7,
        1700000000,
        1,  # tileCount
        1,  # segmentCount
        0.01,
        int(21.0 * 1e7),
        int(105.8 * 1e7),
        45,
        1,
        b"Attribution\x00" + b"\x00" * 52,
        idx_crc,
    )
    (dir_path / "metadata.bin").write_bytes(meta_bytes)

    # 4. cameras.bin: 1 camera (20 bytes)
    # <QiihH: id=1, lat=21.0, lon=105.8, spd=60, hd=45
    cam_bytes = struct.pack(
        vsm.CAMERA_FMT,
        1,
        int(21.0 * 1e7),
        int(105.8 * 1e7),
        60,
        45,
    )
    (dir_path / "cameras.bin").write_bytes(cam_bytes)

    # 5. signs.bin: header (20 bytes) + 1 sign (20 bytes)
    # sign: id=1, lat=21.0, lon=105.8, hd=45, type=1, spd=60, sub=0, flg=0, res=0
    sign_pt_bytes = struct.pack(
        vsm.SIGN_POINT_FMT,
        1,
        int(21.0 * 1e7),
        int(105.8 * 1e7),
        45,
        1,
        60,
        0,
        0,
        0,
    )
    sign_crc = zlib.crc32(sign_pt_bytes) & 0xFFFFFFFF
    sign_hdr_bytes = struct.pack(
        vsm.SIGN_HEADER_FMT,
        b"VNSG",
        1,
        1,  # signCount
        0,
        sign_crc,
        1700000000,
    )
    (dir_path / "signs.bin").write_bytes(sign_hdr_bytes + sign_pt_bytes)

    # 6. names.bin: header (16 bytes) + offsets (4 bytes) + pool ("Pho Hue\0")
    pool = b"Pho Hue\x00"
    offsets = struct.pack("<I", 0)
    names_hdr = struct.pack(
        vsm.NAME_HEADER_FMT,
        b"VNNM",
        2,
        1,  # count
        len(pool),
        0,
    )
    (dir_path / "names.bin").write_bytes(names_hdr + offsets + pool)

    # 7. seg_names.bin: (maxSegId + 1) * 4 bytes -> maxSegId=1 => 2 entries (8 bytes)
    seg_names_bytes = struct.pack("<II", 0, 1)
    (dir_path / "seg_names.bin").write_bytes(seg_names_bytes)

    # 8. manifest.txt
    core_files = [
        "metadata.bin",
        "index.bin",
        "tiles.bin",
        "cameras.bin",
        "signs.bin",
        "names.bin",
        "seg_names.bin",
    ]
    manifest_lines = [f"version {version_str}"]
    for fname in core_files:
        fpath = dir_path / fname
        sha = hashlib.sha256(fpath.read_bytes()).hexdigest()
        manifest_lines.append(f"{fname} {fpath.stat().st_size} {sha}")

    (dir_path / "manifest.txt").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")


class TestValidateSpeedmap(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.td = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_valid_dataset_passes(self):
        """Bộ dữ liệu chuẩn tổng hợp phải vượt qua tất cả kiểm tra."""
        ds_dir = self.td / "valid_ds"
        make_valid_speedmap_dataset(ds_dir)

        validator = vsm.SpeedMapValidator(ds_dir)
        passed = validator.run_all()
        self.assertTrue(passed, f"Kỳ vọng PASSED nhưng có lỗi: {validator.errors}")
        self.assertEqual(len(validator.errors), 0)

    def test_manifest_header_invalid(self):
        """Manifest dòng 1 không đúng format YYYY.MM.DD.HHMM -> lỗi."""
        ds_dir = self.td / "bad_mf_hdr"
        make_valid_speedmap_dataset(ds_dir, version_str="2026.11.18")  # thiếu HHMM

        validator = vsm.SpeedMapValidator(ds_dir)
        passed = validator.run_all()
        self.assertFalse(passed)
        self.assertTrue(any("version YYYY.MM.DD.HHMM" in e for e in validator.errors))

    def test_manifest_file_checksum_mismatch(self):
        """File trong thư mục bị sửa nội dung -> manifest báo sai SHA-256."""
        ds_dir = self.td / "tampered_ds"
        make_valid_speedmap_dataset(ds_dir)
        # Sửa nội dung cameras.bin sau khi tạo manifest
        (ds_dir / "cameras.bin").write_bytes(b"\x00" * 20)

        validator = vsm.SpeedMapValidator(ds_dir)
        passed = validator.run_all()
        self.assertFalse(passed)
        self.assertTrue(any("sai SHA-256" in e for e in validator.errors))

    def test_metadata_magic_or_crc_invalid(self):
        """metadata.bin sai magic hoặc sai CRC32 của index.bin -> lỗi."""
        ds_dir = self.td / "bad_meta"
        make_valid_speedmap_dataset(ds_dir)

        # Ghi đè metadata với magic sai
        mdata = bytearray((ds_dir / "metadata.bin").read_bytes())
        mdata[0:4] = b"XXXX"
        (ds_dir / "metadata.bin").write_bytes(bytes(mdata))

        # Cập nhật manifest để cô lập lỗi metadata
        lines = (ds_dir / "manifest.txt").read_text().splitlines()
        for idx, l in enumerate(lines):
            if l.startswith("metadata.bin"):
                sha = hashlib.sha256(mdata).hexdigest()
                lines[idx] = f"metadata.bin {len(mdata)} {sha}"
        (ds_dir / "manifest.txt").write_text("\n".join(lines) + "\n")

        validator = vsm.SpeedMapValidator(ds_dir)
        passed = validator.run_all()
        self.assertFalse(passed)
        self.assertTrue(any("Magic không phải 'SLMP'" in e for e in validator.errors))

    def test_camera_invalid_speed_rejected(self):
        """Camera có tốc độ không hợp lệ (ví dụ 27 km/h) -> lỗi."""
        ds_dir = self.td / "bad_cam"
        make_valid_speedmap_dataset(ds_dir)

        # Camera với speed=27
        bad_cam = struct.pack(vsm.CAMERA_FMT, 1, int(21.0 * 1e7), int(105.8 * 1e7), 27, 45)
        (ds_dir / "cameras.bin").write_bytes(bad_cam)

        validator = vsm.SpeedMapValidator(ds_dir)
        passed = validator.run_all()
        self.assertFalse(passed)
        self.assertTrue(any("tốc độ sai chuẩn" in e for e in validator.errors))

    def test_sign_speed_on_wrong_type_rejected(self):
        """Biển báo loại khác type 1 nhưng speed != 0 -> lỗi."""
        ds_dir = self.td / "bad_sign"
        make_valid_speedmap_dataset(ds_dir)

        # Sign type 2 (Khu dân cư) nhưng gán speed=60
        bad_pt = struct.pack(vsm.SIGN_POINT_FMT, 1, int(21.0 * 1e7), int(105.8 * 1e7), 45, 2, 60, 0, 0, 0)
        crc = zlib.crc32(bad_pt) & 0xFFFFFFFF
        hdr = struct.pack(vsm.SIGN_HEADER_FMT, b"VNSG", 1, 1, 0, crc, 1700000000)
        (ds_dir / "signs.bin").write_bytes(hdr + bad_pt)

        validator = vsm.SpeedMapValidator(ds_dir)
        passed = validator.run_all()
        self.assertFalse(passed)
        self.assertTrue(any("speed chỉ cho phép ở type 1" in e for e in validator.errors))

    def test_seg_names_size_too_small(self):
        """seg_names.bin không đủ (maxSegId + 1) * 4 bytes -> lỗi."""
        ds_dir = self.td / "bad_segnames"
        make_valid_speedmap_dataset(ds_dir)

        # maxSegId là 1, nhưng seg_names chỉ ghi 4 bytes (cho segId 0)
        (ds_dir / "seg_names.bin").write_bytes(struct.pack("<I", 0))

        validator = vsm.SpeedMapValidator(ds_dir)
        passed = validator.run_all()
        self.assertFalse(passed)
        self.assertTrue(any("thiếu kích thước cho maxSegId" in e for e in validator.errors))

    def _create_dataset_with_speed_signs(self, dir_path: Path, speeds: list[int]):
        make_valid_speedmap_dataset(dir_path)
        body = bytearray()
        for i, spd in enumerate(speeds):
            body.extend(struct.pack(
                vsm.SIGN_POINT_FMT,
                i + 1, int(21.0 * 1e7), int(105.8 * 1e7), 45, 1, spd, 0, 0, 0
            ))
        crc = zlib.crc32(body) & 0xFFFFFFFF
        hdr = struct.pack(vsm.SIGN_HEADER_FMT, b"VNSG", 1, len(speeds), 0, crc, 1700000000)
        sdata = hdr + body
        (dir_path / "signs.bin").write_bytes(sdata)

        # Cập nhật manifest
        lines = (dir_path / "manifest.txt").read_text().splitlines()
        for idx, l in enumerate(lines):
            if l.startswith("signs.bin"):
                sha = hashlib.sha256(sdata).hexdigest()
                lines[idx] = f"signs.bin {len(sdata)} {sha}"
        (dir_path / "manifest.txt").write_text("\n".join(lines) + "\n")

    def test_speed_0_ratio_without_prev_no_warning(self):
        """R4-FIX (F2): Không truyền --prev thì chỉ in INFO, không cảnh báo tỷ lệ biển tốc độ 0."""
        ds_dir = self.td / "ds_no_prev"
        # 3 biển speed=0, 7 biển speed=60 -> 30% speed 0 (>5%)
        self._create_dataset_with_speed_signs(ds_dir, [0, 0, 0, 60, 60, 60, 60, 60, 60, 60])

        validator = vsm.SpeedMapValidator(ds_dir, prev_dir=None)
        passed = validator.run_all()
        self.assertTrue(passed)
        self.assertFalse(any("Tỷ lệ biển loại 1 tốc độ 0" in w for w in validator.warnings))

    def test_speed_0_ratio_with_prev_warns_on_large_delta(self):
        """R4-FIX (F2): Truyền --prev và tỷ lệ biển 0 lệch > 5 điểm % so với bản trước -> CẢNH BÁO."""
        prev_dir = self.td / "ds_prev"
        # Bản trước: 2 biển 0, 8 biển 60 -> 20%
        self._create_dataset_with_speed_signs(prev_dir, [0, 0] + [60] * 8)

        curr_dir = self.td / "ds_curr_large_delta"
        # Bản hiện tại: 4 biển 0, 6 biển 60 -> 40% (delta = +20% > 5%)
        self._create_dataset_with_speed_signs(curr_dir, [0, 0, 0, 0] + [60] * 6)

        validator = vsm.SpeedMapValidator(curr_dir, prev_dir=prev_dir)
        passed = validator.run_all()
        self.assertTrue(passed)  # Cảnh báo không làm fail bộ dữ liệu
        self.assertTrue(any("thay đổi quá ±5 điểm %" in w for w in validator.warnings))

    def test_speed_0_ratio_with_prev_no_warning_within_5pp(self):
        """R4-FIX (F2): Truyền --prev và tỷ lệ biển 0 lệch <= 5 điểm % -> KHÔNG CẢNH BÁO."""
        prev_dir = self.td / "ds_prev_small"
        # Bản trước: 20 biển 0, 80 biển 60 -> 20%
        self._create_dataset_with_speed_signs(prev_dir, [0] * 20 + [60] * 80)

        curr_dir = self.td / "ds_curr_small_delta"
        # Bản hiện tại: 23 biển 0, 77 biển 60 -> 23% (delta = +3% <= 5%)
        self._create_dataset_with_speed_signs(curr_dir, [0] * 23 + [60] * 77)

        validator = vsm.SpeedMapValidator(curr_dir, prev_dir=prev_dir)
        passed = validator.run_all()
        self.assertTrue(passed)
        self.assertFalse(any("thay đổi quá ±5 điểm %" in w for w in validator.warnings))


if __name__ == "__main__":
    unittest.main()
