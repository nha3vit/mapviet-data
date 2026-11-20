#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_fetch_vietmap.py — Unit tests cho fetch_vietmap.py (dùng dữ liệu giả lập, không gọi mạng thật).
"""

import datetime
import io
import json
import shutil
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

from fetch_vietmap import (
    check_remote_version,
    find_latest_remote_version,
    get_candidate_versions,
    load_manifest,
    process_download,
    save_manifest,
    slice_secrect_bin,
    validate_decoded_points,
)
import vietmap_decode as vmd


def create_mock_secrect_bin(edogen_payload: bytes) -> bytes:
    """Tạo mock secrect.bin với header 512 bytes và phân vùng edogen.bin."""
    header = bytearray(512)
    # Entry 0: secrect.bin (kích thước lớn)
    entry0 = b"secrect.bin\x00" + b"\x00" * (64 - len(b"secrect.bin\x00")) + struct.pack("<I", 1000000)
    header[0:68] = entry0
    # Entry 1: edogen.bin
    edogen_size = len(edogen_payload)
    entry1 = b"edogen.bin\x00" + b"\x00" * (64 - len(b"edogen.bin\x00")) + struct.pack("<I", edogen_size)
    header[68:136] = entry1
    # Entry 2: roadsenz.bin
    entry2 = b"roadsenz.bin\x00" + b"\x00" * (64 - len(b"roadsenz.bin\x00")) + struct.pack("<I", 500000)
    header[136:204] = entry2

    # Phần thân: edogen_payload + fake roadsenz data
    fake_roadsenz = b"\xFF" * 1024
    return bytes(header) + edogen_payload + fake_roadsenz


def encode_vietmap_line(lon: float, lat: float, stype: int, spd: int, flag: int, hd: int) -> bytes:
    """Mã hóa dòng dạng lon,lat,type,spd,flag,hd thành bytes bảng thế VietMap."""
    line_str = f"{lon:.5f},{lat:.5f},{stype},{spd},{flag},{hd}"
    b = bytearray()
    for ch in line_str:
        b.append(vmd.REVERSE_SUBSTITUTION[ch])
    return bytes(b)


class TestFetchVietMap(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.tmp_dir = Path(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_get_candidate_versions(self):
        # Tháng thông thường
        dt1 = datetime.datetime(2026, 11, 20, tzinfo=datetime.timezone.utc)
        self.assertEqual(get_candidate_versions(dt1), ["2026T10", "2026T11", "2026T12"])

        # Tháng 12 -> chuyển năm
        dt2 = datetime.datetime(2026, 12, 1, tzinfo=datetime.timezone.utc)
        self.assertEqual(get_candidate_versions(dt2), ["2026T11", "2026T12", "2027T01"])

        # Tháng 1 -> lùi năm trước
        dt3 = datetime.datetime(2026, 1, 15, tzinfo=datetime.timezone.utc)
        self.assertEqual(get_candidate_versions(dt3), ["2025T12", "2026T01", "2026T02"])

    def test_slice_secrect_bin_cuts_toc_and_edogen_only(self):
        payload = b"TEST_EDOGEN_CONTENT" * 10
        raw_secrect = create_mock_secrect_bin(payload)
        self.assertGreater(len(raw_secrect), 512 + len(payload))

        sliced = slice_secrect_bin(raw_secrect)
        expected_size = 512 + len(payload)
        self.assertEqual(len(sliced), expected_size)
        self.assertEqual(sliced[512:], payload)

        # Lỗi khi dữ liệu quá ngắn
        with self.assertRaises(ValueError):
            slice_secrect_bin(b"short")

        # Lỗi khi header không hợp lệ
        with self.assertRaises(ValueError):
            slice_secrect_bin(b"\x00" * 512)

    def test_validate_decoded_points_checks_drop_and_undecodable(self):
        # Tạo payload với 2 điểm hợp lệ
        line1 = encode_vietmap_line(105.80, 21.00, 1, 60, 0, 90)
        line2 = encode_vietmap_line(105.81, 21.01, 11, 0, 0, 180)
        payload = line1 + b"\x83\x71" + line2 + b"\x83\x71"
        sliced = create_mock_secrect_bin(payload)[: 512 + len(payload)]

        count, skipped = validate_decoded_points(sliced, prev_point_count=2)
        self.assertEqual(count, 2)
        self.assertEqual(skipped["undecodable"], 0)

        # Trường hợp số điểm giảm > 5% so với bản trước (2 < 95% của 10)
        with self.assertRaises(ValueError) as ctx:
            validate_decoded_points(sliced, prev_point_count=10)
        self.assertIn("sụt giảm > 5%", str(ctx.exception))

        # Trường hợp undecodable > 10
        bad_payload = payload
        for _ in range(12):
            bad_payload += b"\x01\x02\x03\x04\x83\x71"
        bad_sliced = create_mock_secrect_bin(bad_payload)[: 512 + len(bad_payload)]
        with self.assertRaises(ValueError) as ctx:
            validate_decoded_points(bad_sliced)
        self.assertIn("không thể giải mã quá lớn", str(ctx.exception))

    def test_check_remote_and_find_latest_mock(self):
        # Mock opener
        mock_opener = MagicMock()

        def fake_open(req, timeout=15):
            url = req.full_url
            if "2026T12" in url:
                raise Exception("404 Not Found")
            elif "2026T11" in url:
                mock_resp = MagicMock()
                mock_resp.status = 200
                mock_resp.headers = {
                    "Last-Modified": "Fri, 30 Oct 2026 10:00:09 GMT",
                    "ETag": '"80da4a725568dd1:0"',
                    "Content-Length": "98021066",
                }
                mock_resp.__enter__.return_value = mock_resp
                mock_resp.__exit__.return_value = None
                return mock_resp
            else:
                raise Exception("404 Not Found")

        mock_opener.open.side_effect = fake_open

        info12 = check_remote_version("2026T12", opener=mock_opener)
        self.assertNull if hasattr(self, "assertNull") else None
        self.assertIsNone(info12)

        info11 = check_remote_version("2026T11", opener=mock_opener)
        self.assertIsNotNone(info11)
        self.assertEqual(info11["version"], "2026T11")
        self.assertEqual(info11["zip_size"], 98021066)

        latest = find_latest_remote_version(candidates=["2026T10", "2026T11", "2026T12"], opener=mock_opener)
        self.assertIsNotNone(latest)
        self.assertEqual(latest["version"], "2026T11")

    def test_process_download_with_mock_zip(self):
        line1 = encode_vietmap_line(105.80, 21.00, 1, 60, 0, 90)
        line2 = encode_vietmap_line(105.81, 21.01, 11, 0, 0, 180)
        payload = line1 + b"\x83\x71" + line2 + b"\x83\x71"
        raw_secrect = create_mock_secrect_bin(payload)

        # Tạo zip in-memory
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("secrect.bin", raw_secrect)
            zf.writestr("other.txt", b"something")
        zip_bytes = zip_buf.getvalue()

        # Mock download response (hỗ trợ context manager with)
        mock_opener = MagicMock()
        mock_resp = MagicMock()
        mock_resp.read.side_effect = [zip_bytes, b""]
        mock_opener.open.return_value.__enter__.return_value = mock_resp

        remote_info = {
            "version": "2026T11",
            "filename": "VietMap_SpeedMap_M2_2026T11.zip",
            "url": "https://fake.vietmap.vn/dvr/VietMap_SpeedMap_M2_2026T11.zip",
            "last_modified": "Fri, 30 Oct 2026 10:00:09 GMT",
            "etag": "fake_etag",
            "zip_size": len(zip_bytes),
        }

        m = process_download(
            remote_info=remote_info,
            dest_dir=self.tmp_dir,
            prev_manifest=None,
            opener=mock_opener,
        )

        self.assertEqual(m["version"], "2026T11")
        self.assertEqual(m["points_count"], 2)
        self.assertTrue((self.tmp_dir / "secrect.bin").exists())
        self.assertTrue((self.tmp_dir / "vietmap_manifest.json").exists())

        loaded = load_manifest(self.tmp_dir / "vietmap_manifest.json")
        self.assertEqual(loaded["version"], "2026T11")
        self.assertEqual(loaded["etag"], "fake_etag")
        self.assertEqual(loaded["points_count"], 2)


if __name__ == "__main__":
    unittest.main()
