#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Bản sao từ VietHUD/tools/tests/test_vietmap_mapping_r5.py — nguồn chuẩn là VietHUD/tools; sửa ở đó rồi chép lại
"""
tools/tests/test_vietmap_mapping_r5.py — Kiểm thử quy chuẩn R5a:
  1. Ánh xạ 11 loại VietMap theo bảng Bước 2, bảo toàn 100% điểm VietMap.
  2. Loại bỏ bản sao cũ STALE_OLD_MAP (Base sign 6 cách VM 2 là 10m -> bỏ, 60m -> giữ; Base camera cách VM 4 là 10m -> giữ).
  3. Trạm thu phí Base cách VietMap 8 là 15m -> còn 1 (VietMap thắng), không tính là bản sao cũ.
"""

import sys
from pathlib import Path
_REPO_DIR = Path(__file__).resolve().parent.parent
if str(_REPO_DIR) not in sys.path:
    sys.path.insert(0, str(_REPO_DIR))

import math
import tempfile
import unittest
from pathlib import Path

try:
    from tools import alerts
except ImportError:
    import alerts
try:
    from tools import vietmap_decode as vmd
except ImportError:
    import vietmap_decode as vmd


def encode_vm_line(text: str) -> bytes:
    res = bytearray()
    for ch in text:
        if ch in vmd.REVERSE_SUBSTITUTION:
            res.append(vmd.REVERSE_SUBSTITUTION[ch])
        else:
            raise ValueError(f"Ký tự không thể mã hoá: {ch}")
    return bytes(res)


def meters_to_lat_deg(meters: float) -> float:
    return meters / 111320.0


class TestVietmapMappingR5(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.td = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_mapping_table_rows_and_vietmap_preservation(self):
        """Mỗi dòng trong bảng Bước 2: điểm tổng hợp -> đúng sign_type/subType/speed/heading; 100% VM còn."""
        vm_bin = self.td / "secrect.bin"
        lines = [
            b"HEADER" + encode_vm_line("20261120"),
            encode_vm_line("105.800000,21.000000,1,60,0,90"),   # 1: speed 60, hd 90
            encode_vm_line("105.810000,21.010000,2,0,0,180"),   # 2: resident enter (R.420)
            encode_vm_line("105.820000,21.020000,3,0,0,270"),   # 3: resident exit (R.421)
            encode_vm_line("105.830000,21.030000,4,0,0,45"),    # 4: pending 4
            encode_vm_line("105.840000,21.040000,5,0,0,50"),    # 5: pending 5
            encode_vm_line("105.850000,21.050000,6,0,0,60"),    # 6: pending 6
            encode_vm_line("105.860000,21.060000,7,0,0,70"),    # 7: pending 7
            encode_vm_line("105.870000,21.070000,8,0,0,0"),     # 8: toll booth (hd 0 -> 0xFFFF)
            encode_vm_line("105.880000,21.080000,9,0,0,95"),    # 9: tunnel (sub 9, hd 95)
            encode_vm_line("105.890000,21.090000,10,0,0,100"),  # 10: pending 10
            encode_vm_line("105.900000,21.100000,11,0,0,110"),  # 11: camera
        ]
        vm_bin.write_bytes(b"\x83\x71".join(lines))

        pts, ver = alerts.load_vietmap_alerts(vm_bin)
        self.assertEqual(len(pts), 11, "Phải nạp đủ 11 điểm VietMap")

        # Kiểm tra từng điểm sau load
        p1 = next(p for p in pts if getattr(p, "original_type", None) == 1)
        self.assertEqual(p1.sign_type, alerts.SIGN_TYPE_SPEED_LIMIT)
        self.assertEqual(p1.sub_type, 0)
        self.assertEqual(p1.speed_limit, 60)
        self.assertEqual(p1.heading, 90)

        p2 = next(p for p in pts if getattr(p, "original_type", None) == 2)
        self.assertEqual(p2.sign_type, alerts.SIGN_TYPE_RESIDENT_AREA)
        self.assertEqual(p2.sub_type, 0)
        self.assertEqual(p2.speed_limit, 0)
        self.assertEqual(p2.heading, 180)

        p3 = next(p for p in pts if getattr(p, "original_type", None) == 3)
        self.assertEqual(p3.sign_type, alerts.SIGN_TYPE_RESIDENT_AREA)
        self.assertEqual(p3.sub_type, 1)
        self.assertEqual(p3.speed_limit, 0)
        self.assertEqual(p3.heading, 270)

        # R5b: Loại 4 là đèn giao thông (sign 6, sub 0); 5/6 là cấm vượt bắt đầu (sign 3, sub 0) / hết (sign 3, sub 1);
        # 7 là cảnh báo khác "Chú ý" (sign 10, sub 7); 10 là cảnh báo khác chỉ vẽ (sign 10, sub 10).
        p4 = next(p for p in pts if getattr(p, "original_type", None) == 4)
        self.assertEqual(p4.sign_type, alerts.SIGN_TYPE_TRAFFIC_LIGHT)
        self.assertEqual(p4.sub_type, 0)
        self.assertEqual(p4.speed_limit, 0)

        p5 = next(p for p in pts if getattr(p, "original_type", None) == 5)
        self.assertEqual(p5.sign_type, alerts.SIGN_TYPE_NO_OVERTAKING)
        self.assertEqual(p5.sub_type, 0)
        self.assertEqual(p5.speed_limit, 0)

        p6 = next(p for p in pts if getattr(p, "original_type", None) == 6)
        self.assertEqual(p6.sign_type, alerts.SIGN_TYPE_NO_OVERTAKING)
        self.assertEqual(p6.sub_type, 1)
        self.assertEqual(p6.speed_limit, 0)

        p7 = next(p for p in pts if getattr(p, "original_type", None) == 7)
        self.assertEqual(p7.sign_type, alerts.SIGN_TYPE_DANGER_OTHER)
        self.assertEqual(p7.sub_type, 7)
        self.assertEqual(p7.speed_limit, 0)

        p10 = next(p for p in pts if getattr(p, "original_type", None) == 10)
        self.assertEqual(p10.sign_type, alerts.SIGN_TYPE_DANGER_OTHER)
        self.assertEqual(p10.sub_type, 10)
        self.assertEqual(p10.speed_limit, 0)

        p8 = next(p for p in pts if getattr(p, "original_type", None) == 8)
        self.assertEqual(p8.sign_type, alerts.SIGN_TYPE_TOLL_BOOTH)
        self.assertEqual(p8.sub_type, 0)
        self.assertEqual(p8.speed_limit, 0)
        self.assertEqual(p8.heading, alerts.DIR_OMNI)

        p9 = next(p for p in pts if getattr(p, "original_type", None) == 9)
        self.assertEqual(p9.sign_type, alerts.SIGN_TYPE_DANGER_OTHER)
        self.assertEqual(p9.sub_type, 9)
        self.assertEqual(p9.speed_limit, 0)
        self.assertEqual(p9.heading, 95)

        p11 = next(p for p in pts if getattr(p, "original_type", None) == 11)
        self.assertTrue(p11.is_camera)
        self.assertIsNone(p11.sign_type)
        self.assertEqual(p11.speed_limit, 0)
        self.assertEqual(p11.heading, 110)

        # Chạy merge_and_deduplicate: 100% điểm VietMap phải còn
        master, stats = alerts.merge_and_deduplicate(pts)
        self.assertEqual(len(master), 11)
        self.assertEqual(stats["vietmap_kept"], 11)
        self.assertEqual(stats["vietmap_out"], 11)

    def test_stale_old_map_drops_base_and_wyn_copies(self):
        """
        Kiểm tra loại bỏ bản sao cũ STALE_OLD_MAP:
        - Base sign 6 cách VM 2 là 10m -> bỏ (stale copy)
        - Base sign 6 cách VM 2 là 60m -> giữ (ngoài 45m)
        - Base camera cách VM 4 là 10m -> giữ (không áp dụng cho camera)
        """
        lat0, lon0 = 21.000000, 105.800000

        # 1. VietMap 2 (Resident Enter) tại lat0, lon0
        vm2 = alerts.AlertPoint(
            lat=lat0, lon=lon0, sign_type=alerts.SIGN_TYPE_RESIDENT_AREA,
            speed_limit=0, heading=90, is_camera=False, source="VietMap",
            priority=alerts.PRIORITY_VIETMAP, desc="VM2", original_type=2,
            decoded_heading=90, sub_type=0
        )

        # Base sign 6 (đèn) cách 10m (lat0 + 10m) -> 10m <= 45m -> BỎ
        lat_10m = lat0 + meters_to_lat_deg(10.0)
        base_sign_6_near = alerts.AlertPoint(
            lat=lat_10m, lon=lon0, sign_type=alerts.SIGN_TYPE_TRAFFIC_LIGHT,
            speed_limit=0, heading=90, is_camera=False, source="Base",
            priority=alerts.PRIORITY_BASE, desc="Base Sign 6 near VM2",
            kind="light"
        )

        # Base sign 6 (đèn) cách 60m (lat0 + 60m) -> 60m > 45m -> GIỮ
        lat_60m = lat0 + meters_to_lat_deg(60.0)
        base_sign_6_far = alerts.AlertPoint(
            lat=lat_60m, lon=lon0, sign_type=alerts.SIGN_TYPE_TRAFFIC_LIGHT,
            speed_limit=0, heading=90, is_camera=False, source="Base",
            priority=alerts.PRIORITY_BASE, desc="Base Sign 6 far VM2",
            kind="light"
        )

        # 2. VietMap 4 tại lat2, lon2
        lat2, lon2 = 21.050000, 105.850000
        vm4 = alerts.AlertPoint(
            lat=lat2, lon=lon2, sign_type=alerts.SIGN_TYPE_DANGER_OTHER,
            speed_limit=0, heading=90, is_camera=False, source="VietMap",
            priority=alerts.PRIORITY_VIETMAP, desc="VM4", original_type=4,
            decoded_heading=90, sub_type=4
        )

        # Base camera cách 10m từ VM4 -> KHÔNG bị bỏ (camera không bị áp luật stale copy)
        lat2_10m = lat2 + meters_to_lat_deg(10.0)
        base_cam = alerts.AlertPoint(
            lat=lat2_10m, lon=lon2, sign_type=None,
            speed_limit=60, heading=90, is_camera=True, source="Base",
            priority=alerts.PRIORITY_BASE, desc="Base Camera near VM4",
            kind="camera"
        )

        all_pts = [vm2, base_sign_6_near, base_sign_6_far, vm4, base_cam]
        master, stats = alerts.merge_and_deduplicate(all_pts)

        # base_sign_6_near bị bỏ vì là stale copy của VM2
        self.assertEqual(stats["stale_copy_dropped"][("Base", 2, 6)], 1)
        self.assertNotIn(base_sign_6_near, master)

        # base_sign_6_far được giữ
        self.assertIn(base_sign_6_far, master)

        # vm2, vm4 được giữ
        self.assertIn(vm2, master)
        self.assertIn(vm4, master)

        # base_cam được giữ
        self.assertIn(base_cam, master)

    def test_toll_booth_base_near_vietmap_8_normal_dedup_not_stale(self):
        """
        Trạm thu phí Base cách VietMap 8 là 15 m:
        - Còn 1 (VietMap thắng qua khử trùng thường cùng sign_type 5).
        - KHÔNG tính là bản sao cũ (stale_copy_dropped không tăng).
        """
        lat0, lon0 = 21.000000, 105.800000
        vm8 = alerts.AlertPoint(
            lat=lat0, lon=lon0, sign_type=alerts.SIGN_TYPE_TOLL_BOOTH,
            speed_limit=0, heading=alerts.DIR_OMNI, is_camera=False, source="VietMap",
            priority=alerts.PRIORITY_VIETMAP, desc="VM8 Toll", original_type=8,
            decoded_heading=0, sub_type=0
        )

        lat_15m = lat0 + meters_to_lat_deg(15.0)
        base_toll = alerts.AlertPoint(
            lat=lat_15m, lon=lon0, sign_type=alerts.SIGN_TYPE_TOLL_BOOTH,
            speed_limit=0, heading=alerts.DIR_OMNI, is_camera=False, source="Base",
            priority=alerts.PRIORITY_BASE, desc="Base Toll 15m", sub_type=0
        )

        master, stats = alerts.merge_and_deduplicate([vm8, base_toll])

        # Còn đúng 1 điểm (VietMap)
        self.assertEqual(len(master), 1)
        self.assertEqual(master[0].source, "VietMap")
        self.assertEqual(master[0].sign_type, alerts.SIGN_TYPE_TOLL_BOOTH)

        # KHÔNG tính là stale copy
        self.assertEqual(len(stats["stale_copy_dropped"]), 0)
        self.assertEqual(stats["noise_dropped"], 1)  # Khử trùng bình thường


if __name__ == "__main__":
    unittest.main()
