#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Bản sao từ VietHUD/tools/tests/test_dedup_r3.py — nguồn chuẩn là VietHUD/tools; sửa ở đó rồi chép lại
"""
tools/tests/test_dedup_r3.py — Unit test toàn diện cho quy tắc chuẩn hoá Vòng 3:
Khử điểm gần trùng, nhận diện heading giả, camera nguồn chuẩn duy nhất,
và luật khử trùng khác nguồn / cùng nguồn.
"""

import sys
from pathlib import Path
_REPO_DIR = Path(__file__).resolve().parent.parent
if str(_REPO_DIR) not in sys.path:
    sys.path.insert(0, str(_REPO_DIR))

import math
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

try:
    from tools import alerts
    from tools import validate_speedmap as vsm
except ImportError:
    import alerts
    import validate_speedmap as vsm


def meters_to_lat_deg(meters: float) -> float:
    # 1 deg lat ~ 111,000 m
    return meters / 111000.0


class TestDedupR3(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.td = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_wyn_bogus_heading_and_merge_with_vietmap(self):
        """
        100+ đèn WYN heading 15 + 1 đèn VietMap heading 90 cách 30 m ->
        Bước 1 phát hiện heading 15 giả của WYN light -> chuyển thành 0xFFFF.
        Bước 3 gộp theo luật khác nguồn (bán kính đèn 45m) -> chỉ còn 1 (VietMap).
        """
        pts = []
        # 1 đèn VietMap tại (21.00000, 105.80000), heading 90, priority 1
        pts.append(alerts.AlertPoint(
            lat=21.00000,
            lon=105.80000,
            sign_type=alerts.SIGN_TYPE_TRAFFIC_LIGHT,
            speed_limit=0,
            heading=90,
            is_camera=False,
            source="VietMap",
            priority=alerts.PRIORITY_VIETMAP,
            desc="VM Light",
            kind="light",
        ))

        # 105 đèn WYN cách đèn VietMap ~30m (dphi = 30 / 111000 ~ 0.00027 deg)
        # Tất cả có heading 15 (giả)
        lat_30m = 21.00000 + meters_to_lat_deg(30.0)
        for i in range(105):
            pts.append(alerts.AlertPoint(
                lat=lat_30m + (i * 0.000001),
                lon=105.80000,
                sign_type=alerts.SIGN_TYPE_TRAFFIC_LIGHT,
                speed_limit=0,
                heading=15,
                is_camera=False,
                source="WYN",
                priority=alerts.PRIORITY_WYN,
                desc=f"WYN Light {i}",
                kind="light",
            ))

        master, stats = alerts.merge_and_deduplicate(pts)

        # Kiểm tra bước 1: phát hiện heading giả 15
        self.assertEqual(len(stats["bogus_headings"]), 1)
        self.assertEqual(stats["bogus_headings"][0]["source"], "WYN")
        self.assertEqual(stats["bogus_headings"][0]["kind"], "light")
        self.assertEqual(stats["bogus_headings"][0]["heading"], 15)
        self.assertEqual(stats["bogus_headings"][0]["count"], 105)

        # Kiểm tra bước 3: gộp chỉ còn 1 đèn VietMap duy nhất
        self.assertEqual(len(master), 1)
        self.assertEqual(master[0].source, "VietMap")
        self.assertEqual(master[0].heading, 90)

    def test_camera_and_sign_type_4_proximity(self):
        """
        Camera + sign type 4 cách 20 m (< 30 m) ->
        Bỏ sign type 4, chỉ còn 1 camera, signs không còn type 4.
        """
        # 1 camera tại (21.00000, 105.80000)
        cam = alerts.AlertPoint(
            lat=21.00000,
            lon=105.80000,
            sign_type=None,
            speed_limit=60,
            heading=90,
            is_camera=True,
            source="VietMap",
            priority=alerts.PRIORITY_VIETMAP,
            desc="VM Camera",
            kind="camera",
        )
        # 1 sign type 4 nền cách 20m
        lat_20m = 21.00000 + meters_to_lat_deg(20.0)
        s4 = alerts.AlertPoint(
            lat=lat_20m,
            lon=105.80000,
            sign_type=4,
            speed_limit=0,
            heading=90,
            is_camera=False,
            source="Base",
            priority=alerts.PRIORITY_BASE,
            desc="Base Sign 4",
            kind="sign",
            original_id=1234,
        )

        master, stats = alerts.merge_and_deduplicate([cam, s4])

        self.assertEqual(len(master), 1)
        self.assertTrue(master[0].is_camera)
        self.assertEqual(master[0].source, "VietMap")
        self.assertEqual(stats["sign_type_4_dropped_duplicate"], 1)
        self.assertEqual(stats["sign_type_4_converted_to_camera"], 0)

        # Đóng gói thử ra binary để kiểm tra signs.bin không chứa type 4
        alerts.allocate_stable_ids(master)
        out = self.td / "out_s4"
        _, signs_path, _, _ = alerts.export_binary_files(master, out)
        sdata = signs_path.read_bytes()
        hdr = struct.unpack_from("<4sHIHII", sdata, 0)
        sign_count = hdr[2]
        self.assertEqual(sign_count, 0, "signs.bin không được chứa bất kỳ điểm nào")

    def test_isolated_sign_type_4_converted_to_camera_with_stable_id(self):
        """
        Sign type 4 lẻ (cách camera > 30 m) ->
        Chuyển thành camera speed -1, giữ heading, id ổn định giữa 2 lần chạy.
        """
        lat = 21.05000
        lon = 105.85000
        s4 = alerts.AlertPoint(
            lat=lat,
            lon=lon,
            sign_type=4,
            speed_limit=0,
            heading=180,
            is_camera=False,
            source="Base",
            priority=alerts.PRIORITY_BASE,
            desc="Base Sign 4 Isolated",
            kind="sign",
            original_id=9999,
        )

        # Chạy lần 1
        m1, stats1 = alerts.merge_and_deduplicate([s4])
        self.assertEqual(len(m1), 1)
        self.assertTrue(m1[0].is_camera)
        self.assertEqual(m1[0].speed_limit, -1)
        self.assertEqual(m1[0].heading, 180)
        self.assertEqual(stats1["sign_type_4_converted_to_camera"], 1)

        alerts.allocate_stable_ids(m1)
        id1 = m1[0].id
        self.assertGreaterEqual(id1, 1 << 62)

        # Chạy lần 2
        s4_clone = alerts.AlertPoint(
            lat=lat,
            lon=lon,
            sign_type=4,
            speed_limit=0,
            heading=180,
            is_camera=False,
            source="Base",
            priority=alerts.PRIORITY_BASE,
            desc="Base Sign 4 Isolated",
            kind="sign",
            original_id=9999,
        )
        m2, stats2 = alerts.merge_and_deduplicate([s4_clone])
        alerts.allocate_stable_ids(m2)
        id2 = m2[0].id

        self.assertEqual(id1, id2, "ID camera chuyển đổi từ sign 4 phải tuyệt đối ổn định và lặp lại")

    def test_camera_base_vs_vietmap_opposite_and_distance(self):
        """
        Camera nền cách camera VietMap 25 m, NGƯỢC hướng -> chỉ còn camera VietMap (bán kính camera 30m, khác nguồn bỏ không xét hướng).
        Camera nền cách camera VietMap 35 m -> còn 2 camera.
        """
        vm_cam = alerts.AlertPoint(
            lat=21.00000,
            lon=105.80000,
            sign_type=None,
            speed_limit=60,
            heading=90,
            is_camera=True,
            source="VietMap",
            priority=alerts.PRIORITY_VIETMAP,
            desc="VM Cam",
            kind="camera",
        )

        # Base cam cách 25m, ngược hướng 270 (diff = 180)
        lat_25m = 21.00000 + meters_to_lat_deg(25.0)
        base_cam_25m = alerts.AlertPoint(
            lat=lat_25m,
            lon=105.80000,
            sign_type=None,
            speed_limit=60,
            heading=270,
            is_camera=True,
            source="Base",
            priority=alerts.PRIORITY_BASE,
            desc="Base Cam 25m",
            kind="camera",
            original_id=101,
        )

        # Khác nguồn trong 25m <= 30m -> chỉ còn VietMap
        m_25m, _ = alerts.merge_and_deduplicate([vm_cam, base_cam_25m])
        self.assertEqual(len(m_25m), 1)
        self.assertEqual(m_25m[0].source, "VietMap")

        # Base cam cách 35m > 30m -> giữ cả 2
        lat_35m = 21.00000 + meters_to_lat_deg(35.0)
        base_cam_35m = alerts.AlertPoint(
            lat=lat_35m,
            lon=105.80000,
            sign_type=None,
            speed_limit=60,
            heading=270,
            is_camera=True,
            source="Base",
            priority=alerts.PRIORITY_BASE,
            desc="Base Cam 35m",
            kind="camera",
            original_id=102,
        )
        m_35m, _ = alerts.merge_and_deduplicate([vm_cam, base_cam_35m])
        self.assertEqual(len(m_35m), 2)

    def test_cross_source_light_and_sign_radii(self):
        """
        - Đèn nền/WYN cách đèn VietMap 40 m (< 45m) -> bỏ; cách 50 m (> 45m) -> giữ.
        - Biển nền cùng type cách biển WYN 15 m (< 20m) -> bỏ; khác type -> giữ.
        - Đèn WYN cách đèn VietMap 30 m (< 45m) -> chỉ còn VietMap.
        """
        # 1. Đèn: bán kính 45m
        vm_light = alerts.AlertPoint(
            lat=21.00000,
            lon=105.80000,
            sign_type=alerts.SIGN_TYPE_TRAFFIC_LIGHT,
            speed_limit=0,
            heading=90,
            is_camera=False,
            source="VietMap",
            priority=alerts.PRIORITY_VIETMAP,
            desc="VM Light",
            kind="light",
        )
        # Đèn WYN cách 30m -> bỏ
        lat_30m = 21.00000 + meters_to_lat_deg(30.0)
        wyn_light_30m = alerts.AlertPoint(
            lat=lat_30m,
            lon=105.80000,
            sign_type=alerts.SIGN_TYPE_TRAFFIC_LIGHT,
            speed_limit=0,
            heading=90,
            is_camera=False,
            source="WYN",
            priority=alerts.PRIORITY_WYN,
            desc="WYN Light 30m",
            kind="light",
        )
        m_30m, _ = alerts.merge_and_deduplicate([vm_light, wyn_light_30m])
        self.assertEqual(len(m_30m), 1)
        self.assertEqual(m_30m[0].source, "VietMap")

        # Đèn nền cách 40m (< 45m) -> bỏ
        lat_40m = 21.00000 + meters_to_lat_deg(40.0)
        base_light_40m = alerts.AlertPoint(
            lat=lat_40m,
            lon=105.80000,
            sign_type=alerts.SIGN_TYPE_TRAFFIC_LIGHT,
            speed_limit=0,
            heading=90,
            is_camera=False,
            source="Base",
            priority=alerts.PRIORITY_BASE,
            desc="Base Light 40m",
            kind="light",
            original_id=201,
        )
        m_40m, _ = alerts.merge_and_deduplicate([vm_light, base_light_40m])
        self.assertEqual(len(m_40m), 1)

        # Đèn nền cách 50m (> 45m) -> giữ
        lat_50m = 21.00000 + meters_to_lat_deg(50.0)
        base_light_50m = alerts.AlertPoint(
            lat=lat_50m,
            lon=105.80000,
            sign_type=alerts.SIGN_TYPE_TRAFFIC_LIGHT,
            speed_limit=0,
            heading=90,
            is_camera=False,
            source="Base",
            priority=alerts.PRIORITY_BASE,
            desc="Base Light 50m",
            kind="light",
            original_id=202,
        )
        m_50m, _ = alerts.merge_and_deduplicate([vm_light, base_light_50m])
        self.assertEqual(len(m_50m), 2)

        # 2. Biển khác: bán kính 20m
        wyn_sign1 = alerts.AlertPoint(
            lat=21.10000,
            lon=105.80000,
            sign_type=alerts.SIGN_TYPE_SPEED_LIMIT,
            speed_limit=60,
            heading=90,
            is_camera=False,
            source="WYN",
            priority=alerts.PRIORITY_WYN,
            desc="WYN Speed 60",
            kind="sign",
        )
        # Biển nền cùng type (1) cách 15m (< 20m) -> bỏ
        lat_15m = 21.10000 + meters_to_lat_deg(15.0)
        base_sign1 = alerts.AlertPoint(
            lat=lat_15m,
            lon=105.80000,
            sign_type=alerts.SIGN_TYPE_SPEED_LIMIT,
            speed_limit=0,
            heading=90,
            is_camera=False,
            source="Base",
            priority=alerts.PRIORITY_BASE,
            desc="Base Speed",
            kind="sign",
            original_id=301,
        )
        m_sign_same_type, _ = alerts.merge_and_deduplicate([wyn_sign1, base_sign1])
        self.assertEqual(len(m_sign_same_type), 1)
        self.assertEqual(m_sign_same_type[0].source, "WYN")

        # Biển nền khác type (type 2 - khu dân cư) cách 15m -> giữ
        base_sign2 = alerts.AlertPoint(
            lat=lat_15m,
            lon=105.80000,
            sign_type=alerts.SIGN_TYPE_RESIDENT_AREA,
            speed_limit=0,
            heading=90,
            is_camera=False,
            source="Base",
            priority=alerts.PRIORITY_BASE,
            desc="Base Resident",
            kind="sign",
            original_id=302,
        )
        m_sign_diff_type, _ = alerts.merge_and_deduplicate([wyn_sign1, base_sign2])
        self.assertEqual(len(m_sign_diff_type), 2)

    def test_same_source_vietmap_camera_opposite_vs_identical(self):
        """
        - 2 camera CÙNG nguồn VietMap ngược hướng cách 10 m -> giữ cả 2.
        - 2 camera VietMap cách 1 m cùng hướng -> gộp còn 1.
        """
        cam1 = alerts.AlertPoint(
            lat=21.00000,
            lon=105.80000,
            sign_type=None,
            speed_limit=60,
            heading=90,
            is_camera=True,
            source="VietMap",
            priority=alerts.PRIORITY_VIETMAP,
            desc="VM Cam 1",
            kind="camera",
        )
        # Cách 10m ngược hướng (270)
        lat_10m = 21.00000 + meters_to_lat_deg(10.0)
        cam_opp_10m = alerts.AlertPoint(
            lat=lat_10m,
            lon=105.80000,
            sign_type=None,
            speed_limit=60,
            heading=270,
            is_camera=True,
            source="VietMap",
            priority=alerts.PRIORITY_VIETMAP,
            desc="VM Cam Opp 10m",
            kind="camera",
        )
        m_opp, _ = alerts.merge_and_deduplicate([cam1, cam_opp_10m])
        self.assertEqual(len(m_opp), 2, "Cùng nguồn ngược hướng ở hai chiều đường phải được giữ cả hai")

        # Theo D2: 2 camera VietMap cách 1m cùng hướng nhưng khác toạ độ/hướng -> GIỮ CẢ 2
        lat_1m = 21.00000 + meters_to_lat_deg(1.0)
        cam_dup_1m = alerts.AlertPoint(
            lat=lat_1m,
            lon=105.80000,
            sign_type=None,
            speed_limit=60,
            heading=91,
            is_camera=True,
            source="VietMap",
            priority=alerts.PRIORITY_VIETMAP,
            desc="VM Cam Dup 1m",
            kind="camera",
        )
        m_diff, _ = alerts.merge_and_deduplicate([cam1, cam_dup_1m])
        self.assertEqual(len(m_diff), 2, "VietMap cách 1m không giống hệt phải giữ cả hai theo D2")

        # 2 camera VietMap giống hệt từng thuộc tính -> gộp còn 1
        cam_identical = alerts.AlertPoint(
            lat=21.00000,
            lon=105.80000,
            sign_type=None,
            speed_limit=60,
            heading=90,
            is_camera=True,
            source="VietMap",
            priority=alerts.PRIORITY_VIETMAP,
            desc="VM Cam Identical",
            kind="camera",
        )
        m_dup, _ = alerts.merge_and_deduplicate([cam1, cam_identical])
        self.assertEqual(len(m_dup), 1, "VietMap giống hệt nhau gộp còn 1")

        # Nguồn WYN cách 1m lệch <= 5 độ -> gộp còn 1 (WYN giữ luật <= 2m, +-5 độ)
        cam_wyn_1 = alerts.AlertPoint(21.00000, 105.80000, None, 60, 90, True, "WYN", 2, "WYN 1")
        cam_wyn_2 = alerts.AlertPoint(lat_1m, 105.80000, None, 60, 91, True, "WYN", 2, "WYN 2")
        m_wyn_dup, _ = alerts.merge_and_deduplicate([cam_wyn_1, cam_wyn_2])
        self.assertEqual(len(m_wyn_dup), 1, "WYN cách <= 2m lệch <= 5 độ gộp còn 1")

    def test_validator_rejects_sign_type_4_in_signs_bin(self):
        """
        Kiểm tra validate_speedmap.py: Nếu signs.bin chứa sign_type == 4 -> báo LỖI (theo chuẩn R3).
        """
        ds_dir = self.td / "ds_with_s4"
        ds_dir.mkdir(parents=True, exist_ok=True)

        # Tạo file signs.bin có 1 sign_type == 4
        sign_pt = struct.pack(
            vsm.SIGN_POINT_FMT,
            1,
            int(21.0 * 1e7),
            int(105.8 * 1e7),
            90,
            4,   # sign_type = 4
            0,
            0,
            0,
            0,
        )
        crc = zlib.crc32(sign_pt) & 0xFFFFFFFF
        hdr = struct.pack(vsm.SIGN_HEADER_FMT, b"VNSG", 1, 1, 0, crc, 1700000000)
        (ds_dir / "signs.bin").write_bytes(hdr + sign_pt)

        validator = vsm.SpeedMapValidator(ds_dir)
        validator.validate_signs()
        self.assertIn("signs", validator.section_results)
        self.assertEqual(validator.section_results["signs"]["status"], "FAILED")
        self.assertTrue(any("sign_type 4" in err for err in validator.section_results["signs"]["errors"]))


if __name__ == "__main__":
    unittest.main()
