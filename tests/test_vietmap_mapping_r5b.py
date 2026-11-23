#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Bản sao từ VietHUD/tools/tests/test_vietmap_mapping_r5b.py — nguồn chuẩn là VietHUD/tools; sửa ở đó rồi chép lại
"""
tools/tests/test_vietmap_mapping_r5b.py — Bộ kiểm thử toàn diện quy chuẩn R5b:
  1. Mỗi dòng trong bảng Bước 1: 11 loại VietMap ánh xạ chính xác sign_type, sub_type, speed, heading.
  2. Bảo toàn 100% điểm VietMap qua pipeline (Quyết định D2).
  3. KDC Base nội đô:
     - Không có VietMap <= 300 m -> BỎ (urban_kdc_dropped tăng).
     - Có VietMap <= 300 m (cách 100 m) -> GIỮ (không bị bỏ bởi urban_kdc_dropped).
     - Có VietMap <= 20 m -> Bị khử trùng bình thường bởi VietMap.
  4. Camera Base nội đô: GIỮ NGUYÊN (không bị lọc bỏ).
  5. Cổng 4 kiểm định OSM chỉ tính camera VietMap (không bị kéo tụt bởi Base camera nội đô xa đèn).
"""

import sys
from pathlib import Path
_REPO_DIR = Path(__file__).resolve().parent.parent
if str(_REPO_DIR) not in sys.path:
    sys.path.insert(0, str(_REPO_DIR))

import json
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

try:
    from tools import alerts
except ImportError:
    import alerts
try:
    from tools import validate_speedmap as vsm
except ImportError:
    import validate_speedmap as vsm
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


def write_test_signs_bin(dir_path: Path, points: list):
    pt_bytes = bytearray()
    for idx, pt in enumerate(points, start=1):
        lat, lon, stype, sub = pt[0], pt[1], pt[2], pt[3]
        sres = pt[4] if len(pt) >= 5 else 0
        pt_bytes.extend(
            struct.pack(
                vsm.SIGN_POINT_FMT,
                idx,
                int(round(lat * 1e7)),
                int(round(lon * 1e7)),
                0,
                stype,
                0,
                sub,
                0,
                sres,
            )
        )
    crc = zlib.crc32(pt_bytes) & 0xFFFFFFFF
    hdr = struct.pack(vsm.SIGN_HEADER_FMT, b"VNSG", 1, len(points), 0, crc, 1700000000)
    (dir_path / "signs.bin").write_bytes(hdr + pt_bytes)


def write_test_cameras_bin(dir_path: Path, points: list):
    cam_bytes = bytearray()
    for idx, (cid, lat, lon) in enumerate(points, start=1):
        cam_bytes.extend(
            struct.pack(
                vsm.CAMERA_FMT,
                cid,
                int(round(lat * 1e7)),
                int(round(lon * 1e7)),
                0,
                0,
            )
        )
    (dir_path / "cameras.bin").write_bytes(cam_bytes)


class TestVietmapMappingR5B(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.td = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_step1_mapping_table_rows_and_vietmap_100pct_preservation(self):
        """
        Kiểm tra mỗi dòng trong bảng Bước 1:
          - Type 1  -> Sign 1, sub 0, speed 60, hd 90
          - Type 2  -> Sign 2, sub 0, speed 0, hd 180 (vào KDC)
          - Type 3  -> Sign 2, sub 1, speed 0, hd 270 (hết KDC)
          - Type 4  -> Sign 6, sub 0, speed 0, hd 45  (đèn tín hiệu)
          - Type 5  -> Sign 3, sub 0, speed 0, hd 50  (bắt đầu cấm vượt)
          - Type 6  -> Sign 3, sub 1, speed 0, hd 60  (hết cấm vượt)
          - Type 7  -> Sign 10, sub 7, speed 0, hd 70 (chú ý đoạn đường phía trước)
          - Type 8  -> Sign 5, sub 0, speed 0, hd 0xFFFF (trạm thu phí)
          - Type 9  -> Sign 10, sub 9, speed 0, hd 95 (hầm)
          - Type 10 -> Sign 10, sub 10, speed 0, hd 100 (chỉ vẽ, không đọc)
          - Type 11 -> Camera, speed 0, hd 110 (camera phạt nguội)
          - Bảo toàn 100% điểm VietMap sau merge_and_deduplicate.
        """
        vm_bin = self.td / "secrect.bin"
        lines = [
            b"HEADER" + encode_vm_line("20261120"),
            encode_vm_line("105.800000,21.000000,1,60,0,90"),
            encode_vm_line("105.810000,21.010000,2,0,0,180"),
            encode_vm_line("105.820000,21.020000,3,0,0,270"),
            encode_vm_line("105.830000,21.030000,4,0,0,45"),
            encode_vm_line("105.840000,21.040000,5,0,0,50"),
            encode_vm_line("105.850000,21.050000,6,0,0,60"),
            encode_vm_line("105.860000,21.060000,7,0,0,70"),
            encode_vm_line("105.870000,21.070000,8,0,0,0"),
            encode_vm_line("105.880000,21.080000,9,0,0,95"),
            encode_vm_line("105.890000,21.090000,10,0,0,100"),
            encode_vm_line("105.900000,21.100000,11,0,0,110"),
        ]
        vm_bin.write_bytes(b"\x83\x71".join(lines))

        pts, ver = alerts.load_vietmap_alerts(vm_bin)
        self.assertEqual(len(pts), 11, "Phải nạp đủ 11 điểm VietMap")

        # 1. Type 1: Sign 1 SPEED_LIMIT
        p1 = next(p for p in pts if getattr(p, "original_type", None) == 1)
        self.assertEqual(p1.sign_type, alerts.SIGN_TYPE_SPEED_LIMIT)
        self.assertEqual(p1.sub_type, 0)
        self.assertEqual(p1.speed_limit, 60)
        self.assertEqual(p1.heading, 90)

        # 2. Type 2: Sign 2 RESIDENT_AREA sub 0
        p2 = next(p for p in pts if getattr(p, "original_type", None) == 2)
        self.assertEqual(p2.sign_type, alerts.SIGN_TYPE_RESIDENT_AREA)
        self.assertEqual(p2.sub_type, 0)
        self.assertEqual(p2.speed_limit, 0)
        self.assertEqual(p2.heading, 180)

        # 3. Type 3: Sign 2 RESIDENT_AREA sub 1
        p3 = next(p for p in pts if getattr(p, "original_type", None) == 3)
        self.assertEqual(p3.sign_type, alerts.SIGN_TYPE_RESIDENT_AREA)
        self.assertEqual(p3.sub_type, 1)
        self.assertEqual(p3.speed_limit, 0)
        self.assertEqual(p3.heading, 270)

        # 4. Type 4: Sign 10 DANGER_OTHER sub 4 (R6)
        p4 = next(p for p in pts if getattr(p, "original_type", None) == 4)
        self.assertEqual(p4.sign_type, alerts.SIGN_TYPE_DANGER_OTHER)
        self.assertEqual(p4.sub_type, 4)
        self.assertEqual(p4.speed_limit, 0)
        self.assertEqual(p4.heading, 45)

        # 5. Type 5: Sign 3 NO_OVERTAKING sub 0 (bắt đầu)
        p5 = next(p for p in pts if getattr(p, "original_type", None) == 5)
        self.assertEqual(p5.sign_type, alerts.SIGN_TYPE_NO_OVERTAKING)
        self.assertEqual(p5.sub_type, 0)
        self.assertEqual(p5.speed_limit, 0)
        self.assertEqual(p5.heading, 50)

        # 6. Type 6: Sign 3 NO_OVERTAKING sub 1 (hết)
        p6 = next(p for p in pts if getattr(p, "original_type", None) == 6)
        self.assertEqual(p6.sign_type, alerts.SIGN_TYPE_NO_OVERTAKING)
        self.assertEqual(p6.sub_type, 1)
        self.assertEqual(p6.speed_limit, 0)
        self.assertEqual(p6.heading, 60)

        # 7. Type 7: Sign 10 DANGER_OTHER sub 7
        p7 = next(p for p in pts if getattr(p, "original_type", None) == 7)
        self.assertEqual(p7.sign_type, alerts.SIGN_TYPE_DANGER_OTHER)
        self.assertEqual(p7.sub_type, 7)
        self.assertEqual(p7.speed_limit, 0)
        self.assertEqual(p7.heading, 70)

        # 8. Type 8: Sign 5 TOLL_BOOTH sub 0, DIR_OMNI
        p8 = next(p for p in pts if getattr(p, "original_type", None) == 8)
        self.assertEqual(p8.sign_type, alerts.SIGN_TYPE_TOLL_BOOTH)
        self.assertEqual(p8.sub_type, 0)
        self.assertEqual(p8.speed_limit, 0)
        self.assertEqual(p8.heading, alerts.DIR_OMNI)

        # 9. Type 9: Sign 10 DANGER_OTHER sub 9
        p9 = next(p for p in pts if getattr(p, "original_type", None) == 9)
        self.assertEqual(p9.sign_type, alerts.SIGN_TYPE_DANGER_OTHER)
        self.assertEqual(p9.sub_type, 9)
        self.assertEqual(p9.speed_limit, 0)
        self.assertEqual(p9.heading, 95)

        # 10. Type 10: Sign 10 DANGER_OTHER sub 10
        p10 = next(p for p in pts if getattr(p, "original_type", None) == 10)
        self.assertEqual(p10.sign_type, alerts.SIGN_TYPE_DANGER_OTHER)
        self.assertEqual(p10.sub_type, 10)
        self.assertEqual(p10.speed_limit, 0)
        self.assertEqual(p10.heading, 100)

        # 11. Type 11: Camera
        p11 = next(p for p in pts if getattr(p, "original_type", None) == 11)
        self.assertTrue(p11.is_camera)
        self.assertIsNone(p11.sign_type)
        self.assertEqual(p11.speed_limit, 0)
        self.assertEqual(p11.heading, 110)

        # Kiểm tra bảo tồn 100% VietMap sau merge_and_deduplicate
        master, stats = alerts.merge_and_deduplicate(pts)
        self.assertEqual(len(master), 11)
        self.assertEqual(stats["vietmap_kept"], 11)
        self.assertEqual(stats["vietmap_out"], 11)

    def test_step3_urban_kdc_dropped_when_no_vietmap_nearby(self):
        """
        3.1: Biển vào/hết KDC Base nội đô:
          - Không có VietMap KDC <= 300 m -> BỎ (đếm urban_kdc_dropped)
          - Có VietMap KDC <= 300 m (cách 100 m) -> GIỮ
          - Có VietMap KDC <= 20 m -> Bị khử trùng lặp bình thường bởi VietMap.
        """
        # Điểm trong nội đô Hà Nội (lat 21.02, lon 105.83)
        lat_hn, lon_hn = 21.020000, 105.830000

        # Base KDC 1: Đơn độc trong nội đô HN, không có VietMap KDC nào -> BỎ
        base_kdc_alone = alerts.AlertPoint(
            lat=lat_hn, lon=lon_hn, sign_type=alerts.SIGN_TYPE_RESIDENT_AREA,
            speed_limit=0, heading=90, is_camera=False, source="Base",
            priority=alerts.PRIORITY_BASE, desc="Base KDC Alone in HN",
            sub_type=0
        )

        # Điểm trong nội đô TP.HCM (lat 10.78, lon 106.69)
        lat_hcm, lon_hcm = 10.780000, 106.690000
        vm_kdc_hcm = alerts.AlertPoint(
            lat=lat_hcm, lon=lon_hcm, sign_type=alerts.SIGN_TYPE_RESIDENT_AREA,
            speed_limit=0, heading=90, is_camera=False, source="VietMap",
            priority=alerts.PRIORITY_VIETMAP, desc="VM KDC HCM",
            original_type=2, sub_type=0, decoded_heading=90
        )

        # Trong R5c (Bước A3): Mọi biển KDC Base/WYN cách VietMap <= 300m đều bị loại bỏ
        # (kdc_near_vietmap_dropped) để tránh đọc "bắt đầu KDC" ở lối ra hoặc xung đột.
        # base_kdc_near_100m (cách 100m) và base_kdc_dup_10m (cách 10m) đều <= 300m -> BỎ bởi A3
        lat_100m = lat_hcm + meters_to_lat_deg(100.0)
        base_kdc_near_100m = alerts.AlertPoint(
            lat=lat_100m, lon=lon_hcm, sign_type=alerts.SIGN_TYPE_RESIDENT_AREA,
            speed_limit=0, heading=90, is_camera=False, source="Base",
            priority=alerts.PRIORITY_BASE, desc="Base KDC near VM 100m",
            sub_type=0
        )

        lat_10m = lat_hcm + meters_to_lat_deg(10.0)
        base_kdc_dup_10m = alerts.AlertPoint(
            lat=lat_10m, lon=lon_hcm, sign_type=alerts.SIGN_TYPE_RESIDENT_AREA,
            speed_limit=0, heading=90, is_camera=False, source="Base",
            priority=alerts.PRIORITY_BASE, desc="Base KDC dup VM 10m",
            sub_type=0
        )

        # Base KDC 4: Ở ngoại thành (ngoài 4 hộp nội đô) và cách xa VietMap > 300m -> GIỮ
        base_kdc_far_rural = alerts.AlertPoint(
            lat=21.500000, lon=105.500000, sign_type=alerts.SIGN_TYPE_RESIDENT_AREA,
            speed_limit=0, heading=90, is_camera=False, source="Base",
            priority=alerts.PRIORITY_BASE, desc="Base KDC Far Rural",
            sub_type=0
        )

        candidates = [base_kdc_alone, vm_kdc_hcm, base_kdc_near_100m, base_kdc_dup_10m, base_kdc_far_rural]
        master, stats = alerts.merge_and_deduplicate(candidates)

        # base_kdc_alone bị bỏ bởi urban_kdc_dropped
        self.assertEqual(stats["urban_kdc_dropped"], 1)
        self.assertNotIn(base_kdc_alone, master)

        # base_kdc_near_100m và base_kdc_dup_10m bị bỏ bởi kdc_near_vietmap_dropped (A3: <= 300m)
        self.assertEqual(stats["kdc_near_vietmap_dropped"], 2)
        self.assertNotIn(base_kdc_near_100m, master)
        self.assertNotIn(base_kdc_dup_10m, master)

        # vm_kdc_hcm được giữ nguyên (D2)
        self.assertIn(vm_kdc_hcm, master)

        # base_kdc_far_rural được giữ (vì cách xa VM > 300m và ngoài 4 hộp nội đô)
        self.assertIn(base_kdc_far_rural, master)

    def test_step3_urban_base_camera_preserved(self):
        """3.2: Camera Base trong nội đô vẫn được GIỮ (có thể là camera làn/an ninh thật)."""
        lat_hn, lon_hn = 21.030000, 105.840000
        base_cam_urban = alerts.AlertPoint(
            lat=lat_hn, lon=lon_hn, sign_type=None,
            speed_limit=-1, heading=90, is_camera=True, source="Base",
            priority=alerts.PRIORITY_BASE, desc="Base Camera Urban HN",
            kind="camera", original_id=7777777
        )

        master, stats = alerts.merge_and_deduplicate([base_cam_urban])
        self.assertIn(base_cam_urban, master)
        self.assertEqual(len(master), 1)
        self.assertEqual(master[0].source, "Base")
        self.assertTrue(master[0].is_camera)

    def test_step4_gate_4_considers_only_vietmap_cameras(self):
        """
        3.2 & Bước 4: Cổng 4 chỉ đánh giá camera nguồn VietMap:
          - 10 camera VietMap nội đô: 9 gần đèn OSM (90% >= 85%) -> ĐẠT
          - 10 camera Base nội đô: 0 gần đèn OSM (0% < 85%)
          - Nếu xét gộp cả Base: 9/20 = 45% < 85% -> TRƯỢT.
          - Nhờ sửa cổng 4 chỉ xét VietMap -> ĐẠT (0 lỗi), Base chỉ in THÔNG TIN.
        """
        osm_json = self.td / "osm_ground_truth.json"
        osm_json.write_text(json.dumps({
            "toll_booths": [],
            "traffic_signals": [[21.030000, 105.850000]],
            "tunnel_portals": [],
        }), encoding="utf-8")

        write_test_signs_bin(self.td, [])

        # 10 camera VietMap: id 1001..1010
        # 9 điểm gần đèn (21.0301 cách 21.0300 ~11m), 1 điểm xa (21.0500)
        cams = []
        csv_rows = ["id,kinh_do,vi_do,loai_canh_bao,ma_loai,toc_do_kmh,huong_do,la_camera,nguon_du_lieu\n"]

        for i in range(1, 10):
            cid = 1000 + i
            cams.append((cid, 21.0301, 105.8500))
            csv_rows.append(f"{cid},105.850000,21.030100,VM Cam,11,0,90,1,VietMap\n")
        cid = 1010
        cams.append((cid, 21.0500, 105.8200))
        csv_rows.append(f"{cid},105.820000,21.050000,VM Cam,11,0,90,1,VietMap\n")

        # 10 camera Base: id 2001..2010 đều ở xa đèn (21.0550)
        for i in range(1, 11):
            cid = 2000 + i
            cams.append((cid, 21.0550, 105.8100))
            csv_rows.append(f"{cid},105.810000,21.055000,Base Cam,11,-1,90,1,Base\n")

        write_test_cameras_bin(self.td, cams)
        (self.td / "combined_traffic_alerts.csv").write_text("".join(csv_rows), encoding="utf-8-sig")

        val = vsm.SpeedMapValidator(self.td, osm_path=osm_json)
        val.validate_osm_gates()

        # Cổng 4 phải ĐẠT vì chỉ xét VietMap (9/10 = 90% >= 85%)
        self.assertEqual(len(val.errors), 0, "Gate 4 chỉ xét VietMap nên phải ĐẠT")
        self.assertEqual(val.section_results["osm_gates"]["details"]["urban_camera_signal_ratio"], 0.9)


if __name__ == "__main__":
    unittest.main()
