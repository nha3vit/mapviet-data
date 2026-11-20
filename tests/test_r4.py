# Bản sao từ VietHUD/tools/tests/test_r4.py — nguồn chuẩn là VietHUD/tools; sửa ở đó rồi chép lại
import sys
from pathlib import Path
_REPO_DIR = Path(__file__).resolve().parent.parent
if str(_REPO_DIR) not in sys.path:
    sys.path.insert(0, str(_REPO_DIR))

import struct
import tempfile
import unittest
from pathlib import Path

try:
    from tools import alerts
    from tools import vietmap_decode as vmd
except ImportError:
    import alerts
    import vietmap_decode as vmd


def meters_to_lat_deg(meters: float) -> float:
    # 1 độ vĩ tuyến ~ 111.139 mét
    return meters / 111139.0


def encode_vm_line(text: str) -> bytes:
    return bytes(vmd.REVERSE_SUBSTITUTION[ch] for ch in text)


class TestR4Standardization(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.td = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_vietmap_identical_dedup(self):
        """
        Bước 6:
        2 camera VietMap cách 1 m cùng hướng, khác tốc độ -> giữ cả 2.
        2 dòng VietMap giống hệt -> còn 1.
        (Theo nguyên tắc D2: VietMap chỉ bỏ bản sao giống hệt tuyệt đối).
        """
        lat1 = 21.0000000
        lon1 = 105.8000000
        lat_1m = lat1 + meters_to_lat_deg(1.0)

        # 2 camera cách 1m cùng hướng, khác tốc độ (0 vs 60)
        c1 = alerts.AlertPoint(lat1, lon1, None, 0, 90, True, "VietMap", alerts.PRIORITY_VIETMAP, "VM 1", "camera")
        c2 = alerts.AlertPoint(lat_1m, lon1, None, 60, 90, True, "VietMap", alerts.PRIORITY_VIETMAP, "VM 2", "camera")
        res_diff, _ = alerts.merge_and_deduplicate([c1, c2])
        self.assertEqual(len(res_diff), 2, "2 camera VietMap cách 1m khác tốc độ phải giữ cả hai theo D2")

        # 2 dòng VietMap giống hệt tuyệt đối -> còn 1
        c_dup = alerts.AlertPoint(lat1, lon1, None, 0, 90, True, "VietMap", alerts.PRIORITY_VIETMAP, "VM Dup", "camera")
        res_dup, _ = alerts.merge_and_deduplicate([c1, c_dup])
        self.assertEqual(len(res_dup), 1, "2 dòng VietMap giống hệt nhau phải gộp còn 1")

    def test_vietmap_type_8_and_9_mapping(self):
        """
        Bước 6 & R4-FIX (cập nhật chuẩn R5a):
        VietMap loại 8 -> có trong signs: type 5 (TOLL_BOOTH), sub_type 0, hướng 0 -> 0xFFFF.
        VietMap loại 9 -> có trong signs: type 10 (DANGER_OTHER), sub_type 9, giữ hướng.
        """
        vm_bin = self.td / "secrect.bin"
        lines = [
            b"20261119",
            encode_vm_line("105.840000,21.040000,8,0,0,0"),  # Type 8 hướng 0
            encode_vm_line("105.850000,21.050000,9,0,0,90"),  # Type 9
        ]
        vm_bin.write_bytes(b"\x83\x71".join(lines))

        pts, _ = alerts.load_vietmap_alerts(vm_bin)
        self.assertEqual(len(pts), 2)

        p8 = [p for p in pts if p.sign_type == alerts.SIGN_TYPE_TOLL_BOOTH][0]
        self.assertEqual(p8.sign_type, alerts.SIGN_TYPE_TOLL_BOOTH)
        self.assertEqual(p8.sub_type, 0)
        self.assertEqual(p8.speed_limit, 0)
        self.assertEqual(p8.heading, alerts.DIR_OMNI, "VietMap loại 8 hướng 0 -> 0xFFFF theo F1")
        self.assertFalse(p8.is_camera)

        p9 = [p for p in pts if p.sub_type == 9][0]
        self.assertEqual(p9.sign_type, alerts.SIGN_TYPE_DANGER_OTHER)
        self.assertEqual(p9.sub_type, 9)
        self.assertEqual(p9.speed_limit, 0)
        self.assertEqual(p9.heading, 90)
        self.assertFalse(p9.is_camera)

    def test_vietmap_camera_no_inherit_speed(self):
        """
        Bước 6:
        Camera VietMap 0 + camera WYN 50 cách 10 m -> còn camera VietMap, tốc độ 0 (D4).
        Camera VietMap không bao giờ nhận tốc độ.
        """
        lat1 = 21.0000000
        lon1 = 105.8000000
        lat_10m = lat1 + meters_to_lat_deg(10.0)

        vm_cam = alerts.AlertPoint(lat1, lon1, None, 0, 90, True, "VietMap", alerts.PRIORITY_VIETMAP, "VM Cam", "camera")
        wyn_cam = alerts.AlertPoint(lat_10m, lon1, None, 50, 90, True, "WYN", alerts.PRIORITY_WYN, "WYN Cam", "camera")

        res, stats = alerts.merge_and_deduplicate([vm_cam, wyn_cam])
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].source, "VietMap")
        self.assertEqual(res[0].speed_limit, 0, "Camera VietMap tốc độ 0 giữ nguyên 0 theo D4, không nhận tốc độ từ WYN")

    def test_camera_speed_inheritance_when_unknown(self):
        """
        Bước 6:
        Camera WYN -1 + camera nền 50 cách 10 m -> còn WYN, tốc độ 50 (kế thừa khi Master == -1).
        """
        lat1 = 21.0000000
        lon1 = 105.8000000
        lat_10m = lat1 + meters_to_lat_deg(10.0)

        wyn_cam = alerts.AlertPoint(lat1, lon1, None, -1, 90, True, "WYN", alerts.PRIORITY_WYN, "WYN Cam", "camera")
        base_cam = alerts.AlertPoint(lat_10m, lon1, None, 50, 90, True, "Base", alerts.PRIORITY_BASE, "Base Cam", "camera")

        res, stats = alerts.merge_and_deduplicate([wyn_cam, base_cam])
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].source, "WYN")
        self.assertEqual(res[0].speed_limit, 50, "Camera WYN speed -1 phải kế thừa tốc độ 50 từ Base")

    def test_speed_sign_zero_no_inherit_speed(self):
        """
        Bước 6:
        Biển tốc độ VietMap 0 + biển nền 50 cách 10 m -> còn biển VietMap 0.
        Biển tốc độ không kế thừa vào biển 0.
        """
        lat1 = 21.0000000
        lon1 = 105.8000000
        lat_10m = lat1 + meters_to_lat_deg(10.0)

        vm_sign = alerts.AlertPoint(lat1, lon1, alerts.SIGN_TYPE_SPEED_LIMIT, 0, 90, False, "VietMap", alerts.PRIORITY_VIETMAP, "VM Sign 0", "sign")
        base_sign = alerts.AlertPoint(lat_10m, lon1, alerts.SIGN_TYPE_SPEED_LIMIT, 50, 90, False, "Base", alerts.PRIORITY_BASE, "Base Sign 50", "sign")

        res, stats = alerts.merge_and_deduplicate([vm_sign, base_sign])
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].source, "VietMap")
        self.assertEqual(res[0].speed_limit, 0, "Biển tốc độ VietMap 0 không được nhận kế thừa tốc độ 50")

    def test_base_speed_sign_filtering(self):
        """
        Bước 6 (tuân thủ Sửa đổi Claude 19/11):
        Biển tốc độ nền 255 -> bỏ; nền 50 -> giữ; nền 0 -> GIỮ.
        """
        base_dir = self.td / "base_speed_test"
        base_dir.mkdir(parents=True, exist_ok=True)
        signs_bin = base_dir / "signs.bin"

        # Ghi header VNSG: 3 biển báo
        hdr_fmt = "<4sHIHII"
        pt_fmt = "<IiiHBBBBH"
        body = bytearray()
        # Biển 1: sign_type 1, speed 255 (sai chuẩn -> BỎ)
        body.extend(struct.pack(pt_fmt, 1, 210000000, 1058000000, 90, 1, 255, 0, 0, 0))
        # Biển 2: sign_type 1, speed 50 (hợp lệ -> GIỮ)
        body.extend(struct.pack(pt_fmt, 2, 210100000, 1058100000, 90, 1, 50, 0, 0, 0))
        # Biển 3: sign_type 1, speed 0 (hết hạn chế chuẩn VietHUD -> GIỮ)
        body.extend(struct.pack(pt_fmt, 3, 210200000, 1058200000, 90, 1, 0, 0, 0, 0))

        import zlib
        crc = zlib.crc32(body)
        header = struct.pack(hdr_fmt, b"VNSG", 2, 3, 0, crc, 123456)
        signs_bin.write_bytes(header + body)

        pts, _ = alerts.load_base_alerts(base_dir)
        # Kỳ vọng: biển 255 bị bỏ, biển 50 và 0 được giữ -> 2 điểm
        self.assertEqual(len(pts), 2)
        speeds = sorted(p.speed_limit for p in pts)
        self.assertEqual(speeds, [0, 50])

    def test_bogus_heading_rules(self):
        """
        Bước 6:
        - 120 trạm thu phí WYN hướng 15° -> về 0xFFFF.
        - 120 biển VietMap loại 2 (traffic light) cùng hướng 90° -> giữ 90°, có trong bogus_headings_report_only.
        """
        pts = []
        # 120 trạm thu phí WYN hướng 15°
        for i in range(120):
            pts.append(alerts.AlertPoint(
                lat=20.0 + i * 0.001,
                lon=105.0,
                sign_type=alerts.SIGN_TYPE_TOLL_BOOTH,
                speed_limit=0,
                heading=15,
                is_camera=False,
                source="WYN",
                priority=alerts.PRIORITY_WYN,
                desc=f"WYN Toll {i}",
                kind="sign",
            ))

        # 120 biển VietMap loại 2 (traffic light) hướng 90°
        for i in range(120):
            pts.append(alerts.AlertPoint(
                lat=21.0 + i * 0.001,
                lon=106.0,
                sign_type=alerts.SIGN_TYPE_TRAFFIC_LIGHT,
                speed_limit=0,
                heading=90,
                is_camera=False,
                source="VietMap",
                priority=alerts.PRIORITY_VIETMAP,
                desc=f"VM Light {i}",
                kind="light",
            ))

        bogus, report_only = alerts.clean_bogus_headings(pts)

        # WYN toll booth: chuyển về 0xFFFF
        wyn_pts = [p for p in pts if p.source == "WYN"]
        self.assertTrue(all(p.heading == alerts.DIR_OMNI for p in wyn_pts))
        self.assertEqual(len(bogus), 1)
        self.assertEqual(bogus[0]["source"], "WYN")
        self.assertEqual(bogus[0]["heading"], 15)

        # VietMap light: giữ nguyên 90°, ghi nhận report_only
        vm_pts = [p for p in pts if p.source == "VietMap"]
        self.assertTrue(all(p.heading == 90 for p in vm_pts))
        self.assertEqual(len(report_only), 1)
        self.assertEqual(report_only[0]["source"], "VietMap")
        self.assertEqual(report_only[0]["heading"], 90)

    def test_vietmap_conservation_hard_check(self):
        """
        Bước 6:
        Kiểm tra cứng VietMap: dữ liệu giả lập thiếu 1 điểm VietMap ở đầu ra -> pipeline báo lỗi SystemExit.
        """
        # Giả lập tình huống VietMap bị thất thoát (ví dụ: gán nhầm sign_type=4 bị dedup drop nhầm)
        c1 = alerts.AlertPoint(21.00000, 105.80000, None, 0, 90, True, "VietMap", alerts.PRIORITY_VIETMAP, "VM Cam", "camera")
        s4_bad = alerts.AlertPoint(21.00005, 105.80000, 4, 0, 90, False, "VietMap", alerts.PRIORITY_VIETMAP, "VM Sign 4 Bad", "sign")

        with self.assertRaises(SystemExit) as ctx:
            alerts.merge_and_deduplicate([c1, s4_bad])
        self.assertIn("[LOI D2] Thất thoát dữ liệu VietMap!", str(ctx.exception))

    def test_r4_fix_vietmap_heading_zero_preserved(self):
        """
        R4-FIX (F1):
        - VietMap biển tốc độ hướng 0 + biển nền cùng loại hướng 180 cách 10 m -> còn biển VietMap, hướng 0.
        - VietMap loại 8 hướng 0 -> 0xFFFF.
        """
        lat1 = 21.0000000
        lon1 = 105.8000000
        lat_10m = lat1 + meters_to_lat_deg(10.0)

        # 1. Biển tốc độ VietMap hướng 0 (hướng Bắc hợp lệ) + biển nền cùng loại hướng 180 cách 10m
        vm_sign_0 = alerts.AlertPoint(
            lat=lat1,
            lon=lon1,
            sign_type=alerts.SIGN_TYPE_SPEED_LIMIT,
            speed_limit=60,
            heading=0,
            is_camera=False,
            source="VietMap",
            priority=alerts.PRIORITY_VIETMAP,
            desc="VM Speed 60 hd=0",
            kind="sign",
            original_type=1,
            decoded_heading=0,
        )
        base_sign_180 = alerts.AlertPoint(
            lat=lat_10m,
            lon=lon1,
            sign_type=alerts.SIGN_TYPE_SPEED_LIMIT,
            speed_limit=60,
            heading=180,
            is_camera=False,
            source="Base",
            priority=alerts.PRIORITY_BASE,
            desc="Base Speed 60 hd=180",
            kind="sign",
            original_type=1,
            decoded_heading=180,
        )

        res, stats = alerts.merge_and_deduplicate([vm_sign_0, base_sign_180])
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].source, "VietMap")
        self.assertEqual(res[0].heading, 0, "Biển VietMap hướng 0 là hướng Bắc hợp lệ, không bị ghi đè thành 180 hay 0xFFFF")

        # 2. VietMap loại 8 hướng 0 -> 0xFFFF
        vm_bin = self.td / "secrect_t8.bin"
        lines = [
            b"20261119",
            encode_vm_line("105.840000,21.040000,8,0,0,0"),  # Type 8 heading 0
        ]
        vm_bin.write_bytes(b"\x83\x71".join(lines))
        pts, _ = alerts.load_vietmap_alerts(vm_bin)
        self.assertEqual(len(pts), 1)
        self.assertEqual(pts[0].heading, alerts.DIR_OMNI, "VietMap loại 8 hướng 0 phải chuyển thành 0xFFFF")
        self.assertEqual(pts[0].sign_type, alerts.SIGN_TYPE_TOLL_BOOTH)
        self.assertEqual(pts[0].sub_type, 0)

    def test_r4_fix_vietmap_heading_hard_check_fails_on_tamper(self):
        """
        R4-FIX (F1):
        Kiểm tra cứng hướng VietMap: nếu điểm VietMap ở đầu ra có hướng khác hướng giải mã -> pipeline báo lỗi.
        """
        vm_pt = alerts.AlertPoint(
            lat=21.0000000,
            lon=105.8000000,
            sign_type=alerts.SIGN_TYPE_SPEED_LIMIT,
            speed_limit=60,
            heading=0,
            is_camera=False,
            source="VietMap",
            priority=alerts.PRIORITY_VIETMAP,
            desc="VM Speed 60 hd=0",
            kind="sign",
            original_type=1,
            decoded_heading=0,
        )
        # Giả lập bị sửa hướng sau giải mã thành 90
        vm_pt.heading = 90

        with self.assertRaises(SystemExit) as ctx:
            alerts.merge_and_deduplicate([vm_pt])
        self.assertIn("[LOI F1] Sai lệch hướng VietMap ở đầu ra!", str(ctx.exception))

    def test_base_end_sign_conflict_vietmap(self):
        """
        Mục 19.1 (G1):
        Biển loại 1 tốc độ 0 của nền mâu thuẫn với biển số VietMap (>0) trong 50m cùng hướng (<= 45 độ hoặc 1 bên không rõ) -> bỏ.
        - Biển nền 0 cách biển VietMap 60 40 m cùng hướng -> bỏ;
        - Cách 60 m -> giữ;
        - Ngược hướng (>= 135 độ) -> giữ;
        - Biển VietMap không đổi.
        """
        lat1 = 21.0000000
        lon1 = 105.8000000
        lat_40m = lat1 + meters_to_lat_deg(40.0)
        lat_60m = lat1 + meters_to_lat_deg(60.0)

        vm_60 = alerts.AlertPoint(
            lat=lat1, lon=lon1, sign_type=alerts.SIGN_TYPE_SPEED_LIMIT, speed_limit=60,
            heading=90, is_camera=False, source="VietMap", priority=alerts.PRIORITY_VIETMAP,
            desc="VM 60", kind="sign", original_type=1, decoded_heading=90
        )

        # 1. Cách 40m cùng hướng (90 vs 90) -> bỏ biển nền
        base_40m_same = alerts.AlertPoint(
            lat=lat_40m, lon=lon1, sign_type=alerts.SIGN_TYPE_SPEED_LIMIT, speed_limit=0,
            heading=90, is_camera=False, source="Base", priority=alerts.PRIORITY_BASE,
            desc="Base 0 40m", kind="sign", original_type=1, decoded_heading=90
        )
        res1, stats1 = alerts.merge_and_deduplicate([vm_60, base_40m_same])
        self.assertEqual(len(res1), 1)
        self.assertEqual(res1[0].source, "VietMap")
        self.assertEqual(res1[0].speed_limit, 60)
        self.assertEqual(stats1["base_end_sign_conflict_vietmap_dropped"], 1)

        # 2. Cách 60m cùng hướng -> giữ cả 2
        base_60m_same = alerts.AlertPoint(
            lat=lat_60m, lon=lon1, sign_type=alerts.SIGN_TYPE_SPEED_LIMIT, speed_limit=0,
            heading=90, is_camera=False, source="Base", priority=alerts.PRIORITY_BASE,
            desc="Base 0 60m", kind="sign", original_type=1, decoded_heading=90
        )
        res2, stats2 = alerts.merge_and_deduplicate([vm_60, base_60m_same])
        self.assertEqual(len(res2), 2)
        self.assertEqual(stats2["base_end_sign_conflict_vietmap_dropped"], 0)

        # 3. Cách 40m ngược hướng (90 vs 270, diff=180 >= 135) -> giữ cả 2
        base_40m_opp = alerts.AlertPoint(
            lat=lat_40m, lon=lon1, sign_type=alerts.SIGN_TYPE_SPEED_LIMIT, speed_limit=0,
            heading=270, is_camera=False, source="Base", priority=alerts.PRIORITY_BASE,
            desc="Base 0 40m opp", kind="sign", original_type=1, decoded_heading=270
        )
        res3, stats3 = alerts.merge_and_deduplicate([vm_60, base_40m_opp])
        self.assertEqual(len(res3), 2)
        self.assertEqual(stats3["base_end_sign_conflict_vietmap_dropped"], 0)

        # 4. Cách 40m nhưng một bên không rõ hướng (heading=DIR_OMNI) -> bỏ biển nền
        base_40m_omni = alerts.AlertPoint(
            lat=lat_40m, lon=lon1, sign_type=alerts.SIGN_TYPE_SPEED_LIMIT, speed_limit=0,
            heading=alerts.DIR_OMNI, is_camera=False, source="Base", priority=alerts.PRIORITY_BASE,
            desc="Base 0 40m omni", kind="sign", original_type=1
        )
        res4, stats4 = alerts.merge_and_deduplicate([vm_60, base_40m_omni])
        self.assertEqual(len(res4), 1)
        self.assertEqual(res4[0].source, "VietMap")
        self.assertEqual(stats4["base_end_sign_conflict_vietmap_dropped"], 1)

    def test_osm_signs_priority_and_deduplication(self):
        """
        Mục 19.3 (I):
        - OSM có ưu tiên thấp nhất (PRIORITY_OSM = 4).
        - Đèn OSM cách đèn nguồn khác (Base/WYN/VietMap) <= 45m -> BỎ; cách > 45m -> GIỮ.
        - Trạm thu phí OSM cách trạm nguồn khác <= 20m -> BỎ; cách > 20m -> GIỮ.
        - Giữ reserved = 3 (SOURCE_CODE_OSM).
        """
        lat0, lon0 = 21.0000000, 105.8000000
        lat_30m = lat0 + meters_to_lat_deg(30.0)
        lat_60m = lat0 + meters_to_lat_deg(60.0)
        lat_10m = lat0 + meters_to_lat_deg(10.0)

        # 1. Đèn Base tại lat0 + đèn OSM tại lat_30m (30m <= 45m) -> bỏ đèn OSM
        base_light = alerts.AlertPoint(
            lat=lat0, lon=lon0, sign_type=alerts.SIGN_TYPE_TRAFFIC_LIGHT, speed_limit=0,
            heading=90, is_camera=False, source="Base", priority=alerts.PRIORITY_BASE,
            desc="Base Light", kind="light"
        )
        osm_light_30m = alerts.AlertPoint(
            lat=lat_30m, lon=lon0, sign_type=alerts.SIGN_TYPE_TRAFFIC_LIGHT, speed_limit=0,
            heading=90, is_camera=False, source="OSM", priority=alerts.PRIORITY_OSM,
            desc="OSM Light 30m", kind="light"
        )
        res1, s1 = alerts.merge_and_deduplicate([base_light, osm_light_30m])
        self.assertEqual(len(res1), 1)
        self.assertEqual(res1[0].source, "Base")
        self.assertEqual(s1["osm_kept"], 0)
        self.assertIn("OSM->Base", s1["dropped_by_source_pair"])

        # 2. Đèn Base tại lat0 + đèn OSM tại lat_60m (60m > 45m) -> giữ cả hai
        osm_light_60m = alerts.AlertPoint(
            lat=lat_60m, lon=lon0, sign_type=alerts.SIGN_TYPE_TRAFFIC_LIGHT, speed_limit=0,
            heading=90, is_camera=False, source="OSM", priority=alerts.PRIORITY_OSM,
            desc="OSM Light 60m", kind="light"
        )
        res2, s2 = alerts.merge_and_deduplicate([base_light, osm_light_60m])
        self.assertEqual(len(res2), 2)
        self.assertEqual(s2["osm_kept"], 1)

        # 3. Trạm thu phí Base tại lat0 + trạm thu phí OSM tại lat_10m (10m <= 20m) -> bỏ OSM
        base_toll = alerts.AlertPoint(
            lat=lat0, lon=lon0, sign_type=alerts.SIGN_TYPE_TOLL_BOOTH, speed_limit=0,
            heading=alerts.DIR_OMNI, is_camera=False, source="Base", priority=alerts.PRIORITY_BASE,
            desc="Base Toll", kind="sign"
        )
        osm_toll_10m = alerts.AlertPoint(
            lat=lat_10m, lon=lon0, sign_type=alerts.SIGN_TYPE_TOLL_BOOTH, speed_limit=0,
            heading=alerts.DIR_OMNI, is_camera=False, source="OSM", priority=alerts.PRIORITY_OSM,
            desc="OSM Toll 10m", kind="sign"
        )
        res3, s3 = alerts.merge_and_deduplicate([base_toll, osm_toll_10m])
        self.assertEqual(len(res3), 1)
        self.assertEqual(res3[0].source, "Base")
        self.assertEqual(s3["osm_kept"], 0)

        # 4. Trạm thu phí OSM cách > 20m (lat_30m) -> giữ
        osm_toll_30m = alerts.AlertPoint(
            lat=lat_30m, lon=lon0, sign_type=alerts.SIGN_TYPE_TOLL_BOOTH, speed_limit=0,
            heading=alerts.DIR_OMNI, is_camera=False, source="OSM", priority=alerts.PRIORITY_OSM,
            desc="OSM Toll 30m", kind="sign"
        )
        res4, s4 = alerts.merge_and_deduplicate([base_toll, osm_toll_30m])
        self.assertEqual(len(res4), 2)
        self.assertEqual(s4["osm_kept"], 1)

        # 5. Kiểm tra export_binary_files gán reserved == 3 cho OSM
        with tempfile.TemporaryDirectory() as tmpdir:
            out_p = Path(tmpdir)
            alerts.allocate_stable_ids(res4)
            _, signs_path, _, _ = alerts.export_binary_files(
                master_points=res4,
                out_dir=out_p,
                base_timestamp=12345,
                vietmap_version="T11",
                stats_merge=s4
            )
            data = signs_path.read_bytes()
            # Đọc 2 điểm trong signs.bin
            pt1 = struct.unpack_from(alerts.SIGN_POINT_FMT, data, 20)
            pt2 = struct.unpack_from(alerts.SIGN_POINT_FMT, data, 40)
            res_vals = [pt1[8], pt2[8]]
            self.assertIn(alerts.SOURCE_CODE_BASE, res_vals) # 0
            self.assertIn(alerts.SOURCE_CODE_OSM, res_vals)  # 3


if __name__ == "__main__":
    unittest.main()
