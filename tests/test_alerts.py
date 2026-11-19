# Bản sao từ VietHUD/tools/tests/test_alerts.py — nguồn chuẩn là VietHUD/tools; sửa ở đó rồi chép lại
import sys
from pathlib import Path
_REPO_DIR = Path(__file__).resolve().parent.parent
if str(_REPO_DIR) not in sys.path:
    sys.path.insert(0, str(_REPO_DIR))

import csv
import struct
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

try:
    from tools import alerts
    from tools import sign_manifest
    from tools.vietmap_decode import REVERSE_SUBSTITUTION
except ImportError:
    import alerts
    import sign_manifest
    from vietmap_decode import REVERSE_SUBSTITUTION


def encode_vm_line(text: str) -> bytes:
    res = bytearray()
    for ch in text:
        res.append(REVERSE_SUBSTITUTION[ch])
    return bytes(res)


class TestAlerts(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.td = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_vietmap_mapping_types(self):
        """VietMap type 1 -> sign 1 có speed; type 2 -> sign 6; type 11 -> camera speed 0."""
        vm_bin = self.td / "secrect.bin"
        lines = [
            b"HEADER" + encode_vm_line("20261118"),
            encode_vm_line("105.840000,21.040000,1,60,0,90"),   # Type 1: speed 60
            encode_vm_line("105.850000,21.050000,2,0,0,180"),   # Type 2: traffic light
            encode_vm_line("105.860000,21.060000,4,0,0,0"),     # Type 4: resident
            encode_vm_line("105.870000,21.070000,5,0,0,45"),    # Type 5: toll booth
            encode_vm_line("105.880000,21.080000,10,0,0,270"),  # Type 10: no overtaking
            encode_vm_line("105.890000,21.090000,11,0,0,15"),   # Type 11: camera
        ]
        vm_bin.write_bytes(b"\x83\x71".join(lines))

        pts, ver = alerts.load_vietmap_alerts(vm_bin)
        self.assertEqual(len(pts), 6)

        cams = [p for p in pts if p.is_camera]
        signs = [p for p in pts if not p.is_camera]

        self.assertEqual(len(cams), 1)
        self.assertEqual(cams[0].desc, "VietMap Camera")
        self.assertEqual(cams[0].speed_limit, 0)

        self.assertEqual(len(signs), 5)
        # Type 1 -> Sign 1
        s1 = next(p for p in signs if p.sign_type == 1)
        self.assertEqual(s1.speed_limit, 60)
        # Type 2 -> Sign 6
        s6 = next(p for p in signs if p.sign_type == 6)
        self.assertEqual(s6.speed_limit, 0)
        # Type 4 -> Sign 2
        s2 = next(p for p in signs if p.sign_type == 2)
        self.assertEqual(s2.sub_type, 0)

    def test_signs_cameras_bin_separation_and_speed_constraints(self):
        """signs.bin không chứa camera; cameras.bin chỉ có speed in {-1, 0} ∪ {5..130 bội số 5}."""
        pts = [
            # Camera hợp lệ speed 60
            alerts.AlertPoint(21.01, 105.81, None, 60, 90, True, "VietMap", 1, "Cam 60"),
            # Camera phạt nguội speed 0
            alerts.AlertPoint(21.02, 105.82, None, 0, 90, True, "VietMap", 1, "Cam 0"),
            # Camera với speed bất thường 255 -> phải bị ép về -1
            alerts.AlertPoint(21.03, 105.83, None, 255, 90, True, "WYN", 2, "Cam 255"),
            # Camera với speed 1 -> phải bị ép về -1
            alerts.AlertPoint(21.04, 105.84, None, 1, 90, True, "WYN", 2, "Cam 1"),
            # Biển báo tốc độ 80
            alerts.AlertPoint(21.05, 105.85, 1, 80, 90, False, "VietMap", 1, "Sign 80"),
            # Đèn đỏ với speed 50 (bất thường) -> phải bị ép về 0 vì không phải sign_type 1
            alerts.AlertPoint(21.06, 105.86, 6, 50, 90, False, "VietMap", 1, "Light 50"),
        ]

        alerts.allocate_stable_ids(pts)
        out_dir = self.td / "out_clean"
        cams_path, signs_path, _, _ = alerts.export_binary_files(pts, out_dir, base_timestamp=123456)

        cdata = cams_path.read_bytes()
        cam_count = len(cdata) // 20
        self.assertEqual(cam_count, 4)
        for i in range(cam_count):
            cid, lat_e7, lon_e7, spd, hd = struct.unpack_from("<QiihH", cdata, i * 20)
            self.assertTrue(spd in (-1, 0) or (5 <= spd <= 130 and spd % 5 == 0), f"Camera speed {spd} ngoài dải cho phép")

        sdata = signs_path.read_bytes()
        hdr = struct.unpack_from("<4sHIHII", sdata, 0)
        sign_count = hdr[2]
        self.assertEqual(sign_count, 2)
        for i in range(sign_count):
            sid, lat_e7, lon_e7, hd, stype, spd, sub, flg, res = struct.unpack_from("<IiiHBBBBH", sdata, 20 + i * 20)
            self.assertIn(stype, (1, 6))
            if stype == 1:
                self.assertEqual(spd, 80)
            else:
                self.assertEqual(spd, 0)

    def test_camera_speed_r2_rules_and_inheritance(self):
        """R2: speed 27 -> -1; speed -1 nền giữ -1; kế thừa speed 13 bị từ chối; kế thừa speed 60 được chấp nhận."""
        # 1. Clean camera speed
        self.assertEqual(alerts.clean_camera_speed(27), -1)
        self.assertEqual(alerts.clean_camera_speed(13), -1)
        self.assertEqual(alerts.clean_camera_speed(0), 0)
        self.assertEqual(alerts.clean_camera_speed(-1), -1)
        self.assertEqual(alerts.clean_camera_speed(60), 60)
        self.assertEqual(alerts.clean_camera_speed(104), -1)

        # 2. Base camera với speed -1 giữ nguyên -1
        base_dir = self.td / "base_test"
        base_dir.mkdir(parents=True, exist_ok=True)
        cam_bin = base_dir / "cameras.bin"
        # 1 camera speed -1, 1 camera speed 50
        cdata = bytearray()
        cdata.extend(struct.pack("<QiihH", 1, 210000000, 1050000000, -1, 90))
        cdata.extend(struct.pack("<QiihH", 2, 211000000, 1051000000, 50, 180))
        cam_bin.write_bytes(cdata)

        pts, _ = alerts.load_base_alerts(base_dir)
        self.assertEqual(len(pts), 2)
        self.assertEqual(pts[0].speed_limit, -1)
        self.assertEqual(pts[1].speed_limit, 50)

        # 3. Kế thừa speed 13 bị từ chối
        master = alerts.AlertPoint(21.00000, 105.80000, None, -1, alerts.DIR_OMNI, True, "VietMap", 1, "Master VM")
        sub_bad = alerts.AlertPoint(21.00005, 105.80000, None, 13, 90, True, "WYN", 2, "Sub 13")
        m_res, _ = alerts.merge_and_deduplicate([master, sub_bad])
        self.assertEqual(len(m_res), 1)
        self.assertEqual(m_res[0].speed_limit, -1, "Speed 13 sai chuẩn không được kế thừa")

        # 4. Kế thừa speed 60 hợp lệ được chấp nhận khi Master == -1 (nguồn WYN/Base)
        master2 = alerts.AlertPoint(21.00000, 105.80000, None, -1, alerts.DIR_OMNI, True, "WYN", 2, "Master WYN 2")
        sub_good = alerts.AlertPoint(21.00005, 105.80000, None, 60, 90, True, "Base", 3, "Sub 60")
        m_res2, _ = alerts.merge_and_deduplicate([master2, sub_good])
        self.assertEqual(len(m_res2), 1)
        self.assertEqual(m_res2[0].speed_limit, 60, "Speed 60 hợp lệ phải được kế thừa cho master -1")

    def test_dedup_distance_and_heading(self):
        """
        Chuẩn R3:
          - Khác nguồn: Điểm nguồn thấp hơn (WYN) nằm trong bán kính điểm nguồn cao (VietMap)
            sẽ bị BỎ, không xét hướng (kể cả ngược hướng 180°).
          - Cùng nguồn: Giữ nguyên từng chiều xe; chỉ gộp nếu trùng tuyệt đối (<= 2m, cùng hướng +-5°).
        """
        p_vm_high = alerts.AlertPoint(21.00000, 105.80000, 1, 60, 90, False, "VietMap", 1, "High")
        p_wyn_same = alerts.AlertPoint(21.00008, 105.80000, 1, 0, 90, False, "WYN", 2, "Low Same")
        master, stats = alerts.merge_and_deduplicate([p_vm_high, p_wyn_same])
        self.assertEqual(len(master), 1)
        self.assertEqual(master[0].source, "VietMap")

        # Khác nguồn: Ngược hướng 180 độ trong 10m -> vẫn BỎ WYN theo luật R3 (khác nguồn không xét hướng)
        p_wyn_opp = alerts.AlertPoint(21.00008, 105.80000, 1, 60, 270, False, "WYN", 2, "Opposite")
        master_opp, _ = alerts.merge_and_deduplicate([p_vm_high, p_wyn_opp])
        self.assertEqual(len(master_opp), 1)
        self.assertEqual(master_opp[0].source, "VietMap")

        # Cùng nguồn: 2 điểm cùng nguồn VietMap ngược hướng cách 10m -> GIỮ CẢ HAI
        p_vm_opp = alerts.AlertPoint(21.00008, 105.80000, 1, 60, 270, False, "VietMap", 1, "VM Opp")
        master_same_src_opp, _ = alerts.merge_and_deduplicate([p_vm_high, p_vm_opp])
        self.assertEqual(len(master_same_src_opp), 2)

        # Cùng nguồn: 2 điểm cùng nguồn VietMap khác toạ độ E7/hướng -> GIỮ CẢ HAI (D2)
        p_vm_dup = alerts.AlertPoint(21.000009, 105.80000, 1, 60, 91, False, "VietMap", 1, "VM Dup")
        master_same_src_diff, _ = alerts.merge_and_deduplicate([p_vm_high, p_vm_dup])
        self.assertEqual(len(master_same_src_diff), 2, "VietMap không giống hệt phải giữ cả hai theo D2")

        # Cùng nguồn: 2 điểm giống hệt -> GỘP CÒN 1
        p_vm_identical = alerts.AlertPoint(21.00000, 105.80000, 1, 60, 90, False, "VietMap", 1, "VM Identical")
        master_identical, _ = alerts.merge_and_deduplicate([p_vm_high, p_vm_identical])
        self.assertEqual(len(master_identical), 1, "Bản sao VietMap giống hệt gộp còn 1")

    def test_dedup_radius_light_vs_sign(self):
        """Đèn cách 20m -> gộp; biển cách 20m -> không gộp."""
        # 20m tương đương ~0.00018 độ lat
        # Đèn (sign_type 6, radius 25m)
        light1 = alerts.AlertPoint(21.00000, 105.80000, 6, 0, 90, False, "VietMap", 1, "L1")
        light2 = alerts.AlertPoint(21.00018, 105.80000, 6, 0, 90, False, "WYN", 2, "L2")
        m_lights, _ = alerts.merge_and_deduplicate([light1, light2])
        self.assertEqual(len(m_lights), 1, "Đèn cách 20m phải được gộp (bán kính 25m)")

        # Biển báo (sign_type 1, radius 15m)
        sign1 = alerts.AlertPoint(21.00000, 105.80000, 1, 60, 90, False, "VietMap", 1, "S1")
        sign2 = alerts.AlertPoint(21.00018, 105.80000, 1, 60, 90, False, "WYN", 2, "S2")
        m_signs, _ = alerts.merge_and_deduplicate([sign1, sign2])
        self.assertEqual(len(m_signs), 2, "Biển cách 20m không được gộp (bán kính 15m)")

    def test_inheritance_speed_and_heading(self):
        """Kế thừa heading/speed khi master thiếu."""
        # Master VietMap thiếu tốc độ và hướng (omni)
        master = alerts.AlertPoint(21.00000, 105.80000, None, 0, alerts.DIR_OMNI, True, "VietMap", 1, "Master")
        # Sub WYN có tốc độ 60 và hướng 90
        sub = alerts.AlertPoint(21.00005, 105.80000, None, 60, 90, True, "WYN", 2, "Sub")

        m_res, stats = alerts.merge_and_deduplicate([master, sub])
        self.assertEqual(len(m_res), 1)
        self.assertEqual(m_res[0].speed_limit, 0, "Camera VietMap tốc độ 0 giữ nguyên 0 theo D4, không nhận tốc độ")
        self.assertEqual(m_res[0].heading, 90, "Heading DIR_OMNI được kế thừa từ sub")
        self.assertEqual(stats["inherited_speed"], 0)
        self.assertEqual(stats["inherited_heading"], 1)

    def test_reproducible_binary_build(self):
        """Chạy 2 lần cùng đầu vào -> cameras.bin/signs.bin giống từng byte."""
        pts1 = [
            alerts.AlertPoint(21.01, 105.81, 1, 60, 90, False, "VietMap", 1, "P1"),
            alerts.AlertPoint(21.02, 105.82, 6, 0, 180, False, "WYN", 2, "P2"),
            alerts.AlertPoint(21.03, 105.83, None, 0, 270, True, "VietMap", 1, "C1"),
        ]
        pts2 = [
            alerts.AlertPoint(21.01, 105.81, 1, 60, 90, False, "VietMap", 1, "P1"),
            alerts.AlertPoint(21.02, 105.82, 6, 0, 180, False, "WYN", 2, "P2"),
            alerts.AlertPoint(21.03, 105.83, None, 0, 270, True, "VietMap", 1, "C1"),
        ]

        m1, _ = alerts.merge_and_deduplicate(pts1)
        alerts.allocate_stable_ids(m1)
        out1 = self.td / "run1"
        c1, s1, _, _ = alerts.export_binary_files(m1, out1, base_timestamp=999999)

        m2, _ = alerts.merge_and_deduplicate(pts2)
        alerts.allocate_stable_ids(m2)
        out2 = self.td / "run2"
        c2, s2, _, _ = alerts.export_binary_files(m2, out2, base_timestamp=999999)

        self.assertEqual(c1.read_bytes(), c2.read_bytes())
        self.assertEqual(s1.read_bytes(), s2.read_bytes())

    def test_manifest_sign_and_verify(self):
        """Manifest + ký + verify bằng một khoá EC P-256 sinh tạm."""
        priv_key = ec.generate_private_key(ec.SECP256R1())
        pub_key = priv_key.public_key()

        pts = [alerts.AlertPoint(21.01, 105.81, 1, 60, 90, False, "VietMap", 1, "P1")]
        alerts.allocate_stable_ids(pts)
        out = self.td / "manifest_test"
        alerts.export_binary_files(pts, out, base_timestamp=100)

        mf, sig = alerts.write_manifest(out, version="2026.11.18", key=priv_key)
        self.assertTrue(mf.exists())
        self.assertIsNotNone(sig)
        self.assertTrue(sig.exists())

        # Verify
        self.assertTrue(sign_manifest.verify_manifest(mf, pub_key=pub_key))

    def test_no_combined_traffic_alerts_as_input(self):
        """alerts.py không nhận --alerts-csv làm đầu vào nữa, chỉ dùng --wyn."""
        import argparse
        from unittest.mock import patch

        # Kiểm tra parser không còn tuỳ chọn --alerts-csv
        with self.assertRaises(SystemExit):
            with patch("sys.argv", ["alerts.py", "--alerts-csv", "some.csv", "--out", str(self.td)]):
                alerts.main()

        # Tạo file wyn_points.csv chuẩn và nạp thử
        wyn_csv = self.td / "wyn_points.csv"
        with open(wyn_csv, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["lat", "lon", "kind", "sign_type", "speed_kmh", "heading", "source"])
            writer.writeheader()
            writer.writerow({
                "lat": "21.050000",
                "lon": "105.850000",
                "kind": "camera",
                "sign_type": "",
                "speed_kmh": "60",
                "heading": "90",
                "source": "WYN"
            })
            writer.writerow({
                "lat": "21.060000",
                "lon": "105.860000",
                "kind": "light",
                "sign_type": "6",
                "speed_kmh": "0",
                "heading": "",
                "source": "WYN"
            })

        wyn_pts = alerts.load_wyn_alerts(wyn_csv)
        self.assertEqual(len(wyn_pts), 2)
        c = [p for p in wyn_pts if p.is_camera]
        s = [p for p in wyn_pts if not p.is_camera]
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0].speed_limit, 60)
        self.assertEqual(len(s), 1)
        self.assertEqual(s[0].sign_type, 6)


if __name__ == "__main__":
    unittest.main()
