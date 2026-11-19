import os
import struct
import tempfile
import unittest
import zlib

import alerts
import vietmap_decode as vm


def fake_secrect(rows, version="261022"):
    text = version + "\r\n" + "".join(r + "\r\n" for r in rows)
    return vm.encode_text(text)


def vh_sign(sid, lat, lon, direction, stype, speed=0):
    return (sid, round(lat * 1e7), round(lon * 1e7), direction, stype, speed, 0, 0, 0)


def vh_camera(cid, lat, lon, direction, speed=-1):
    return (cid, round(lat * 1e7), round(lon * 1e7), speed, direction)


class DecodeTest(unittest.TestCase):
    def test_roundtrip_and_skips(self):
        data = fake_secrect([
            "105.8,21.0,1,50,1,90",
            "105.8,21.0,1,50,1,90",          # exact duplicate
            "120.0,21.0,1,50,1,90",          # outside Vietnam
            "105.8,21.0,99,0,1,90",         # unknown type
            "105.8,21.0,1",                  # bad fields
            "105.9,21.1,11,0,1,359",
        ])
        data += b"\x11\x8c" + b"\x83\x71"   # line in another encoding
        res = vm.decode_bytes(data)
        self.assertEqual(res.version, "261022")
        self.assertEqual([(p.type, p.speed_limit, p.heading) for p in res.points], [(1, 50, 90), (11, 0, 359)])
        self.assertEqual(res.skipped, {"undecodable": 1, "bad_fields": 1, "out_of_bounds": 1,
                                       "unknown_type": 1, "duplicate": 1})

    def test_container_format_edogen_extraction(self):
        edogen_text = "261022\r\n105.8,21.0,1,50,1,90\r\n106.0,20.0,7,0,1,180\r\n"
        edogen_bytes = vm.encode_text(edogen_text)
        edogen_size = len(edogen_bytes)
        hdr = bytearray(512)
        hdr[0:10] = b"edogen.bin"
        struct.pack_into("<I", hdr, 64, edogen_size)
        container = bytes(hdr) + edogen_bytes + b"\xff" * 500
        res = vm.decode_bytes(container)
        self.assertEqual(res.version, "261022")
        self.assertEqual(len(res.points), 2)
        self.assertEqual(res.points[0].type, 1)
        self.assertEqual(res.points[1].type, 7)

    def test_real_substitution_table(self):
        # First data row of the real file (bytes copied from secrect.bin).
        raw = bytes.fromhex("82cfb739a8b7af64a8d96482a3")
        self.assertEqual("".join(vm.SUBSTITUTION[b] for b in raw), "104.84728321,")


class MergeTest(unittest.TestCase):
    def point(self, ptype, lat, lon, heading, speed=0):
        return vm.VietMapPoint(lon, lat, ptype, speed, heading)

    def test_duplicate_sign_within_radius_is_dropped(self):
        vh = [vh_sign(1, 21.0, 105.8, 90, alerts.SIGN_SPEED, 60)]
        pts = [self.point(vm.TYPE_SPEED_LIMIT, 21.0001, 105.8, 100, 50)]  # ~11 m, 10 deg
        _, signs, s = alerts.merge([], vh, pts)
        self.assertEqual(len(signs), 1)
        self.assertEqual(s["by_vietmap_type"]["vietmap_type_1"]["speed_conflict_kept_viethud"], 1)

    def test_far_or_other_direction_or_other_kind_is_added(self):
        vh = [vh_sign(1, 21.0, 105.8, 90, alerts.SIGN_SPEED, 60)]
        pts = [
            self.point(vm.TYPE_SPEED_LIMIT, 21.001, 105.8, 90, 60),     # ~111 m away
            self.point(vm.TYPE_SPEED_LIMIT, 21.0, 105.8, 270, 60),      # opposite direction
            self.point(vm.TYPE_TRAFFIC_LIGHT, 21.0, 105.8, 90),         # different kind
        ]
        _, signs, s = alerts.merge([], vh, pts)
        self.assertEqual(len(signs), 4)
        added = signs[1:]
        self.assertTrue(all(r[0] & 0x80000000 for r in added))
        self.assertEqual([r[4] for r in added], [alerts.SIGN_SPEED, alerts.SIGN_SPEED, alerts.SIGN_LIGHT])
        self.assertTrue(all(r[8] == alerts.SOURCE_VIETMAP for r in added))

    def test_unknown_heading_matches_any(self):
        vh = [vh_camera(5, 21.0, 105.8, alerts.DIR_ANY)]
        cams, _, _ = alerts.merge(vh, [], [self.point(vm.TYPE_CAMERA, 21.0, 105.8001, 200)])
        self.assertEqual(len(cams), 1)

    def test_camera_heading_tolerance(self):
        vh = [vh_camera(5, 21.0, 105.8, 0)]
        pts = [self.point(vm.TYPE_CAMERA, 21.0, 105.8, 50),   # within 60 deg -> duplicate
               self.point(vm.TYPE_CAMERA, 21.0, 105.8, 180)]  # opposite -> new camera
        cams, _, _ = alerts.merge(vh, [], pts)
        self.assertEqual(len(cams), 2)
        self.assertEqual(cams[1][3], -1)
        self.assertTrue(cams[1][0] >= 1 << 62)

    def test_vietmap_points_dedup_among_themselves(self):
        pts = [self.point(vm.TYPE_URBAN_START, 21.0, 105.8, 10),
               self.point(vm.TYPE_URBAN_START, 21.00005, 105.8, 15)]
        _, signs, s = alerts.merge([], [], pts)
        self.assertEqual(len(signs), 1)
        self.assertEqual(signs[0][4], alerts.SIGN_URBAN)
        self.assertEqual(s["by_vietmap_type"]["vietmap_type_4"]["duplicate_of_vm"], 1)

    def test_ids_are_stable(self):
        pts = [self.point(vm.TYPE_CAMERA, 21.0, 105.8, 10), self.point(vm.TYPE_NO_OVERTAKING, 20.0, 106.0, 0)]
        a = alerts.merge([], [], pts)
        b = alerts.merge([], [], pts)
        self.assertEqual(a[0], b[0])
        self.assertEqual(a[1], b[1])

    def test_all_vietmap_types_mapping(self):
        pts = [
            self.point(vm.TYPE_SPEED_LIMIT, 21.01, 105.01, 90, 60),      # sign 1
            self.point(vm.TYPE_TRAFFIC_LIGHT, 21.02, 105.02, 90),        # sign 6
            self.point(vm.TYPE_VM_LIGHT_3, 21.03, 105.03, 90),           # sign 6
            self.point(vm.TYPE_URBAN_START, 21.04, 105.04, 90),          # sign 2, subType 0
            self.point(vm.TYPE_TOLL_BOOTH, 21.05, 105.05, 90),           # sign 5
            self.point(vm.TYPE_VM_LIGHT_6, 21.06, 105.06, 90),           # sign 6
            self.point(vm.TYPE_VM_DANGER_7, 21.07, 105.07, 90),          # sign 10, subType 0
            self.point(vm.TYPE_VM_TYPE_8, 21.08, 105.08, 0),             # sign 10, subType 8, omni
            self.point(vm.TYPE_VM_TYPE_9, 21.09, 105.09, 45),            # sign 10, subType 9
            self.point(vm.TYPE_NO_OVERTAKING, 21.10, 105.10, 90),        # sign 3
            self.point(vm.TYPE_CAMERA, 21.11, 105.11, 90),               # camera
        ]
        cams, signs, s = alerts.merge([], [], pts)
        self.assertEqual(len(cams), 1)
        self.assertEqual(len(signs), 10)
        # Check type 8 has DIR_ANY (0xFFFF) and subType 8
        s8 = [s for s in signs if s[6] == 8][0]
        self.assertEqual(s8[3], alerts.DIR_ANY)
        self.assertEqual(s8[4], alerts.SIGN_DANGER)
        # Check type 9 has heading 45 and subType 9
        s9 = [s for s in signs if s[6] == 9][0]
        self.assertEqual(s9[3], 45)
        self.assertEqual(s9[4], alerts.SIGN_DANGER)


class EndToEndTest(unittest.TestCase):
    def test_main_writes_valid_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            vh_dir, out = os.path.join(tmp, "vh"), os.path.join(tmp, "out")
            os.makedirs(vh_dir)
            alerts.write_cameras(os.path.join(vh_dir, "cameras.bin"), [vh_camera(9, 21.0, 105.8, 90, 50)])
            alerts.write_signs(os.path.join(vh_dir, "signs.bin"), 1,
                               [vh_sign(1, 21.0, 105.8, 90, alerts.SIGN_SPEED, 60)], 1234)
            src = os.path.join(tmp, "secrect.bin")
            with open(src, "wb") as f:
                f.write(fake_secrect(["105.8,21.0,1,60,1,90", "106.0,20.0,11,0,1,45"]))
            os.environ["MAPVIET_ALERTS_VERSION"] = "2026.01.01.0000"
            os.environ.pop("MAPVIET_SIGNING_KEY_FILE", None)
            alerts.main(["--viethud", vh_dir, "--vietmap", src, "--out", out, "--skip-verify"])

            cams = alerts.read_cameras(os.path.join(out, "cameras.bin"))
            ver, ts, signs = alerts.read_signs(os.path.join(out, "signs.bin"))
            self.assertEqual((len(cams), len(signs), ver, ts), (2, 1, 1, 1234))
            with open(os.path.join(out, "manifest.txt")) as f:
                manifest = f.read().splitlines()
            self.assertEqual(manifest[0], "version 2026.01.01.0000")
            self.assertEqual([l.split()[0] for l in manifest[1:]], ["cameras.bin", "signs.bin"])
            with open(os.path.join(out, "signs.bin"), "rb") as f:
                body = f.read()
            self.assertEqual(struct.unpack_from("<I", body, 12)[0], zlib.crc32(body[20:]) & 0xFFFFFFFF)


if __name__ == "__main__":
    unittest.main()
