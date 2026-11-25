import csv
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

_PIPELINE_DIR = Path(__file__).resolve().parent.parent
_PARENT_DIR = _PIPELINE_DIR.parent
if str(_PIPELINE_DIR) not in sys.path:
    sys.path.insert(0, str(_PIPELINE_DIR))
if str(_PARENT_DIR) not in sys.path:
    sys.path.append(str(_PARENT_DIR))

try:
    from tools import alerts
    from tools import vietmap_decode as vmd
    from tools.build_clean_alerts import CAMERA_FMT, SIGN_HEADER_FMT, SIGN_POINT_FMT, build_clean_alerts
except ImportError:
    import alerts
    import vietmap_decode as vmd
    from build_clean_alerts import CAMERA_FMT, SIGN_HEADER_FMT, SIGN_POINT_FMT, build_clean_alerts


def encode_line(text: str) -> bytes:
    return bytes(vmd.REVERSE_SUBSTITUTION[ch] for ch in text)


def _write_wyn_csv(path: Path, rows: list[dict]):
    fieldnames = ["lat", "lon", "kind", "sign_type", "speed_kmh", "heading"]
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _write_secrect_bin(path: Path, records: list[str], version: str = "20261125"):
    lines = [b"HEADER" + encode_line(version)]
    for rec in records:
        lines.append(encode_line(rec))
    path.write_bytes(b"\x83\x71".join(lines))


def _write_osm_gt(path: Path, traffic_signals: list[list[float]]):
    path.write_text(json.dumps({"traffic_signals": traffic_signals}), encoding="utf-8")


def _read_cameras(cams_path: Path) -> list[dict]:
    data = cams_path.read_bytes()
    size = struct.calcsize(CAMERA_FMT)
    cams = []
    for off in range(0, len(data), size):
        cid, lat_e7, lon_e7, speed, heading = struct.unpack_from(CAMERA_FMT, data, off)
        cams.append({
            "id": cid,
            "lat": lat_e7 / 1e7,
            "lon": lon_e7 / 1e7,
            "speed": speed,
            "heading": heading,
        })
    return cams


def _read_signs(signs_path: Path) -> list[dict]:
    data = signs_path.read_bytes()
    hdr_size = struct.calcsize(SIGN_HEADER_FMT)
    pt_size = struct.calcsize(SIGN_POINT_FMT)
    _, _, count, _, _, _ = struct.unpack_from(SIGN_HEADER_FMT, data, 0)
    signs = []
    for i in range(count):
        sid, lat_e7, lon_e7, heading, stype, speed, sub_type, flags, res = struct.unpack_from(
            SIGN_POINT_FMT, data, hdr_size + i * pt_size
        )
        signs.append({
            "id": sid,
            "lat": lat_e7 / 1e7,
            "lon": lon_e7 / 1e7,
            "heading": heading,
            "sign_type": stype,
            "speed": speed,
            "sub_type": sub_type,
            "flags": flags,
            "reserved": res,
        })
    return signs


class TestBuildCleanAlertsRules(unittest.TestCase):
    def _run_build(self, tmp: Path, wyn_rows, vm_records, osm_signals=None):
        wyn_csv = tmp / "wyn.csv"
        secrect_bin = tmp / "secrect.bin"
        osm_gt = tmp / "osm_gt.json"
        empty_curated = tmp / "curated_empty"
        empty_curated.mkdir(parents=True, exist_ok=True)
        out_dir = tmp / "out"

        _write_wyn_csv(wyn_csv, wyn_rows)
        _write_secrect_bin(secrect_bin, vm_records)
        _write_osm_gt(osm_gt, osm_signals or [])

        build_clean_alerts(
            wyn_csv=wyn_csv,
            secrect_bin=secrect_bin,
            output_dir=out_dir,
            version_str="2026.11.25.0001",
            alerts_only=True,
            curated_dir=empty_curated,
            osm_gt_path=osm_gt,
            sign_output=False,
        )
        stats = json.loads((out_dir / "stats.json").read_text(encoding="utf-8"))
        cams = _read_cameras(out_dir / "cameras.bin")
        signs = _read_signs(out_dir / "signs.bin")
        return cams, signs, stats

    def test_type4_near_osm_signal_without_wyn_not_converted_to_camera(self):
        with tempfile.TemporaryDirectory() as td:
            cams, signs, stats = self._run_build(
                Path(td),
                wyn_rows=[],
                vm_records=[
                    "105.854200,21.028550,4,0,0,90",  # ~5.5m from OSM signal, NO WYN cam
                    "105.854200,21.035000,4,0,0,180", # isolated Type 4
                ],
                osm_signals=[[21.028500, 105.854200]],
            )
            self.assertEqual(cams, [])
            self.assertEqual(stats["counts_by_source_and_type"]["VietMap"]["type4_redlight_cam"], 0)
            self.assertEqual(stats["counts_by_source_and_type"]["VietMap"]["camera_total"], 0)
            self.assertEqual(len(signs), 1)
            self.assertEqual(signs[0]["sign_type"], 6)

    def test_type4_rescues_opposite_heading_when_matched_to_wyn_and_respects_type11_priority(self):
        with tempfile.TemporaryDirectory() as td:
            cams, _, stats = self._run_build(
                Path(td),
                wyn_rows=[
                    # 1. WYN speed camera heading 90
                    {"lat": "21.040000", "lon": "105.840000", "kind": "camera", "sign_type": "4", "speed_kmh": "60", "heading": "90"},
                    # 2. WYN redlight/surveillance camera heading 10 (WYN 0/15 = DIR_OMNI)
                    {"lat": "21.045000", "lon": "105.840000", "kind": "camera", "sign_type": "4", "speed_kmh": "-1", "heading": "10"},
                    # 3. WYN camera heading 10 where both Type 4 and Type 11 exist in opposite heading 190
                    {"lat": "21.050000", "lon": "105.840000", "kind": "camera", "sign_type": "4", "speed_kmh": "80", "heading": "10"},
                ],
                vm_records=[
                    # Same heading (~11m <= 30m) -> drop duplicate
                    "105.840000,21.040100,4,0,0,100",
                    # Opposite heading (~22m <= 40m) -> rescue with speed 60
                    "105.840000,21.040200,4,0,0,270",
                    # Opposite heading (~22m <= 40m) near WYN(-1) + OSM signal -> rescue redlight (-1)
                    "105.840000,21.045200,4,0,0,190",
                    # Type 4 appears earlier in file than Type 11 (~3m apart, opposite heading 190)
                    "105.840000,21.050150,4,0,0,190",
                    "105.840000,21.050180,11,0,0,190",
                ],
                osm_signals=[[21.045050, 105.840000]],
            )
            vm_stat = stats["counts_by_source_and_type"]["VietMap"]
            self.assertEqual(vm_stat["type4_speed_cam"], 1)
            self.assertEqual(vm_stat["type4_redlight_cam"], 1)
            self.assertEqual(vm_stat["camera_total"], 3)
            # Total cameras = 3 WYN + 2 rescued Type4 + 1 Type11 = 6
            self.assertEqual(len(cams), 6)
            rescued_speed = [c for c in cams if abs(c["lat"] - 21.040200) < 1e-5]
            self.assertEqual(len(rescued_speed), 1)
            self.assertEqual(rescued_speed[0]["speed"], 60)
            self.assertEqual(rescued_speed[0]["heading"], 270)
            # Ensure Type 11 won at 21.050180 and Type 4 at 21.050150 was suppressed
            cluster_3 = [c for c in cams if 21.0499 < c["lat"] < 21.0505]
            self.assertEqual(len(cluster_3), 2)
            self.assertTrue(any(abs(c["lat"] - 21.050180) < 1e-5 for c in cluster_3))

    def test_type11_heading_aware_dedup_30m_preserves_opposite_heading(self):
        with tempfile.TemporaryDirectory() as td:
            cams, _, stats = self._run_build(
                Path(td),
                wyn_rows=[
                    {"lat": "21.060000", "lon": "105.850000", "kind": "camera", "sign_type": "4", "speed_kmh": "80", "heading": "90"},
                ],
                vm_records=[
                    "105.850000,21.060200,11,0,0,110",  # ~22m same heading -> dropped
                    "105.850000,21.060210,11,0,0,270",  # ~23m opposite heading -> kept
                ],
            )
            self.assertEqual(len(cams), 2)
            wyn_cam = [c for c in cams if c["speed"] == 80]
            vm_cam = [c for c in cams if c["speed"] == -1]
            self.assertEqual(len(wyn_cam), 1)
            self.assertEqual(len(vm_cam), 1)
            self.assertEqual(vm_cam[0]["heading"], 270)
            self.assertEqual(stats["counts_by_source_and_type"]["VietMap"]["camera_total"], 1)

    def test_type8_toll_dedup_300m(self):
        with tempfile.TemporaryDirectory() as td:
            _, signs, stats = self._run_build(
                Path(td),
                wyn_rows=[
                    {"lat": "21.070000", "lon": "105.860000", "kind": "sign", "sign_type": "5", "speed_kmh": "0", "heading": "0"},
                ],
                vm_records=[
                    "105.860000,21.071800,8,0,0,0",  # ~200m <= 300m -> dropped
                    "105.860000,21.073200,8,0,0,0",  # ~355m > 300m -> kept
                ],
            )
            tolls = [s for s in signs if s["sign_type"] == 5]
            self.assertEqual(len(tolls), 2)
            self.assertEqual(stats["counts_by_source_and_type"]["VietMap"]["toll"], 1)

    def test_wyn_odd_speed_normalized_and_noise_signs_dropped(self):
        with tempfile.TemporaryDirectory() as td:
            cams, signs, _ = self._run_build(
                Path(td),
                wyn_rows=[
                    {"lat": "21.080000", "lon": "105.870000", "kind": "camera", "sign_type": "4", "speed_kmh": "104", "heading": "90"},
                    {"lat": "21.090000", "lon": "105.870000", "kind": "camera", "sign_type": "4", "speed_kmh": "92", "heading": "180"},
                    {"lat": "21.100000", "lon": "105.870000", "kind": "sign", "sign_type": "2", "speed_kmh": "0", "heading": "0"},
                    {"lat": "21.110000", "lon": "105.870000", "kind": "sign", "sign_type": "3", "speed_kmh": "0", "heading": "0"},
                    {"lat": "21.120000", "lon": "105.870000", "kind": "sign", "sign_type": "10", "speed_kmh": "0", "heading": "0"},
                ],
                vm_records=[
                    "105.870000,21.130000,7,0,0,0",
                    "105.870000,21.140000,10,0,0,0",
                ],
            )
            self.assertEqual(len(cams), 2)
            self.assertTrue(all(c["speed"] == -1 for c in cams))
            self.assertEqual(signs, [])

    def test_alerts_py_visual_only_flags_and_wyn_kdc_skip(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            wyn_csv = tmp / "wyn.csv"
            secrect_bin = tmp / "secrect.bin"
            _write_wyn_csv(wyn_csv, [
                {"lat": "21.100000", "lon": "105.870000", "kind": "sign", "sign_type": "2", "speed_kmh": "0", "heading": "0"},
                {"lat": "21.110000", "lon": "105.870000", "kind": "sign", "sign_type": "3", "speed_kmh": "0", "heading": "0"},
                {"lat": "21.120000", "lon": "105.870000", "kind": "sign", "sign_type": "10", "speed_kmh": "0", "heading": "0"},
            ])
            _write_secrect_bin(secrect_bin, [
                "105.850000,21.020000,4,0,0,90",
                "105.850000,21.030000,7,0,0,0",
                "105.850000,21.040000,10,0,0,0",
            ])
            vm_pts, _ = alerts.load_vietmap_alerts(secrect_bin)
            wyn_pts = alerts.load_wyn_alerts(wyn_csv)
            self.assertEqual(len(vm_pts), 3)
            self.assertTrue(all(p.flags == 1 for p in vm_pts))
            self.assertEqual(len(wyn_pts), 1)
            self.assertEqual(wyn_pts[0].sign_type, 10)
            self.assertEqual(wyn_pts[0].flags, 1)


if __name__ == "__main__":
    unittest.main()
