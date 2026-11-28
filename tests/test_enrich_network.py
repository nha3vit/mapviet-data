import struct
import sys
import tempfile
import unittest
from pathlib import Path

_REPO_DIR = Path(__file__).resolve().parent.parent
if str(_REPO_DIR) not in sys.path:
    sys.path.insert(0, str(_REPO_DIR))

try:
    from tools import enrich_network as en
except ImportError:
    import enrich_network as en


def _make_names_bin(names: list[str]) -> bytes:
    offs = []
    pool = bytearray()
    for nm in names:
        offs.append(len(pool))
        pool += nm.encode("utf-8") + b"\x00"
    hdr = en.NAME_HEADER_STRUCT.pack(b"VNNM", 2, len(names), len(pool), 0)
    return hdr + (struct.pack(f"<{len(names)}I", *offs) if names else b"") + bytes(pool)


def _read_names_bin(path: Path) -> list[str]:
    raw = path.read_bytes()
    _, _, cnt, _, _ = en.NAME_HEADER_STRUCT.unpack_from(raw, 0)
    offs = struct.unpack_from(f"<{cnt}I", raw, en.NAME_HEADER_STRUCT.size) if cnt else ()
    pool = raw[en.NAME_HEADER_STRUCT.size + cnt * 4 :]
    out = []
    for o in offs:
        end = pool.find(b"\x00", o)
        out.append((pool[o:end] if end != -1 else pool[o:]).decode("utf-8"))
    return out


class TestEnrichNetwork(unittest.TestCase):
    def _build_fixture(self, src: Path, tsv: Path):
        src.mkdir(parents=True, exist_ok=True)
        (src / "names.bin").write_bytes(_make_names_bin(["Đường Cũ"]))
        # 4 segments: segId 0..3
        (src / "seg_names.bin").write_bytes(struct.pack("<4I", 1, 0, 0, 0))
        (src / "index.bin").write_bytes(b"IDX")
        (src / "metadata.bin").write_bytes(b"META")

        # Đường hướng Bắc (heading=0, direction=1 FWD): lon=105.800000, lat=21.000000..21.001000
        # seg 0: speedSrc=0 (UNKNOWN) -> điền từ roadsen fwd=60
        # seg 1: speedSrc=4 (DEFAULT=50) + unnamed -> thay bằng 80 (speedSrc=1) & điền tên "Quốc lộ 5"
        # seg 2: speedSrc=1 (OSM_MAX=30 <= 40) -> bảo toàn 30
        # seg 3: speedSrc=1 (OSM_MAX=60 >= 50) -> cập nhật theo roadsen = 80
        s_la, e_la = int(21.0000 * 1e7), int(21.0010 * 1e7)
        lo = int(105.8000 * 1e7)
        segs = b"".join([
            en.SEGMENT_STRUCT.pack(0, s_la, lo, e_la, lo, 0, 1, 1, -1, 0, 0),
            en.SEGMENT_STRUCT.pack(1, s_la + 20000, lo, e_la + 20000, lo, 0, 1, 1, 50, 4, 0),
            en.SEGMENT_STRUCT.pack(2, s_la, lo + 20000, e_la, lo + 20000, 0, 2, 0, 30, 1, 0),
            en.SEGMENT_STRUCT.pack(3, s_la + 20000, lo + 20000, e_la + 20000, lo + 20000, 0, 1, 1, 60, 1, 0),
        ])
        (src / "tiles.bin").write_bytes(segs)

        tsv.write_text(
            "\n".join([
                "10\t1\tQuốc lộ 5\t11\t200\t60\t60\t105.8000\t20.9999\t105.8000\t21.0012",
                "11\t2\tCao tốc 01\t11\t200\t80\t80\t105.8000\t21.0019\t105.8000\t21.0032",
                "12\t3\tSân bay\t11\t200\t50\t50\t105.8020\t20.9999\t105.8020\t21.0012",
                "13\t4\tĐại lộ Thăng Long\t11\t200\t80\t80\t105.8020\t21.0019\t105.8020\t21.0032",
            ]) + "\n",
            encoding="utf-8",
        )

    def _assert_enriched(self, dst: Path, stats: dict):
        self.assertEqual(stats["status"], "ok")
        self.assertEqual(stats["unknown_filled"], 1)
        self.assertEqual(stats["default_changed"], 1)
        self.assertEqual(stats["osm_kept_low"], 1)
        self.assertEqual(stats["osm_updated"], 1)
        self.assertEqual(stats["names_added"], 3)

        raw = (dst / "tiles.bin").read_bytes()
        unpacked = [en.SEGMENT_STRUCT.unpack_from(raw, i * en.SEGMENT_STRUCT.size) for i in range(4)]
        self.assertEqual((unpacked[0][8], unpacked[0][9]), (60, 1))
        self.assertEqual((unpacked[1][8], unpacked[1][9]), (80, 1))
        self.assertEqual((unpacked[2][8], unpacked[2][9]), (30, 1))
        self.assertEqual((unpacked[3][8], unpacked[3][9]), (80, 1))

        names = _read_names_bin(dst / "names.bin")
        seg_names = struct.unpack("<4I", (dst / "seg_names.bin").read_bytes())
        self.assertEqual(names[seg_names[0] - 1], "Đường Cũ")
        self.assertEqual(names[seg_names[1] - 1], "Cao tốc 01")
        self.assertEqual(names[seg_names[2] - 1], "Sân bay")
        self.assertEqual(names[seg_names[3] - 1], "Đại lộ Thăng Long")

    def test_python_and_native_enricher_parity(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = tmp / "src"
            tsv = tmp / "roadsen.tsv"
            self._build_fixture(src, tsv)

            dst_py = tmp / "dst_py"
            stats_py = en.enrich_speedmap_network(src, dst_py, roadsen_tsv=tsv, prefer_native=False)
            self._assert_enriched(dst_py, stats_py)
            self.assertEqual(stats_py["engine"], "python")

            dst_c = tmp / "dst_c"
            stats_c = en.enrich_speedmap_network(src, dst_c, roadsen_tsv=tsv, prefer_native=True)
            self._assert_enriched(dst_c, stats_c)
            if en._ensure_native_enricher() is not None:
                self.assertEqual(stats_c["engine"], "native_c")


if __name__ == "__main__":
    unittest.main()
