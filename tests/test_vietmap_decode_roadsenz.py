import hashlib
import json
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

_REPO_DIR = Path(__file__).resolve().parent.parent
if str(_REPO_DIR) not in sys.path:
    sys.path.insert(0, str(_REPO_DIR))

try:
    from tools import vietmap_decode as vmd
except ImportError:
    import vietmap_decode as vmd


def _encode_cipher_bytes(text: str, use_crlf: bool = False) -> bytes:
    """Mã hoá ngược chuỗi UTF-8 sang byte cipher của citiesen/districtsen/roadsen (dùng trong test)."""
    enc_map: dict[int, int] = {}
    for k, v in vmd.TEXT_CIPHER_BYTE_MAP.items():
        if v not in enc_map:
            enc_map[v] = k
    raw = text.encode("utf-8")
    out = bytearray(enc_map.get(b, b) for b in raw)
    if use_crlf:
        out += b"\x83\x71"
    return bytes(out)


def _build_container(edogen: bytes, cities: bytes, districts: bytes, roadsenz: bytes) -> bytes:
    hdr = bytearray(512)
    total = len(edogen) + len(cities) + len(districts) + len(roadsenz)
    entries = [
        (b"secrect.bin", total),
        (b"edogen.bin", len(edogen)),
        (b"citiesen.bin", len(cities)),
        (b"districtsen.bin", len(districts)),
        (b"roadsenz.bin", len(roadsenz)),
    ]
    for idx, (nm, sz) in enumerate(entries):
        off = idx * 68
        hdr[off : off + len(nm)] = nm
        struct.pack_into("<I", hdr, off + 64, sz)
    hdr[472:480] = b"20261128"
    return bytes(hdr) + edogen + cities + districts + roadsenz


class TestVietMapRoadsAndToc(unittest.TestCase):
    def test_parse_toc_and_cities_districts_utf8(self):
        cities = _encode_cipher_bytes("13\tTP. Đà Nẵng", True) + _encode_cipher_bytes("12\tTP. Hồ Chí Minh", False)
        districts = _encode_cipher_bytes("267\t13\tX. Minh Châu", False)
        raw = _build_container(b"edogen-placeholder", cities, districts, b"roadsen.bin\x00" + b"\x00" * 20)

        toc = vmd.parse_toc(raw)
        self.assertEqual(toc["edogen.bin"].offset, 512)
        self.assertEqual(toc["citiesen.bin"].size, len(cities))
        self.assertEqual(vmd.extract_toc_version(raw), "20261128")

        c_map = vmd.decode_cities(raw)
        self.assertEqual(c_map[13], "TP. Đà Nẵng")
        self.assertEqual(c_map[12], "TP. Hồ Chí Minh")

        d_map = vmd.decode_districts(raw)
        self.assertEqual(d_map[267], (13, "X. Minh Châu"))

    def test_decompress_roadsenz_uncompressed_and_checksum(self):
        payload = b"1001\t2002\tQL.1A\t12\t100\t80\t80\t105.8\t21.0\t105.81\t21.01\r\n"
        # Block uncompressed (u_sz == c_sz)
        sub_hdr = b"roadsen.bin\x00".ljust(24, b"\x00") + struct.pack("<II", len(payload), 0)
        blk = struct.pack("<III", len(payload), len(payload), sum(payload)) + payload
        out = vmd.decompress_roadsenz(sub_hdr + blk, verify_checksum=True)
        self.assertEqual(out, payload)

    def test_decompress_roadsenz_bitstream_and_bad_checksum_raises(self):
        # Kiểm thử block LZ77 nén 2 byte literal ('A', 'B')
        # p=0: ob=0, lb=4 -> off=0,ln=0 (4 bit 0), sau đó literal 'A'=0x41 (8 bit)
        # p=1: ob=1, lb=5 -> off=0,ln=0 (6 bit 0), sau đó literal 'B'=0x42 (8 bit)
        # Tổng 22 bit: 0000 01000001 000000 01000010 -> 00000100 00010000 00010000 10000000 = 0x04 0x10 0x10 0x80
        comp = bytes([0x04, 0x10, 0x10, 0x80])
        chk = ord("A") + ord("B")
        blk = struct.pack("<III", 2, len(comp), chk) + comp
        self.assertEqual(vmd.decompress_roadsenz(blk), b"AB")

        bad_blk = struct.pack("<III", 2, len(comp), chk + 1) + comp
        with self.assertRaises(ValueError):
            vmd.decompress_roadsenz(bad_blk, verify_checksum=True)

    def test_hydrate_full_secrect_bin_downloads_from_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            slim_path = tmp / "slim_secrect.bin"
            # Slim chỉ có TOC ghi roadsenz.bin nhưng bị cắt file (chỉ 600 bytes)
            full_payload = _build_container(b"edogen", b"", b"", b"roadsen.bin\x00" + b"X" * 100)
            slim_path.write_bytes(full_payload[:520])
            self.assertFalse(vmd.has_full_roadsenz(slim_path))

            zpath = tmp / "VietMap.zip"
            with zipfile.ZipFile(zpath, "w") as zf:
                zf.writestr("nested/secrect.bin", full_payload)
            zsha = hashlib.sha256(zpath.read_bytes()).hexdigest()

            mf = tmp / "vietmap_manifest.json"
            mf.write_text(json.dumps({"version": "202611", "download_url": zpath.as_uri(), "zip_sha256": zsha}))

            resolved = vmd.hydrate_full_secrect_bin(slim_path, manifest_path=mf, cache_dir=tmp / "cache")
            self.assertIsNotNone(resolved)
            self.assertTrue(vmd.has_full_roadsenz(resolved))
            self.assertEqual(resolved.read_bytes(), full_payload)


if __name__ == "__main__":
    unittest.main()
