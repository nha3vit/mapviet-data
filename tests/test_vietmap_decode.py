# Bản sao từ VietHUD/tools/tests/test_vietmap_decode.py — nguồn chuẩn là VietHUD/tools; sửa ở đó rồi chép lại
import sys
from pathlib import Path
_REPO_DIR = Path(__file__).resolve().parent.parent
if str(_REPO_DIR) not in sys.path:
    sys.path.insert(0, str(_REPO_DIR))

import unittest
from pathlib import Path
try:
    from tools.vietmap_decode import (
        decode_bytes,
        decode_file,
        REVERSE_SUBSTITUTION,
        TYPE_SPEED_LIMIT,
        TYPE_TRAFFIC_LIGHT,
        TYPE_VM_LIGHT_3,
        TYPE_URBAN_START,
        TYPE_TOLL_BOOTH,
        TYPE_VM_LIGHT_6,
        TYPE_VM_DANGER_7,
        TYPE_NO_OVERTAKING,
        TYPE_CAMERA,
    )
except ImportError:
    from vietmap_decode import (
        decode_bytes,
        decode_file,
        REVERSE_SUBSTITUTION,
        TYPE_SPEED_LIMIT,
        TYPE_TRAFFIC_LIGHT,
        TYPE_VM_LIGHT_3,
        TYPE_URBAN_START,
        TYPE_TOLL_BOOTH,
        TYPE_VM_LIGHT_6,
        TYPE_VM_DANGER_7,
        TYPE_NO_OVERTAKING,
        TYPE_CAMERA,
    )


def encode_line(text: str) -> bytes:
    """Mã hoá một chuỗi ký tự thành bytes dùng bảng REVERSE_SUBSTITUTION."""
    res = bytearray()
    for ch in text:
        if ch in REVERSE_SUBSTITUTION:
            res.append(REVERSE_SUBSTITUTION[ch])
        else:
            raise ValueError(f"Ký tự không thể mã hoá: {ch}")
    return bytes(res)


class TestVietMapDecode(unittest.TestCase):
    def test_decode_synthetic_data(self):
        # Tạo dữ liệu test tổng hợp
        lines = [
            b"HEADER" + encode_line("20261118"),  # Dòng version có byte lạ phía trước
            encode_line("105.840000,21.040000,1,60,0,90"),   # Type 1: speed 60
            encode_line("105.850000,21.050000,2,0,0,180"),   # Type 2: traffic light
            encode_line("105.860000,21.060000,4,0,0,0"),     # Type 4: resident
            encode_line("105.870000,21.070000,5,0,0,45"),    # Type 5: toll booth
            encode_line("105.880000,21.080000,10,0,0,270"),  # Type 10: no overtaking
            encode_line("105.890000,21.090000,11,0,0,15"),   # Type 11: camera
            encode_line("105.895000,21.095000,3,0,0,15"),    # Type 3: known (light)
            encode_line("105.896000,21.096000,6,0,0,15"),    # Type 6: known (light)
            encode_line("105.897000,21.097000,7,0,0,15"),    # Type 7: known (danger)
            encode_line("105.898000,21.098000,8,0,0,0"),     # Type 8: known (R4)
            encode_line("105.899000,21.099000,9,0,0,15"),    # Type 9: known (R4)
            encode_line("105.899500,21.099500,99,0,0,15"),   # Type 99: truly unknown
            b"\xFF\xFE\xFD",                                  # Undecodable bytes
        ]

        data = b"\x83\x71".join(lines)
        res = decode_bytes(data)

        self.assertEqual(res.version, "20261118")
        # 6 loại cũ + 3 loại R3 (3, 6, 7) + 2 loại R4 (8, 9) = 11 điểm known
        self.assertEqual(len(res.points), 11)
        self.assertEqual(res.skipped["unknown_type"], 1)
        self.assertEqual(res.skipped["unknown_type_by_type"][99], 1)
        self.assertEqual(res.skipped["undecodable"], 1)

        # Kiểm tra chi tiết từng điểm giải mã
        p0 = res.points[0]
        self.assertEqual(p0.type, TYPE_SPEED_LIMIT)
        self.assertEqual(p0.speed_limit, 60)
        self.assertEqual(p0.heading, 90)

        p1 = res.points[1]
        self.assertEqual(p1.type, TYPE_TRAFFIC_LIGHT)
        self.assertEqual(p1.speed_limit, 0)
        self.assertEqual(p1.heading, 180)

        p5 = res.points[5]
        self.assertEqual(p5.type, TYPE_CAMERA)
        self.assertEqual(p5.speed_limit, 0)

        p6 = res.points[6]
        self.assertEqual(p6.type, TYPE_VM_LIGHT_3)
        p7 = res.points[7]
        self.assertEqual(p7.type, TYPE_VM_LIGHT_6)
        p8 = res.points[8]
        self.assertEqual(p8.type, TYPE_VM_DANGER_7)

    def test_decode_container_secrect_bin(self):
        import struct

        # Tạo edogen payload
        lines = [
            encode_line("20261119"),
            encode_line("105.840000,21.040000,1,60,0,90"),
        ]
        edogen_bytes = b"\x83\x71".join(lines)
        cities_bytes = b"CITIES_DATA_WITH_NON_SUBSTITUTION_BYTES\x83\x71" * 10

        hdr = bytearray(512)
        # Entry 0: secrect.bin
        hdr[0:11] = b"secrect.bin"
        struct.pack_into("<I", hdr, 64, len(edogen_bytes) + len(cities_bytes))
        # Entry 1: edogen.bin
        hdr[68:78] = b"edogen.bin"
        struct.pack_into("<I", hdr, 68 + 64, len(edogen_bytes))
        # Entry 2: citiesen.bin
        hdr[136:148] = b"citiesen.bin"
        struct.pack_into("<I", hdr, 136 + 64, len(cities_bytes))

        full_container = bytes(hdr) + edogen_bytes + cities_bytes
        res = decode_bytes(full_container)

        self.assertEqual(res.version, "20261119")
        self.assertEqual(len(res.points), 1)
        self.assertEqual(res.points[0].type, TYPE_SPEED_LIMIT)
        # cities_bytes không bị đọc tràn vào, nên undecodable phải là 0
        self.assertEqual(res.skipped["undecodable"], 0)


if __name__ == "__main__":
    unittest.main()
