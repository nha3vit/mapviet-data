#!/usr/bin/env python3
import os
import shutil
import struct
import tempfile
import unittest
import zlib

from postprocess import (
    INDEX_ENTRY_FMT,
    METADATA_FMT,
    SEGMENT_FMT,
    deduplicate_tiles,
    is_geom_duplicate,
)


class TestPostprocess(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.src_dir = os.path.join(self.test_dir, "src")
        self.dst_dir = os.path.join(self.test_dir, "dst")
        os.makedirs(self.src_dir)
        os.makedirs(self.dst_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_is_geom_duplicate(self):
        # seg1: (1, startLat, startLon, endLat, endLon)
        seg1 = (1, 210000000, 1058000000, 210001000, 105801000, 90, 3, 0, 50, 1, 0)
        # seg2: exact same
        seg2 = (2, 210000000, 1058000000, 210001000, 105801000, 90, 3, 0, 50, 1, 0)
        # seg3: reverse
        seg3 = (3, 210001000, 105801000, 210000000, 1058000000, 270, 3, 0, 50, 1, 0)
        # seg4: different
        seg4 = (4, 210005000, 105805000, 210006000, 105806000, 90, 3, 0, 50, 1, 0)

        self.assertTrue(is_geom_duplicate(seg1, seg2))
        self.assertTrue(is_geom_duplicate(seg1, seg3))
        self.assertFalse(is_geom_duplicate(seg1, seg4))

    def test_deduplicate_tiles_drops_duplicates_and_keeps_smallest_id(self):
        # 1. Tạo 4 segment cho Tile 1
        # seg10: toạ độ A -> B
        seg10 = struct.pack(SEGMENT_FMT, 10, 210000000, 1058000000, 210001000, 105801000, 90, 3, 0, 50, 1, 0)
        # seg20: toạ độ A -> B (trùng xuôi với seg10)
        seg20 = struct.pack(SEGMENT_FMT, 20, 210000000, 1058000000, 210001000, 105801000, 90, 3, 0, 50, 1, 0)
        # seg5: toạ độ B -> A (trùng ngược, nhưng id = 5 < 10)
        seg5 = struct.pack(SEGMENT_FMT, 5, 210001000, 105801000, 210000000, 1058000000, 270, 3, 0, 50, 1, 0)
        # seg30: toạ độ B -> C (khác biệt)
        seg30 = struct.pack(SEGMENT_FMT, 30, 210001000, 105801000, 210002000, 105802000, 90, 3, 0, 50, 1, 0)

        tiles_data = seg10 + seg20 + seg5 + seg30
        with open(os.path.join(self.src_dir, "tiles.bin"), "wb") as f:
            f.write(tiles_data)

        # 2. Tạo index.bin cho 1 tile
        seg_size = struct.calcsize(SEGMENT_FMT)
        tile_length = 4 * seg_size
        idx_entry = struct.pack(INDEX_ENTRY_FMT, 1001, 210000000, 210002000, 1058000000, 105802000, 0, tile_length)
        with open(os.path.join(self.src_dir, "index.bin"), "wb") as f:
            f.write(idx_entry)

        # 3. Tạo metadata.bin
        crc = zlib.crc32(idx_entry) & 0xFFFFFFFF
        meta_data = struct.pack(
            METADATA_FMT,
            b"SLMP", 2, b"VN-TEST\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            b"2026.11\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            1700000000, 1, 4, 0.01, 210000000, 1058000000, 90, 10,
            b"attribution\x00" + b"\x00" * 52, crc
        )
        with open(os.path.join(self.src_dir, "metadata.bin"), "wb") as f:
            f.write(meta_data)

        # 4. Tạo seg_names.bin cho các segment (35 entry u32)
        seg_names = [0] * 35
        seg_names[5] = 105
        seg_names[10] = 110
        seg_names[20] = 120
        seg_names[30] = 130
        seg_names_data = struct.pack(f"<{len(seg_names)}I", *seg_names)
        with open(os.path.join(self.src_dir, "seg_names.bin"), "wb") as f:
            f.write(seg_names_data)

        # Thực thi deduplicate_tiles
        dropped = deduplicate_tiles(self.src_dir, self.dst_dir)

        # Xác thực số segment bị loại bỏ: 2
        self.assertEqual(dropped, 2)

        # Đọc tiles.bin kết quả
        with open(os.path.join(self.dst_dir, "tiles.bin"), "rb") as f:
            dst_tiles = f.read()

        num_dst_segs = len(dst_tiles) // seg_size
        self.assertEqual(num_dst_segs, 2)

        dst_seg_0 = struct.unpack_from(SEGMENT_FMT, dst_tiles, 0)
        dst_seg_1 = struct.unpack_from(SEGMENT_FMT, dst_tiles, seg_size)

        # Đoạn 1 phải là id 5 (nhỏ nhất trong 10, 20, 5)
        self.assertEqual(dst_seg_0[0], 5)
        # Đoạn 2 phải là id 30
        self.assertEqual(dst_seg_1[0], 30)

        # Đọc index.bin kết quả
        with open(os.path.join(self.dst_dir, "index.bin"), "rb") as f:
            dst_idx = f.read()
        dst_idx_entry = struct.unpack(INDEX_ENTRY_FMT, dst_idx)
        self.assertEqual(dst_idx_entry[5], 0)  # new offset = 0
        self.assertEqual(dst_idx_entry[6], 2 * seg_size)  # new length = 2 * 28 = 56

        # Đọc metadata.bin kết quả
        with open(os.path.join(self.dst_dir, "metadata.bin"), "rb") as f:
            dst_meta = f.read()
        dst_meta_fields = struct.unpack(METADATA_FMT, dst_meta)
        self.assertEqual(dst_meta_fields[6], 2)  # segCount = 2
        expected_crc = zlib.crc32(dst_idx) & 0xFFFFFFFF
        self.assertEqual(dst_meta_fields[13], expected_crc)  # indexCrc32 updated

        # Đọc seg_names.bin kết quả
        with open(os.path.join(self.dst_dir, "seg_names.bin"), "rb") as f:
            dst_names = f.read()
        dst_seg_names = struct.unpack(f"<{len(dst_names)//4}I", dst_names)
        self.assertEqual(dst_seg_names[5], 105)
        self.assertEqual(dst_seg_names[10], 0)  # bị xoá về 0
        self.assertEqual(dst_seg_names[20], 0)  # bị xoá về 0
        self.assertEqual(dst_seg_names[30], 130)


if __name__ == "__main__":
    unittest.main()
