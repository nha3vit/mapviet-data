#!/usr/bin/env python3
"""Unit tests for urban_flags.py."""
import os
import shutil
import struct
import tempfile
import unittest

from urban_flags import (
    FLAG_URBAN,
    SEGMENT_FMT,
    SEG_SIZE,
    UrbanIndex,
    parse_osm_xml,
    tag_tiles,
)

SAMPLE_OSM_XML = """<?xml version="1.0" encoding="UTF-8"?>
<osm version="0.6" generator="test">
  <!-- Place node: town (radius 1500m) -->
  <node id="1001" lat="20.9850000" lon="106.5100000">
    <tag k="name" v="Thị trấn Kinh Môn"/>
    <tag k="place" v="town"/>
  </node>

  <!-- Nodes for residential polygon -->
  <node id="2001" lat="20.9000000" lon="106.4000000"/>
  <node id="2002" lat="20.9100000" lon="106.4000000"/>
  <node id="2003" lat="20.9100000" lon="106.4100000"/>
  <node id="2004" lat="20.9000000" lon="106.4100000"/>

  <way id="3001">
    <nd ref="2001"/>
    <nd ref="2002"/>
    <nd ref="2003"/>
    <nd ref="2004"/>
    <nd ref="2001"/>
    <tag k="landuse" v="residential"/>
  </way>
</osm>
"""


def pack_segment(
    seg_id, s_lat, s_lon, e_lat, e_lon, length_m=100, road_class=3, speed_limit=0, flags=0
):
    return struct.pack(
        SEGMENT_FMT,
        seg_id,
        int(s_lat * 1e7),
        int(s_lon * 1e7),
        int(e_lat * 1e7),
        int(e_lon * 1e7),
        length_m,
        road_class,
        speed_limit,
        90,
        0,
        flags,
    )


class TestUrbanFlags(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.osm_file = os.path.join(self.test_dir, "test.osm")
        with open(self.osm_file, "w", encoding="utf-8") as f:
            f.write(SAMPLE_OSM_XML)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_urban_index_and_tagging(self):
        index = UrbanIndex()
        parse_osm_xml(self.osm_file, index)

        # 1. Test is_urban on index directly
        # Point near town node (distance ~200m)
        self.assertTrue(index.is_urban(20.9860, 106.5110))
        # Point inside residential polygon
        self.assertTrue(index.is_urban(20.9050, 106.4050))
        # Point far away in rural area
        self.assertFalse(index.is_urban(20.7000, 106.2000))
        # Point 3km away from town (town radius is 1500m)
        self.assertFalse(index.is_urban(20.9500, 106.5100))

        # 2. Test tag_tiles on tiles.bin
        # Seg 1: near town (should be tagged)
        seg1 = pack_segment(1, 20.9855, 106.5105, 20.9865, 106.5115, flags=0)
        # Seg 2: inside residential polygon (should be tagged)
        seg2 = pack_segment(2, 20.9040, 106.4040, 20.9060, 106.4060, flags=0)
        # Seg 3: rural area (should NOT be tagged)
        seg3 = pack_segment(3, 20.7000, 106.2000, 20.7010, 106.2010, flags=0)
        # Seg 4: already urban (flags=0x40)
        seg4 = pack_segment(4, 20.9850, 106.5100, 20.9860, 106.5110, flags=FLAG_URBAN)

        tiles_path = os.path.join(self.test_dir, "tiles.bin")
        with open(tiles_path, "wb") as f:
            f.write(seg1 + seg2 + seg3 + seg4)

        tagged, total = tag_tiles(self.test_dir, index)
        self.assertEqual(tagged, 2)
        self.assertEqual(total, 3)

        with open(tiles_path, "rb") as f:
            updated_data = f.read()

        s1_unpacked = struct.unpack_from(SEGMENT_FMT, updated_data, 0 * SEG_SIZE)
        s2_unpacked = struct.unpack_from(SEGMENT_FMT, updated_data, 1 * SEG_SIZE)
        s3_unpacked = struct.unpack_from(SEGMENT_FMT, updated_data, 2 * SEG_SIZE)
        s4_unpacked = struct.unpack_from(SEGMENT_FMT, updated_data, 3 * SEG_SIZE)

        self.assertTrue(s1_unpacked[-1] & FLAG_URBAN)
        self.assertTrue(s2_unpacked[-1] & FLAG_URBAN)
        self.assertFalse(s3_unpacked[-1] & FLAG_URBAN)
        self.assertTrue(s4_unpacked[-1] & FLAG_URBAN)


if __name__ == "__main__":
    unittest.main()
