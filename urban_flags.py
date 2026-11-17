#!/usr/bin/env python3
"""Tag urban road segments in MapViet network data based on OSM urban areas.

Reads OSM data to identify:
1. Polygons with landuse in {residential, commercial, retail, industrial}
2. Place nodes with place in:
   - city: radius 3000 m
   - town: radius 1500 m
   - village: radius 600 m
   - suburb, quarter, neighbourhood: radius 400 m

For each segment in tiles.bin:
If its midpoint falls within an urban polygon or place radius,
set bit 0x40 (URBAN) in the segment's flags byte.
"""
import math
import os
import struct
import sys
from collections import defaultdict

SEGMENT_FMT = "<IiiiiHBBhBB"
SEG_SIZE = struct.calcsize(SEGMENT_FMT)
INDEX_ENTRY_FMT = "<IiiiiII"
INDEX_ENTRY_SIZE = struct.calcsize(INDEX_ENTRY_FMT)

FLAG_URBAN = 0x40

URBAN_LANDUSE = {"residential", "commercial", "retail", "industrial"}
RADIUS_BY_PLACE = {
    "city": 3000.0,
    "town": 1500.0,
    "village": 600.0,
    "suburb": 400.0,
    "quarter": 400.0,
    "neighbourhood": 400.0,
}

GRID_SIZE = 0.05  # ~5.5 km grid cell


def distance_m(lat1, lon1, lat2, lon2):
    """Approximate distance in meters between two lat/lon points."""
    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)
    mean_lat = math.radians((lat1 + lat2) / 2.0)
    x = d_lon * math.cos(mean_lat) * 6371000.0
    y = d_lat * 6371000.0
    return math.hypot(x, y)


def point_in_poly(lat, lon, poly_coords):
    """Ray casting algorithm to determine if (lat, lon) is inside polygon."""
    inside = False
    n = len(poly_coords)
    if n < 3:
        return False
    p1_lat, p1_lon = poly_coords[0]
    for i in range(1, n + 1):
        p2_lat, p2_lon = poly_coords[i % n]
        if min(p1_lat, p2_lat) < lat <= max(p1_lat, p2_lat):
            if lon <= max(p1_lon, p2_lon):
                if p1_lat != p2_lat:
                    x_inters = (lat - p1_lat) * (p2_lon - p1_lon) / (p2_lat - p1_lat) + p1_lon
                    if p1_lon == p2_lon or lon <= x_inters:
                        inside = not inside
                elif p1_lon == p2_lon and lon <= p1_lon:
                    inside = not inside
        p1_lat, p1_lon = p2_lat, p2_lon
    return inside


class UrbanIndex:
    def __init__(self):
        self.cell_places = defaultdict(list)  # (cell) -> list of (plat, plon, radius_m)
        self.cell_polygons = defaultdict(list)  # (cell) -> list of (min_lat, min_lon, max_lat, max_lon, coords)

    def _grid_cell(self, lat, lon):
        return int(lat // GRID_SIZE), int(lon // GRID_SIZE)

    def add_place(self, lat, lon, radius_m):
        dlat = radius_m / 111000.0
        cos_lat = max(0.1, math.cos(math.radians(lat)))
        dlon = radius_m / (111000.0 * cos_lat)

        min_c_lat, min_c_lon = self._grid_cell(lat - dlat, lon - dlon)
        max_c_lat, max_c_lon = self._grid_cell(lat + dlat, lon + dlon)

        place = (lat, lon, radius_m)
        for c_lat in range(min_c_lat, max_c_lat + 1):
            for c_lon in range(min_c_lon, max_c_lon + 1):
                self.cell_places[(c_lat, c_lon)].append(place)

    def add_polygon(self, coords):
        if len(coords) < 3:
            return
        min_lat = min(p[0] for p in coords)
        max_lat = max(p[0] for p in coords)
        min_lon = min(p[1] for p in coords)
        max_lon = max(p[1] for p in coords)

        min_c_lat, min_c_lon = self._grid_cell(min_lat, min_lon)
        max_c_lat, max_c_lon = self._grid_cell(max_lat, max_lon)

        item = (min_lat, min_lon, max_lat, max_lon, coords)
        for c_lat in range(min_c_lat, max_c_lat + 1):
            for c_lon in range(min_c_lon, max_c_lon + 1):
                self.cell_polygons[(c_lat, c_lon)].append(item)

    def is_urban(self, lat, lon):
        cell = self._grid_cell(lat, lon)

        # 1. Check place radii
        for plat, plon, radius_m in self.cell_places.get(cell, []):
            if distance_m(lat, lon, plat, plon) <= radius_m:
                return True

        # 2. Check polygons
        for min_lat, min_lon, max_lat, max_lon, coords in self.cell_polygons.get(cell, []):
            if min_lat <= lat <= max_lat and min_lon <= lon <= max_lon:
                if point_in_poly(lat, lon, coords):
                    return True

        return False


def parse_osm_xml(osm_file, index: UrbanIndex):
    """Parse .osm XML using standard library ElementTree."""
    import xml.etree.ElementTree as ET

    nodes = {}  # id -> (lat, lon)
    context = ET.iterparse(osm_file, events=("end",))

    for event, elem in context:
        tag = elem.tag
        if tag == "node":
            node_id = elem.get("id")
            lat = float(elem.get("lat"))
            lon = float(elem.get("lon"))
            nodes[node_id] = (lat, lon)

            for child in elem:
                if child.tag == "tag" and child.get("k") == "place":
                    place_type = child.get("v")
                    if place_type in RADIUS_BY_PLACE:
                        index.add_place(lat, lon, RADIUS_BY_PLACE[place_type])
            elem.clear()

        elif tag == "way":
            is_urban_landuse = False
            for child in elem:
                if child.tag == "tag" and child.get("k") == "landuse":
                    if child.get("v") in URBAN_LANDUSE:
                        is_urban_landuse = True

            if is_urban_landuse:
                refs = [c.get("ref") for c in elem if c.tag == "nd"]
                if len(refs) >= 4 and refs[0] == refs[-1]:
                    coords = [nodes[r] for r in refs if r in nodes]
                    if len(coords) >= 4:
                        index.add_polygon(coords)
            elem.clear()


def parse_osm_pbf(osm_file, index: UrbanIndex):
    """Parse .osm.pbf using pyosmium if available, otherwise raise ImportError."""
    try:
        import osmium
    except ImportError:
        raise ImportError("pyosmium not installed. Install osmium or use .osm XML input.")

    class OsmiumUrbanCollector(osmium.SimpleHandler):
        def __init__(self, idx: UrbanIndex):
            super().__init__()
            self.idx = idx

        def node(self, n):
            place = n.tags.get("place")
            if place in RADIUS_BY_PLACE:
                self.idx.add_place(n.location.lat, n.location.lon, RADIUS_BY_PLACE[place])

        def way(self, w):
            landuse = w.tags.get("landuse")
            if landuse in URBAN_LANDUSE and w.is_closed() and len(w.nodes) >= 4:
                try:
                    coords = [(pt.lat, pt.lon) for pt in w.nodes]
                    self.idx.add_polygon(coords)
                except osmium.InvalidLocationError:
                    pass

    handler = OsmiumUrbanCollector(index)
    handler.apply_file(osm_file, locations=True)


def parse_osm(osm_file, index: UrbanIndex):
    if osm_file.endswith(".osm") or osm_file.endswith(".xml"):
        parse_osm_xml(osm_file, index)
    else:
        try:
            parse_osm_pbf(osm_file, index)
        except ImportError:
            # If pyosmium is not installed but the file is XML named differently
            parse_osm_xml(osm_file, index)


def tag_tiles(network_dir_or_tiles, index: UrbanIndex):
    tiles_path = (
        os.path.join(network_dir_or_tiles, "tiles.bin")
        if os.path.isdir(network_dir_or_tiles)
        else network_dir_or_tiles
    )
    if not os.path.exists(tiles_path):
        raise FileNotFoundError(f"tiles.bin not found at {tiles_path}")

    with open(tiles_path, "rb") as f:
        tiles_data = bytearray(f.read())

    total_segments = len(tiles_data) // SEG_SIZE
    tagged_urban = 0
    already_urban = 0

    for i in range(total_segments):
        offset = i * SEG_SIZE
        seg = struct.unpack_from(SEGMENT_FMT, tiles_data, offset)
        seg_id, s_lat, s_lon, e_lat, e_lon, length_m, road_class, speed_limit, heading, one_way, flags = seg

        if flags & FLAG_URBAN:
            already_urban += 1
            continue

        mid_lat = (s_lat + e_lat) / 2.0 / 1e7
        mid_lon = (s_lon + e_lon) / 2.0 / 1e7

        if index.is_urban(mid_lat, mid_lon):
            new_flags = flags | FLAG_URBAN
            struct.pack_into(
                SEGMENT_FMT,
                tiles_data,
                offset,
                seg_id,
                s_lat,
                s_lon,
                e_lat,
                e_lon,
                length_m,
                road_class,
                speed_limit,
                heading,
                one_way,
                new_flags,
            )
            tagged_urban += 1

    with open(tiles_path, "wb") as f:
        f.write(tiles_data)

    total_urban = already_urban + tagged_urban
    print(f"Processed segments: {total_segments}")
    print(f"Already urban: {already_urban}")
    print(f"Urban segments tagged: {tagged_urban}")
    print(f"Total urban segments: {total_urban}")
    return tagged_urban, total_urban


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <osm_file> <network_dir_or_tiles.bin>")
        sys.exit(1)

    osm_file = sys.argv[1]
    network_dir = sys.argv[2]

    index = UrbanIndex()
    print(f"Parsing OSM data from {osm_file}...")
    parse_osm(osm_file, index)
    print("Tagging segments in tiles.bin...")
    tag_tiles(network_dir, index)


if __name__ == "__main__":
    main()
