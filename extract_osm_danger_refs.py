#!/usr/bin/env python3
"""
extract_osm_danger_refs.py — Trích xuất tham chiếu giao cắt đường sắt & cầu từ OSM PBF.

Đầu ra JSON / JSON.gz nhẹ (< vài trăm KB) dùng để build-alerts lọc chuẩn xác
VietMap Type 7 & Type 10 tại giao cắt đường sắt (railway=level_crossing|rail)
hoặc cầu hẹp/nguy hiểm (bridge=*), đưa vào signs.bin (sign_type=10, sub_type=7).
"""

from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path


def extract_osm_danger_refs(pbf_path: Path, out_path: Path) -> dict:
    import osmium

    rail_nodes: list[list[float]] = []
    rail_ways: list[list[list[float]]] = []
    bridge_ways: list[list[list[float]]] = []

    class Handler(osmium.SimpleHandler):
        def node(self, n):
            if not n.location.valid() or len(n.tags) == 0:
                return
            rw = n.tags.get("railway")
            if rw in ("level_crossing", "crossing"):
                rail_nodes.append([round(n.location.lat, 6), round(n.location.lon, 6)])

        def way(self, w):
            if len(w.tags) == 0 or len(w.nodes) < 2:
                return
            rw = w.tags.get("railway")
            br = w.tags.get("bridge")
            hw = w.tags.get("highway")
            is_rail = rw in ("rail", "narrow_gauge", "light_rail", "tram", "subway")
            is_bridge = bool(hw and br and br.lower() not in ("no", "false", "0"))
            if not (is_rail or is_bridge):
                return
            pts = []
            for nd in w.nodes:
                if nd.location.valid():
                    pts.append([round(nd.location.lat, 6), round(nd.location.lon, 6)])
            if len(pts) < 2:
                return
            if is_rail:
                rail_ways.append(pts)
            if is_bridge:
                # Chia điểm mẫu tối đa 25m nếu đoạn cầu rất dài; thông thường way OSM đã đủ đỉnh
                bridge_ways.append(pts)

    Handler().apply_file(str(pbf_path), locations=True)
    payload = {
        "rail_nodes": rail_nodes,
        "rail_ways": rail_ways,
        "bridge_ways": bridge_ways,
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if str(out_path).endswith(".gz"):
        out_path.write_bytes(gzip.compress(raw, compresslevel=6))
    else:
        out_path.write_bytes(raw)
    return {
        "rail_nodes": len(rail_nodes),
        "rail_ways": len(rail_ways),
        "bridge_ways": len(bridge_ways),
        "bytes": out_path.stat().st_size,
    }


def main():
    parser = argparse.ArgumentParser(description="Trích xuất OSM rail/bridge danger refs từ .osm.pbf")
    parser.add_argument("pbf", type=Path, help="Đường dẫn vietnam.osm.pbf")
    parser.add_argument("out", type=Path, help="Đường dẫn file .json hoặc .json.gz đầu ra")
    args = parser.parse_args()
    stats = extract_osm_danger_refs(args.pbf, args.out)
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
