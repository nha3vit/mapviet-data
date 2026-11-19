# mapviet-data

Daily road-network pack for the MapViet Android app, built automatically from the latest
OpenStreetMap Vietnam extract (Geofabrik) with the VietHUD pipeline.

- Workflow: `.github/workflows/build-network.yml` (daily 08:30 ICT + manual run)
- Output (GitHub Releases, `latest`): `manifest.txt`, `manifest.txt.sig` (ECDSA P-256, base64 DER),
  `metadata.bin.gz index.bin.gz tiles.bin.gz names.bin.gz seg_names.bin.gz lights.bin.gz`
- `manifest.txt`: `version <ver>` then `<file> <size> <sha256> <gz_size>` (size/sha256 of the uncompressed file)
- `lights.bin`: OSM `highway=traffic_signals` in VNSG sign format (type 6)

## Alert pack (cameras + signs)

- Workflow: `.github/workflows/build-alerts.yml` (daily 09:00 ICT, on changes to the sources/scripts, + manual run)
- Inputs: VietHUD `speedmap/` (`cameras.bin`, `signs.bin`; signed manifest checked by `verify_viethud.py`
  with the VietHUD key), the VietMap point database `sources/vietmap/secrect.bin` (container; only the
  `edogen.bin` partition is decoded by `vietmap_decode.py`) and WYN points `sources/wyn/wyn_points.csv`.
- `alerts.py` (copy of `VietHUD/tools/alerts.py`, the canonical source) merges with source priority
  **VietMap > WYN > VietHUD base**: a lower-priority point of the same kind within 30 m (camera),
  45 m (traffic light) or 20 m (other sign) of a higher-priority point is dropped. Every decoded VietMap
  point is kept unchanged (the build stops otherwise). All cameras go to `cameras.bin`; `signs.bin` has
  no sign type 4. Camera speed: `0` = no speed enforcement, `-1` = unknown, else a multiple of 5 in [5, 130].
- After the build, `validate_speedmap.py --alerts-only` and `validate_alerts.py` must pass.
- Output (GitHub Release with the fixed tag **`alerts`**, not `latest`): `manifest.txt`
  (`version <ver>` then `<file> <size> <sha256>`), `manifest.txt.sig` (MapViet key),
  `cameras.bin`, `signs.bin` (VietHUD binary formats), `stats.json`.
- App URL: `https://github.com/nha3vit/mapviet-data/releases/download/alerts/manifest.txt`

Run locally:

```bash
mkdir vh && for f in manifest.txt manifest.txt.sig cameras.bin signs.bin; do
  curl -fsSL -o vh/$f https://raw.githubusercontent.com/911273/VietHUD/main/speedmap/$f; done
pip install cryptography==50.0.1
python3 verify_viethud.py vh
python3 alerts.py --base vh --vietmap sources/vietmap/secrect.bin --wyn sources/wyn/wyn_points.csv --out alerts_out --no-sign
python3 validate_alerts.py alerts_out --vietmap sources/vietmap/secrect.bin
python3 -m unittest discover -s tests
```

## Sources and licences

- Road network and `lights.bin`: © OpenStreetMap contributors, Open Database License (ODbL).
- Pipeline and speedmap alert data: VietHUD (github.com/911273/VietHUD), used with the author's permission.
- VietMap warning points (`sources/vietmap/`): © VietMap, used and redistributed with VietMap's permission.
  Not covered by the ODbL.
- WYN warning points (`sources/wyn/`): extracted from the WYN app, redistributed with WYN's permission — thanks to WYN.
  Not covered by the ODbL.
