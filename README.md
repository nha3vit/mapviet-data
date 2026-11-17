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
- Inputs: VietHUD `speedmap/` (`cameras.bin`, `signs.bin`; signed manifest verified with the VietHUD key)
  and the VietMap point database `sources/vietmap/secrect.bin` (decoded by `vietmap_decode.py`).
- `alerts.py` keeps every VietHUD point and adds VietMap points that VietHUD does not have
  (same kind within 30 m and heading within 45° for signs / 60° for cameras = duplicate).
- Output (GitHub Release with the fixed tag **`alerts`**, not `latest`): `manifest.txt`
  (`version <ver>` then `<file> <size> <sha256>`), `manifest.txt.sig` (MapViet key),
  `cameras.bin`, `signs.bin` (VietHUD binary formats), `stats.json`.
- App URL: `https://github.com/nha3vit/mapviet-data/releases/download/alerts/manifest.txt`

Run locally:

```bash
mkdir vh && for f in manifest.txt manifest.txt.sig cameras.bin signs.bin; do
  curl -fsSL -o vh/$f https://raw.githubusercontent.com/911273/VietHUD/main/speedmap/$f; done
python3 alerts.py --viethud vh --vietmap sources/vietmap/secrect.bin --out alerts_out
python3 vietmap_decode.py sources/vietmap/secrect.bin vietmap.csv   # inspect VietMap points
python3 -m unittest test_alerts
```

## Sources and licences

- Road network and `lights.bin`: © OpenStreetMap contributors, Open Database License (ODbL).
- Pipeline and speedmap alert data: VietHUD (github.com/911273/VietHUD), used with the author's permission.
- VietMap warning points (`sources/vietmap/`): © VietMap, used and redistributed with VietMap's permission.
  Not covered by the ODbL.
