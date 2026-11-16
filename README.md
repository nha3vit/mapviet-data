# mapviet-data

Daily road-network pack for the MapViet Android app, built automatically from the latest
OpenStreetMap Vietnam extract (Geofabrik) with the VietHUD pipeline.

- Workflow: `.github/workflows/build-network.yml` (daily 08:30 ICT + manual run)
- Output (GitHub Releases, `latest`): `manifest.txt`, `manifest.txt.sig` (ECDSA P-256, base64 DER),
  `metadata.bin.gz index.bin.gz tiles.bin.gz names.bin.gz seg_names.bin.gz lights.bin.gz`
- `manifest.txt`: `version <ver>` then `<file> <size> <sha256> <gz_size>` (size/sha256 of the uncompressed file)
- `lights.bin`: OSM `highway=traffic_signals` in VNSG sign format (type 6)

Data © OpenStreetMap contributors, available under the Open Database License (ODbL).
Pipeline: VietHUD (github.com/911273/VietHUD), used with the author's permission.
