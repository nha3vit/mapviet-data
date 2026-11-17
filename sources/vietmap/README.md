# VietMap warning points

`secrect.bin` — warning-point database from the VietMap C61 Pro / C61 Sony / R4A / R1 dashcam
update package (version line `261022`, file dated 2026-10-27). © VietMap, used and redistributed
in MapViet with VietMap's permission (confirmed by the project owner on 2026-11-17).

Format: CSV text with a fixed one-byte substitution, decoded by `../../vietmap_decode.py`
(`lon,lat,type,speed_limit,flag,heading`; types 1 speed limit, 2 traffic light,
4 urban-zone start, 10 no overtaking, 11 camera).

To update: replace `secrect.bin` with the file from a newer VietMap package and push;
the `build-alerts` workflow rebuilds and republishes the `alerts` release.
