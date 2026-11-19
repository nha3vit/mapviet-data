# VietMap warning points

`secrect.bin` — warning-point database from the VietMap package (version line `20261022`, container TOC edogen.bin 2,684,000 bytes, 83,823 points). © VietMap, used and redistributed
in MapViet with VietMap's permission (confirmed by the project owner on 2026-11-17).

Format: Container header (512 bytes TOC) + CSV text with a fixed one-byte substitution, decoded by `vietmap_decode.py`
(`lon,lat,type,speed_limit,flag,heading`; all 11 types: 1 speed limit, 2 traffic light, 3 red light camera, 4 urban-zone start, 5 toll booth, 6 intersection, 7 danger, 8 other omni, 9 other, 10 no overtaking, 11 traffic camera).

To update: replace `secrect.bin` with the file from a newer VietMap package and push;
the `build-alerts` workflow rebuilds and republishes the `alerts` release.
