#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_road_signs.py — Xác thực chữ ký MapViet và tính toàn vẹn của osm_signs.bin từ release mạng đường OSM.
"""

import argparse
import base64
import gzip
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# MapViet manifest signing key (từ ManifestVerifier.kt trong core:data)
MAPVIET_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE10fhw+XnmfcvGR2+Jbg2fT+zFOAT
dNdYFcPdqKvU3APC0dF9vzILhmpSr2xJtg3DXZ++frzrQtDYY24iTkjdyA==
-----END PUBLIC KEY-----
"""


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_road_signs(road_dir: str | Path) -> Path:
    """
    Xác thực chữ ký số MapViet trên manifest.txt, giải nén và kiểm tra size + SHA256 của osm_signs.bin.
    Trả về đường dẫn tệp osm_signs.bin đã giải nén; dừng pipeline nếu có lỗi.
    """
    road_dir = Path(road_dir)
    manifest = road_dir / "manifest.txt"
    manifest_sig = road_dir / "manifest.txt.sig"
    osm_gz = road_dir / "osm_signs.bin.gz"

    if not manifest.exists():
        raise SystemExit(f"[LỖI] Không tìm thấy manifest mạng đường tại: {manifest}")
    if not manifest_sig.exists():
        raise SystemExit(f"[LỖI] Không tìm thấy chữ ký số manifest mạng đường tại: {manifest_sig}")
    if not osm_gz.exists():
        raise SystemExit(f"[LỖI] Không tìm thấy osm_signs.bin.gz tại: {osm_gz}")

    sig_b64 = manifest_sig.read_text(encoding="utf-8").strip()
    try:
        sig = base64.b64decode(sig_b64)
    except Exception as e:
        raise SystemExit(f"[LỖI] Chữ ký manifest.txt.sig không hợp lệ dạng Base64: {e}")

    # 1. Xác thực chữ ký ECDSA P-256 MapViet
    verified = False
    err_msg = ""
    with tempfile.TemporaryDirectory() as tmp:
        pub = Path(tmp) / "pub.pem"
        sigf = Path(tmp) / "sig.der"
        pub.write_text(MAPVIET_PUBLIC_KEY_PEM, encoding="utf-8")
        sigf.write_bytes(sig)
        r = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(pub), "-signature", str(sigf), str(manifest)],
            capture_output=True,
            text=True,
        )
        if r.returncode == 0 and "OK" in r.stdout:
            verified = True
        else:
            err_msg = f"{r.stdout.strip()} {r.stderr.strip()}"

    if not verified:
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            pub_key = serialization.load_pem_public_key(MAPVIET_PUBLIC_KEY_PEM.encode("utf-8"))
            pub_key.verify(sig, manifest.read_bytes(), ec.ECDSA(hashes.SHA256()))
            verified = True
        except Exception as e:
            err_msg = str(e)

    if not verified:
        raise SystemExit(f"[LỖI] Chữ ký manifest mạng đường KHÔNG HỢP LỆ (chưa ký bởi MapViet): {err_msg}")

    # 2. Đọc entry osm_signs.bin trong manifest.txt
    lines = manifest.read_text(encoding="utf-8").splitlines()
    entry = None
    for line in lines:
        parts = line.strip().split()
        if len(parts) >= 4 and parts[0] == "osm_signs.bin":
            entry = {
                "name": parts[0],
                "size": int(parts[1]),
                "sha256": parts[2].lower(),
                "gz_size": int(parts[3]),
            }
            break

    if not entry:
        raise SystemExit("[LỖI] osm_signs.bin không được liệt kê trong manifest mạng đường")

    # 3. Kiểm tra kích thước file nén
    actual_gz_size = osm_gz.stat().st_size
    if actual_gz_size != entry["gz_size"]:
        raise SystemExit(
            f"[LỖI] Kích thước file nén osm_signs.bin.gz không khớp: {actual_gz_size} != {entry['gz_size']}"
        )

    # 4. Giải nén osm_signs.bin.gz
    out_bin = road_dir / "osm_signs.bin"
    with gzip.open(osm_gz, "rb") as fi, open(out_bin, "wb") as fo:
        shutil.copyfileobj(fi, fo, 1 << 20)

    # 5. Kiểm tra size và sha256 sau khi giải nén
    actual_size = out_bin.stat().st_size
    if actual_size != entry["size"]:
        out_bin.unlink(missing_ok=True)
        raise SystemExit(
            f"[LỖI] Kích thước sau giải nén của osm_signs.bin không khớp: {actual_size} != {entry['size']}"
        )

    actual_sha = sha256_file(out_bin).lower()
    if actual_sha != entry["sha256"]:
        out_bin.unlink(missing_ok=True)
        raise SystemExit(
            f"[LỖI] SHA256 sau giải nén của osm_signs.bin không khớp: {actual_sha} != {entry['sha256']}"
        )

    print(f"[✓] Đã xác thực thành công osm_signs.bin: {actual_size:,} bytes, sha256={actual_sha}")
    return out_bin


def main():
    parser = argparse.ArgumentParser(description="Xác thực chữ ký và giải nén osm_signs.bin từ release mạng đường.")
    parser.add_argument("road_dir", type=Path, help="Thư mục chứa manifest.txt, manifest.txt.sig, osm_signs.bin.gz")
    args = parser.parse_args()
    verify_road_signs(args.road_dir)


if __name__ == "__main__":
    main()
