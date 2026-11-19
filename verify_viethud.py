#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_viethud.py — Kiểm tra chữ ký ECDSA và toàn vẹn dữ liệu (size + SHA256) của gói VietHUD speedmap.
"""

import argparse
import base64
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# VietHUD manifest signing key (firmware src/update/DataInstaller.cpp).
VIETHUD_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEln5apjIcBBwLnKzVMOhMFCBVA6rD
7FhcGMXJpIKiMDUBgVvLwKBFiOlI4PqASEINgUEu4aTpkTVdW8iZ9B2WzQ==
-----END PUBLIC KEY-----
"""


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_viethud(src_dir: str | Path) -> str:
    """
    Kiểm tra chữ ký VietHUD manifest + kích thước & SHA256 của cameras.bin và signs.bin.
    Trả về chuỗi version nếu hợp lệ; raise SystemExit nếu có lỗi.
    """
    src_dir = Path(src_dir)
    manifest = src_dir / "manifest.txt"
    manifest_sig = src_dir / "manifest.txt.sig"

    if not manifest.exists():
        raise SystemExit(f"Không tìm thấy manifest tại: {manifest}")
    if not manifest_sig.exists():
        raise SystemExit(f"Không tìm thấy chữ ký manifest tại: {manifest_sig}")

    sig_b64 = manifest_sig.read_text(encoding="utf-8").strip()
    try:
        sig = base64.b64decode(sig_b64)
    except Exception as e:
        raise SystemExit(f"Chữ ký manifest.txt.sig không hợp lệ dạng Base64: {e}")

    # Xác thực chữ ký ECDSA P-256 qua openssl
    verified = False
    with tempfile.TemporaryDirectory() as tmp:
        pub = Path(tmp) / "pub.pem"
        sigf = Path(tmp) / "sig.der"
        pub.write_text(VIETHUD_PUBLIC_KEY_PEM, encoding="utf-8")
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

    # Fallback kiểm tra qua thư viện cryptography nếu có và openssl chưa đạt
    if not verified:
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            pub_key = serialization.load_pem_public_key(VIETHUD_PUBLIC_KEY_PEM.encode("utf-8"))
            pub_key.verify(sig, manifest.read_bytes(), ec.ECDSA(hashes.SHA256()))
            verified = True
        except Exception:
            pass

    if not verified:
        raise SystemExit(f"VietHUD manifest signature INVALID: {err_msg if 'err_msg' in locals() else 'Verification failed'}")

    # Đọc và đối chiếu entries trong manifest
    lines = manifest.read_text(encoding="utf-8").splitlines()
    version = lines[0].split(" ", 1)[1] if lines and lines[0].startswith("version ") else "?"

    entries = {}
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 3:
            entries[parts[0]] = (int(parts[1]), parts[2].lower())

    for name in ("cameras.bin", "signs.bin"):
        if name not in entries:
            raise SystemExit(f"VietHUD manifest không có file bắt buộc: {name}")
        p = src_dir / name
        if not p.exists():
            raise SystemExit(f"File {name} không tồn tại tại {p}")
        size, digest = entries[name]
        act_size = p.stat().st_size
        if act_size != size:
            raise SystemExit(f"VietHUD {name} sai kích thước: kỳ vọng {size}, thực tế {act_size}")
        act_digest = sha256_file(p)
        if act_digest != digest:
            raise SystemExit(f"VietHUD {name} sai SHA256: kỳ vọng {digest}, thực tế {act_digest}")

    return version


def main():
    parser = argparse.ArgumentParser(description="Kiểm tra chữ ký và toàn vẹn dữ liệu VietHUD speedmap.")
    parser.add_argument("dir", type=Path, help="Thư mục chứa manifest.txt, manifest.txt.sig, cameras.bin, signs.bin")
    args = parser.parse_args()

    ver = verify_viethud(args.dir)
    print(f"[OK] VietHUD speedmap verified: version {ver}")


if __name__ == "__main__":
    main()
