#!/usr/bin/env python3
"""tools/sign_manifest.py — Ký và xác thực manifest dữ liệu VietHUD bằng khoá MapViet.

Quy định khoá:
  Thứ tự tìm khoá riêng (Private Key):
    1. Biến môi trường MAPVIET_SIGNING_KEY_FILE
    2. Biến môi trường VIETHUD_SIGNING_KEY (tương thích ngược)
    3. Đường dẫn mặc định: ~/.mapviet/mapviet_signing_key.pem

  Thứ tự tìm khoá công khai (Public Key):
    1. Tham số dòng lệnh --pub <file>
    2. Biến môi trường MAPVIET_SIGNING_PUB_FILE
    3. Đường dẫn mặc định: ~/.mapviet/mapviet_signing_pub.pem

Định dạng chữ ký (.sig):
  ECDSA P-256 / SHA-256 trên toàn bộ byte thô của manifest.txt, DER-encoded,
  mã hoá Base64 kèm ký tự xuống dòng '\\n'.
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def find_private_key_path() -> Path | None:
    """Tìm đường dẫn khoá riêng theo thứ tự ưu tiên."""
    env_mapviet = os.environ.get("MAPVIET_SIGNING_KEY_FILE")
    if env_mapviet and Path(env_mapviet).exists():
        return Path(env_mapviet)

    env_viethud = os.environ.get("VIETHUD_SIGNING_KEY")
    if env_viethud and Path(env_viethud).exists():
        return Path(env_viethud)

    default_mapviet = Path.home() / ".mapviet" / "mapviet_signing_key.pem"
    if default_mapviet.exists():
        return default_mapviet

    return None


def find_public_key_path(pub_arg: Path | str | None = None) -> Path | None:
    """Tìm đường dẫn khoá công khai theo thứ tự ưu tiên."""
    if pub_arg:
        p = Path(pub_arg)
        if p.exists():
            return p

    env_pub = os.environ.get("MAPVIET_SIGNING_PUB_FILE")
    if env_pub and Path(env_pub).exists():
        return Path(env_pub)

    default_pub = Path.home() / ".mapviet" / "mapviet_signing_pub.pem"
    if default_pub.exists():
        return default_pub

    return None


def load_private_key(path: Path | None = None):
    """Nạp khoá riêng ECDSA từ file PEM."""
    p = path or find_private_key_path()
    if not p or not p.exists():
        raise FileNotFoundError(
            "Không tìm thấy khoá ký private key (kiểm tra MAPVIET_SIGNING_KEY_FILE, "
            "VIETHUD_SIGNING_KEY, hoặc ~/.mapviet/mapviet_signing_key.pem)"
        )
    return serialization.load_pem_private_key(p.read_bytes(), password=None)


def load_public_key(path: Path | None = None):
    """Nạp khoá công khai ECDSA từ file PEM (hoặc trích từ khoá riêng nếu có)."""
    p = path or find_public_key_path()
    if p and p.exists():
        return serialization.load_pem_public_key(p.read_bytes())

    # Fallback: nếu có khoá riêng thì lấy public_key từ khoá riêng
    priv_path = find_private_key_path()
    if priv_path and priv_path.exists():
        priv = load_private_key(priv_path)
        return priv.public_key()

    raise FileNotFoundError(
        "Không tìm thấy khoá công khai public key (kiểm tra --pub, MAPVIET_SIGNING_PUB_FILE, "
        "hoặc ~/.mapviet/mapviet_signing_pub.pem)"
    )


def sign_data(data: bytes, key) -> str:
    """Tạo chữ ký base64 cho dữ liệu bytes."""
    sig = key.sign(data, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode("ascii") + "\n"


def sign_manifest(manifest: Path, key=None) -> Path:
    """Ký một file manifest và ghi ra file .sig cạnh nó."""
    if key is None:
        key = load_private_key()
    data = manifest.read_bytes()
    sig_str = sign_data(data, key)
    out = manifest.with_name(manifest.name + ".sig")
    out.write_bytes(sig_str.encode("ascii"))
    return out


def verify_manifest(manifest: Path, pub_key=None) -> bool:
    """Xác thực chữ ký file manifest."""
    sig_path = manifest.with_name(manifest.name + ".sig")
    if not sig_path.exists():
        return False
    try:
        if pub_key is None:
            pub_key = load_public_key()
        sig = base64.b64decode(sig_path.read_text().strip())
        pub_key.verify(sig, manifest.read_bytes(), ec.ECDSA(hashes.SHA256()))
        return True
    except (FileNotFoundError, InvalidSignature, ValueError):
        return False


def main():
    parser = argparse.ArgumentParser(description="Ký và xác thực manifest VietHUD bằng ECDSA P-256")
    parser.add_argument("manifests", nargs="+", type=Path, help="Đường dẫn các file manifest")
    parser.add_argument("--verify", action="store_true", help="Chỉ kiểm tra chữ ký (mặc định là ký)")
    parser.add_argument("--pub", type=Path, default=None, help="File public key dùng để xác thực")
    parser.add_argument("--key", type=Path, default=None, help="File private key dùng để ký")
    args = parser.parse_args()

    ok = True
    if args.verify:
        try:
            pub_key = load_public_key(args.pub)
        except Exception as e:
            sys.exit(f"[LOI] {e}")

        for m in args.manifests:
            if not m.exists():
                print(f"[LOI] File không tồn tại: {m}")
                ok = False
                continue
            good = verify_manifest(m, pub_key=pub_key)
            ok &= good
            print(f"{m}: {'OK' if good else 'BAD/MISSING signature'}")
    else:
        try:
            key = load_private_key(args.key)
        except Exception as e:
            sys.exit(f"[LOI] {e}")

        for m in args.manifests:
            if not m.exists():
                print(f"[LOI] File không tồn tại: {m}")
                ok = False
                continue
            sig_file = sign_manifest(m, key=key)
            print(f"[OK] Đã ký {m} -> {sig_file}")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
