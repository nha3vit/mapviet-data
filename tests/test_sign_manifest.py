# Bản sao từ VietHUD/tools/tests/test_sign_manifest.py — nguồn chuẩn là VietHUD/tools; sửa ở đó rồi chép lại
import sys
from pathlib import Path
_REPO_DIR = Path(__file__).resolve().parent.parent
if str(_REPO_DIR) not in sys.path:
    sys.path.insert(0, str(_REPO_DIR))

import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

try:
    from tools import sign_manifest
except ImportError:
    import sign_manifest


class TestSignManifest(unittest.TestCase):
    def setUp(self):
        # Tạo khoá EC P-256 tạm thời cho test (không dùng khoá thật)
        self.priv_key = ec.generate_private_key(ec.SECP256R1())
        self.pub_key = self.priv_key.public_key()

        self.priv_pem = self.priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.pub_pem = self.pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        self.temp_dir = tempfile.TemporaryDirectory()
        self.td = Path(self.temp_dir.name)

        self.priv_file = self.td / "test_key.pem"
        self.priv_file.write_bytes(self.priv_pem)

        self.pub_file = self.td / "test_pub.pem"
        self.pub_file.write_bytes(self.pub_pem)

        self.manifest_file = self.td / "manifest.txt"
        self.manifest_file.write_text("version 2026.11.18\ntest.bin 100 abc\n", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_key_lookup_order(self):
        # 1. MAPVIET_SIGNING_KEY_FILE có độ ưu tiên cao nhất
        file1 = self.td / "key1.pem"
        file1.write_bytes(self.priv_pem)
        file2 = self.td / "key2.pem"
        file2.write_bytes(self.priv_pem)

        old_mapviet = os.environ.get("MAPVIET_SIGNING_KEY_FILE")
        old_viethud = os.environ.get("VIETHUD_SIGNING_KEY")

        try:
            os.environ["MAPVIET_SIGNING_KEY_FILE"] = str(file1)
            os.environ["VIETHUD_SIGNING_KEY"] = str(file2)
            self.assertEqual(sign_manifest.find_private_key_path(), file1)

            del os.environ["MAPVIET_SIGNING_KEY_FILE"]
            self.assertEqual(sign_manifest.find_private_key_path(), file2)
        finally:
            if old_mapviet is not None:
                os.environ["MAPVIET_SIGNING_KEY_FILE"] = old_mapviet
            elif "MAPVIET_SIGNING_KEY_FILE" in os.environ:
                del os.environ["MAPVIET_SIGNING_KEY_FILE"]

            if old_viethud is not None:
                os.environ["VIETHUD_SIGNING_KEY"] = old_viethud
            elif "VIETHUD_SIGNING_KEY" in os.environ:
                del os.environ["VIETHUD_SIGNING_KEY"]

    def test_sign_and_verify(self):
        sig_file = sign_manifest.sign_manifest(self.manifest_file, key=self.priv_key)
        self.assertTrue(sig_file.exists())

        # Xác thực thành công với đúng public key
        self.assertTrue(sign_manifest.verify_manifest(self.manifest_file, pub_key=self.pub_key))

        # Giả mạo nội dung manifest -> verify phải fail
        tampered_manifest = self.td / "tampered_manifest.txt"
        tampered_manifest.write_text("tampered content\n", encoding="utf-8")
        # Chép file sig sang tampered
        tampered_sig = self.td / "tampered_manifest.txt.sig"
        tampered_sig.write_text(sig_file.read_text())
        self.assertFalse(sign_manifest.verify_manifest(tampered_manifest, pub_key=self.pub_key))


if __name__ == "__main__":
    unittest.main()
