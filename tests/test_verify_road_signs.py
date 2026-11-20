#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import gzip
import hashlib
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import base64

from verify_road_signs import MAPVIET_PUBLIC_KEY_PEM, verify_road_signs


class TestVerifyRoadSigns(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.tmp_dir = Path(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_verify_road_signs_success_and_failure(self):
        # 1. Tạo private key tương ứng với MAPVIET_PUBLIC_KEY_PEM để ký giả lập
        # Vì chúng ta không có private key thật của MapViet trong test, ta tạo một keypair mới
        test_key = ec.generate_private_key(ec.SECP256R1())
        test_pub_pem = test_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        # Mock MAPVIET_PUBLIC_KEY_PEM trong module
        import verify_road_signs as vrs
        orig_key = vrs.MAPVIET_PUBLIC_KEY_PEM
        vrs.MAPVIET_PUBLIC_KEY_PEM = test_pub_pem

        try:
            raw_osm = b"TEST_OSM_SIGNS_DATA"
            raw_size = len(raw_osm)
            raw_sha = hashlib.sha256(raw_osm).hexdigest()

            gz_path = self.tmp_dir / "osm_signs.bin.gz"
            with gzip.open(gz_path, "wb") as f:
                f.write(raw_osm)
            gz_size = gz_path.stat().st_size

            manifest_content = (
                f"version 2026.11.20\n"
                f"osm_signs.bin {raw_size} {raw_sha} {gz_size}\n"
            )
            manifest_path = self.tmp_dir / "manifest.txt"
            manifest_path.write_text(manifest_content, encoding="utf-8")

            # Ký manifest
            sig_der = test_key.sign(manifest_content.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
            sig_b64 = base64.b64encode(sig_der).decode("utf-8")
            (self.tmp_dir / "manifest.txt.sig").write_text(sig_b64, encoding="utf-8")

            # Gọi verify_road_signs -> thành công
            out_bin = verify_road_signs(self.tmp_dir)
            self.assertTrue(out_bin.exists())
            self.assertEqual(out_bin.read_bytes(), raw_osm)

            # Sửa file nén -> lỗi
            gz_path.write_bytes(b"corrupted")
            with self.assertRaises(SystemExit):
                verify_road_signs(self.tmp_dir)

        finally:
            vrs.MAPVIET_PUBLIC_KEY_PEM = orig_key


if __name__ == "__main__":
    unittest.main()
