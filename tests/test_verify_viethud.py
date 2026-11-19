#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_verify_viethud.py — Unit test kiểm tra chữ ký và toàn vẹn VietHUD.
"""

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_REPO_DIR = Path(__file__).resolve().parent.parent
if str(_REPO_DIR) not in sys.path:
    sys.path.insert(0, str(_REPO_DIR))

import verify_viethud


class TestVerifyVietHUD(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.td = Path(self.temp_dir.name)

        # Chép reference/viethud/samples sang temp_dir
        self.samples_dir = _REPO_DIR.parent / "reference" / "viethud" / "samples"
        if not self.samples_dir.exists():
            env_dir = os.environ.get("VIETHUD_SAMPLES_DIR")
            self.samples_dir = Path(env_dir) if env_dir else self.samples_dir
        if not all((self.samples_dir / f).exists() for f in ["manifest.txt", "manifest.txt.sig", "cameras.bin", "signs.bin"]):
            self.temp_dir.cleanup()
            self.skipTest("Không có bộ mẫu VietHUD (reference/viethud/samples hoặc VIETHUD_SAMPLES_DIR)")

        for f in ["manifest.txt", "manifest.txt.sig", "cameras.bin", "signs.bin"]:
            shutil.copy(self.samples_dir / f, self.td / f)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_valid_signature_passes(self):
        """Chữ ký đúng và toàn vẹn file từ samples -> xác thực thành công."""
        ver = verify_viethud.verify_viethud(self.td)
        self.assertTrue(len(ver) > 0)
        self.assertNotEqual(ver, "?")

    def test_corrupted_byte_in_signs_bin_fails(self):
        """Sửa 1 byte trong signs.bin -> báo lỗi sai SHA256 hoặc kích thước."""
        signs_file = self.td / "signs.bin"
        data = bytearray(signs_file.read_bytes())
        data[100] = (data[100] + 1) % 256
        signs_file.write_bytes(data)

        with self.assertRaises(SystemExit) as ctx:
            verify_viethud.verify_viethud(self.td)
        self.assertIn("sai SHA256", str(ctx.exception))

    def test_corrupted_signature_fails(self):
        """Sửa chữ ký manifest.txt.sig -> báo lỗi chữ ký không hợp lệ."""
        sig_file = self.td / "manifest.txt.sig"
        sig_file.write_text("AAAA" + sig_file.read_text()[4:], encoding="utf-8")

        with self.assertRaises(SystemExit) as ctx:
            verify_viethud.verify_viethud(self.td)
        self.assertIn("manifest signature INVALID", str(ctx.exception))

    def test_missing_file_fails(self):
        """Thiếu cameras.bin -> báo lỗi không tồn tại."""
        (self.td / "cameras.bin").unlink()

        with self.assertRaises(SystemExit) as ctx:
            verify_viethud.verify_viethud(self.td)
        self.assertIn("không tồn tại", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
