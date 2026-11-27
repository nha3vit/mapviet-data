#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fetch_vietmap.py — Tự động kiểm tra, tải và cắt gọn dữ liệu cảnh báo VietMap SpeedMap M2 hàng tháng.

Quy trình:
1. Thăm dò các phiên bản tiềm năng (tháng trước, tháng này, tháng sau) tại https://download.vietmap.vn/dvr/ bằng HEAD request.
2. So sánh ETag, Last-Modified, zip_size với sources/vietmap/vietmap_manifest.json.
3. Nếu có cập nhật mới (hoặc --force):
   - Tải file zip về bộ nhớ tạm
   - Tính SHA-256 của file zip
   - Giải nén secrect.bin
   - Cắt giữ đúng bảng mục lục 512 bytes + phân vùng edogen.bin (loại bỏ roadsenz.bin để bảo vệ repo)
   - Kiểm định bằng vietmap_decode.py (chặn nếu số điểm giảm > 5% hoặc undecodable > 10)
   - Ghi secrect.bin và vietmap_manifest.json vào thư mục đích (mặc định sources/vietmap)
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import struct
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Optional

try:
    from tools import vietmap_decode as vmd
except ImportError:
    import vietmap_decode as vmd

VIETMAP_DVR_BASE_URL = "https://download.vietmap.vn/dvr"
USER_AGENT = "MapViet-Data-Updater/1.0"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def get_candidate_versions(dt: Optional[datetime.datetime] = None) -> list[str]:
    """
    Tính danh sách các phiên bản tiềm năng theo thứ tự thời gian tăng dần:
    [tháng trước, tháng hiện tại, tháng kế tiếp].
    Ví dụ tháng 11/2026 -> ['2026T10', '2026T11', '2026T12'].
    """
    if dt is None:
        dt = datetime.datetime.now(datetime.timezone.utc)

    cur_year = dt.year
    cur_month = dt.month

    # Tháng trước
    if cur_month == 1:
        prev_year = cur_year - 1
        prev_month = 12
    else:
        prev_year = cur_year
        prev_month = cur_month - 1

    # Tháng kế tiếp
    if cur_month == 12:
        next_year = cur_year + 1
        next_month = 1
    else:
        next_year = cur_year
        next_month = cur_month + 1

    return [
        f"{prev_year}T{prev_month:02d}",
        f"{cur_year}T{cur_month:02d}",
        f"{next_year}T{next_month:02d}",
    ]


def check_remote_version(version: str, opener: Any = None) -> Optional[dict[str, Any]]:
    """Gửi HEAD request kiểm tra phiên bản trên máy chủ VietMap DVR."""
    filename = f"VietMap_SpeedMap_M2_{version}.zip"
    url = f"{VIETMAP_DVR_BASE_URL}/{filename}"

    req = urllib.request.Request(url, method="HEAD")
    req.add_header("User-Agent", USER_AGENT)

    _open = opener.open if opener is not None else urllib.request.urlopen

    try:
        with _open(req, timeout=15) as resp:
            if resp.status == 200:
                headers = resp.headers
                last_modified = headers.get("Last-Modified", "")
                etag = headers.get("ETag", "").strip('"')
                content_len = int(headers.get("Content-Length", 0))
                return {
                    "version": version,
                    "filename": filename,
                    "url": url,
                    "last_modified": last_modified,
                    "etag": etag,
                    "zip_size": content_len,
                }
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, Exception):
        return None
    return None


def find_latest_remote_version(
    candidates: Optional[list[str]] = None, opener: Any = None
) -> Optional[dict[str, Any]]:
    """Thăm dò danh sách candidates theo thứ tự từ mới nhất đến cũ hơn, trả về bản mới nhất có mã 200 OK."""
    if candidates is None:
        candidates = get_candidate_versions()

    # Duyệt ngược từ tương lai/mới nhất về trước
    for v in reversed(candidates):
        info = check_remote_version(v, opener=opener)
        if info is not None:
            return info
    return None


def slice_secrect_bin(raw_secrect_bytes: bytes) -> bytes:
    """
    Cắt giữ mục lục 512 bytes + phân vùng edogen.bin từ secrect.bin thô.
    Loại bỏ hoàn toàn các phân vùng phía sau (roadsenz.bin > 100MB).
    """
    if len(raw_secrect_bytes) < 512:
        raise ValueError(f"Dữ liệu secrect.bin quá ngắn: {len(raw_secrect_bytes)} bytes < 512 bytes")

    if not (raw_secrect_bytes.startswith(b"secrect.bin") or b"edogen.bin" in raw_secrect_bytes[:512]):
        raise ValueError("Định dạng secrect.bin không hợp lệ: thiếu bảng mục lục (TOC)")

    toc: dict[str, int] = {}
    for i in range(0, 512, 68):
        chunk = raw_secrect_bytes[i : i + 68]
        if len(chunk) < 68:
            break
        name = chunk[:64].rstrip(b"\x00").decode("latin1", errors="ignore").strip()
        if name:
            size = struct.unpack("<I", chunk[64:68])[0]
            toc[name] = size

    edogen_size = toc.get("edogen.bin")
    if not edogen_size:
        raise ValueError("Không tìm thấy phân vùng edogen.bin trong bảng mục lục TOC của secrect.bin")

    total_cut = 512 + edogen_size
    if len(raw_secrect_bytes) < total_cut:
        raise ValueError(
            f"secrect.bin không đủ kích thước cho edogen.bin: {len(raw_secrect_bytes)} < {total_cut}"
        )

    return raw_secrect_bytes[:total_cut]


def validate_decoded_points(
    sliced_bytes: bytes,
    prev_point_count: Optional[int] = None,
    default_version: str = "Unknown",
) -> tuple[int, dict[str, Any]]:
    """
    Giải mã bằng vietmap_decode.py và kiểm định chất lượng:
    - Báo lỗi nếu undecodable > 10
    - Báo lỗi nếu tổng số điểm giảm > 5% so với bản trước
    """
    res = vmd.decode_bytes(sliced_bytes, default_version=default_version)
    undecodable = res.skipped.get("undecodable", 0)
    if undecodable > 10:
        raise ValueError(f"Số dòng không thể giải mã quá lớn ({undecodable} > 10)")

    point_count = len(res.points)
    if point_count == 0:
        raise ValueError("Giải mã không được điểm cảnh báo nào!")

    if prev_point_count is not None and prev_point_count > 0:
        min_allowed = int(prev_point_count * 0.95)
        if point_count < min_allowed:
            raise ValueError(
                f"Số điểm VietMap sụt giảm > 5%: {point_count} < {min_allowed} (bản trước: {prev_point_count})"
            )

    return point_count, res.skipped


def load_manifest(manifest_path: Path) -> Optional[dict[str, Any]]:
    if manifest_path.exists():
        try:
            return json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def save_manifest(manifest_path: Path, data: dict[str, Any]) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def process_download(
    remote_info: dict[str, Any],
    dest_dir: Path,
    prev_manifest: Optional[dict[str, Any]] = None,
    opener: Any = None,
) -> dict[str, Any]:
    """Tải zip, giải nén secrect.bin, cắt edogen, kiểm định và lưu manifest."""
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    url = remote_info["url"]

    print(f"[*] Đang tải {remote_info['filename']} từ {url} ({remote_info['zip_size']:,} bytes)...")

    _open = opener.open if opener is not None else urllib.request.urlopen

    with tempfile.TemporaryDirectory() as tmp_dir:
        zip_tmp_path = Path(tmp_dir) / remote_info["filename"]
        req = urllib.request.Request(url)
        req.add_header("User-Agent", USER_AGENT)

        with _open(req, timeout=300) as resp, open(zip_tmp_path, "wb") as out_f:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                out_f.write(chunk)

        zip_sha256 = sha256_file(zip_tmp_path)
        print(f"    [✓] Đã tải xong zip: SHA-256 = {zip_sha256}")

        # Giải nén secrect.bin từ zip
        with zipfile.ZipFile(zip_tmp_path, "r") as zf:
            secrect_names = [n for n in zf.namelist() if n.lower().endswith("secrect.bin")]
            if not secrect_names:
                raise ValueError("Không tìm thấy tệp secrect.bin trong file nén ZIP!")
            raw_secrect_bytes = zf.read(secrect_names[0])

        full_secrect_size = len(raw_secrect_bytes)
        print(f"    - secrect.bin gốc: {full_secrect_size:,} bytes")

        # Cắt giữ 512 bytes mục lục + edogen.bin
        sliced_secrect = slice_secrect_bin(raw_secrect_bytes)
        sliced_size = len(sliced_secrect)
        sliced_sha256 = sha256_bytes(sliced_secrect)
        print(f"    [✓] Đã cắt giữ 512B TOC + edogen.bin: {sliced_size:,} bytes (SHA-256 = {sliced_sha256})")

        # Kiểm định giải mã
        prev_points = (prev_manifest or {}).get("points_count")
        points_count, skipped_stats = validate_decoded_points(
            sliced_secrect, prev_point_count=prev_points, default_version=remote_info["version"]
        )
        print(f"    [✓] Giải mã thành công {points_count:,} điểm VietMap (undecodable={skipped_stats.get('undecodable', 0)})")

        # Ghi secrect.bin vào thư mục đích
        secrect_dest = dest_dir / "secrect.bin"
        secrect_dest.write_bytes(sliced_secrect)

        # Ghi manifest
        new_manifest = {
            "version": remote_info["version"],
            "description": remote_info["filename"],
            "download_url": remote_info["url"],
            "etag": remote_info["etag"],
            "last_modified": remote_info["last_modified"],
            "zip_size": remote_info["zip_size"],
            "zip_sha256": zip_sha256,
            "secrect_bin_size": sliced_size,
            "secrect_bin_sha256": sliced_sha256,
            "points_count": points_count,
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

        save_manifest(dest_dir / "vietmap_manifest.json", new_manifest)
        print(f"[✓] Đã ghi {secrect_dest} và {dest_dir / 'vietmap_manifest.json'}")
        return new_manifest


def main():
    parser = argparse.ArgumentParser(description="Tự động kiểm tra và cập nhật dữ liệu VietMap SpeedMap M2.")
    parser.add_argument("--dest-dir", type=Path, default=Path("sources/vietmap"),
                        help="Thư mục lưu trữ secrect.bin và vietmap_manifest.json")
    parser.add_argument("--force", action="store_true",
                        help="Bắt buộc tải lại ngay cả khi manifest không thay đổi")
    parser.add_argument("--check-only", action="store_true",
                        help="Chỉ kiểm tra phiên bản mới trên máy chủ, không tải")
    parser.add_argument("--input-secrect", type=Path, default=None,
                        help="File secrect.bin có sẵn trên máy để cắt thử nghiệm cục bộ")

    args = parser.parse_args()

    # Chế độ cắt thử nghiệm cục bộ từ file có sẵn
    if args.input_secrect:
        if not args.input_secrect.exists():
            raise SystemExit(f"Không tìm thấy input secrect: {args.input_secrect}")
        raw = args.input_secrect.read_bytes()
        sliced = slice_secrect_bin(raw)
        out_p = args.dest_dir / "secrect.bin"
        args.dest_dir.mkdir(parents=True, exist_ok=True)
        out_p.write_bytes(sliced)
        print(f"Đã cắt file cục bộ: {len(raw):,} -> {len(sliced):,} bytes ({out_p})")
        pts_count, _ = validate_decoded_points(sliced)
        print(f"Giải mã: {pts_count:,} điểm")
        return

    # Thăm dò phiên bản mới nhất
    latest_remote = find_latest_remote_version()
    if not latest_remote:
        print("[!] Không tìm thấy phiên bản VietMap SpeedMap M2 nào trên máy chủ!")
        if "GITHUB_OUTPUT" in os.environ:
            with open(os.environ["GITHUB_OUTPUT"], "a") as gh_out:
                gh_out.write("updated=false\n")
        return

    print(f"[*] Phiên bản mới nhất trên máy chủ: {latest_remote['version']} ({latest_remote['filename']})")
    print(f"    - URL: {latest_remote['url']}")
    print(f"    - Last-Modified: {latest_remote['last_modified']}")
    print(f"    - ETag: {latest_remote['etag']}")
    print(f"    - Zip size: {latest_remote['zip_size']:,} bytes")

    if args.check_only:
        return

    # So sánh với manifest hiện có
    manifest_path = args.dest_dir / "vietmap_manifest.json"
    current_manifest = load_manifest(manifest_path)

    need_update = args.force
    if not need_update:
        if not current_manifest:
            need_update = True
            print("[*] Chưa có manifest tại local, cần tải cập nhật.")
        elif current_manifest.get("version") != latest_remote["version"]:
            need_update = True
            print(f"[*] Phiên bản mới ({latest_remote['version']} != {current_manifest.get('version')}), cần cập nhật.")
        elif current_manifest.get("etag") != latest_remote["etag"]:
            need_update = True
            print("[*] ETag thay đổi, cần cập nhật.")
        elif current_manifest.get("last_modified") != latest_remote["last_modified"]:
            need_update = True
            print("[*] Last-Modified thay đổi, cần cập nhật.")
        elif current_manifest.get("zip_size") != latest_remote["zip_size"]:
            need_update = True
            print("[*] Kích thước file nén thay đổi, cần cập nhật.")

    if not need_update:
        print("[✓] Dữ liệu VietMap hiện tại đã là mới nhất. Không cần cập nhật.")
        if "GITHUB_OUTPUT" in os.environ:
            with open(os.environ["GITHUB_OUTPUT"], "a") as gh_out:
                gh_out.write("updated=false\n")
                gh_out.write(f"version={latest_remote['version']}\n")
        return

    # Thực hiện tải, cắt và kiểm định
    new_m = process_download(
        remote_info=latest_remote,
        dest_dir=args.dest_dir,
        prev_manifest=current_manifest,
    )

    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as gh_out:
            gh_out.write("updated=true\n")
            gh_out.write(f"version={new_m['version']}\n")


if __name__ == "__main__":
    main()
