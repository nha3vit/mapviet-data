# MapViet data pipeline — mạng đường OSM tự build hằng ngày

Mỗi ngày GitHub Actions tải bản OSM Việt Nam mới nhất (Geofabrik), build mạng đường bằng pipeline VietHUD (`synthesize_and_pack.py`, ghim phiên bản), tách đèn tín hiệu OSM thành `lights.bin`, nén `.gz`, ký `manifest.txt` và phát hành lên GitHub Releases. App MapViet tải gói này khi mở app có mạng (chỉ khi có phiên bản mới).

Đo thử trên máy Mac (OSM 2026-11-15): 8,85 triệu đoạn đường, 171 541 tile, 8 213 đèn tín hiệu; giải nén 289 MB, **tải về 117 MB**; build 4,4 phút, RAM đỉnh 7,4 GB → cần runner 16 GB RAM (repo **công khai** dùng `ubuntu-latest` miễn phí có 16 GB).

## Thiết lập (chủ dự án tự làm — có bước liên quan khoá bí mật)

1. Tạo repo **công khai** trên GitHub, ví dụ `mapviet-data` (dữ liệu OSM theo giấy phép ODbL, công khai là phù hợp).
2. Tạo cặp khoá ký (chạy trên máy của bạn, **không gửi khoá bí mật cho ai**):
   ```bash
   openssl ecparam -name prime256v1 -genkey -noout -out mapviet_signing_key.pem
   openssl ec -in mapviet_signing_key.pem -pubout -out mapviet_signing_pub.pem
   ```
   Cất `mapviet_signing_key.pem` an toàn (password manager). **Không** đưa vào git.
3. Thêm secret `MAPVIET_SIGNING_KEY` vào repo (Settings → Secrets and variables → Actions → New repository secret) với **toàn bộ nội dung** file `mapviet_signing_key.pem`.
4. Chép vào repo `mapviet-data`:
   - `data-pipeline/workflows/build-network.yml` → `.github/workflows/build-network.yml`
   - `data-pipeline/postprocess.py` → `postprocess.py` (gốc repo)
5. Vào tab **Actions** → `build-network` → **Run workflow** để chạy lần đầu (~10–15 phút).
6. Gửi cho Claude: tên tài khoản/tổ chức GitHub chứa repo và nội dung `mapviet_signing_pub.pem` (khoá **công khai**, an toàn để chia sẻ) → Claude cấu hình URL + public key vào app.

URL app sẽ dùng: `https://github.com/<owner>/mapviet-data/releases/latest/download/manifest.txt`

## Chạy thử cục bộ

```bash
python3 -m venv .venv && .venv/bin/pip install "osmium>=3.6,<5"
curl -fLO https://download.geofabrik.de/asia/vietnam-latest.osm.pbf
git clone https://github.com/nha3vit/VietHUD.git && cd VietHUD/tools/viethud-pipeline
VIETHUD_PIPELINE_HOME=/tmp/vh ../../../.venv/bin/python synthesize_and_pack.py \
  --pbf ../../../vietnam-latest.osm.pbf --out /tmp/net --region VN --custom-alerts /tmp/vh/empty
python3 ../../../data-pipeline/postprocess.py /tmp/net /tmp/release
```

Dữ liệu: © OpenStreetMap contributors (ODbL). Pipeline: VietHUD (dùng với sự đồng ý của tác giả).

## Gói cảnh báo (VietHUD + VietMap + WYN) — Chuẩn R6

Workflow `workflows/build-alerts.yml` (chép vào `mapviet-data/.github/workflows/`) chạy hằng ngày hoặc kích hoạt thủ công:
1. Tải `cameras.bin`/`signs.bin` VietHUD và kiểm chữ ký bằng `verify_viethud.py`.
2. Gộp VietHUD nền với VietMap (`sources/vietmap/secrect.bin` qua `vietmap_decode.py`) và WYN (`sources/wyn/wyn_points.csv`) bằng engine `alerts.py` chuẩn R6:
   - Ưu tiên nguồn: VietMap (P1) > WYN (P2) > Nền VietHUD (P3).
   - Bảo toàn 100% dữ liệu VietMap (nguyên tắc D2: giữ đủ 83.823 điểm, không sửa toạ độ, loại, tốc độ, hướng).
   - Xử lý triệt để lỗi phân loại WYN: loại bỏ 6.210 điểm WYN mã 2 ("báo hết đoạn đường") không có tốc độ gán nhãn 50 km/h sai lệch; xử lý đúng nhóm cấm vượt (P.125 / DP.135).
   - Bổ sung nhóm biển báo hướng đi và cấm dừng đỗ: Đoạn đường cấm dừng cấm đỗ (loại 22), Cấm rẽ trái (loại 23), Cấm rẽ phải (loại 24), Cấm quay đầu (loại 25), Hướng đi bắt buộc / Cấm đi thẳng (loại 26).
   - Lọc nhiễu không gian: bán kính 30 m (camera), 45 m (đèn tín hiệu), 20 m (biển khác).
   - Không có biển loại 4 trong signs.bin.
   - Nhận diện và quy chuẩn heading giả, kế thừa thuộc tính hợp lệ.
3. Ký `manifest.txt` bằng khoá MapViet qua `sign_manifest.py` (tạo `manifest.txt.sig`).
4. Kiểm định nghiêm ngặt bằng `validate_speedmap.py --alerts-only` và `validate_alerts.py` trước khi phát hành.
5. Phát hành ở release cố định `alerts` (không đánh dấu `latest`, không chạm đến release `latest` của mạng đường).

App tải từ: `https://github.com/nha3vit/mapviet-data/releases/download/alerts/manifest.txt`

Chạy test cảnh báo:
```bash
python3 -m unittest discover -s tests -v
```

Bản quyền dữ liệu: VietMap © VietMap; dữ liệu WYN — cảm ơn WYN; speedmap nền từ VietHUD.
