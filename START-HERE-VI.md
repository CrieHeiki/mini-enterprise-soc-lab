# Bắt đầu từ đây — Ubuntu -> GitHub

Đây là **bộ khung repository**, không chứa mã nguồn và cấu hình đang chạy trong Ubuntu. Hãy sao chép các file thật từ `/opt/soclab/` và `~/SOC-Lab/`, kiểm tra an toàn, rồi commit lên GitHub.

## Thứ tự
1. Giải nén `mini-enterprise-soc-lab-starter.zip` tại thư mục Home.
2. Sao chép đúng 5 file `.py` hiện đang triển khai vào `detection-engineering/src/`.
3. Sao chép các file `.md` của CASE-001, CASE-002 và incident-response; KHÔNG sao chép `evidence/*.jsonl`.
4. Xem lại Wazuh rules và systemd units để chọn bản công khai an toàn; không sao chép nguyên cây `/var/ossec/`.
5. Kiểm tra nội dung README, phiên bản, bằng chứng, mã nguồn và screenshot.
6. Chạy `python3 scripts/check_publish_ready.py`. Đây chỉ là một bước kiểm tra cơ bản; phải tự rà soát bảo mật.
7. Cài Git, thiết lập định danh commit và SSH public key, tạo GitHub repository trống, `git init`, `git add` có chọn lọc, `git commit`, `git push`.

**Bảo toàn lab đang hoạt động:** Chỉ sao chép file vào repo; không sửa hoặc restart các script live để chuẩn bị GitHub.
