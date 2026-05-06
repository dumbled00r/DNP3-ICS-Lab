# ICS Lab: Modbus & DNP3 Security Testbed

Lab này cung cấp một môi trường thử nghiệm **chỉ chạy cục bộ (local-only)** để nghiên cứu các giao thức **ICS (industrial control system)** và các kịch bản tấn công an ninh:

- Modbus TCP client/server với lưu lượng bình thường và các kịch bản tấn công: **DoS, chèn lệnh (command injection), trinh sát/nghe lén (reconnaissance)**.
- DNP3 master/outstation (mô phỏng bằng JSON‑over‑TCP) với các kịch bản **giả mạo master, sửa đổi dữ liệu qua proxy, replay frame**.

Mã nguồn chỉ được dùng cho **mục đích học tập và nghiên cứu trong môi trường kiểm soát**. **Không** sử dụng chống lại hệ thống thật/production.

## Bố cục dự án

- `modbus/` – Mô phỏng Modbus TCP và tấn công.
  - `server.py` – Modbus TCP server, lưu bảng holding register (giả lập cảm biến) và định kỳ thay đổi giá trị.
  - `client.py` – Modbus TCP client, định kỳ đọc/ghi register để tạo lưu lượng “bình thường”.
  - `attacks/`
    - `dos.py` – Tấn công DoS bằng **flood kết nối TCP** hoặc **flood request Modbus**.
    - `command_injection.py` – Tấn công **chèn lệnh**, ghi giá trị độc hại vào các holding register quan trọng.
    - `sniff_recon.py` – Script **trinh sát/nghe lén** thụ động dùng Scapy, quan sát gói Modbus TCP.
- `dnp3/` – Mô phỏng DNP3 kiểu đơn giản (frame JSON qua TCP) và tấn công.
  - `outstation.py` – Outstation giữ bảng điểm (point table) đơn giản.
  - `master.py` – Master định kỳ gửi yêu cầu READ/WRITE tới outstation.
  - `attacks/`
    - `master_spoof.py` – **Giả mạo master**, gửi lệnh WRITE trái phép tới outstation.
    - `data_modification.py` – **Proxy man‑in‑the‑middle** đứng giữa master và outstation, sửa nội dung frame.
    - `replay_attack.py` – Ghi lại frame hợp lệ và **phát lại (replay)**.
- `config/` – Cấu hình địa chỉ/port cho client/server (hỗ trợ nhiều máy).
- `scripts/` – Script chạy kịch bản end‑to‑end (Modbus và DNP3).

Xem thêm file kế hoạch chi tiết trong `.cursor/plans/` nếu cần.

## Yêu cầu môi trường

- Python 3.10+.
- Cài đặt thư viện từ `requirements.txt`:

```bash
pip install -r requirements.txt
```

## Cấu hình (multi-machine)

Thông tin địa chỉ mạng cho các thành phần (server, client, proxy, outstation, master,…) được đặt trong thư mục `config/`:

- `config/modbus.json`
- `config/dnp3.json`

Bạn có thể chỉnh `host` và `port` để thử nghiệm trên nhiều máy (miễn vẫn nằm trong lab/VM an toàn).

---

## Chi tiết các kịch bản tấn công Modbus

### 1. DoS – Từ chối dịch vụ Modbus (`modbus/attacks/dos.py`)

- **Mục tiêu**: Làm cho Modbus server bị quá tải, phản hồi chậm hoặc không trả lời client hợp lệ.
- **Ý tưởng**:
  - Flood **kết nối TCP**: liên tục mở/đóng rất nhiều kết nối tới cổng Modbus.
  - Flood **request Modbus**: trên một (hoặc vài) kết nối, gửi request đọc register với tần suất rất cao.
- **Đặc điểm chính**:
  - Sử dụng `pymodbus.ModbusTcpClient` để tạo kết nối và gửi request.
  - Chạy đa luồng để tăng tải (tham số `--threads`).
  - Có thể giới hạn thời gian bằng `--duration` hoặc chạy vô hạn tới khi `Ctrl+C`.
- **Tham số dòng lệnh tiêu biểu**:

```bash
cd ics_lab
# Flood cả TCP và Modbus request trong 20 giây, 5 luồng (qua script kịch bản)
python scripts/run_modbus_scenario.py --attacks dos

# Hoặc chạy trực tiếp attacker:
python modbus/attacks/dos.py --host 127.0.0.1 --port 5020 --mode both --duration 20 --threads 5
```

- **Triển khai trong lab**:
  1. Chạy `modbus/server.py` và `modbus/client.py` (hoặc dùng `scripts/run_modbus_scenario.py`).
  2. Khởi chạy `dos.py` để flood.
  3. Quan sát log server/client: client bắt đầu timeout, lỗi kết nối, hoặc giá trị không được cập nhật đều.

### 2. Chèn lệnh – Command Injection (`modbus/attacks/command_injection.py`)

- **Mục tiêu**: Ghi các giá trị bất thường vào vùng register quan trọng (ví dụ vượt ngưỡng cảnh báo, tắt/bật coil điều khiển) mà không cần chiếm quyền trên server.
- **Ý tưởng**:
  - Attacker **sử dụng đúng giao thức Modbus**, nhưng:
    - Chọn **địa chỉ register nhạy cảm** (ví dụ 0,1,2…).
    - Ghi các **giá trị nằm ngoài biên an toàn** (ví dụ 5000–10000 thay vì 0–1000).
- **Đặc điểm chính**:
  - Cho phép chỉ định danh sách địa chỉ (`--addresses`) và khoảng giá trị độc hại (`--min-value`, `--max-value`).
  - Lặp lại nhiều lần (`--iterations`; 0 = lặp rất lâu đến khi dừng tay).
  - Log ở mức `WARNING` để dễ thấy các ghi “malicious write”.
- **Tham số dòng lệnh tiêu biểu**:

```bash
cd ics_lab
# Chạy qua scenario script: sẽ tự kích hoạt command injection khi chọn tấn công tương ứng
python scripts/run_modbus_scenario.py --attacks cmd

# Hoặc chạy trực tiếp attacker:
python modbus/attacks/command_injection.py \
  --host 127.0.0.1 --port 5020 \
  --addresses 0 1 2 \
  --min-value 5000 --max-value 10000 \
  --iterations 0
```

- **Triển khai trong lab**:
  1. Khởi động server & client.
  2. Bật script command injection.
  3. Quan sát log client: các giá trị register đột ngột nhảy lên rất cao/bất thường, mô phỏng tình huống bị attacker điều khiển từ xa.

### 3. Trinh sát / Nghe lén – Reconnaissance (`modbus/attacks/sniff_recon.py`)

- **Mục tiêu**: Minh họa việc một attacker có thể **quan sát lưu lượng Modbus** để:
  - Xác định **địa chỉ register** được đọc/ghi thường xuyên.
  - Nhìn thấy **tần suất truy vấn**, từ đó lập “bản đồ” hệ thống trước khi tấn công sâu hơn.
- **Ý tưởng**:
  - Sử dụng **Scapy** để sniff gói TCP trên cổng Modbus (mặc định 5020).
  - Mỗi gói tin được log: địa chỉ IP nguồn/đích, cổng, độ dài payload, v.v.
- **Đặc điểm chính**:
  - Chạy thụ động, không can thiệp lưu lượng.
  - Có thể cần quyền `sudo` để sniff trên một số hệ thống.
  - Tham số `--count` để giới hạn số gói bắt (0 = chạy tới khi `Ctrl+C`).
- **Triển khai trong lab**:

```bash
cd ics_lab
sudo python modbus/attacks/sniff_recon.py --iface lo --port 5020 --count 100
```

- **Quan sát**:
  - Mặc dù không decode toàn bộ cấu trúc Modbus, attacker đã biết:
    - Ai đang nói chuyện với ai (IP/port).
    - Mức độ, tần suất truy vấn.
  - Đây là bước tiền đề để lập kế hoạch DoS/command injection chính xác hơn.

---

## Chi tiết các kịch bản tấn công DNP3

DNP3 trong lab này **không** tuân chuẩn bit‑level đầy đủ mà dùng frame JSON đơn giản qua TCP để dễ nhìn log và tập trung vào khía cạnh bảo mật.

### 1. Giả mạo master – Spoofed Master (`dnp3/attacks/master_spoof.py`)

- **Mục tiêu**: Cho thấy rằng nếu **không có cơ chế xác thực**, outstation không thể phân biệt master hợp pháp với master giả.
- **Ý tưởng**:
  - Script spoofed master kết nối trực tiếp tới outstation (cổng mặc định 20000).
  - Gửi các frame JSON dạng WRITE/COMMAND tới các điểm dữ liệu (point) giống như master thật.
- **Đặc điểm chính**:
  - Chia sẻ cùng giao thức JSON với master thật nên rất khó phân biệt nếu chỉ nhìn ở cấp độ ứng dụng.
  - Có thể chạy song song với master bình thường, tạo “lệnh chồng lấn”.
- **Triển khai**:

```bash
cd ics_lab
python scripts/run_dnp3_scenario.py --attacks spoof
```

- **Quan sát**:
  - Log của outstation sẽ ghi nhận lệnh từ master giả như lệnh bình thường.
  - Giá trị điểm dữ liệu có thể thay đổi ngoài ý muốn của master hợp pháp.

### 2. Sửa đổi dữ liệu qua proxy – Man‑in‑the‑middle (`dnp3/attacks/data_modification.py`)

- **Mục tiêu**: Minh họa tấn công **MITM**: attacker đứng giữa master và outstation, sửa đổi nội dung frame trên đường đi.
- **Ý tưởng**:
  - Proxy lắng nghe trên một cổng trung gian (ví dụ 21000).
  - Master kết nối tới proxy, proxy kết nối tới outstation:
    - Master ↔ Proxy (`21000`) ↔ Outstation (`20000`).
  - Khi nhận frame từ master, proxy:
    - Ghi log frame gốc.
    - Thay đổi các trường như `value`, `status`, `timestamp`,…
    - Forward frame đã sửa tới outstation.
- **Đặc điểm chính**:
  - Có thể áp dụng nhiều chính sách sửa: ép giá trị về một ngưỡng, đảo bit, thay đổi trạng thái alarm, v.v.
  - Log song song cả frame gốc và frame đã chỉnh sửa để dễ so sánh.
- **Triển khai**:

```bash
cd ics_lab
python scripts/run_dnp3_scenario.py --attacks proxy
```

- **Quan sát**:
  - Master tin rằng giá trị đang là A (do nó gửi/nhận lại), trong khi outstation thực sự nhận B.
  - Minh họa rủi ro khi kênh truyền không được bảo vệ bởi MAC/chữ ký số.

### 3. Replay attack – Ghi lại và phát lại frame (`dnp3/attacks/replay_attack.py`)

- **Mục tiêu**: Cho thấy nếu **không có cơ chế chống replay** (sequence number, timestamp, MAC,…), outstation có thể chấp nhận lại các frame cũ.
- **Ý tưởng**:
  - Giai đoạn 1 – **record**:
    - Lắng nghe một thời gian ngắn, ghi lại các frame JSON hợp lệ vào file log (ví dụ `dnp3_frames.log`).
  - Giai đoạn 2 – **replay**:
    - Ngắt kết nối master thật.
    - Phát lại toàn bộ frame trong file về outstation như thể là lưu lượng mới.
- **Đặc điểm chính**:
  - Dùng cùng script `replay_attack.py` với sub‑command `record` hoặc `replay`.
  - Thời gian ghi, tên file log, host/port đều cấu hình được qua tham số dòng lệnh.
- **Triển khai (qua scenario script)**:

```bash
cd ics_lab
python scripts/run_dnp3_scenario.py --attacks replay
```

Hoặc xem chi tiết hơn bằng cách chạy trực tiếp:

```bash
# Giai đoạn record
python dnp3/attacks/replay_attack.py record \
  --host 127.0.0.1 --port 20000 \
  --duration 5 --output dnp3_frames.log

# Giai đoạn replay
python dnp3/attacks/replay_attack.py replay \
  --host 127.0.0.1 --port 20000 \
  --input dnp3_frames.log
```

- **Quan sát**:
  - Outstation tiếp tục nhận các trạng thái “hợp lệ” nhưng thực chất đã cũ.
  - Nếu ứng dụng trên SCADA/HMI không kiểm tra timestamp/seq, người vận hành sẽ nghĩ hệ thống vẫn đang ở trạng thái ổn định trong khi thực tế có thể đã thay đổi.

---

## Gợi ý chạy nhanh các kịch bản

### Modbus

- Chạy full kịch bản (server + client + tất cả tấn công):

```bash
cd ics_lab
python scripts/run_modbus_scenario.py             # mặc định --attacks all
```

- Chỉ chọn một/một vài kiểu tấn công:

```bash
python scripts/run_modbus_scenario.py --attacks dos
python scripts/run_modbus_scenario.py --attacks cmd
python scripts/run_modbus_scenario.py --attacks sniff
python scripts/run_modbus_scenario.py --attacks dos cmd
```

### DNP3

- Chạy full kịch bản (spoof + proxy + replay):

```bash
cd ics_lab
python scripts/run_dnp3_scenario.py              # mặc định --attacks all
```

- Chỉ chạy từng loại tấn công:

```bash
python scripts/run_dnp3_scenario.py --attacks spoof
python scripts/run_dnp3_scenario.py --attacks proxy
python scripts/run_dnp3_scenario.py --attacks replay
python scripts/run_dnp3_scenario.py --attacks spoof replay
```

## Ghi chú an toàn

- Tất cả ví dụ chỉ nên dùng trên **localhost hoặc mạng lab cô lập**.
- Không nhắm vào hệ thống production hoặc bên thứ ba.
- Tấn công DoS và flood có thể làm dịch vụ không phản hồi; luôn chuẩn bị dừng script bằng `Ctrl+C` khi cần.

