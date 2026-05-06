import argparse
import json
import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Any, Optional


DEFAULT_CONFIG_PATH = "../config/dnp3.json"
BUFFER_SIZE = 4096


@dataclass
class DNP3Point:
    point_id: int
    value: Any
    timestamp: float = field(default_factory=time.time)


class DNP3Outstation:
    """
    Simple TCP-based DNP3-style outstation.

    Frames are JSON lines with fields:
      - type: "READ" | "WRITE"
      - point_id: int
      - value: any (for WRITE)
      - seq: int
      - timestamp: float (client send time)
    """

    def __init__(self, host: str, port: int, logger: logging.Logger) -> None:
        self.host = host
        self.port = port
        self.logger = logger
        self.points: Dict[int, DNP3Point] = {}
        # Initialize a few example points
        for pid in range(5):
            self.points[pid] = DNP3Point(point_id=pid, value=0)
        self._stop_event = threading.Event()

    def start(self) -> None:
        self.logger.info("Starting DNP3 outstation on %s:%d", self.host, self.port)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((self.host, self.port))
            server_sock.listen(5)
            server_sock.settimeout(1.0)

            while not self._stop_event.is_set():
                try:
                    client_sock, addr = server_sock.accept()
                except socket.timeout:
                    continue
                self.logger.info("Accepted connection from %s:%d", *addr)
                threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, addr),
                    daemon=True,
                ).start()

    def stop(self) -> None:
        self._stop_event.set()

    def _handle_client(self, client_sock: socket.socket, addr: Any) -> None:
        with client_sock:
            buf = b""
            while not self._stop_event.is_set():
                try:
                    data = client_sock.recv(BUFFER_SIZE)
                    if not data:
                        self.logger.info("Connection closed by %s:%d", *addr)
                        break
                    buf += data
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        if not line.strip():
                            continue
                        self._process_frame(line.decode("utf-8"), client_sock)
                except ConnectionResetError:
                    self.logger.warning("Connection reset by %s:%d", *addr)
                    break
                except Exception as exc:
                    self.logger.exception("Error in client handler: %s", exc)
                    break

    def _process_frame(self, raw: str, client_sock: socket.socket) -> None:
        try:
            frame = json.loads(raw)
        except json.JSONDecodeError:
            self.logger.warning("Received invalid JSON frame: %s", raw)
            return

        ftype = frame.get("type")
        seq = frame.get("seq")
        point_id = frame.get("point_id")

        if ftype == "READ":
            self.logger.info(
                "[MASTER->OUTSTATION] READ seq=%s point_id=%s", seq, point_id
            )
            point = self.points.get(point_id)
            if point is None:
                resp = self._build_error(seq, "POINT_NOT_FOUND")
            else:
                resp = {
                    "type": "READ_RESPONSE",
                    "seq": seq,
                    "point_id": point.point_id,
                    "value": point.value,
                    "timestamp": point.timestamp,
                    "outstation_time": time.time(),
                    "status": "OK",
                }
        elif ftype == "WRITE":
            new_value = frame.get("value")
            self.logger.info(
                "[MASTER->OUTSTATION] WRITE seq=%s point_id=%s value=%s",
                seq,
                point_id,
                new_value,
            )
            point = self.points.get(point_id)
            if point is None:
                resp = self._build_error(seq, "POINT_NOT_FOUND")
            else:
                point.value = new_value
                point.timestamp = time.time()
                resp = {
                    "type": "WRITE_RESPONSE",
                    "seq": seq,
                    "point_id": point.point_id,
                    "value": point.value,
                    "timestamp": point.timestamp,
                    "outstation_time": time.time(),
                    "status": "OK",
                }
        else:
            self.logger.warning("Received unknown frame type: %s", ftype)
            resp = self._build_error(seq, "UNKNOWN_TYPE")

        self._send_frame(resp, client_sock)

    def _build_error(self, seq: Optional[int], code: str) -> Dict[str, Any]:
        return {
            "type": "ERROR",
            "seq": seq,
            "code": code,
            "outstation_time": time.time(),
        }

    def _send_frame(self, frame: Dict[str, Any], client_sock: socket.socket) -> None:
        raw = json.dumps(frame).encode("utf-8") + b"\n"
        client_sock.sendall(raw)
        self.logger.info("[OUTSTATION->MASTER] %s", frame)


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def configure_logging(verbose: bool = False) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [OUTSTATION] %(levelname)s: %(message)s",
    )
    return logging.getLogger("dnp3_outstation")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simple TCP-based DNP3-style outstation",
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help="Path to DNP3 JSON config (default: %(default)s)",
    )
    parser.add_argument(
        "--host",
        help="Override outstation host (otherwise taken from config)",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Override outstation port (otherwise taken from config)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    logger = configure_logging(verbose=args.verbose)
    cfg = load_config(args.config)
    out_cfg = cfg.get("outstation", {})
    host = args.host or out_cfg.get("host", "127.0.0.1")
    port = args.port or int(out_cfg.get("port", 20000))

    outstation = DNP3Outstation(host=host, port=port, logger=logger)
    try:
        outstation.start()
    except KeyboardInterrupt:
        logger.info("Stopping outstation (KeyboardInterrupt)")
    finally:
        outstation.stop()


if __name__ == "__main__":
    main()

