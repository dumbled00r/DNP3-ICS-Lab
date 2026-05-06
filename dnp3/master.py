import argparse
import json
import logging
import socket
import time
from typing import Any, Dict, Optional


DEFAULT_CONFIG_PATH = "../config/dnp3.json"
BUFFER_SIZE = 4096


class DNP3Master:
    """
    Simple TCP-based DNP3-style master.

    Sends JSON line frames with fields:
      - type: "READ" | "WRITE"
      - point_id: int
      - value: any (for WRITE)
      - seq: int
      - timestamp: float (master send time)
    """

    def __init__(
        self,
        host: str,
        port: int,
        poll_interval: float,
        logger: logging.Logger,
    ) -> None:
        self.host = host
        self.port = port
        self.poll_interval = poll_interval
        self.logger = logger
        self.seq = 0

    def run(self) -> None:
        self.logger.info(
            "Starting DNP3 master, connecting to %s:%d (poll_interval=%.2fs)",
            self.host,
            self.port,
            self.poll_interval,
        )
        while True:
            try:
                with socket.create_connection((self.host, self.port), timeout=5.0) as sock:
                    self.logger.info("Connected to outstation")
                    self._session_loop(sock)
            except (ConnectionRefusedError, TimeoutError, OSError) as exc:
                self.logger.warning("Connection failed: %s; retrying in 2s", exc)
                time.sleep(2.0)
            except KeyboardInterrupt:
                self.logger.info("Master interrupted by user, exiting")
                break

    def _session_loop(self, sock: socket.socket) -> None:
        sock.settimeout(5.0)
        buf = b""
        last_poll = 0.0

        while True:
            now = time.time()
            if now - last_poll >= self.poll_interval:
                # Simple demo: alternate between READ of point 0 and WRITE to point 1
                if (self.seq % 2) == 0:
                    self._send_read(sock, point_id=0)
                else:
                    new_value = int(now) % 100
                    self._send_write(sock, point_id=1, value=new_value)
                last_poll = now

            try:
                data = sock.recv(BUFFER_SIZE)
                if not data:
                    self.logger.info("Outstation closed connection")
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    self._handle_frame(line.decode("utf-8"))
            except socket.timeout:
                continue
            except ConnectionResetError:
                self.logger.warning("Connection reset by outstation")
                break
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                self.logger.exception("Error in master session: %s", exc)
                break

    def _next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def _send_read(self, sock: socket.socket, point_id: int) -> None:
        frame = {
            "type": "READ",
            "point_id": point_id,
            "seq": self._next_seq(),
            "timestamp": time.time(),
        }
        self._send_frame(sock, frame)
        self.logger.info("[MASTER->OUTSTATION] READ seq=%s point_id=%s", frame["seq"], point_id)

    def _send_write(self, sock: socket.socket, point_id: int, value: Any) -> None:
        frame = {
            "type": "WRITE",
            "point_id": point_id,
            "value": value,
            "seq": self._next_seq(),
            "timestamp": time.time(),
        }
        self._send_frame(sock, frame)
        self.logger.info(
            "[MASTER->OUTSTATION] WRITE seq=%s point_id=%s value=%s",
            frame["seq"],
            point_id,
            value,
        )

    def _send_frame(self, sock: socket.socket, frame: Dict[str, Any]) -> None:
        raw = json.dumps(frame).encode("utf-8") + b"\n"
        sock.sendall(raw)

    def _handle_frame(self, raw: str) -> None:
        try:
            frame = json.loads(raw)
        except json.JSONDecodeError:
            self.logger.warning("Received invalid JSON from outstation: %s", raw)
            return

        ftype = frame.get("type")
        seq = frame.get("seq")
        status = frame.get("status")

        if ftype in ("READ_RESPONSE", "WRITE_RESPONSE"):
            point_id = frame.get("point_id")
            value = frame.get("value")
            ts = frame.get("timestamp")
            self.logger.info(
                "[OUTSTATION->MASTER] %s seq=%s point_id=%s value=%s ts=%s status=%s",
                ftype,
                seq,
                point_id,
                value,
                ts,
                status,
            )
        elif ftype == "ERROR":
            code = frame.get("code")
            self.logger.warning("[OUTSTATION->MASTER] ERROR seq=%s code=%s", seq, code)
        else:
            self.logger.info("[OUTSTATION->MASTER] %s", frame)


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def configure_logging(verbose: bool = False) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [MASTER] %(levelname)s: %(message)s",
    )
    return logging.getLogger("dnp3_master")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simple TCP-based DNP3-style master",
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help="Path to DNP3 JSON config (default: %(default)s)",
    )
    parser.add_argument(
        "--host",
        help="Override master target host (otherwise taken from config)",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Override master target port (otherwise taken from config)",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        help="Override poll interval seconds (otherwise taken from config)",
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
    master_cfg = cfg.get("master", {})
    host = args.host or master_cfg.get("host", "127.0.0.1")
    port = args.port or int(master_cfg.get("port", 20000))
    poll_interval = args.poll_interval or float(master_cfg.get("poll_interval_s", 1.0))

    master = DNP3Master(
        host=host,
        port=port,
        poll_interval=poll_interval,
        logger=logger,
    )
    master.run()


if __name__ == "__main__":
    main()

