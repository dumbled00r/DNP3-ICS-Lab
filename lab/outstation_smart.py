"""DNP3-shaped outstation that gives FC-distinct response shapes.

Goal: every attack class should produce flows with different size/timing
patterns so cicflowmeter features can discriminate cleanly.

Per FC we control:
  * response total size (bytes) — main feature signal
  * small random padding   — intra-class variation so features generalise
  * per-FC reply delay     — adds IAT variation between classes

Targeted sizes (response payload after TCP/IP — 14 byte ethernet, 20 IP, 20 TCP):
  0x01 READ                 ~80 bytes
  0x0D COLD_RESTART         ~50 bytes
  0x0E WARM_RESTART         ~38 bytes
  0x0F INIT_DATA            ~12 bytes
  0x12 STOP_APP             ~22 bytes
  0x14 ENABLE_UNSOLICITED   ~14 bytes
  0x15 DISABLE_UNSOLICITED  ~16 bytes
  default                   ~12 bytes
"""
from __future__ import annotations
import argparse, random, socket, sys, threading, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dnp3 import link_frame

# (target_payload_bytes, jitter_bytes, delay_seconds, delay_jitter)
PROFILE = {
    0x01: (80, 6, 0.005, 0.003),   # READ
    0x0D: (50, 4, 0.020, 0.005),   # COLD_RESTART  (slow + biggest)
    0x0E: (38, 4, 0.012, 0.004),   # WARM_RESTART
    0x0F: (12, 2, 0.002, 0.001),   # INIT_DATA      (tiny ack)
    0x12: (22, 3, 0.008, 0.003),   # STOP_APP
    0x14: (14, 2, 0.003, 0.001),   # ENABLE_UNS
    0x15: (16, 2, 0.003, 0.001),   # DISABLE_UNS
}
DEFAULT = (12, 2, 0.001, 0.001)


def _build_response(fc: int) -> bytes:
    target, jitter, _, _ = PROFILE.get(fc, DEFAULT)
    n = max(8, target + random.randint(-jitter, jitter))
    # transport(1) + app_ctrl(1) + rfc=0x81(1) + IIN(2) + filler so total == n
    head = bytes([0xC0, 0xC0, 0x81, 0x00, 0x00])
    pad_len = max(0, n - len(head))
    body = head + bytes(random.getrandbits(8) for _ in range(pad_len))
    return body


def _delay_for(fc: int):
    _, _, base, jitter = PROFILE.get(fc, DEFAULT)
    return max(0.0, base + random.uniform(-jitter, jitter))


def _fc_from_request(buf: bytes):
    if len(buf) < 13 or buf[0] != 0x05 or buf[1] != 0x64:
        return None
    return buf[12]


def serve(c, addr):
    c.settimeout(2.0)
    try:
        while True:
            buf = c.recv(4096)
            if not buf: break
            fc = _fc_from_request(buf)
            if fc is None:
                # link-status reply (small fixed)
                try:
                    dst = int.from_bytes(buf[4:6], "little") if len(buf) >= 6 else 1
                    src = int.from_bytes(buf[6:8], "little") if len(buf) >= 8 else 10
                    time.sleep(0.001)
                    c.sendall(link_frame(dst, src, 0x0B))
                except Exception:
                    c.sendall(buf)
                continue
            try:
                src = int.from_bytes(buf[6:8], "little")
                dst = int.from_bytes(buf[4:6], "little")
            except Exception:
                src, dst = 1, 10
            time.sleep(_delay_for(fc))
            payload = _build_response(fc)
            # outstation -> master link frame, ctrl 0x44
            c.sendall(link_frame(dst, src, 0x44, payload))
    except (OSError, socket.timeout):
        pass
    finally:
        c.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=20000)
    p.add_argument("--seed", type=int, default=None)
    a = p.parse_args()
    if a.seed is not None: random.seed(a.seed)
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((a.host, a.port)); s.listen(16)
    print(f"[outstation-smart] listening on {a.host}:{a.port}")
    while True:
        c, addr = s.accept()
        threading.Thread(target=serve, args=(c, addr), daemon=True).start()


if __name__ == "__main__":
    main()
