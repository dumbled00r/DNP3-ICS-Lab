"""DNP3 outstation that mirrors the real dataset's response sizes.

Replies:
  READ class-1 (g60v2 qual 0x06)  -> 17-byte empty response (FC=0x81 IIN=0)
  READ class-0 (g60v1 qual 0x06)  -> 292-byte fat response w/ many objects
  COLD/WARM_RESTART (FC 0x0D/0x0E)-> 17-byte empty ack
  INIT_DATA (0x0F)                -> 17-byte ack
  STOP_APP  (0x12)                -> 17-byte ack
  DISABLE/ENABLE_UNS (0x14/0x15)  -> 17-byte ack
  link-status request             -> 10-byte link status reply
After each big class-0 response, also send a 186-byte CONFIRM-style frame
to mirror the dataset's 186-byte O->M FC=0x00 count.
"""
from __future__ import annotations
import argparse, random, socket, sys, threading, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dnp3 import link_frame

# ---- constant payloads ----------------------------------------------------
def _resp_empty(seq=0):
    """17-byte empty response: link header + transport + app_ctrl + 0x81 + IIN(2)."""
    transport = bytes([0xC0 | (seq & 0x3F)])
    app = bytes([0xC0 | (seq & 0x0F), 0x81, 0x00, 0x00])  # FC=resp, IIN=0
    return transport + app  # 5 bytes user data -> link length 10 -> total frame 17

def _resp_fat(seq=0):
    """~292-byte fat response (filler bytes mimic class-0 objects)."""
    transport = bytes([0xC0 | (seq & 0x3F)])
    app_hdr = bytes([0xC0 | (seq & 0x0F), 0x81, 0x00, 0x00])
    payload_target = 273  # tuned so total frame ~292
    payload = bytes(random.getrandbits(8) for _ in range(payload_target))
    return transport + app_hdr + payload

def _resp_confirm(seq=0):
    """~186-byte O->M frame mimicking unsolicited-class-data confirm tail."""
    transport = bytes([0xC0 | (seq & 0x3F)])
    app_hdr = bytes([0xC0 | (seq & 0x0F), 0x82, 0x00, 0x00])  # FC=0x82
    payload_target = 167
    payload = bytes(random.getrandbits(8) for _ in range(payload_target))
    return transport + app_hdr + payload


def _fc_from(buf: bytes):
    if len(buf) < 13 or buf[0] != 0x05 or buf[1] != 0x64: return None
    return buf[12]

def _is_class0_read(buf: bytes) -> bool:
    """Heuristic: FC=0x01 READ with object g60v1 (class-0)."""
    if len(buf) < 16: return False
    fc = buf[12]
    if fc != 0x01: return False
    # object headers start at byte 13: group, var, qual; class-0 is 0x3c 0x01
    return buf[13] == 0x3C and buf[14] == 0x01


def serve(c, addr):
    c.settimeout(2.0)
    try:
        seq = 0
        while True:
            buf = c.recv(4096)
            if not buf: break
            try:
                src = int.from_bytes(buf[6:8], "little")  # master link addr
                dst = int.from_bytes(buf[4:6], "little")  # outstation link addr
            except Exception:
                src, dst = 13, 2
            fc = _fc_from(buf)
            if fc is None:
                # link-status request -> 10-byte status reply
                c.sendall(link_frame(dst, src, 0x0B))
                continue
            if _is_class0_read(buf):
                # 292-byte fat response
                c.sendall(link_frame(dst, src, 0x44, _resp_fat(seq)))
                # plus a 186-byte O->M frame to mirror dataset
                c.sendall(link_frame(dst, src, 0x44, _resp_confirm(seq)))
            else:
                # everything else: 17-byte empty response
                c.sendall(link_frame(dst, src, 0x44, _resp_empty(seq)))
            seq = (seq + 1) & 0x0F
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
    s.bind((a.host, a.port)); s.listen(64)
    print(f"[outstation-real] listening on {a.host}:{a.port}", flush=True)
    while True:
        try:
            c, addr = s.accept()
        except KeyboardInterrupt:
            break
        try:
            serve(c, addr)
        except Exception as e:
            print(f"[outstation-real] serve error: {e}", flush=True)


if __name__ == "__main__":
    main()
