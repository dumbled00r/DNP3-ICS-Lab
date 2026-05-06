"""DNP3_INFO — harvest device info via repeated reads.

Reads device-attribute objects (g0v240) and class-0 integrity data, plus
common object groups, to fingerprint the outstation. Recon, no writes.
"""
import argparse, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dnp3 import app_request, send_tcp, OBJ_CLASS0, OBJ_DEV_ATTR_ALL, now
from config import OUTSTATION_IP, OUTSTATION_PORT, OUTSTATION_ADDR, MASTER_ADDR

# read a handful of common groups, qualifier 0x06 = no range, all points
GROUPS = [1, 2, 10, 12, 20, 21, 30, 32, 40, 41, 50]
PROBES = [OBJ_DEV_ATTR_ALL, OBJ_CLASS0] + [bytes([g, 0, 0x06]) for g in GROUPS]

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=OUTSTATION_IP)
    p.add_argument("--port", type=int, default=OUTSTATION_PORT)
    p.add_argument("--rounds", type=int, default=3)
    p.add_argument("--interval", type=float, default=0.3)
    a = p.parse_args()
    print(f"[{now()}] DNP3_INFO start rounds={a.rounds}")
    seq = 0
    for _ in range(a.rounds):
        for obj in PROBES:
            send_tcp(app_request(MASTER_ADDR, OUTSTATION_ADDR, 0x01, obj, seq=seq & 0x0F),
                     a.host, a.port)
            seq += 1
            time.sleep(a.interval)
    print(f"[{now()}] DNP3_INFO stop")

if __name__ == "__main__":
    main()
