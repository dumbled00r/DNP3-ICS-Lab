"""NORMAL traffic — periodic SCADA polling of the outstation.

Mix of class-0 integrity polls and class-1/2/3 event polls, on a steady
1–3s cadence with small jitter, just like a real master.
"""
import argparse, random, socket, time
from dnp3 import app_request, OBJ_CLASS0, OBJ_CLASS1, OBJ_CLASS2, OBJ_CLASS3, now
from config import OUTSTATION_IP, OUTSTATION_PORT, OUTSTATION_ADDR, MASTER_ADDR

POLLS = [
    ("class0", OBJ_CLASS0),
    ("class1", OBJ_CLASS1),
    ("class2", OBJ_CLASS2),
    ("class3", OBJ_CLASS3),
]

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=OUTSTATION_IP)
    p.add_argument("--port", type=int, default=OUTSTATION_PORT)
    p.add_argument("--duration", type=int, default=600, help="seconds")
    p.add_argument("--cadence", type=float, default=2.0)
    a = p.parse_args()

    print(f"[{now()}] NORMAL start -> {a.host}:{a.port} for {a.duration}s")
    end = time.time() + a.duration
    seq = 0
    s = socket.create_connection((a.host, a.port), timeout=5)
    try:
        while time.time() < end:
            name, obj = POLLS[seq % len(POLLS)] if seq % 5 else POLLS[0]
            req = app_request(MASTER_ADDR, OUTSTATION_ADDR, 0x01, obj, seq=seq & 0x0F)
            s.sendall(req)
            try:
                s.recv(4096)
            except socket.timeout:
                pass
            seq += 1
            time.sleep(a.cadence + random.uniform(-0.3, 0.3))
    finally:
        s.close()
    print(f"[{now()}] NORMAL stop")

if __name__ == "__main__":
    main()
