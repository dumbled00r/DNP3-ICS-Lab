"""DNP3_ENUMERATE — sweep outstation link addresses (Redpoint-style).

Sends a link-layer 'Request Link Status' (ctrl 0xC9) to every dst address
in a range and records which respond. Reconnaissance traffic.
"""
import argparse, socket, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dnp3 import link_frame, now
from config import OUTSTATION_IP, OUTSTATION_PORT, MASTER_ADDR

def probe(host, port, src, dst, timeout=1.0):
    pkt = link_frame(src, dst, 0xC9)        # request link status
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(pkt)
            try:    return s.recv(64)
            except socket.timeout: return b""
    except OSError:
        return b""

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=OUTSTATION_IP)
    p.add_argument("--port", type=int, default=OUTSTATION_PORT)
    p.add_argument("--start", type=int, default=0)
    p.add_argument("--end", type=int, default=1024)
    p.add_argument("--src", type=int, default=MASTER_ADDR)
    a = p.parse_args()
    print(f"[{now()}] DNP3_ENUMERATE {a.start}..{a.end}")
    for dst in range(a.start, a.end + 1):
        r = probe(a.host, a.port, a.src, dst)
        if r: print(f"  alive dst={dst}")
        time.sleep(0.02)
    print(f"[{now()}] DNP3_ENUMERATE stop")

if __name__ == "__main__":
    main()
