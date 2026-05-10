"""Blackhole outstation — accepts TCP, reads data, never sends any response.

Simulates the "no response" effect of a MITM_DoS attack: the attacker
has positioned itself between master and outstation, forwarded the TCP
handshake, but silently drops all application-layer responses.

Used by build_dataset.py / build_dataset.sh to generate MITM_DOS training
flows on loopback without needing real ARP poisoning.

Resulting flow features vs NORMAL:
  TotLen Bwd Pkts ≈ 0  (TCP-level ACKs only, no DNP3 payload)
  Bwd Pkt Len Mean ≈ 0
  Down/Up Ratio   ≈ 0
  Short flow duration (master recv-timeout fires, reconnects)
"""
from __future__ import annotations
import argparse, socket, threading


def _handle(conn: socket.socket) -> None:
    conn.settimeout(30.0)
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            # discard silently — never send a DNP3 response
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main() -> None:
    ap = argparse.ArgumentParser(description="Blackhole outstation (MITM_DoS simulation)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=20000)
    a = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.host, a.port))
    srv.listen(64)
    print(f"[outstation-blackhole] listening on {a.host}:{a.port}", flush=True)
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=_handle, args=(conn,), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()


if __name__ == "__main__":
    main()
