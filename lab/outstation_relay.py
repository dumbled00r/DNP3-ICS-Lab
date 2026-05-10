"""Transparent TCP relay with configurable response latency — ARP_POISONING sim.

Listens on --port (default 20000). Every connection is forwarded to
--backend-port (default 20001) with --delay added to each backend response.
Simulates the extra RTT of a MITM attacker who is in the forwarding path
(ARP cache poisoned, IP forwarding ON, no traffic dropped).

Resulting flow features vs NORMAL:
  Flow IAT Mean  : higher (extra round-trip through relay adds ~15–25 ms)
  Bwd IAT Mean   : higher (relay delay on backward direction)
  Flow IAT Std   : slightly higher (jittered relay adds variance)
  Content        : identical (full bidirectional exchange, same packet sizes)

Setup for dataset generation:
  python lab/outstation_real.py  --host 127.0.0.1 --port 20001
  python lab/outstation_relay.py --host 127.0.0.1 --port 20000
  python lab/master_session.py   --host 127.0.0.1 --port 20000
"""
from __future__ import annotations
import argparse, random, socket, threading, time


def _pipe(src: socket.socket, dst: socket.socket,
          delay: float, jitter: float) -> None:
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            if delay > 0:
                time.sleep(delay + random.uniform(0, jitter))
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass


def _handle(client: socket.socket,
            backend_host: str, backend_port: int,
            delay: float, jitter: float) -> None:
    try:
        backend = socket.create_connection((backend_host, backend_port), timeout=5)
    except OSError:
        try:
            client.close()
        except OSError:
            pass
        return
    backend.settimeout(None)
    client.settimeout(None)
    # client → backend: no delay (master sends to attacker instantly)
    # backend → client: delay   (attacker adds latency before forwarding reply)
    t_fwd = threading.Thread(target=_pipe,
                             args=(client, backend, 0.0, 0.0), daemon=True)
    t_bwd = threading.Thread(target=_pipe,
                             args=(backend, client, delay, jitter), daemon=True)
    t_fwd.start()
    t_bwd.start()
    t_fwd.join()
    t_bwd.join()


def main() -> None:
    ap = argparse.ArgumentParser(
        description="TCP relay with latency injection (ARP_POISONING simulation)")
    ap.add_argument("--host",         default="127.0.0.1")
    ap.add_argument("--port",         type=int,   default=20000)
    ap.add_argument("--backend-host", default="127.0.0.1")
    ap.add_argument("--backend-port", type=int,   default=20001)
    ap.add_argument("--delay",        type=float, default=0.015,
                    help="base latency added to each outstation response (seconds)")
    ap.add_argument("--jitter",       type=float, default=0.008,
                    help="random extra latency [0, jitter] per response")
    a = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.host, a.port))
    srv.listen(64)
    print(f"[outstation-relay] {a.host}:{a.port} "
          f"-> {a.backend_host}:{a.backend_port}  "
          f"delay={a.delay*1000:.0f}±{a.jitter*1000:.0f}ms", flush=True)
    try:
        while True:
            client, _ = srv.accept()
            threading.Thread(
                target=_handle,
                args=(client, a.backend_host, a.backend_port, a.delay, a.jitter),
                daemon=True
            ).start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()


if __name__ == "__main__":
    main()
