"""Minimal DNP3-echo outstation for live-detection testing.

Listens on TCP/20000, echoes whatever DNP3 frame the master sends back.
Not a protocol-correct outstation — just enough to make every flow have
a backward direction so cicflowmeter produces realistic bidirectional
features. Use this when you can't run the full opendnp3-based outstation
(e.g. directly on OPNsense, with no Pi).

  python3 outstation_echo.py
  python3 outstation_echo.py --host 0.0.0.0 --port 20000
"""
import argparse, socket, threading


def serve(c, addr):
    try:
        while True:
            data = c.recv(4096)
            if not data: break
            try:
                c.sendall(data)
            except OSError:
                break
    finally:
        c.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=20000)
    a = p.parse_args()

    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((a.host, a.port))
    s.listen(16)
    print(f"[outstation-echo] listening on {a.host}:{a.port}")
    while True:
        c, addr = s.accept()
        threading.Thread(target=serve, args=(c, addr), daemon=True).start()


if __name__ == "__main__":
    main()
