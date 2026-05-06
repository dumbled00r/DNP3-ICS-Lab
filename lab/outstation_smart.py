"""DNP3-shaped outstation that produces FC-dependent response sizes.

Goal: give each attack class a distinct flow shape so cicflowmeter features
can discriminate between them. Not a protocol-correct outstation — just
sized correctly per request type.

Per app function code we send back:
  0x01 READ                ->  ~50 bytes (response with class data objects)
  0x02 WRITE               ->  ~12 bytes (ack with IIN)
  0x0D COLD_RESTART        ->  ~20 bytes (response + g51v1 time-needed)
  0x0E WARM_RESTART        ->  ~20 bytes (response + g51v1)
  0x0F INIT_DATA           ->  ~12 bytes (ack)
  0x12 STOP_APP            ->  ~12 bytes (ack + status)
  0x15 DISABLE_UNSOLICITED ->  ~12 bytes (ack)
  others                   ->  echo (fall back)
For link-layer-only requests (transport not present) reply with link status.
"""
from __future__ import annotations
import argparse, socket, sys, threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dnp3 import link_frame, app_request, crc

# Map FC -> response payload bytes (transport+app+objects, no link header).
# Sizes chosen to mirror typical opendnp3 responses.
def _resp_for(fc: int) -> bytes:
    transport = bytes([0xC0])
    app_ctrl  = 0xC0
    rfc       = 0x81                  # response
    iin       = bytes([0x00, 0x00])   # IIN bits
    if fc == 0x0D or fc == 0x0E:      # COLD/WARM restart
        # response + IIN + g51v1 (time-needed, 7 bytes payload)
        body = bytes([app_ctrl, rfc]) + iin + bytes([0x33,0x01,0x07,0x01]) + b"\x00"*7
    elif fc == 0x0F:                  # INIT_DATA
        body = bytes([app_ctrl, rfc]) + iin
    elif fc == 0x12:                  # STOP_APP
        body = bytes([app_ctrl, rfc]) + iin + bytes([0x5A,0x01,0x07,0x01,0x00])
    elif fc == 0x15 or fc == 0x14:    # DISABLE/ENABLE_UNS
        body = bytes([app_ctrl, rfc]) + iin
    elif fc == 0x01:                  # READ
        # response with class-0 fake binary inputs (~30 byte object body)
        body = (bytes([app_ctrl, rfc]) + iin
                + bytes([0x01,0x02,0x00,0x00,0x09]) + b"\x80"*10)
    else:
        body = bytes([app_ctrl, rfc]) + iin
    return transport + body


def _fc_from_request(buf: bytes) -> int | None:
    """Extract DNP3 application function code from a master->outstation frame.
    Frame layout: 0x05 0x64 LEN CTRL DST(2) SRC(2) HDR_CRC(2) [TR(1) APP_CTRL(1) FC(1) ...] BLK_CRC(2)
    => app FC is at offset 12 from frame start.
    """
    if len(buf) < 13 or buf[0] != 0x05 or buf[1] != 0x64:
        return None
    return buf[12]


def _wrap_response(src_addr: int, dst_addr: int, payload: bytes) -> bytes:
    """Build a link-layer frame from outstation -> master.
    src_addr = outstation, dst_addr = master.
    Control byte: DIR=0 (outstation->master), PRM=1, FUNC=4 (unconfirmed user data) -> 0x44.
    """
    return link_frame(src_addr, dst_addr, 0x44, payload)


def serve(c, addr):
    c.settimeout(2.0)
    try:
        while True:
            buf = c.recv(4096)
            if not buf: break
            fc = _fc_from_request(buf)
            if fc is None:
                # link-status request, echo back a link-status response
                # ctrl 0x0B = secondary, link status response
                try:
                    dst = int.from_bytes(buf[4:6], "little") if len(buf) >= 6 else 1
                    src = int.from_bytes(buf[6:8], "little") if len(buf) >= 8 else 10
                    c.sendall(link_frame(dst, src, 0x0B))
                except Exception:
                    c.sendall(buf)
                continue
            try:
                src = int.from_bytes(buf[6:8], "little")  # master link addr
                dst = int.from_bytes(buf[4:6], "little")  # outstation link addr
            except Exception:
                src, dst = 1, 10
            payload = _resp_for(fc)
            c.sendall(_wrap_response(src_addr=dst, dst_addr=src, payload=payload))
    except (OSError, socket.timeout):
        pass
    finally:
        c.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=20000)
    a = p.parse_args()
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((a.host, a.port)); s.listen(16)
    print(f"[outstation-smart] listening on {a.host}:{a.port}")
    while True:
        c, addr = s.accept()
        threading.Thread(target=serve, args=(c, addr), daemon=True).start()


if __name__ == "__main__":
    main()
