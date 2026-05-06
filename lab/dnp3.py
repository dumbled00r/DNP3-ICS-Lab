"""Minimal DNP3 frame builder — link + transport + application layers.

Function codes used here:
  0x01 READ   0x0D COLD_RESTART   0x0E WARM_RESTART   0x0F INIT_DATA
  0x12 STOP_APPL   0x14 ENABLE_UNS   0x15 DISABLE_UNS

Link control:
  0xC4  master->outstation, unconfirmed user data (PRM=1, DIR=1, FC=4)
  0xC9  request link status (FC=9)
"""
import socket, time

START = b"\x05\x64"

def crc(data: bytes) -> bytes:
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA6BC if c & 1 else c >> 1
    c ^= 0xFFFF
    return c.to_bytes(2, "little")

def _blocks(udata: bytes) -> bytes:
    out = b""
    for i in range(0, len(udata), 16):
        ch = udata[i:i+16]
        out += ch + crc(ch)
    return out

def link_frame(src: int, dst: int, ctrl: int, udata: bytes = b"") -> bytes:
    length = 5 + len(udata)             # ctrl + dst(2) + src(2) + udata
    hdr = START + bytes([length, ctrl]) + dst.to_bytes(2,"little") + src.to_bytes(2,"little")
    return hdr + crc(hdr) + _blocks(udata)

def app_request(src: int, dst: int, fc: int, objects: bytes = b"", seq: int = 0) -> bytes:
    transport = bytes([0xC0 | (seq & 0x3F)])           # FIR+FIN
    app       = bytes([0xC0 | (seq & 0x0F), fc])       # FIR+FIN, no CON/UNS
    return link_frame(src, dst, 0xC4, transport + app + objects)

# ---- common object headers ----
# class poll: g60v2 (class1), v3 (class2), v4 (class3), v1 (class0)
OBJ_CLASS0 = b"\x3C\x01\x06"   # group 60, var 1, qual 0x06 (all)
OBJ_CLASS1 = b"\x3C\x02\x06"
OBJ_CLASS2 = b"\x3C\x03\x06"
OBJ_CLASS3 = b"\x3C\x04\x06"
# device attributes — group 0, var 240 (all attributes), qualifier 0x00 8-bit start/stop 0..0
OBJ_DEV_ATTR_ALL = b"\x00\xF0\x00\x00\x00"

def send_tcp(payload: bytes, host: str, port: int, timeout: float = 5.0) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(payload)
        try:
            return s.recv(4096)
        except socket.timeout:
            return b""

def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")
