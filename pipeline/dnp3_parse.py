"""Shared DNP3 frame parser for payload-based detection.

Parses raw TCP payload bytes into a sequence of DNP3Frame objects.
Used by both opnsense/pkt_inspect.py (live) and pipeline/predict_pcap.py (offline).

DNP3 wire format:
  [0]   0x05  start1
  [1]   0x64  start2
  [2]   length    = 5 + user_data_len (link hdr counts as 5)
  [3]   ctrl      = link-layer control byte
  [4-5] dest      = destination address (LE)
  [6-7] src       = source address (LE)
  [8-9] CRC       of bytes [0..7]
  Then user data in 16-byte chunks, each followed by 2-byte CRC.
  First user-data byte  (offset 10) = transport byte
  Second user-data byte (offset 11) = app control byte
  Third  user-data byte (offset 12) = application function code (FC)

Link-layer ctrl=0xC9 = REQUEST_LINK_STATUS (no transport/app layer).
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

# Application-layer function codes that indicate command-injection attacks.
ATTACK_FC: dict[int, str] = {
    0x0D: "COLD_RESTART",
    0x0E: "WARM_RESTART",
    0x0F: "INIT_DATA",
    0x12: "STOP_APP",
    0x14: "INIT_APPLICATION",
    0x15: "DISABLE_UNSOLICITED",
}

# Link-layer ctrl byte for REQUEST_LINK_STATUS (used by scanning attacks).
LINK_STATUS_CTRL = 0xC9

# Human-readable FC names for logging.
_FC_NAMES: dict[int, str] = {
    0x00: "CONFIRM",
    0x01: "READ",
    0x02: "WRITE",
    0x03: "SELECT",
    0x04: "OPERATE",
    0x05: "DIRECT_OPERATE",
    0x06: "DIRECT_OPERATE_NR",
    0x07: "FREEZE",
    0x08: "FREEZE_NR",
    0x09: "FREEZE_CLEAR",
    0x0A: "FREEZE_CLEAR_NR",
    0x0B: "FREEZE_AT_TIME",
    0x0C: "FREEZE_AT_TIME_NR",
    0x0D: "COLD_RESTART",
    0x0E: "WARM_RESTART",
    0x0F: "INIT_DATA",
    0x10: "INIT_APPLICATION",
    0x11: "START_APPLICATION",
    0x12: "STOP_APP",
    0x13: "SAVE_CONFIG",
    0x14: "INIT_APPLICATION",
    0x15: "DISABLE_UNSOLICITED",
    0x16: "ENABLE_UNSOLICITED",
    0x17: "ASSIGN_CLASS",
    0x18: "DELAY_MEAS",
    0x19: "RECORD_CURRENT_TIME",
    0x81: "RESPONSE",
    0x82: "UNSOLICITED_RESPONSE",
    0x83: "AUTHENTICATION_RESPONSE",
}


@dataclass
class DNP3Frame:
    ctrl: int               # link-layer control byte
    src: int                # link-layer source address
    dst: int                # link-layer destination address
    fc: Optional[int]       # app-layer FC, None for link-only frames
    user_data_len: int      # bytes in user data section (excl. CRCs)
    wire_size: int          # total bytes consumed from buffer

    @property
    def is_link_status(self) -> bool:
        return self.ctrl == LINK_STATUS_CTRL

    @property
    def is_attack(self) -> bool:
        return self.fc in ATTACK_FC

    @property
    def attack_class(self) -> Optional[str]:
        return ATTACK_FC.get(self.fc) if self.fc is not None else None

    @property
    def fc_name(self) -> str:
        if self.fc is None:
            return "LINK_ONLY"
        return _FC_NAMES.get(self.fc, f"FC_0x{self.fc:02X}")

    def __repr__(self) -> str:
        return (f"DNP3Frame(ctrl=0x{self.ctrl:02X} src={self.src} dst={self.dst} "
                f"fc={self.fc_name} wire={self.wire_size})")


def _user_data_wire_size(udata_len: int) -> int:
    """Number of wire bytes for udata_len user-data bytes (including CRCs)."""
    full_blocks, rem = divmod(udata_len, 16)
    return full_blocks * 18 + ((rem + 2) if rem else 0)


def parse_frames(buf: bytes | bytearray) -> list[DNP3Frame]:
    """Parse all DNP3 frames from a raw TCP payload buffer."""
    frames: list[DNP3Frame] = []
    i = 0
    n = len(buf)

    while i < n - 1:
        # Scan for start bytes 0x05 0x64
        if buf[i] != 0x05 or buf[i + 1] != 0x64:
            i += 1
            continue

        # Need at least 10 bytes for the link header
        if i + 10 > n:
            break

        length = buf[i + 2]          # length field = 5 + udata_len
        ctrl   = buf[i + 3]
        dst    = buf[i + 4] | (buf[i + 5] << 8)
        src    = buf[i + 6] | (buf[i + 7] << 8)

        udata_len = max(0, length - 5)
        wire_udata = _user_data_wire_size(udata_len)
        frame_size = 10 + wire_udata

        if i + frame_size > n:
            break  # incomplete frame at end of buffer

        fc: Optional[int] = None
        if udata_len >= 3:
            # offset 10 = transport byte, offset 11 = app ctrl, offset 12 = FC
            fc = buf[i + 12]

        frames.append(DNP3Frame(
            ctrl=ctrl,
            src=src,
            dst=dst,
            fc=fc,
            user_data_len=udata_len,
            wire_size=frame_size,
        ))
        i += frame_size

    return frames


def parse_payload(payload: bytes | bytearray) -> list[DNP3Frame]:
    """Alias for parse_frames — preferred name in live-detection context."""
    return parse_frames(payload)
