"""Extract per-flow DNP3 payload features from a PCAP file.

Reads raw TCP packets, groups them by 5-tuple flow, parses every DNP3
frame in each packet's payload, and computes flow-level payload features.
Output is a CSV row per flow, suitable for training a payload-based ML model.

Features computed per flow:
  total_frames        total DNP3 frames parsed in the flow
  fwd_frames          frames from the originator (master side)
  bwd_frames          frames from the responder (outstation side)
  response_ratio      bwd / total  (0 = MITM_DOS; ~0.5 = normal exchange)
  attack_fc_count     frames whose FC is in the attack set
  attack_fc_ratio     attack_fc_count / total_frames
  link_status_count   ctrl=0xC9 frames (scanning attacks)
  link_status_ratio   link_status_count / total_frames
  unique_fcs          number of distinct FC values seen
  most_common_req_fc  most frequent FC value (int, -1 if none)
  fc_read             FC=0x01 count
  fc_cold_restart     FC=0x0D count
  fc_warm_restart     FC=0x0E count
  fc_init_data        FC=0x0F count
  fc_stop_app         FC=0x12 count
  fc_init_app         FC=0x14 count
  fc_disable_unsol    FC=0x15 count
  fc_response         FC=0x81 count
  fc_unsol_response   FC=0x82 count
  mean_udata_len      mean user-data section length across frames
  max_udata_len       max user-data section length
  min_udata_len       min user-data section length (excl. link-only frames)

Usage:
  python pipeline/pcap_payload_features.py \
      dataset/pcap/COLD_RESTART.pcap --label COLD_RESTART --out /tmp/cr.csv

  # batch: process entire pcap/ directory
  python pipeline/pcap_payload_features.py \
      --pcap-dir dataset/pcap --label-from-stem \
      --out dataset/payload_features.csv
"""
from __future__ import annotations

import argparse
import collections
import struct
import sys
from pathlib import Path
from typing import Optional

import pandas as pd

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
from dnp3_parse import parse_frames, ATTACK_FC, LINK_STATUS_CTRL


# ---------------------------------------------------------------------------
# Minimal pcap + Ethernet/IP/TCP reader (no scapy dependency)
# ---------------------------------------------------------------------------

def _iter_tcp_payloads(path: Path):
    """Yield (src_ip, src_port, dst_ip, dst_port, payload_bytes) per TCP pkt."""
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            return
        magic = struct.unpack("<I", hdr[:4])[0]
        bo = "<" if magic == 0xa1b2c3d4 else ">"

        while True:
            rec = f.read(16)
            if len(rec) < 16:
                break
            _, _, incl_len, _ = struct.unpack(bo + "IIII", rec)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break

            # Ethernet
            if len(data) < 14:
                continue
            eth_type = struct.unpack(">H", data[12:14])[0]
            ip_start = 14
            if eth_type == 0x8100:          # 802.1Q VLAN
                ip_start += 4
            if eth_type not in (0x0800, 0x8100):
                continue

            # IPv4
            if len(data) < ip_start + 20:
                continue
            if data[ip_start + 9] != 6:     # not TCP
                continue
            ip_ihl = (data[ip_start] & 0x0F) * 4
            src_ip = ".".join(str(b) for b in data[ip_start + 12: ip_start + 16])
            dst_ip = ".".join(str(b) for b in data[ip_start + 16: ip_start + 20])

            # TCP
            tcp_start = ip_start + ip_ihl
            if len(data) < tcp_start + 20:
                continue
            src_port = struct.unpack(">H", data[tcp_start:     tcp_start + 2])[0]
            dst_port = struct.unpack(">H", data[tcp_start + 2: tcp_start + 4])[0]
            data_off = ((data[tcp_start + 12] >> 4) & 0xF) * 4
            payload  = data[tcp_start + data_off:]
            if payload:
                yield src_ip, src_port, dst_ip, dst_port, payload


# ---------------------------------------------------------------------------
# Flow accumulator
# ---------------------------------------------------------------------------

class _FlowAcc:
    __slots__ = (
        "total", "fwd", "bwd",
        "attack_fc", "link_status",
        "fc_counts", "udata_lens",
        "fwd_key",
    )

    def __init__(self, fwd_key: tuple) -> None:
        self.fwd_key = fwd_key      # (src_ip, src_port, dst_ip, dst_port) of first pkt
        self.total      = 0
        self.fwd        = 0
        self.bwd        = 0
        self.attack_fc  = 0
        self.link_status = 0
        self.fc_counts: dict[int, int] = collections.defaultdict(int)
        self.udata_lens: list[int] = []

    def add_frames(self, frames, is_fwd: bool) -> None:
        for f in frames:
            self.total += 1
            if is_fwd:
                self.fwd += 1
            else:
                self.bwd += 1
            if f.is_attack:
                self.attack_fc += 1
            if f.is_link_status:
                self.link_status += 1
            if f.fc is not None:
                self.fc_counts[f.fc] += 1
            if f.user_data_len > 0:
                self.udata_lens.append(f.user_data_len)

    def to_dict(self) -> dict:
        t = self.total or 1      # avoid div-by-zero
        udata = self.udata_lens or [0]
        most_common_fc = max(self.fc_counts, key=self.fc_counts.get) \
            if self.fc_counts else -1

        return {
            "total_frames":       self.total,
            "fwd_frames":         self.fwd,
            "bwd_frames":         self.bwd,
            "response_ratio":     self.bwd / t,
            "attack_fc_count":    self.attack_fc,
            "attack_fc_ratio":    self.attack_fc / t,
            "link_status_count":  self.link_status,
            "link_status_ratio":  self.link_status / t,
            "unique_fcs":         len(self.fc_counts),
            "most_common_req_fc": most_common_fc,
            "fc_read":            self.fc_counts.get(0x01, 0),
            "fc_cold_restart":    self.fc_counts.get(0x0D, 0),
            "fc_warm_restart":    self.fc_counts.get(0x0E, 0),
            "fc_init_data":       self.fc_counts.get(0x0F, 0),
            "fc_stop_app":        self.fc_counts.get(0x12, 0),
            "fc_init_app":        self.fc_counts.get(0x14, 0),
            "fc_disable_unsol":   self.fc_counts.get(0x15, 0),
            "fc_response":        self.fc_counts.get(0x81, 0),
            "fc_unsol_response":  self.fc_counts.get(0x82, 0),
            "mean_udata_len":     sum(udata) / len(udata),
            "max_udata_len":      max(udata),
            "min_udata_len":      min(udata),
        }


# ---------------------------------------------------------------------------
# Per-PCAP extraction
# ---------------------------------------------------------------------------

def extract_flows(path: Path, dnp3_port: int = 0) -> list[dict]:
    """Return one feature dict per TCP flow in the PCAP.

    dnp3_port: if non-zero, only consider packets to/from this port.
               if 0, accept any port (auto-detect from packet content).
    """
    flows: dict[tuple, _FlowAcc] = {}

    for src_ip, src_port, dst_ip, dst_port, payload in _iter_tcp_payloads(path):
        if dnp3_port and dst_port != dnp3_port and src_port != dnp3_port:
            continue
        frames = parse_frames(payload)
        if not frames:
            continue

        # Canonical flow key: smaller (ip,port) pair first
        fwd_key = (src_ip, src_port, dst_ip, dst_port)
        rev_key = (dst_ip, dst_port, src_ip, src_port)

        if fwd_key in flows:
            key, is_fwd = fwd_key, True
        elif rev_key in flows:
            key, is_fwd = rev_key, False
        else:
            key, is_fwd = fwd_key, True
            flows[key] = _FlowAcc(fwd_key=fwd_key)

        flows[key].add_frames(frames, is_fwd)

    return [acc.to_dict() for acc in flows.values() if acc.total > 0]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _process_one(pcap: Path, label: str) -> list[dict]:
    rows = extract_flows(pcap)
    for r in rows:
        r["Label"] = label
    print(f"  {pcap.name}: {len(rows)} flows", flush=True)
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Extract per-flow DNP3 payload features from PCAP(s)."
    )
    ap.add_argument("pcap", nargs="?", help="single PCAP file")
    ap.add_argument("--label",          default="UNKNOWN",
                    help="class label to assign to all flows in this PCAP")
    ap.add_argument("--pcap-dir",       default=None,
                    help="directory of <LABEL>.pcap files (batch mode)")
    ap.add_argument("--label-from-stem", action="store_true",
                    help="use pcap filename stem as label (batch mode)")
    ap.add_argument("--out",            default="-",
                    help='output CSV path, or "-" for stdout')
    ap.add_argument("--port",           type=int, default=0,
                    help="DNP3 port filter (0 = no filter, accept all)")
    a = ap.parse_args()

    all_rows: list[dict] = []

    if a.pcap_dir:
        pcap_dir = Path(a.pcap_dir)
        pcaps = sorted(pcap_dir.glob("*.pcap"))
        if not pcaps:
            sys.exit(f"no .pcap files found in {pcap_dir}")
        for pcap in pcaps:
            label = pcap.stem if a.label_from_stem else a.label
            all_rows.extend(_process_one(pcap, label))
    elif a.pcap:
        all_rows.extend(_process_one(Path(a.pcap), a.label))
    else:
        ap.print_help()
        sys.exit(1)

    if not all_rows:
        sys.exit("no DNP3 flows found in input PCAP(s)")

    df = pd.DataFrame(all_rows)
    # reorder: Label last
    cols = [c for c in df.columns if c != "Label"] + ["Label"]
    df = df[cols]

    if a.out == "-":
        print(df.to_csv(index=False))
    else:
        out = Path(a.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(out, index=False)
        print(f"saved {len(df)} rows -> {out}")


if __name__ == "__main__":
    main()
