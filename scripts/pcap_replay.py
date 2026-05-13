"""Replay DNP3 TCP flows from a PCAP to a live host:port.

Reads every master→outstation TCP payload from the PCAP and sends it as a
real TCP connection to --host:--port, so pkt_inspect.py (sniffing on the
interface) sees live DNP3 traffic and fires alerts.

Works with:
  • Lab pcaps      (DLT_NULL loopback, default port 20000)
  • UOWM pcaps     (DLT_EN10MB Ethernet, default port 20001)

The target needs something listening on --port to accept the connection.
Use lab/outstation_blackhole.py for a minimal sink:
  python3 lab/outstation_blackhole.py --host 127.0.0.1 --port 20000

Usage:
  # lab pcap (already the right port):
  python3 scripts/pcap_replay.py dataset/pcap/COLD_RESTART.pcap

  # UOWM attacker pcap (port 20001 in pcap -> our port 20000):
  python3 scripts/pcap_replay.py path/to/COLD_RESTART_Attacker.pcap --src-port 20001

  # Speed up 4x, verbose:
  python3 scripts/pcap_replay.py dataset/pcap/DNP3_INFO.pcap --speed 4 -v
"""
from __future__ import annotations

import argparse
import collections
import socket
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_HERE / "pipeline"))

try:
    from pcap_payload_features import _iter_tcp_payloads
except ImportError as e:
    sys.exit(f"Cannot import pipeline helpers: {e}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detect_dnp3_port(pcap: Path) -> int:
    """Return the most common dst_port in the pcap (likely the DNP3 port)."""
    counts: dict[int, int] = collections.Counter()
    for _, _, _, dst_port, _ in _iter_tcp_payloads(pcap):
        counts[dst_port] += 1
    if not counts:
        return 20000
    port = max(counts, key=counts.get)
    return port


def _collect_flows(pcap: Path, src_port: int) -> list[list[bytes]]:
    """Group forward payloads (going TO src_port) by TCP flow.

    Returns a list of flows; each flow is a list of payload chunks in order.
    """
    flows: dict[tuple, list[bytes]] = collections.OrderedDict()
    for s_ip, s_port, d_ip, d_port, data in _iter_tcp_payloads(pcap):
        if d_port != src_port:
            continue
        key = (s_ip, s_port, d_ip, d_port)
        flows.setdefault(key, []).append(data)
    return list(flows.values())


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------

def replay_flow(chunks: list[bytes], host: str, port: int,
                gap: float, verbose: bool) -> int:
    """Send one flow's chunks over a single TCP connection. Returns bytes sent."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((host, port))
    except OSError as e:
        print(f"  [!] connect failed: {e}")
        return 0

    sent = 0
    try:
        for chunk in chunks:
            s.sendall(chunk)
            sent += len(chunk)
            if gap > 0:
                time.sleep(gap)
    except OSError:
        pass
    finally:
        try:
            s.close()
        except OSError:
            pass

    if verbose:
        print(f"  -> {sent} bytes in {len(chunks)} segments")
    return sent


def run(args) -> None:
    pcap = Path(args.pcap)
    if not pcap.exists():
        sys.exit(f"File not found: {pcap}")

    # Determine which port to treat as the DNP3 destination in the pcap
    src_port = args.src_port
    if src_port == 0:
        src_port = _detect_dnp3_port(pcap)
        print(f"Auto-detected DNP3 port in pcap: {src_port}")

    flows = _collect_flows(pcap, src_port)
    if not flows:
        sys.exit(f"No forward DNP3 payloads found (dst_port={src_port}) in {pcap.name}\n"
                 f"Try --src-port 20001 for UOWM pcaps.")

    total_chunks = sum(len(f) for f in flows)
    total_bytes  = sum(sum(len(c) for c in f) for f in flows)
    print(f"PCAP     : {pcap.name}")
    print(f"Flows    : {len(flows)}")
    print(f"Segments : {total_chunks}")
    print(f"Bytes    : {total_bytes}")
    print(f"Target   : {args.host}:{args.port}")
    print(f"Speed    : {args.speed}x   gap={args.gap/args.speed*1000:.1f} ms/segment")
    print()

    gap = args.gap / args.speed
    flow_pause = args.flow_pause / args.speed
    sent_total = 0

    for i, chunks in enumerate(flows):
        if args.verbose:
            print(f"Flow {i+1}/{len(flows)}  ({len(chunks)} segments)")
        sent_total += replay_flow(chunks, args.host, args.port, gap, args.verbose)
        if i < len(flows) - 1 and flow_pause > 0:
            time.sleep(flow_pause)

    print(f"\nDone. Sent {sent_total} bytes across {len(flows)} flows.")
    print(f"Check: tail /var/log/dnp3guard/verdicts.log")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Replay DNP3 PCAP traffic to a live endpoint for detection testing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("pcap",
                    help="PCAP file to replay")
    ap.add_argument("--host",       default="127.0.0.1",
                    help="target host (default: 127.0.0.1)")
    ap.add_argument("--port",       type=int, default=20000,
                    help="target TCP port pkt_inspect.py is monitoring (default: 20000)")
    ap.add_argument("--src-port",   type=int, default=0,
                    help="DNP3 port *in the pcap* to treat as destination "
                         "(0 = auto-detect; use 20001 for UOWM pcaps)")
    ap.add_argument("--speed",      type=float, default=1.0,
                    help="playback speed multiplier (2.0 = twice as fast)")
    ap.add_argument("--gap",        type=float, default=0.005,
                    help="inter-segment delay in seconds at 1x speed (default: 0.005)")
    ap.add_argument("--flow-pause", type=float, default=1.0,
                    help="pause between flows in seconds at 1x speed (default: 1.0)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
