"""Live DNP3 payload inspector — payload-based detection path.

Sniffs TCP/{port} traffic with scapy, parses each packet's DNP3 payload,
and fires instant alerts for:

  COMMAND_INJECTION  -- app-layer FC in {cold_restart, warm_restart, init_data,
                         stop_app, init_application, disable_unsolicited}
                         (FC bytes 0x0D/0x0E/0x0F/0x10/0x12/0x14/0x15)

  DNP3_RECON         -- link-layer ctrl=0xC9 (REQUEST_LINK_STATUS) bursts
                         from one source exceeding --scan-threshold within
                         --scan-window seconds  (DNP3_INFO / DNP3_ENUMERATE)

Both alert types are written to --log (same verdicts.log used by live_predict.py).
The log format is identical so downstream consumers (dnp3guard.py, syslog, etc.)
see a single stream.

Designed to run alongside live_predict.py:
  live_predict.py handles MITM_DOS / REPLAY / ARP_POISONING (flow ML)
  pkt_inspect.py  handles COMMAND_INJECTION / DNP3_RECON (payload)

Usage:
  python pkt_inspect.py --iface vmx0 --port 20000
  python pkt_inspect.py --iface vmx0 --port 20000 --log /var/log/dnp3guard/verdicts.log
  python pkt_inspect.py --iface igb1 --port 20000 --scan-threshold 30 --scan-window 5
"""
from __future__ import annotations

import argparse
import collections
import logging
import os
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Deque

# ---------------------------------------------------------------------------
# Path setup: works both from repo (opnsense/) and installed (/usr/local/dnp3guard/)
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent
# Repo layout: opnsense/../pipeline; Installed layout: dnp3guard/pipeline
for _candidate in (_HERE.parent / "pipeline", _HERE / "pipeline"):
    if (_candidate / "dnp3_parse.py").exists():
        sys.path.insert(0, str(_candidate))
        break

try:
    from dnp3_parse import parse_payload, ATTACK_FC, LINK_STATUS_CTRL
except ImportError as _e:
    sys.exit(f"[pkt_inspect] cannot import dnp3_parse.py: {_e}")

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

def _setup_logger(log_path: str, level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("pkt_inspect")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    fh = RotatingFileHandler(log_path, maxBytes=20 * 1024 * 1024, backupCount=5)
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger


# ---------------------------------------------------------------------------
# Per-source sliding-window rate tracker (for ctrl=0xC9 scan detection)
# ---------------------------------------------------------------------------

class _RateTracker:
    """Tracks event timestamps per source IP in a sliding window."""

    def __init__(self, window_sec: float, threshold: int) -> None:
        self._window = window_sec
        self._threshold = threshold
        self._events: dict[str, Deque[float]] = collections.defaultdict(
            lambda: collections.deque()
        )
        # Cooldown: don't re-alert the same src within window_sec
        self._last_alert: dict[str, float] = {}

    def record(self, src_ip: str) -> bool:
        """Add an event for src_ip.  Returns True if threshold is exceeded."""
        now = time.monotonic()
        dq = self._events[src_ip]
        dq.append(now)
        cutoff = now - self._window
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) >= self._threshold:
            last = self._last_alert.get(src_ip, 0.0)
            if now - last >= self._window:
                self._last_alert[src_ip] = now
                return True
        return False


# ---------------------------------------------------------------------------
# Packet callback
# ---------------------------------------------------------------------------

class Inspector:
    def __init__(
        self,
        port: int,
        logger: logging.Logger,
        scan_threshold: int,
        scan_window: float,
    ) -> None:
        self._port = port
        self._log = logger
        self._scan = _RateTracker(scan_window, scan_threshold)
        # Cooldown for COMMAND_INJECTION per (src_ip, fc) to reduce log flood
        self._last_fc_alert: dict[tuple, float] = {}
        self._fc_cooldown = 5.0  # seconds between repeated FC alerts

    def handle_packet(self, pkt) -> None:  # type: ignore[no-untyped-def]
        try:
            from scapy.layers.inet import IP, TCP
            if not pkt.haslayer(TCP):
                return
            tcp = pkt[TCP]
            if tcp.dport != self._port and tcp.sport != self._port:
                return
            raw = bytes(tcp.payload)
            if not raw:
                return

            src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"
            self._inspect(src_ip, raw)
        except Exception:
            pass

    def _inspect(self, src_ip: str, payload: bytes) -> None:
        frames = parse_payload(payload)
        for frame in frames:
            # --- COMMAND_INJECTION check ---
            if frame.is_attack:
                key = (src_ip, frame.fc)
                now = time.monotonic()
                last = self._last_fc_alert.get(key, 0.0)
                if now - last >= self._fc_cooldown:
                    self._last_fc_alert[key] = now
                    self._log.warning(
                        "ALERT-PAYLOAD src=%s port=%d COMMAND_INJECTION fc=%s(0x%02X)",
                        src_ip, self._port, frame.attack_class, frame.fc
                    )

            # --- Scan / recon check (ctrl=0xC9 rate) ---
            if frame.is_link_status:
                if self._scan.record(src_ip):
                    self._log.warning(
                        "ALERT-PAYLOAD src=%s port=%d DNP3_RECON "
                        "ctrl=0xC9 burst detected",
                        src_ip, self._port
                    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Live DNP3 payload inspector (COMMAND_INJECTION + recon)"
    )
    ap.add_argument("--iface",          default=None,
                    help="capture interface (None = scapy default)")
    ap.add_argument("--port",           type=int,   default=20000,
                    help="DNP3 TCP port to monitor")
    ap.add_argument("--log",            default="/var/log/dnp3guard/verdicts.log")
    ap.add_argument("--log-level",      default="INFO")
    ap.add_argument("--scan-threshold", type=int,   default=40,
                    help="ctrl=0xC9 packets per src within window to trigger DNP3_RECON")
    ap.add_argument("--scan-window",    type=float, default=10.0,
                    help="sliding window in seconds for scan rate counting")
    a = ap.parse_args()

    logger = _setup_logger(a.log, a.log_level)
    logger.info(
        "[pkt_inspect] starting  iface=%s port=%d "
        "scan_threshold=%d scan_window=%.1fs",
        a.iface or "default", a.port, a.scan_threshold, a.scan_window
    )

    try:
        from scapy.all import sniff
    except ImportError:
        sys.exit("[pkt_inspect] scapy not installed: pip install scapy")

    inspector = Inspector(
        port=a.port,
        logger=logger,
        scan_threshold=a.scan_threshold,
        scan_window=a.scan_window,
    )

    bpf = f"tcp port {a.port}"
    kwargs: dict = {"filter": bpf, "prn": inspector.handle_packet, "store": False}
    if a.iface:
        kwargs["iface"] = a.iface

    try:
        sniff(**kwargs)
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("[pkt_inspect] stopped")


if __name__ == "__main__":
    main()
