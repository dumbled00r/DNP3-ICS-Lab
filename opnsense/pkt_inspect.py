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
import threading
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Deque, Optional

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
# Per-flow payload feature accumulator (mirrors pcap_payload_features._FlowAcc)
# ---------------------------------------------------------------------------

class _FlowAcc:
    __slots__ = ("total", "fwd", "bwd", "attack_fc", "link_status",
                 "fc_counts", "udata_lens", "last_seen")

    def __init__(self) -> None:
        self.total = 0; self.fwd = 0; self.bwd = 0
        self.attack_fc = 0; self.link_status = 0
        self.fc_counts: dict[int, int] = collections.defaultdict(int)
        self.udata_lens: list[int] = []
        self.last_seen = time.monotonic()

    def add(self, frames, is_fwd: bool) -> None:
        self.last_seen = time.monotonic()
        for f in frames:
            self.total += 1
            if is_fwd: self.fwd += 1
            else:       self.bwd += 1
            if f.is_attack:      self.attack_fc += 1
            if f.is_link_status: self.link_status += 1
            if f.fc is not None: self.fc_counts[f.fc] += 1
            if f.user_data_len > 0: self.udata_lens.append(f.user_data_len)

    def to_feature_dict(self) -> dict:
        t = self.total or 1
        ud = self.udata_lens or [0]
        mc = max(self.fc_counts, key=self.fc_counts.get) if self.fc_counts else -1
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
            "most_common_req_fc": mc,
            "fc_read":            self.fc_counts.get(0x01, 0),
            "fc_cold_restart":    self.fc_counts.get(0x0D, 0),
            "fc_warm_restart":    self.fc_counts.get(0x0E, 0),
            "fc_init_data":       self.fc_counts.get(0x0F, 0),
            "fc_stop_app":        self.fc_counts.get(0x12, 0),
            "fc_init_app":        self.fc_counts.get(0x14, 0),
            "fc_disable_unsol":   self.fc_counts.get(0x15, 0),
            "fc_response":        self.fc_counts.get(0x81, 0),
            "fc_unsol_response":  self.fc_counts.get(0x82, 0),
            "mean_udata_len":     sum(ud) / len(ud),
            "max_udata_len":      max(ud),
            "min_udata_len":      min(ud),
        }


# ---------------------------------------------------------------------------
# Optional payload ML model loader
# ---------------------------------------------------------------------------

def _load_payload_model(path: Optional[str]):
    if not path:
        return None, None, None
    try:
        import joblib, numpy as np, pandas as pd
        art = joblib.load(path)
        return art["pipeline"], art["label_encoder"], art["features"]
    except Exception as e:
        print(f"[pkt_inspect] payload model load failed: {e}", file=sys.stderr)
        return None, None, None


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
        payload_model_path: Optional[str] = None,
        flow_timeout: float = 30.0,
    ) -> None:
        self._port = port
        self._log = logger
        self._scan = _RateTracker(scan_window, scan_threshold)
        self._last_fc_alert: dict[tuple, float] = {}
        self._fc_cooldown = 5.0

        # Per-flow accumulators keyed by canonical 4-tuple
        self._flows: dict[tuple, _FlowAcc] = {}
        self._flow_lock = threading.Lock()
        self._flow_timeout = flow_timeout

        # Payload ML model (optional)
        self._pipe, self._le, self._feats = _load_payload_model(payload_model_path)
        if self._pipe is not None:
            self._log.info("[pkt_inspect] payload ML model loaded from %s", payload_model_path)

        # Background thread to expire idle flows and run payload ML on them
        self._reaper = threading.Thread(target=self._reap_loop, daemon=True)
        self._reaper.start()

    def _flow_key(self, src_ip, src_port, dst_ip, dst_port) -> tuple:
        """Canonical bidirectional key (smaller tuple first)."""
        a = (src_ip, src_port, dst_ip, dst_port)
        b = (dst_ip, dst_port, src_ip, src_port)
        return a if a < b else b

    def handle_packet(self, pkt) -> None:
        try:
            from scapy.layers.inet import IP, TCP
            if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
                return
            tcp = pkt[TCP]
            ip  = pkt[IP]
            if tcp.dport != self._port and tcp.sport != self._port:
                return
            raw = bytes(tcp.payload)
            is_fwd = (tcp.dport == self._port)
            src_ip, dst_ip = ip.src, ip.dst

            frames = parse_payload(raw) if raw else []

            # --- Immediate per-frame rule checks ---
            for frame in frames:
                if frame.is_attack:
                    key = (src_ip, frame.fc)
                    now = time.monotonic()
                    if now - self._last_fc_alert.get(key, 0.0) >= self._fc_cooldown:
                        self._last_fc_alert[key] = now
                        self._log.warning(
                            "ALERT-PAYLOAD src=%s port=%d COMMAND_INJECTION fc=%s(0x%02X)",
                            src_ip, self._port, frame.attack_class, frame.fc,
                        )
                if frame.is_link_status:
                    if self._scan.record(src_ip):
                        self._log.warning(
                            "ALERT-PAYLOAD src=%s port=%d DNP3_RECON ctrl=0xC9 burst",
                            src_ip, self._port,
                        )

            # --- Accumulate into per-flow state (for payload ML) ---
            if frames and self._pipe is not None:
                fk = self._flow_key(src_ip, tcp.sport, dst_ip, tcp.dport)
                with self._flow_lock:
                    if fk not in self._flows:
                        self._flows[fk] = _FlowAcc()
                    self._flows[fk].add(frames, is_fwd)

            # --- Expire flow immediately on FIN/RST ---
            if self._pipe is not None:
                flags = tcp.flags
                if flags & 0x01 or flags & 0x04:   # FIN or RST
                    fk = self._flow_key(src_ip, tcp.sport, dst_ip, tcp.dport)
                    with self._flow_lock:
                        acc = self._flows.pop(fk, None)
                    if acc and acc.total > 0:
                        self._run_payload_ml(acc, src_ip)

        except Exception:
            pass

    def _run_payload_ml(self, acc: _FlowAcc, src_ip: str) -> None:
        try:
            import numpy as np, pandas as pd
            feat = acc.to_feature_dict()
            row  = pd.DataFrame([feat])[self._feats].astype(np.float32)
            pred_enc = self._pipe.predict(row)[0]
            proba    = self._pipe.predict_proba(row)[0]
            label    = self._le.inverse_transform([pred_enc])[0]
            conf     = float(proba[pred_enc])
            if label != "NORMAL":
                self._log.warning(
                    "ALERT-PAYLOAD-ML src=%s port=%d label=%s conf=%.2f "
                    "frames=%d attack_fc=%d link_status=%d",
                    src_ip, self._port, label, conf,
                    acc.total, acc.attack_fc, acc.link_status,
                )
            else:
                self._log.debug(
                    "PAYLOAD-ML NORMAL conf=%.2f frames=%d", conf, acc.total)
        except Exception as e:
            self._log.debug("payload ML error: %s", e)

    def _reap_loop(self) -> None:
        """Expire flows idle longer than _flow_timeout and run ML on them."""
        while True:
            time.sleep(5)
            cutoff = time.monotonic() - self._flow_timeout
            expired = []
            with self._flow_lock:
                for k, acc in list(self._flows.items()):
                    if acc.last_seen < cutoff:
                        expired.append((k, self._flows.pop(k)))
            for (src_ip, src_port, dst_ip, dst_port), acc in expired:
                if acc.total > 0:
                    self._run_payload_ml(acc, src_ip)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Live DNP3 payload inspector (COMMAND_INJECTION + recon + ML)"
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
    ap.add_argument("--payload-model",  default=None,
                    help="path to payload_model.joblib; enables per-flow ML "
                         "classification of COLD_RESTART/WARM_RESTART/etc.")
    ap.add_argument("--flow-timeout",   type=float, default=30.0,
                    help="seconds of inactivity before a flow is expired for ML scoring")
    a = ap.parse_args()

    logger = _setup_logger(a.log, a.log_level)
    logger.info(
        "[pkt_inspect] starting  iface=%s port=%d "
        "scan_threshold=%d scan_window=%.1fs payload_model=%s",
        a.iface or "default", a.port, a.scan_threshold, a.scan_window,
        a.payload_model or "none",
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
        payload_model_path=a.payload_model,
        flow_timeout=a.flow_timeout,
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
