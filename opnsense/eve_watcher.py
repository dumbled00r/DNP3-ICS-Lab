"""Tail Suricata's eve.json and cache recent alert 5-tuples for correlation.

Used by live_predict.py to suppress AI alerts on flows Suricata already
detected via signature match.
"""
from __future__ import annotations
import json, logging, os, threading, time
from pathlib import Path
from typing import Optional


class EveWatcher:
    """Background tail of eve.json. Maintains a TTL cache keyed by the
    5-tuple (src_ip, src_port, dst_ip, dst_port). Lookup is O(1)."""

    def __init__(self, path: str, ttl: float = 60.0):
        self.path = Path(path)
        self.ttl  = ttl
        # value = (last_seen_ts, signature_id, signature_name)
        self._cache: dict[tuple, tuple] = {}
        self._lock = threading.Lock()
        self._stop = False
        self._t = threading.Thread(target=self._tail, daemon=True)
        self._t.start()

    def lookup(self, src_ip: str, src_port: int,
               dst_ip: str, dst_port: int) -> Optional[tuple]:
        """Return (sig_id, sig_name) if a Suricata alert matches this 5-tuple
        within the TTL window, else None."""
        key = (src_ip, int(src_port), dst_ip, int(dst_port))
        cutoff = time.time() - self.ttl
        with self._lock:
            v = self._cache.get(key)
            if v and v[0] >= cutoff:
                return (v[1], v[2])
            # also try the reverse direction (Suricata may have logged
            # response packets first if the alert was on a backward packet)
            rkey = (dst_ip, int(dst_port), src_ip, int(src_port))
            v = self._cache.get(rkey)
            if v and v[0] >= cutoff:
                return (v[1], v[2])
        return None

    def _tail(self):
        while not self._stop:
            try:
                self._tail_loop()
            except Exception as e:
                logging.warning("EveWatcher tail error: %s; retry in 2s", e)
                time.sleep(2)

    def _tail_loop(self):
        # Wait for the file to exist
        while not self.path.exists() and not self._stop:
            time.sleep(1)
        with open(self.path, "r") as f:
            f.seek(0, os.SEEK_END)             # start at tail
            while not self._stop:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    self._purge()
                    continue
                self._ingest(line)

    def _ingest(self, line: str):
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            return
        if ev.get("event_type") != "alert":
            return
        s_ip   = ev.get("src_ip");   s_port = ev.get("src_port")
        d_ip   = ev.get("dest_ip");  d_port = ev.get("dest_port")
        if None in (s_ip, s_port, d_ip, d_port):
            return
        sig    = ev.get("alert", {}) or {}
        sig_id = sig.get("signature_id", 0)
        sig_nm = sig.get("signature", "")
        key = (s_ip, int(s_port), d_ip, int(d_port))
        now = time.time()
        with self._lock:
            self._cache[key] = (now, sig_id, sig_nm)

    def _purge(self):
        cutoff = time.time() - self.ttl
        with self._lock:
            for k, v in list(self._cache.items()):
                if v[0] < cutoff:
                    del self._cache[k]

    def stop(self):
        self._stop = True
