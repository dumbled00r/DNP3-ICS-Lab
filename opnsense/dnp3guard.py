"""dnp3guard — live DNP3 flow scoring on OPNsense.

Pipeline:
  scapy sniff (BPF tcp port 20000)
    -> cicflowmeter FlowSession (in-process)
    -> on each completed flow -> feature vector -> model.predict()
    -> if verdict != benign -> POST OPNsense API to add src IP to alias
"""
from __future__ import annotations
import argparse, configparser, ipaddress, logging, signal, sys, threading, time
from collections import deque
from logging.handlers import RotatingFileHandler

import joblib
import numpy as np
import pandas as pd
import requests
from scapy.sendrecv import sniff
from cicflowmeter.flow_session import FlowSession   # hieulw/cicflowmeter


# ---------- OPNsense API ----------
class OPNsense:
    def __init__(self, base, key, secret, verify, alias, ttl):
        self.s = requests.Session()
        self.s.auth = (key, secret)
        self.s.verify = verify
        self.base, self.alias, self.ttl = base.rstrip("/"), alias, ttl
        self._cache: dict[str, float] = {}
        self._lock = threading.Lock()

    def block(self, ip: str, reason: str):
        with self._lock:
            now = time.time()
            # de-dupe: don't re-POST if blocked within last 60s
            if now - self._cache.get(ip, 0) < 60:
                return
            self._cache[ip] = now
        url = f"{self.base}/api/firewall/alias_util/add/{self.alias}"
        try:
            r = self.s.post(url, json={"address": ip}, timeout=5)
            r.raise_for_status()
            logging.warning("BLOCK %s reason=%s api=%s", ip, reason, r.status_code)
            if self.ttl > 0:
                threading.Timer(self.ttl, self._unblock, (ip,)).start()
        except Exception as e:
            logging.error("OPNsense API block failed for %s: %s", ip, e)

    def _unblock(self, ip):
        url = f"{self.base}/api/firewall/alias_util/delete/{self.alias}"
        try:
            self.s.post(url, json={"address": ip}, timeout=5)
            logging.info("UNBLOCK %s (ttl expired)", ip)
        except Exception as e:
            logging.error("OPNsense API unblock failed for %s: %s", ip, e)


# ---------- scoring sink ----------
class Scorer:
    def __init__(self, model, feature_cols, benign_label, opnsense):
        self.model = model
        self.cols = feature_cols
        self.benign = benign_label
        self.opn = opnsense
        self.recent = deque(maxlen=500)

    def __call__(self, flow_dict: dict):
        try:
            row = {c: flow_dict.get(c, 0) for c in self.cols}
            X = pd.DataFrame([row], columns=self.cols).fillna(0).replace(
                [np.inf, -np.inf], 0)
            verdict = str(self.model.predict(X)[0])
            src = flow_dict.get("src_ip") or flow_dict.get("Src IP")
            self.recent.append((time.time(), src, verdict))
            if verdict != self.benign:
                logging.warning("flow %s -> %s", src, verdict)
                if src and self._is_routable(src):
                    self.opn.block(src, verdict)
            else:
                logging.debug("flow %s -> %s", src, verdict)
        except Exception as e:
            logging.exception("scoring failed: %s", e)

    @staticmethod
    def _is_routable(ip: str) -> bool:
        try:
            return not ipaddress.ip_address(ip).is_loopback
        except ValueError:
            return False


# ---------- glue: cicflowmeter session that calls our scorer per flow ----------
class ScoringSession(FlowSession):
    """Wraps FlowSession.  When it would normally write a CSV row, call scorer."""
    scorer: Scorer = None              # injected before sniff()
    _gc_interval = 1                   # check expired flows every N packets

    def garbage_collect(self, latest_time):
        # FlowSession.garbage_collect emits expired flows.  Capture them.
        keys = list(self.flows.keys())
        for k in keys:
            flow = self.flows[k]
            if latest_time is not None and (latest_time - flow.latest_timestamp) > self.flow_timeout:
                data = flow.get_data()
                if ScoringSession.scorer:
                    ScoringSession.scorer(data)
                del self.flows[k]


# ---------- main ----------
def setup_log(path, level):
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[RotatingFileHandler(path, maxBytes=5_000_000, backupCount=3),
                  logging.StreamHandler(sys.stdout)],
    )

def load_features(path):
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    args = ap.parse_args()

    cfg = configparser.ConfigParser()
    cfg.read(args.config)

    setup_log(cfg["log"]["path"], cfg["log"].get("level", "INFO"))
    logging.info("dnp3guard starting; iface=%s", cfg["capture"]["iface"])

    model = joblib.load(cfg["model"]["path"])
    feats = load_features(cfg["model"]["features_file"])
    logging.info("model loaded; %d features", len(feats))

    opn = OPNsense(
        cfg["opnsense_api"]["base_url"],
        cfg["opnsense_api"]["key"],
        cfg["opnsense_api"]["secret"],
        cfg["opnsense_api"].getboolean("verify_tls", fallback=False),
        cfg["opnsense_api"]["alias_name"],
        cfg["opnsense_api"].getint("block_ttl_sec", fallback=3600),
    )

    ScoringSession.scorer = Scorer(model, feats, cfg["model"]["benign_label"], opn)
    ScoringSession.flow_timeout = cfg["capture"].getint("flow_timeout", fallback=15)

    # graceful shutdown
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT,  lambda *_: stop.set())

    sniff(
        iface=cfg["capture"]["iface"],
        filter=cfg["capture"]["bpf"],
        session=ScoringSession,
        store=False,
        stop_filter=lambda *_: stop.is_set(),
    )
    logging.info("dnp3guard stopped")

if __name__ == "__main__":
    main()
