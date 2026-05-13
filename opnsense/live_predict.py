"""Tail a cicflowmeter live CSV, predict each new flow, alert non-NORMAL.

Pairs with `cicflowmeter -i <iface> -c <csv>` running in the background.
Together they form: live capture -> feature extraction -> prediction -> alert.

Usage:
  live_predict.py --csv /var/log/dnp3guard/live.csv \
                  --model /usr/local/dnp3guard/model.joblib \
                  --log   /var/log/dnp3guard/verdicts.log
"""
from __future__ import annotations
import argparse, csv, logging, os, sys, time, threading
from logging.handlers import RotatingFileHandler
csv.field_size_limit(10 * 1024 * 1024)  # cicflowmeter rows can exceed default 131 KB
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

# Same rename map as pipeline/predict_pcap.py — keep both in sync.
CIC_RENAME = {
    "src_port": "Src Port", "dst_port": "Dst Port", "protocol": "Protocol",
    "timestamp": "Timestamp",
    "flow_duration": "Flow Duration",
    "flow_byts_s": "Flow Byts/s", "flow_pkts_s": "Flow Pkts/s",
    "fwd_pkts_s": "Fwd Pkts/s",  "bwd_pkts_s": "Bwd Pkts/s",
    "tot_fwd_pkts": "Tot Fwd Pkts", "tot_bwd_pkts": "Tot Bwd Pkts",
    "totlen_fwd_pkts": "TotLen Fwd Pkts", "totlen_bwd_pkts": "TotLen Bwd Pkts",
    "fwd_pkt_len_max": "Fwd Pkt Len Max", "fwd_pkt_len_min": "Fwd Pkt Len Min",
    "fwd_pkt_len_mean": "Fwd Pkt Len Mean", "fwd_pkt_len_std": "Fwd Pkt Len Std",
    "bwd_pkt_len_max": "Bwd Pkt Len Max", "bwd_pkt_len_min": "Bwd Pkt Len Min",
    "bwd_pkt_len_mean": "Bwd Pkt Len Mean", "bwd_pkt_len_std": "Bwd Pkt Len Std",
    "pkt_len_max": "Pkt Len Max", "pkt_len_min": "Pkt Len Min",
    "pkt_len_mean": "Pkt Len Mean", "pkt_len_std": "Pkt Len Std",
    "pkt_len_var": "Pkt Len Var",
    "fwd_header_len": "Fwd Header Len", "bwd_header_len": "Bwd Header Len",
    "fwd_seg_size_min": "Fwd Seg Size Min", "fwd_act_data_pkts": "Fwd Act Data Pkts",
    "flow_iat_mean": "Flow IAT Mean", "flow_iat_max": "Flow IAT Max",
    "flow_iat_min": "Flow IAT Min",   "flow_iat_std": "Flow IAT Std",
    "fwd_iat_tot": "Fwd IAT Tot", "fwd_iat_max": "Fwd IAT Max",
    "fwd_iat_min": "Fwd IAT Min", "fwd_iat_mean": "Fwd IAT Mean",
    "fwd_iat_std": "Fwd IAT Std",
    "bwd_iat_tot": "Bwd IAT Tot", "bwd_iat_max": "Bwd IAT Max",
    "bwd_iat_min": "Bwd IAT Min", "bwd_iat_mean": "Bwd IAT Mean",
    "bwd_iat_std": "Bwd IAT Std",
    "fwd_psh_flags": "Fwd PSH Flags", "bwd_psh_flags": "Bwd PSH Flags",
    "fwd_urg_flags": "Fwd URG Flags", "bwd_urg_flags": "Bwd URG Flags",
    "fin_flag_cnt": "FIN Flag Cnt", "syn_flag_cnt": "SYN Flag Cnt",
    "rst_flag_cnt": "RST Flag Cnt", "psh_flag_cnt": "PSH Flag Cnt",
    "ack_flag_cnt": "ACK Flag Cnt", "urg_flag_cnt": "URG Flag Cnt",
    "ece_flag_cnt": "ECE Flag Cnt", "cwr_flag_count": "CWE Flag Count",
    "down_up_ratio": "Down/Up Ratio", "pkt_size_avg": "Pkt Size Avg",
    "init_fwd_win_byts": "Init Fwd Win Byts", "init_bwd_win_byts": "Init Bwd Win Byts",
    "active_max": "Active Max", "active_min": "Active Min",
    "active_mean": "Active Mean", "active_std": "Active Std",
    "idle_max": "Idle Max", "idle_min": "Idle Min",
    "idle_mean": "Idle Mean", "idle_std": "Idle Std",
    "fwd_byts_b_avg": "Fwd Byts/b Avg", "fwd_pkts_b_avg": "Fwd Pkts/b Avg",
    "bwd_byts_b_avg": "Bwd Byts/b Avg", "bwd_pkts_b_avg": "Bwd Pkts/b Avg",
    "fwd_blk_rate_avg": "Fwd Blk Rate Avg", "bwd_blk_rate_avg": "Bwd Blk Rate Avg",
    "fwd_seg_size_avg": "Fwd Seg Size Avg", "bwd_seg_size_avg": "Bwd Seg Size Avg",
    "subflow_fwd_pkts": "Subflow Fwd Pkts", "subflow_bwd_pkts": "Subflow Bwd Pkts",
    "subflow_fwd_byts": "Subflow Fwd Byts", "subflow_bwd_byts": "Subflow Bwd Byts",
}


def setup_log(path, level="INFO"):
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[RotatingFileHandler(path, maxBytes=5_000_000, backupCount=3),
                  logging.StreamHandler(sys.stdout)],
    )


def load_model(p: Path):
    art = joblib.load(p)
    if not isinstance(art, dict) or "pipeline" not in art:
        raise SystemExit("model.joblib must be the dict produced by export_model.py")
    return art["pipeline"], art["label_encoder"], art["features"]


def predict_row(row: dict, pipe, le, feats) -> str:
    renamed = {CIC_RENAME.get(k, k): v for k, v in row.items()}
    X = pd.DataFrame([{c: renamed.get(c, 0) for c in feats}])
    X = X.replace([np.inf, -np.inf], 0).fillna(0).astype(float)
    return str(le.inverse_transform(pipe.predict(X))[0])


def follow_csv(path: Path):
    """Yield (header_dict, row_dict) for every new CSV row written to `path`."""
    while not path.exists():
        time.sleep(0.5)
    with open(path, "r", newline="") as f:
        # Wait for header line to land
        header = None
        while not header:
            line = f.readline()
            if line:
                header = next(csv.reader([line]))
                logging.info("CSV opened, %d columns", len(header))
            else:
                time.sleep(0.2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            try:
                values = next(csv.reader([line.rstrip("\n")]))
                if len(values) != len(header):
                    continue
                yield dict(zip(header, values))
            except Exception as e:
                logging.warning("bad CSV row: %s", e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv",   type=Path, required=True)
    ap.add_argument("--model", type=Path, required=True)
    ap.add_argument("--log",   type=Path, default=Path("/var/log/dnp3guard/verdicts.log"))
    ap.add_argument("--benign", default="NORMAL")
    ap.add_argument("--port", type=int, default=20000,
                    help="only score flows touching this TCP port (0=any)")
    ap.add_argument("--eve-json", default=None,
                    help="Suricata eve.json path; AI alerts on flows already "
                         "alerted on by Suricata are logged as SUPPRESSED")
    ap.add_argument("--eve-ttl", type=float, default=60.0,
                    help="seconds to keep Suricata alerts in the lookup cache")
    a = ap.parse_args()

    a.log.parent.mkdir(parents=True, exist_ok=True)
    setup_log(a.log)
    pipe, le, feats = load_model(a.model)
    logging.info("model loaded; %d features", len(feats))
    logging.info("watching %s", a.csv)

    eve = None
    if a.eve_json:
        try:
            from eve_watcher import EveWatcher
        except ImportError:
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            from eve_watcher import EveWatcher
        eve = EveWatcher(a.eve_json, ttl=a.eve_ttl)
        logging.info("EveWatcher tailing %s (ttl=%.0fs)", a.eve_json, a.eve_ttl)

    n = 0
    n_alerts = 0
    for row in follow_csv(a.csv):
        if a.port:
            try:
                sp = int(row.get("src_port", 0)); dp = int(row.get("dst_port", 0))
            except ValueError:
                sp = dp = 0
            if sp != a.port and dp != a.port:
                continue        # not DNP3, don't score against DNP3-only model
        try:
            verdict = predict_row(row, pipe, le, feats)
        except Exception as e:
            logging.exception("predict failed: %s", e)
            continue
        n += 1
        src   = row.get("src_ip", "?")
        dst   = row.get("dst_ip", "?")
        sp    = row.get("src_port", "?")
        dp    = row.get("dst_port", "?")
        if verdict != a.benign:
            covered = eve.lookup(src, sp, dst, dp) if eve else None
            if covered:
                sig_id, sig_nm = covered
                logging.info("SUPPRESS AI=%s sig=%d (%s) %s:%s->%s:%s",
                             verdict, sig_id, sig_nm, src, sp, dst, dp)
            else:
                n_alerts += 1
                tag = "ALERT-AI" if eve else "ALERT"
                logging.warning("%s %s %s:%s->%s:%s  flow=%d alerts=%d",
                                tag, verdict, src, sp, dst, dp, n, n_alerts)
        else:
            logging.info("ok    %s %s:%s->%s:%s  flow=%d",
                         verdict, src, sp, dst, dp, n)


if __name__ == "__main__":
    main()
