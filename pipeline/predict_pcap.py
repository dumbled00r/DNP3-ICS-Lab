"""End-to-end: pcap -> CICFlowMeter features -> trained model -> labelled CSV.

  python predict_pcap.py capture.pcap
  python predict_pcap.py capture.pcap --model artifacts/model.joblib --out out.csv

Produces:
  <pcap-name>_flows.csv        raw cicflowmeter output (same schema as data_sample)
  <pcap-name>_predicted.csv    same + 'predicted_label' column
And prints a class-count summary to stdout.
"""
from __future__ import annotations
import argparse, os, subprocess, sys, time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

# Map hieulw cicflowmeter v0.4.x snake_case columns -> data_sample/ "Title Case"
# column names that the model was trained on. Anything not in this map keeps
# its original name.
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


def run_cicflowmeter(pcap: Path, out_csv: Path) -> None:
    """Invoke hieulw/cicflowmeter CLI on the pcap."""
    if out_csv.exists():
        out_csv.unlink()
    cmd = ["cicflowmeter", "-f", str(pcap), "-c", str(out_csv)]
    print(f"[+] {' '.join(cmd)}")
    t0 = time.time()
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stdout + r.stderr)
        raise SystemExit(f"cicflowmeter failed (exit {r.returncode})")
    print(f"[+] flows extracted in {time.time()-t0:.1f}s -> {out_csv}")


def predict(flows_csv: Path, model_path: Path, out_csv: Path) -> pd.DataFrame:
    art = joblib.load(model_path)
    if not isinstance(art, dict) or "pipeline" not in art:
        raise SystemExit("model.joblib must be the dict produced by export_model.py")
    pipe, le, feats = art["pipeline"], art["label_encoder"], art["features"]

    if flows_csv.stat().st_size == 0:
        print(f"[!] {flows_csv} is empty — cicflowmeter produced 0 flows.")
        print("    Causes: pcap had no IP/TCP traffic, BPF filter excluded everything,")
        print("            or all flows were too short to terminate within the capture.")
        return None
    df = pd.read_csv(flows_csv)
    if df.empty:
        print(f"[!] no flow rows in {flows_csv}"); return None
    # hieulw cicflowmeter emits snake_case; rename to the "Title Case" schema
    # the model was trained on.
    df = df.rename(columns=CIC_RENAME)
    missing = [c for c in feats if c not in df.columns]
    if missing:
        print(f"[!] {len(missing)} feature(s) missing from cicflowmeter output, "
              f"filled with 0: {missing[:5]}{'...' if len(missing) > 5 else ''}")
        for c in missing:
            df[c] = 0
    X = df[feats].replace([np.inf, -np.inf], 0).fillna(0)

    yhat = le.inverse_transform(pipe.predict(X))
    df["predicted_label"] = yhat
    df.to_csv(out_csv, index=False)
    return df


def summary(df: pd.DataFrame) -> None:
    counts = df["predicted_label"].value_counts()
    total = int(counts.sum())
    print("\n=== Verdict summary ===")
    print(f"{'class':<22}{'count':>8}{'pct':>8}")
    for label, n in counts.items():
        print(f"{label:<22}{n:>8}{100*n/total:>7.1f}%")
    print(f"{'TOTAL':<22}{total:>8}")
    attacks = int((df["predicted_label"] != "NORMAL").sum())
    print(f"\n{attacks} attack flow(s) of {total} ({100*attacks/total:.1f}%)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", type=Path)
    ap.add_argument("--model", type=Path, default=Path("artifacts/model.joblib"))
    ap.add_argument("--flows", type=Path, default=None,
                    help="cicflowmeter CSV output path (default: <pcap>_flows.csv)")
    ap.add_argument("--out",   type=Path, default=None,
                    help="labelled CSV output path (default: <pcap>_predicted.csv)")
    ap.add_argument("--skip-extract", action="store_true",
                    help="reuse existing flows CSV instead of re-running cicflowmeter")
    a = ap.parse_args()

    if not a.pcap.exists():
        raise SystemExit(f"no such pcap: {a.pcap}")
    flows = a.flows or a.pcap.with_name(a.pcap.stem + "_flows.csv")
    out   = a.out   or a.pcap.with_name(a.pcap.stem + "_predicted.csv")

    if not a.skip_extract:
        run_cicflowmeter(a.pcap, flows)
    elif not flows.exists():
        raise SystemExit(f"--skip-extract set but {flows} missing")

    df = predict(flows, a.model, out)
    if df is None:
        return
    print(f"[+] labelled -> {out}")
    summary(df)


if __name__ == "__main__":
    main()
