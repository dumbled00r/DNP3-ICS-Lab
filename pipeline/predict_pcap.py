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

    df = pd.read_csv(flows_csv)
    # cicflowmeter and the training csv use the same human-readable column
    # names. Anything missing -> 0; anything extra -> ignored.
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
    print(f"[+] labelled -> {out}")
    summary(df)


if __name__ == "__main__":
    main()
