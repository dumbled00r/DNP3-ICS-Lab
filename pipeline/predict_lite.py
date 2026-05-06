"""Score a CICFlowMeter CSV against the lite bundle (no sklearn, no scipy).

Inputs : <pcap>.csv from cicflowmeter, plus artifacts/bundle/
Outputs: <pcap>_predicted.csv  + class-count summary

Loads only numpy + xgboost. Designed for OPNsense.

  python predict_lite.py flows.csv
  python predict_lite.py flows.csv --bundle /usr/local/dnp3guard/bundle
  python predict_lite.py capture.pcap --extract           # also runs cicflowmeter
"""
from __future__ import annotations
import argparse, os, subprocess, sys, time
from pathlib import Path

import numpy as np
import xgboost as xgb


def load_bundle(d: Path):
    sc = np.load(d / "scaler.npz")
    booster = xgb.Booster()
    booster.load_model(str(d / "model.ubj"))
    feats  = (d / "features.txt").read_text().splitlines()
    feats  = [l.strip() for l in feats if l.strip() and not l.startswith("#")]
    labels = (d / "labels.txt").read_text().splitlines()
    labels = [l.strip() for l in labels if l.strip()]
    return sc["mean"], sc["scale"], booster, feats, labels


def read_csv(path: Path):
    """Tiny CSV reader: returns (header_list, rows_as_dict_list).  Avoids pandas."""
    import csv
    with open(path, newline="") as f:
        r = csv.DictReader(f)
        rows = list(r)
        header = r.fieldnames or []
    return header, rows


def to_matrix(rows, feats):
    n = len(rows)
    X = np.zeros((n, len(feats)), dtype=np.float32)
    for i, row in enumerate(rows):
        for j, c in enumerate(feats):
            v = row.get(c, "")
            try:
                f = float(v)
                if not np.isfinite(f): f = 0.0
            except (TypeError, ValueError):
                f = 0.0
            X[i, j] = f
    return X


def run_cicflowmeter(pcap: Path, out_csv: Path):
    if out_csv.exists(): out_csv.unlink()
    cmd = ["cicflowmeter", "-f", str(pcap), "-c", str(out_csv)]
    print(f"[+] {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stdout + r.stderr)
        raise SystemExit(f"cicflowmeter failed (exit {r.returncode})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=Path, help="flows.csv  OR  capture.pcap (with --extract)")
    ap.add_argument("--bundle", type=Path,
                    default=Path("/usr/local/dnp3guard/bundle"))
    ap.add_argument("--extract", action="store_true",
                    help="treat <input> as a pcap and run cicflowmeter first")
    ap.add_argument("--out", type=Path, default=None)
    a = ap.parse_args()

    if a.extract:
        flows = a.input.with_name(a.input.stem + "_flows.csv")
        run_cicflowmeter(a.input, flows)
    else:
        flows = a.input
    if not flows.exists():
        raise SystemExit(f"no such file: {flows}")

    mean, scale, booster, feats, labels = load_bundle(a.bundle)
    header, rows = read_csv(flows)
    if not rows:
        print("[!] zero flows in csv — nothing to score"); return

    X = to_matrix(rows, feats)
    Xs = (X - mean) / np.where(scale == 0, 1, scale)
    yhat_idx = booster.predict(xgb.DMatrix(Xs)).astype(int)
    yhat = [labels[i] if 0 <= i < len(labels) else f"<unk:{i}>" for i in yhat_idx]

    out = a.out or flows.with_name(flows.stem.replace("_flows", "") + "_predicted.csv")
    with open(out, "w") as f:
        f.write(",".join(header + ["predicted_label"]) + "\n")
        for row, lbl in zip(rows, yhat):
            f.write(",".join(_q(row.get(h, "")) for h in header) + f",{lbl}\n")
    print(f"[+] labelled -> {out}")

    from collections import Counter
    cnt = Counter(yhat); total = len(yhat)
    print("\n=== Verdict summary ===")
    print(f"{'class':<22}{'count':>8}{'pct':>8}")
    for lbl, n in cnt.most_common():
        print(f"{lbl:<22}{n:>8}{100*n/total:>7.1f}%")
    print(f"{'TOTAL':<22}{total:>8}")
    atk = sum(n for l, n in cnt.items() if l != "NORMAL")
    print(f"\n{atk} attack flow(s) of {total} ({100*atk/total:.1f}%)")


def _q(s):
    s = str(s)
    return f'"{s}"' if "," in s or '"' in s else s


if __name__ == "__main__":
    main()
