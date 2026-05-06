"""Concatenate per-class cicflowmeter CSVs, add Label column, 80/20 split,
emit Training_Balanced.csv + Testing_Balanced.csv mirroring data_sample/.

Also renames hieulw cicflowmeter snake_case columns to data_sample's Title
Case so the existing export_model.py / dnp3_anomaly_detection.py work
unchanged.
"""
import argparse, sys
from pathlib import Path
import numpy as np
import pandas as pd

# import the same rename map the predict path uses, to keep one source of truth
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pipeline"))
from predict_pcap import CIC_RENAME


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv-dir", required=True, type=Path,
                    help="dir containing <CLASS>.csv files (one per label)")
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--test-frac", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()

    frames = []
    for csv in sorted(a.csv_dir.glob("*.csv")):
        label = csv.stem
        try:
            df = pd.read_csv(csv)
        except pd.errors.EmptyDataError:
            print(f"  skip {csv.name} (empty)"); continue
        if df.empty:
            print(f"  skip {csv.name} (no rows)"); continue
        df = df.rename(columns=CIC_RENAME)
        df["Label"] = label
        frames.append(df)
        print(f"  {label:<22} {len(df):>5} flows")

    if not frames:
        raise SystemExit("no CSVs with rows in --csv-dir")

    full = pd.concat(frames, ignore_index=True, sort=False)
    full = full.sample(frac=1.0, random_state=a.seed).reset_index(drop=True)

    cut = int(len(full) * (1 - a.test_frac))
    train, test = full.iloc[:cut], full.iloc[cut:]

    a.out_dir.mkdir(parents=True, exist_ok=True)
    train.to_csv(a.out_dir / "MyDataset_Training_Balanced.csv", index=False)
    test.to_csv (a.out_dir / "MyDataset_Testing_Balanced.csv",  index=False)

    print(f"\nTotal: {len(full)} flows  ({len(train)} train / {len(test)} test)")
    print("Per-class counts:")
    print(full["Label"].value_counts().to_string())
    print(f"\nWritten to {a.out_dir}/")


if __name__ == "__main__":
    main()
