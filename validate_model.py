"""Score the held-out test CSV with the saved model.joblib and print metrics.

Tells you definitively whether the model itself works — no cicflowmeter, no
live capture, no OPNsense in the loop.
"""
import os
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (accuracy_score, f1_score, classification_report,
                             confusion_matrix)

TEST_CSV = Path(r"d:\BKCSLab\DNP3\ics_lab\data_sample\CICFlowMeter_Testing_Balanced.csv")
MODEL    = Path(r"d:\BKCSLab\DNP3\ics_lab\artifacts\model.joblib")

DROP_COLS = ["Unnamed: 0.1", "Unnamed: 0", "Flow ID",
             "Src IP", "Dst IP", "Timestamp"]


def main():
    art  = joblib.load(MODEL)
    pipe = art["pipeline"]; le = art["label_encoder"]; feats = art["features"]

    df = pd.read_csv(TEST_CSV)
    for c in DROP_COLS:
        if c in df.columns: df.drop(columns=c, inplace=True)
    y_true_str = df.pop("Label").values
    df = df.select_dtypes(include=[np.number])
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(df.median(), inplace=True)

    missing = [c for c in feats if c not in df.columns]
    if missing:
        raise SystemExit(f"missing features: {missing}")
    X = df[feats].astype(np.float32)

    y_true = le.transform(y_true_str)
    y_pred = pipe.predict(X)

    acc = accuracy_score(y_true, y_pred)
    f1m = f1_score(y_true, y_pred, average="macro")
    f1w = f1_score(y_true, y_pred, average="weighted")
    print(f"\nTest set: {len(y_true)} flows, {len(le.classes_)} classes")
    print(f"  accuracy        : {acc:.4f}")
    print(f"  macro f1        : {f1m:.4f}")
    print(f"  weighted f1     : {f1w:.4f}\n")

    print("Per-class report:")
    print(classification_report(
        y_true, y_pred,
        labels=range(len(le.classes_)),
        target_names=le.classes_,
        digits=4, zero_division=0,
    ))

    cm = confusion_matrix(y_true, y_pred, labels=range(len(le.classes_)))
    cm_df = pd.DataFrame(cm, index=le.classes_, columns=le.classes_)
    print("Confusion matrix (rows=true, cols=pred):")
    with pd.option_context("display.max_columns", None, "display.width", 200):
        print(cm_df.to_string())

    # Worst classes (lowest f1) — likely the same ones the live system will miss
    f1_per = f1_score(y_true, y_pred, average=None,
                      labels=range(len(le.classes_)), zero_division=0)
    print("\nClasses ranked by F1 (worst first):")
    for cls, score in sorted(zip(le.classes_, f1_per), key=lambda t: t[1]):
        print(f"  {cls:<22} f1={score:.4f}")


if __name__ == "__main__":
    main()
