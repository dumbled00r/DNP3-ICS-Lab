"""Print a per-class report + confusion matrix for the deployed model on
the test CSV. Highlights which classes the model is confusing.
"""
import argparse
from pathlib import Path
import joblib, numpy as np, pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

DROP_COLS = ["Unnamed: 0.1", "Unnamed: 0", "Flow ID",
             "Src IP", "Dst IP", "Timestamp"]


def load(path):
    df = pd.read_csv(path)
    for c in DROP_COLS:
        if c in df.columns: df.drop(columns=c, inplace=True)
    y = df.pop("Label").values
    df = df.select_dtypes(include=[np.number])
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(df.median(), inplace=True)
    return df, y


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="/usr/local/dnp3guard/model.joblib")
    ap.add_argument("--test",  default="/var/log/dnp3guard/dataset/MyDataset_Testing_Balanced.csv")
    a = ap.parse_args()

    art = joblib.load(a.model)
    pipe, le, feats = art["pipeline"], art["label_encoder"], art["features"]

    Xte, yte = load(a.test)
    for c in feats:
        if c not in Xte.columns: Xte[c] = 0
    X = Xte[feats].astype(np.float32)
    y_true = le.transform(yte)
    y_pred = pipe.predict(X)

    print(classification_report(y_true, y_pred,
        labels=range(len(le.classes_)), target_names=le.classes_,
        digits=4, zero_division=0))
    cm = confusion_matrix(y_true, y_pred, labels=range(len(le.classes_)))
    cm_df = pd.DataFrame(cm, index=le.classes_, columns=le.classes_)
    print("Confusion matrix (rows=true, cols=pred):")
    with pd.option_context("display.max_columns", None, "display.width", 200):
        print(cm_df.to_string())


if __name__ == "__main__":
    main()
