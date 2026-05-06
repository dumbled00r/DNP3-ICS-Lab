"""Train the chosen model on the full balanced dataset and dump artifacts
that dnp3guard on OPNsense will load: model.joblib + features.txt.

We deliberately pick a sklearn-only model (XGBoost or RandomForest) and
bundle preprocessing into a Pipeline, so OPNsense doesn't need
TensorFlow/Keras (heavy and painful on FreeBSD).

Usage:
  python export_model.py --model xgb        # default
  python export_model.py --model rf
"""
import argparse, os, joblib
import numpy as np
import pandas as pd

from sklearn.feature_selection import VarianceThreshold
from sklearn.preprocessing  import StandardScaler, LabelEncoder
from sklearn.pipeline       import Pipeline
from sklearn.ensemble       import RandomForestClassifier
from sklearn.metrics        import accuracy_score
from xgboost                import XGBClassifier

TRAIN_CSV = r"d:\BKCSLab\DNP3\ics_lab\data_sample\CICFlowMeter_Training_Balanced.csv"
TEST_CSV  = r"d:\BKCSLab\DNP3\ics_lab\data_sample\CICFlowMeter_Testing_Balanced.csv"
OUT_DIR   = r"d:\BKCSLab\DNP3\ics_lab\artifacts"

DROP_COLS = ["Unnamed: 0.1", "Unnamed: 0", "Flow ID",
             "Src IP", "Dst IP", "Timestamp"]


def load(path):
    df = pd.read_csv(path)
    for c in DROP_COLS:
        if c in df.columns:
            df.drop(columns=c, inplace=True)
    y = df.pop("Label").values
    df = df.select_dtypes(include=[np.number])
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(df.median(), inplace=True)
    return df, y


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=["xgb", "rf"], default="xgb")
    args = ap.parse_args()
    os.makedirs(OUT_DIR, exist_ok=True)

    Xtr, ytr = load(TRAIN_CSV)
    Xte, yte = load(TEST_CSV)
    common = [c for c in Xtr.columns if c in Xte.columns]
    Xtr = Xtr[common].astype(np.float32)
    Xte = Xte[common].astype(np.float32)

    # Variance threshold on numpy to avoid feature-name warning, then re-wrap.
    vt = VarianceThreshold(0.0).fit(Xtr.to_numpy())
    kept = [common[i] for i in vt.get_support(indices=True)]
    Xtr = pd.DataFrame(vt.transform(Xtr.to_numpy()), columns=kept)
    Xte = pd.DataFrame(vt.transform(Xte.to_numpy()), columns=kept)
    print(f"kept {len(kept)}/{len(common)} features")

    le = LabelEncoder().fit(ytr)
    ytr_enc, yte_enc = le.transform(ytr), le.transform(yte)

    if args.model == "xgb":
        clf = XGBClassifier(n_estimators=400, max_depth=8, learning_rate=0.1,
                            tree_method="hist", n_jobs=-1, eval_metric="mlogloss",
                            random_state=42, verbosity=0)
    else:
        clf = RandomForestClassifier(n_estimators=400, n_jobs=-1, random_state=42)

    pipe = Pipeline([("scaler", StandardScaler()), ("clf", clf)])
    pipe.fit(Xtr, ytr_enc)

    # Compute accuracy manually instead of pipe.score() — avoids a sklearn>=1.6
    # / xgboost<2.1 incompatibility in __sklearn_tags__.
    yhat = pipe.predict(Xte)
    print(f"test acc = {accuracy_score(yte_enc, yhat):.4f}")

    # Save as a plain dict so loading on OPNsense doesn't need any custom class
    # to be importable (no module-shipping headaches).
    artifact = {"pipeline": pipe, "label_encoder": le, "features": kept}
    joblib.dump(artifact, os.path.join(OUT_DIR, "model.joblib"))
    with open(os.path.join(OUT_DIR, "features.txt"), "w") as f:
        f.write("\n".join(kept) + "\n")
    print(f"saved -> {OUT_DIR}/model.joblib  ({len(kept)} features)")
    print(f"saved -> {OUT_DIR}/features.txt")


if __name__ == "__main__":
    main()
