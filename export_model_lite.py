"""Export the trained model in a scikit-learn-free, scipy-free bundle that
runs on OPNsense with only numpy + xgboost installed.

Inputs : artifacts/model.joblib  (the sklearn Pipeline + LabelEncoder dict)
Outputs: artifacts/bundle/
           scaler.npz     (mean, scale  -- StandardScaler params)
           model.ubj      (xgboost native binary)
           labels.txt     (one class per line, in encoder order)
           features.txt   (copied from artifacts/)
"""
import json, os, shutil
from pathlib import Path

import joblib
import numpy as np

ART = Path(r"d:\BKCSLab\DNP3\ics_lab\artifacts")
OUT = ART / "bundle"

def main():
    OUT.mkdir(exist_ok=True)
    art = joblib.load(ART / "model.joblib")
    pipe, le, feats = art["pipeline"], art["label_encoder"], art["features"]

    scaler = pipe.named_steps["scaler"]
    np.savez(OUT / "scaler.npz",
             mean=scaler.mean_.astype(np.float32),
             scale=scaler.scale_.astype(np.float32))

    clf = pipe.named_steps["clf"]
    booster = clf.get_booster()
    booster.save_model(str(OUT / "model.ubj"))

    (OUT / "labels.txt").write_text("\n".join(le.classes_) + "\n")
    shutil.copy(ART / "features.txt", OUT / "features.txt")

    print(f"bundle written to {OUT}")
    for p in OUT.iterdir():
        print(f"  {p.name:<14} {p.stat().st_size:>10} bytes")

if __name__ == "__main__":
    main()
