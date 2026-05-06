"""Train and export model artifacts for OPNsense.

Feature-selection modes:
  --features all          (default) keep every numeric column
  --features variance     drop only zero-variance (constant) columns
  --features top-K        keep top K features by mutual information
  --features smart-K      variance -> correlation prune (>0.95) -> XGB
                          gain importance -> top K. Recommended.
  --features importance-K train XGB once, keep top K by feature_importances_
  --features corr-K       drop highly correlated, then top K by MI

Outputs: artifacts/model.joblib + features.txt (used by dnp3guard + predict_pcap)

  python export_model.py
  python export_model.py --features smart-40
  python export_model.py --features importance-30
"""
import argparse, os, joblib, re
import numpy as np
import pandas as pd

from sklearn.feature_selection import VarianceThreshold, mutual_info_classif
from sklearn.preprocessing  import StandardScaler, LabelEncoder
from sklearn.pipeline       import Pipeline
from sklearn.ensemble       import RandomForestClassifier
from sklearn.metrics        import accuracy_score, f1_score
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


def _drop_zero_variance(X):
    vt = VarianceThreshold(0.0).fit(X.to_numpy())
    return X.iloc[:, vt.get_support(indices=True)]


def _drop_correlated(X: pd.DataFrame, threshold: float = 0.95):
    """Drop one column from each pair with |corr| > threshold."""
    corr = X.corr().abs()
    upper = corr.where(np.triu(np.ones(corr.shape, dtype=bool), k=1))
    drop = [c for c in upper.columns if any(upper[c] > threshold)]
    return X.drop(columns=drop), drop


def _topk_mutual_info(X, y, k):
    y_enc = LabelEncoder().fit_transform(y)
    scores = mutual_info_classif(X.to_numpy(), y_enc, random_state=42)
    cols = list(X.columns)
    order = np.argsort(scores)[::-1][:k]
    return [cols[i] for i in sorted(order)], scores, order


def _topk_xgb_importance(X, y, k):
    y_enc = LabelEncoder().fit_transform(y)
    probe = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1,
                          tree_method="hist", n_jobs=-1, eval_metric="mlogloss",
                          random_state=42, verbosity=0)
    probe.fit(X.to_numpy(), y_enc)
    scores = probe.feature_importances_
    cols = list(X.columns)
    order = np.argsort(scores)[::-1][:k]
    return [cols[i] for i in sorted(order)], scores, order


def select_features(Xtr: pd.DataFrame, ytr: np.ndarray, mode: str):
    """Return (kept_columns, reason_string)."""
    cols = list(Xtr.columns)
    if mode == "all":
        return cols, "kept all numeric features"
    if mode == "variance":
        kept = list(_drop_zero_variance(Xtr).columns)
        return kept, f"dropped {len(cols)-len(kept)} zero-variance"

    m = re.fullmatch(r"(top|importance|corr|smart)-(\d+)", mode)
    if not m:
        raise SystemExit(f"unknown --features mode: {mode}")
    kind, k = m.group(1), int(m.group(2))
    k = min(k, len(cols))

    if kind == "top":
        kept, scores, order = _topk_mutual_info(Xtr, ytr, k)
        top5 = [(cols[i], round(float(scores[i]), 4)) for i in order[:5]]
        return kept, f"top-{k} by mutual_info; best 5: {top5}"

    if kind == "importance":
        kept, scores, order = _topk_xgb_importance(Xtr, ytr, k)
        top5 = [(cols[i], round(float(scores[i]), 4)) for i in order[:5]]
        return kept, f"top-{k} by XGB importance; best 5: {top5}"

    if kind == "corr":
        X2, dropped = _drop_correlated(Xtr, 0.95)
        kept, scores, order = _topk_mutual_info(X2, ytr, k)
        return kept, (f"dropped {len(dropped)} correlated (>0.95) "
                      f"then top-{k} by mutual_info")

    if kind == "smart":
        # variance -> correlation -> XGB importance
        X2 = _drop_zero_variance(Xtr)
        zv_dropped = len(cols) - X2.shape[1]
        X3, corr_dropped = _drop_correlated(X2, 0.95)
        kept, scores, order = _topk_xgb_importance(X3, ytr, k)
        cols3 = list(X3.columns)
        top5 = [(cols3[i], round(float(scores[i]), 4)) for i in order[:5]]
        return kept, (f"smart pipeline: -{zv_dropped} zero-var, "
                      f"-{len(corr_dropped)} correlated, "
                      f"top-{k} by XGB importance; best 5: {top5}")
    raise SystemExit(f"unhandled mode: {mode}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=["xgb", "rf"], default="xgb")
    ap.add_argument("--features", default="all",
                    help='"all" (default), "variance", or "top-N" (e.g. top-40)')
    args = ap.parse_args()
    os.makedirs(OUT_DIR, exist_ok=True)

    Xtr, ytr = load(TRAIN_CSV)
    Xte, yte = load(TEST_CSV)
    common = [c for c in Xtr.columns if c in Xte.columns]
    Xtr = Xtr[common].astype(np.float32)
    Xte = Xte[common].astype(np.float32)

    kept, reason = select_features(Xtr, ytr, args.features)
    Xtr, Xte = Xtr[kept], Xte[kept]
    print(f"features: {len(kept)}/{len(common)}  ({reason})")

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
    yhat = pipe.predict(Xte)
    print(f"test acc = {accuracy_score(yte_enc, yhat):.4f}  "
          f"macro-f1 = {f1_score(yte_enc, yhat, average='macro'):.4f}")

    artifact = {"pipeline": pipe, "label_encoder": le, "features": kept}
    joblib.dump(artifact, os.path.join(OUT_DIR, "model.joblib"))
    with open(os.path.join(OUT_DIR, "features.txt"), "w") as f:
        f.write("\n".join(kept) + "\n")
    print(f"saved -> {OUT_DIR}/model.joblib  ({len(kept)} features)")
    print(f"saved -> {OUT_DIR}/features.txt")


if __name__ == "__main__":
    main()
