"""Train and export model artifacts for OPNsense.

Feature-selection modes:
  --features all          (default) keep every numeric column
  --features variance     drop only zero-variance (constant) columns
  --features top-K        keep top K features by mutual information
  --features smart-K      variance -> correlation prune (>0.95) -> XGB
                          gain importance -> top K. Recommended.
  --features importance-K train XGB once, keep top K by feature_importances_
  --features corr-K       drop highly correlated, then top K by MI

Hybrid training (mix original dataset + self-captured lab flows):
  --train accepts multiple paths; all are concatenated before training.
  Apply --collapse to merge COLD/WARM/INIT/STOP/DISABLE_UNS ->
  DNP3_COMMAND_INJECTION in both datasets at load time.

Examples:
  python export_model.py
  python export_model.py --features smart-30 --collapse

  # Hybrid: original + lab capture
  python export_model.py \\
    --train data_sample/CICFlowMeter_Training_Balanced.csv \\
            /var/log/dnp3guard/dataset_vmx0/MyDataset_Training_Balanced.csv \\
    --test  data_sample/CICFlowMeter_Testing_Balanced.csv \\
            /var/log/dnp3guard/dataset_vmx0/MyDataset_Testing_Balanced.csv \\
    --collapse --features smart-30

Outputs: artifacts/model.joblib + features.txt (used by dnp3guard + predict_pcap)
"""
import argparse, os, sys, joblib, re
from pathlib import Path
import numpy as np
import pandas as pd

from sklearn.feature_selection import VarianceThreshold, mutual_info_classif
from sklearn.preprocessing  import StandardScaler, LabelEncoder
from sklearn.pipeline       import Pipeline
from sklearn.ensemble       import RandomForestClassifier
from sklearn.metrics        import accuracy_score, f1_score, classification_report
from xgboost                import XGBClassifier

# ---------------------------------------------------------------------------
# Column rename: hieulw cicflowmeter snake_case -> Title Case used by
# data_sample/ CSVs.  Applied defensively; no-op if columns are already
# Title Case (e.g. when --train already points at label_and_split output).
# Keep in sync with pipeline/predict_pcap.py and opnsense/live_predict.py.
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT / "pipeline"))
try:
    from predict_pcap import CIC_RENAME
except ImportError:
    CIC_RENAME = {}   # fallback: no rename (columns already Title Case)

COLLAPSE_FC_INJECTION = {
    "COLD_RESTART":        "DNP3_COMMAND_INJECTION",
    "WARM_RESTART":        "DNP3_COMMAND_INJECTION",
    "INIT_DATA":           "DNP3_COMMAND_INJECTION",
    "STOP_APP":            "DNP3_COMMAND_INJECTION",
    "DISABLE_UNSOLICITED": "DNP3_COMMAND_INJECTION",
}

# Classes handled by pkt_inspect.py (payload path).  In --behavioral-only mode
# these are dropped from training so the flow-ML model focuses on the 3
# behavioral anomalies (MITM_DOS, REPLAY, ARP_POISONING) + NORMAL.
PAYLOAD_CLASSES = frozenset({
    "COLD_RESTART", "WARM_RESTART", "INIT_DATA", "STOP_APP",
    "DISABLE_UNSOLICITED", "DNP3_COMMAND_INJECTION",
    "DNP3_INFO", "DNP3_ENUMERATE", "DNP3_RECON",
})

TRAIN_CSV_DEFAULT = str(_ROOT / "data_sample" / "CICFlowMeter_Training_Balanced.csv")
TEST_CSV_DEFAULT  = str(_ROOT / "data_sample" / "CICFlowMeter_Testing_Balanced.csv")
OUT_DIR_DEFAULT   = str(_ROOT / "artifacts")

DROP_COLS = {"Unnamed: 0.1", "Unnamed: 0", "Flow ID", "Src IP", "Dst IP", "Timestamp"}


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_one(path: str, collapse: bool,
             behavioral_only: bool = False) -> tuple[pd.DataFrame, np.ndarray]:
    """Load a single CSV, normalise column names, optionally collapse/filter labels."""
    df = pd.read_csv(path)
    df = df.rename(columns=CIC_RENAME)
    for c in list(DROP_COLS):
        if c in df.columns:
            df.drop(columns=c, inplace=True)
    if "Label" not in df.columns:
        raise SystemExit(f"{path}: no 'Label' column after rename")
    y = df.pop("Label").astype(str)
    if collapse:
        y = y.map(lambda v: COLLAPSE_FC_INJECTION.get(v, v))
    if behavioral_only:
        mask = ~y.isin(PAYLOAD_CLASSES)
        df = df[mask].reset_index(drop=True)
        y  = y[mask].reset_index(drop=True)
    df = df.select_dtypes(include=[np.number])
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    return df, y.values


def load_multi(paths: list[str], collapse: bool, seed: int = 42,
               behavioral_only: bool = False) -> tuple[pd.DataFrame, np.ndarray]:
    """Load and concatenate multiple CSVs; shuffle the combined result."""
    frames, labels = [], []
    for p in paths:
        try:
            df, y = load_one(p, collapse, behavioral_only=behavioral_only)
        except Exception as e:
            print(f"[warn] skip {p}: {e}", file=sys.stderr)
            continue
        n = len(df)
        label_counts = pd.Series(y).value_counts().to_dict()
        print(f"  loaded  {p}")
        print(f"    rows={n}  classes={label_counts}")
        frames.append(df)
        labels.append(y)
    if not frames:
        raise SystemExit("no valid CSVs loaded")
    combined = pd.concat(frames, ignore_index=True, sort=False)
    y_all    = np.concatenate(labels)
    # fill per-column medians computed on combined set
    combined.fillna(combined.median(numeric_only=True), inplace=True)
    # shuffle
    rng = np.random.default_rng(seed)
    idx = rng.permutation(len(combined))
    return combined.iloc[idx].reset_index(drop=True), y_all[idx]


# ---------------------------------------------------------------------------
# Feature selection
# ---------------------------------------------------------------------------

def _drop_zero_variance(X):
    vt = VarianceThreshold(0.0).fit(X.to_numpy())
    return X.iloc[:, vt.get_support(indices=True)]


def _drop_correlated(X: pd.DataFrame, threshold: float = 0.95):
    corr  = X.corr().abs()
    upper = corr.where(np.triu(np.ones(corr.shape, dtype=bool), k=1))
    drop  = [c for c in upper.columns if any(upper[c] > threshold)]
    return X.drop(columns=drop), drop


def _topk_mutual_info(X, y, k):
    y_enc  = LabelEncoder().fit_transform(y)
    scores = mutual_info_classif(X.to_numpy(), y_enc, random_state=42)
    cols   = list(X.columns)
    order  = np.argsort(scores)[::-1][:k]
    return [cols[i] for i in sorted(order)], scores, order


def _topk_xgb_importance(X, y, k):
    y_enc = LabelEncoder().fit_transform(y)
    probe = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1,
                          tree_method="hist", n_jobs=-1, eval_metric="mlogloss",
                          random_state=42, verbosity=0)
    probe.fit(X.to_numpy(), y_enc)
    scores = probe.feature_importances_
    cols   = list(X.columns)
    order  = np.argsort(scores)[::-1][:k]
    return [cols[i] for i in sorted(order)], scores, order


def select_features(Xtr: pd.DataFrame, ytr: np.ndarray, mode: str):
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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Train + export DNP3Guard model artifact.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--model", choices=["xgb", "rf"], default="xgb")
    ap.add_argument("--features", default="all",
                    help='"all", "variance", "top-N", "smart-N", '
                         '"importance-N", "corr-N"')
    ap.add_argument("--train", nargs="+", default=[TRAIN_CSV_DEFAULT],
                    help="one or more training CSV paths (concatenated)")
    ap.add_argument("--test",  nargs="+", default=[TEST_CSV_DEFAULT],
                    help="one or more test CSV paths (concatenated)")
    ap.add_argument("--out",   default=OUT_DIR_DEFAULT)
    ap.add_argument("--collapse", action="store_true",
                    help="merge COLD/WARM/INIT/STOP/DISABLE_UNS -> "
                         "DNP3_COMMAND_INJECTION in all datasets")
    ap.add_argument("--behavioral-only", action="store_true",
                    help="drop payload-detectable classes (FC-injection, recon) and "
                         "train only on NORMAL/MITM_DOS/REPLAY/ARP_POISONING; "
                         "pairs with pkt_inspect.py for full multimodal coverage")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    bo = getattr(args, "behavioral_only", False)
    if bo:
        print("\n[mode] behavioral-only: dropping payload-detectable classes")

    print("\n=== Loading training data ===")
    Xtr, ytr = load_multi(args.train, collapse=args.collapse, seed=args.seed,
                          behavioral_only=bo)
    print(f"  total training rows: {len(Xtr)}")

    print("\n=== Loading test data ===")
    Xte, yte = load_multi(args.test, collapse=args.collapse, seed=args.seed,
                          behavioral_only=bo)
    print(f"  total test rows:     {len(Xte)}")

    # align columns to the intersection present in both train and test
    common = [c for c in Xtr.columns if c in Xte.columns]
    if not common:
        raise SystemExit("train and test share no common numeric columns")
    Xtr = Xtr[common].astype(np.float32)
    Xte = Xte[common].astype(np.float32)
    print(f"\n  common columns: {len(common)}")

    print(f"\n=== Feature selection: {args.features} ===")
    kept, reason = select_features(Xtr, ytr, args.features)
    Xtr, Xte = Xtr[kept], Xte[kept]
    print(f"  features: {len(kept)}/{len(common)}  ({reason})")

    # fit label encoder on union of train+test labels so it doesn't barf on
    # labels present only in one split
    all_labels = np.concatenate([ytr, yte])
    le = LabelEncoder().fit(all_labels)
    ytr_enc = le.transform(ytr)
    yte_enc = le.transform(yte)
    print(f"\n  classes ({len(le.classes_)}): {list(le.classes_)}")

    print(f"\n=== Training {args.model.upper()} ===")
    if args.model == "xgb":
        clf = XGBClassifier(n_estimators=400, max_depth=8, learning_rate=0.1,
                            tree_method="hist", n_jobs=-1, eval_metric="mlogloss",
                            random_state=args.seed, verbosity=0)
    else:
        clf = RandomForestClassifier(n_estimators=400, n_jobs=-1,
                                     random_state=args.seed)

    pipe = Pipeline([("scaler", StandardScaler()), ("clf", clf)])
    pipe.fit(Xtr, ytr_enc)

    yhat = pipe.predict(Xte)
    acc  = accuracy_score(yte_enc, yhat)
    f1   = f1_score(yte_enc, yhat, average="macro", zero_division=0)
    print(f"\n=== Results ===")
    print(f"  test acc = {acc:.4f}   macro-f1 = {f1:.4f}")
    print()
    print(classification_report(yte_enc, yhat,
                                 target_names=le.classes_,
                                 zero_division=0))

    artifact = {"pipeline": pipe, "label_encoder": le, "features": kept}
    out_model = os.path.join(args.out, "model.joblib")
    out_feats = os.path.join(args.out, "features.txt")
    joblib.dump(artifact, out_model)
    with open(out_feats, "w") as fh:
        fh.write("\n".join(kept) + "\n")
    print(f"saved -> {out_model}  ({len(kept)} features)")
    print(f"saved -> {out_feats}")


if __name__ == "__main__":
    main()
