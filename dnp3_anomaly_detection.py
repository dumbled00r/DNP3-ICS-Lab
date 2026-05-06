# -*- coding: utf-8 -*-
"""
DNP3 Anomaly Detection - Binary & Multiclass Classification
Dataset : CICFlowMeter DNP3 (11 balanced classes, 5126 train / 2200 test)
Models  : ML (LR, DT, RF, XGB, SVM, KNN) + DL (MLP, ResNet-MLP, LSTM) via Keras
Output  : results/ <- CSV tables, confusion-matrix PNGs, training-history PNGs

Fixes vs v1:
  - Drop 11 zero-variance features in preprocessing
  - Replace 1D-CNN (wrong for unordered tabular features, early-stops at epoch ~11)
    with Residual MLP (skip connections) - standard DL approach for tabular data
  - Fix LSTM: was silently dropping 7 features due to seq_len truncation;
    now uses Reshape((n_features, 1)) so each feature is its own timestep
  - Increase PATIENCE 10->15, EPOCHS 60->100 for better convergence
"""

import os, time, warnings
import numpy as np
import pandas as pd
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.feature_selection import VarianceThreshold
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, roc_auc_score, classification_report,
                             confusion_matrix)
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from xgboost import XGBClassifier

import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, callbacks

warnings.filterwarnings("ignore")
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
tf.get_logger().setLevel("ERROR")

RESULTS   = r"d:\BKCSLab\DNP3\results"
TRAIN_CSV = r"d:\BKCSLab\DNP3\CICFlowMeter_Training_Balanced.csv"
TEST_CSV  = r"d:\BKCSLab\DNP3\CICFlowMeter_Testing_Balanced.csv"
os.makedirs(RESULTS, exist_ok=True)

# ---------------------------------------------------------------
# 1.  DATA LOADING & PREPROCESSING
# ---------------------------------------------------------------
DROP_COLS = ["Unnamed: 0.1", "Unnamed: 0", "Flow ID",
             "Src IP", "Dst IP", "Timestamp"]

def load_and_preprocess():
    train = pd.read_csv(TRAIN_CSV)
    test  = pd.read_csv(TEST_CSV)

    for df in [train, test]:
        for c in DROP_COLS:
            if c in df.columns:
                df.drop(columns=c, inplace=True)

    y_train_raw = train.pop("Label").values
    y_test_raw  = test.pop("Label").values

    train = train.select_dtypes(include=[np.number])
    test  = test.select_dtypes(include=[np.number])

    common = [c for c in train.columns if c in test.columns]
    train, test = train[common].copy(), test[common].copy()

    for df in [train, test]:
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
    train.fillna(train.median(), inplace=True)
    test.fillna(train.median(), inplace=True)

    # Drop zero-variance features (fitted on train only)
    vt = VarianceThreshold(threshold=0.0)
    X_train_raw = vt.fit_transform(train.values.astype(np.float32))
    X_test_raw  = vt.transform(test.values.astype(np.float32))
    kept = [common[i] for i in vt.get_support(indices=True)]

    n_dropped = len(common) - len(kept)
    print("Features : %d raw  ->  %d after dropping %d zero-variance cols" % (
          len(common), len(kept), n_dropped))
    print("Train    : %d  |  Test: %d" % (X_train_raw.shape[0], X_test_raw.shape[0]))
    print("Note     : small dataset (<%dk rows) -> fast training is expected" %
          (X_train_raw.shape[0] // 1000 + 1))
    print("Classes  : %s" % sorted(set(y_train_raw)))
    return X_train_raw, X_test_raw, y_train_raw, y_test_raw, kept


# ---------------------------------------------------------------
# 2.  LABEL ENCODERS
# ---------------------------------------------------------------
def make_labels(y_train_raw, y_test_raw):
    y_train_bin = (y_train_raw != "NORMAL").astype(int)
    y_test_bin  = (y_test_raw  != "NORMAL").astype(int)

    le = LabelEncoder()
    y_train_mc = le.fit_transform(y_train_raw)
    y_test_mc  = le.transform(y_test_raw)

    print("\nBinary  - train positives: %d / %d" % (y_train_bin.sum(), len(y_train_bin)))
    print("Multiclass (%d classes): %s" % (len(le.classes_), list(le.classes_)))
    return y_train_bin, y_test_bin, y_train_mc, y_test_mc, le


# ---------------------------------------------------------------
# 3.  EVALUATION HELPERS
# ---------------------------------------------------------------
def evaluate(name, y_true, y_pred, y_prob=None, task="binary"):
    avg = "binary" if task == "binary" else "macro"
    rec = {
        "model"    : name,
        "accuracy" : round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred, average=avg, zero_division=0), 4),
        "recall"   : round(recall_score(y_true, y_pred, average=avg, zero_division=0), 4),
        "f1"       : round(f1_score(y_true, y_pred, average=avg, zero_division=0), 4),
    }
    if y_prob is not None and task == "binary":
        rec["roc_auc"] = round(roc_auc_score(y_true, y_prob), 4)
    return rec


def save_confusion_matrix(y_true, y_pred, labels, title, filename):
    cm = confusion_matrix(y_true, y_pred)
    sz = max(6, len(labels))
    fig, ax = plt.subplots(figsize=(sz, sz - 1))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=labels, yticklabels=labels, ax=ax)
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
    ax.set_title(title)
    plt.tight_layout()
    fig.savefig(os.path.join(RESULTS, filename), dpi=120)
    plt.close(fig)


def save_training_history(history, name, task):
    fig, axes = plt.subplots(1, 2, figsize=(12, 4))
    axes[0].plot(history.history["loss"],     label="train")
    axes[0].plot(history.history["val_loss"], label="val")
    axes[0].set_title("%s Loss" % name); axes[0].legend()
    axes[1].plot(history.history["accuracy"],     label="train")
    axes[1].plot(history.history["val_accuracy"], label="val")
    axes[1].set_title("%s Accuracy" % name); axes[1].legend()
    plt.tight_layout()
    safe = name.replace(" ", "_").replace("/", "-")
    fig.savefig(os.path.join(RESULTS, "%s_%s_history.png" % (task, safe)), dpi=100)
    plt.close(fig)


# ---------------------------------------------------------------
# 4.  ML MODELS
# ---------------------------------------------------------------
def get_ml_models(task):
    return {
        "Logistic Regression": LogisticRegression(max_iter=1000, n_jobs=-1),
        "Decision Tree"      : DecisionTreeClassifier(random_state=42),
        "Random Forest"      : RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42),
        "XGBoost"            : XGBClassifier(
                                   n_estimators=200,
                                   eval_metric="logloss" if task == "binary" else "mlogloss",
                                   tree_method="hist", n_jobs=-1,
                                   random_state=42, verbosity=0),
        "SVM (RBF)"          : SVC(kernel="rbf", probability=True, random_state=42),
        "KNN (k=5)"          : KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
    }


def run_ml(X_tr, X_te, y_tr, y_te, task, label_names):
    print("\n" + "="*60)
    print("  ML MODELS  -  %s" % task.upper())
    print("="*60)
    results = []
    for name, clf in get_ml_models(task).items():
        t0 = time.time()
        clf.fit(X_tr, y_tr)
        train_time = time.time() - t0

        t0 = time.time()
        y_pred = clf.predict(X_te)
        infer_time = time.time() - t0

        y_prob = None
        if hasattr(clf, "predict_proba") and task == "binary":
            y_prob = clf.predict_proba(X_te)[:, 1]

        rec = evaluate(name, y_te, y_pred, y_prob, task)
        rec["train_sec"] = round(train_time, 2)
        rec["infer_sec"] = round(infer_time, 4)
        results.append(rec)

        print("  %-25s acc=%.4f  f1=%.4f  train=%.1fs" % (
              name, rec["accuracy"], rec["f1"], train_time))

        safe = name.replace(" ", "_").replace("(", "").replace(")", "")
        save_confusion_matrix(y_te, y_pred, label_names,
                              "%s - %s" % (name, task),
                              "%s_cm_%s.png" % (task, safe))
    return results


# ---------------------------------------------------------------
# 5.  DEEP LEARNING MODELS  (Keras)
# ---------------------------------------------------------------
EPOCHS     = 100
BATCH_SIZE = 128
PATIENCE   = 15     # increased: small dataset has noisy val curves


def _head(x, n_classes):
    """Shared output head."""
    if n_classes == 2:
        out  = layers.Dense(1, activation="sigmoid")(x)
        loss = "binary_crossentropy"
    else:
        out  = layers.Dense(n_classes, activation="softmax")(x)
        loss = "sparse_categorical_crossentropy"
    return out, loss


def build_mlp(input_dim, n_classes):
    """Standard deep MLP with BatchNorm + Dropout."""
    inp = keras.Input(shape=(input_dim,))
    x = layers.Dense(256, activation="relu")(inp)
    x = layers.BatchNormalization()(x)
    x = layers.Dropout(0.3)(x)
    x = layers.Dense(128, activation="relu")(x)
    x = layers.BatchNormalization()(x)
    x = layers.Dropout(0.3)(x)
    x = layers.Dense(64, activation="relu")(x)
    x = layers.Dropout(0.2)(x)
    out, loss = _head(x, n_classes)
    model = keras.Model(inp, out)
    model.compile(optimizer=keras.optimizers.Adam(1e-3),
                  loss=loss, metrics=["accuracy"])
    return model


def build_residual_mlp(input_dim, n_classes):
    """Residual MLP (ResNet-style) - best-practice DL architecture for tabular data.
    Replaces 1D-CNN which is inappropriate for unordered feature vectors
    (caused early stopping at ~11 epochs due to unstable gradients from
    treating independent network-flow stats as a spatial sequence).
    """
    def res_block(x, units, dropout=0.2):
        shortcut = layers.Dense(units)(x)           # learned projection shortcut
        x = layers.Dense(units, activation="relu")(x)
        x = layers.BatchNormalization()(x)
        x = layers.Dropout(dropout)(x)
        x = layers.Dense(units, activation="relu")(x)
        x = layers.BatchNormalization()(x)
        x = layers.Add()([x, shortcut])
        return layers.Activation("relu")(x)

    inp = keras.Input(shape=(input_dim,))
    x = layers.Dense(256, activation="relu")(inp)
    x = layers.BatchNormalization()(x)
    x = res_block(x, 256, dropout=0.3)
    x = res_block(x, 128, dropout=0.3)
    x = res_block(x, 64,  dropout=0.2)
    x = layers.Dense(32, activation="relu")(x)
    x = layers.Dropout(0.1)(x)
    out, loss = _head(x, n_classes)
    model = keras.Model(inp, out)
    model.compile(optimizer=keras.optimizers.Adam(1e-3),
                  loss=loss, metrics=["accuracy"])
    return model


def build_lstm(input_dim, n_classes):
    """LSTM treating each feature as its own timestep (n_features, 1).
    Fixed from v1 which used seq_len=8 and silently dropped
    (input_dim % 8) = 7 features due to integer truncation.
    """
    inp = keras.Input(shape=(input_dim,))
    x   = layers.Reshape((input_dim, 1))(inp)   # (batch, n_features, 1)
    x = layers.LSTM(128, return_sequences=True)(x)
    x = layers.LSTM(64)(x)
    x = layers.Dense(64, activation="relu")(x)
    x = layers.Dropout(0.3)(x)
    out, loss = _head(x, n_classes)
    model = keras.Model(inp, out)
    model.compile(optimizer=keras.optimizers.Adam(1e-3),
                  loss=loss, metrics=["accuracy"])
    return model


def run_dl(X_tr, X_te, y_tr, y_te, task, label_names):
    print("\n" + "="*60)
    print("  DL MODELS  -  %s" % task.upper())
    print("="*60)

    n_classes = 2 if task == "binary" else len(label_names)
    input_dim = X_tr.shape[1]
    results   = []

    cb_es = callbacks.EarlyStopping(patience=PATIENCE,
                                    restore_best_weights=True,
                                    monitor="val_loss")
    cb_lr = callbacks.ReduceLROnPlateau(patience=6, factor=0.5,
                                        min_lr=1e-5, monitor="val_loss",
                                        verbose=0)

    builders = {
        "MLP"        : lambda: build_mlp(input_dim, n_classes),
        "ResNet-MLP" : lambda: build_residual_mlp(input_dim, n_classes),
        "LSTM"       : lambda: build_lstm(input_dim, n_classes),
    }

    for name, build_fn in builders.items():
        print("\n  Training %s ..." % name)
        model = build_fn()

        t0   = time.time()
        hist = model.fit(
            X_tr, y_tr,
            validation_split=0.15,
            epochs=EPOCHS,
            batch_size=BATCH_SIZE,
            callbacks=[cb_es, cb_lr],
            verbose=0
        )
        train_time = time.time() - t0

        t0          = time.time()
        y_prob_raw  = model.predict(X_te, verbose=0)
        infer_time  = time.time() - t0

        if n_classes == 2:
            y_prob = y_prob_raw.ravel()
            y_pred = (y_prob >= 0.5).astype(int)
        else:
            y_prob = y_prob_raw
            y_pred = np.argmax(y_prob, axis=1)

        y_prob_eval = y_prob if task == "binary" else None
        rec = evaluate(name, y_te, y_pred, y_prob_eval, task)
        rec["train_sec"] = round(train_time, 2)
        rec["infer_sec"] = round(infer_time, 4)
        rec["epochs_run"] = len(hist.history["loss"])
        results.append(rec)

        print("  %-12s acc=%.4f  f1=%.4f  train=%.1fs  epochs=%d" % (
              name, rec["accuracy"], rec["f1"], train_time, rec["epochs_run"]))

        save_confusion_matrix(y_te, y_pred, label_names,
                              "%s - %s" % (name, task),
                              "%s_cm_%s.png" % (task, name.replace("/", "-")))
        save_training_history(hist, name, task)

    return results


# ---------------------------------------------------------------
# 6.  COMPARISON PLOTS
# ---------------------------------------------------------------
def plot_comparison(df, task):
    metrics = ["accuracy", "precision", "recall", "f1"]
    if "roc_auc" in df.columns:
        metrics.append("roc_auc")

    x     = np.arange(len(df))
    width = 0.15
    fig, ax = plt.subplots(figsize=(14, 6))

    for i, m in enumerate(metrics):
        ax.bar(x + i * width, df[m], width, label=m.upper())

    ax.set_xticks(x + width * (len(metrics) - 1) / 2)
    ax.set_xticklabels(df["model"], rotation=30, ha="right", fontsize=9)
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("Score")
    ax.set_title("Model Comparison - %s" % task.capitalize())
    ax.legend(loc="lower right", fontsize=8)
    plt.tight_layout()
    fig.savefig(os.path.join(RESULTS, "%s_comparison.png" % task), dpi=120)
    plt.close(fig)


def plot_f1_vs_time(df, task):
    fig, ax = plt.subplots(figsize=(10, 5))
    colors = plt.cm.tab10(np.linspace(0, 1, len(df)))
    for i, (_, row) in enumerate(df.iterrows()):
        ax.scatter(row["train_sec"], row["f1"], color=colors[i], s=120, zorder=3)
        ax.annotate(row["model"], (row["train_sec"], row["f1"]),
                    textcoords="offset points", xytext=(5, 4), fontsize=8)
    ax.set_xlabel("Training Time (s)")
    ax.set_ylabel("F1 Score")
    ax.set_title("F1 vs Training Time - %s" % task.capitalize())
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    fig.savefig(os.path.join(RESULTS, "%s_f1_vs_time.png" % task), dpi=120)
    plt.close(fig)


# ---------------------------------------------------------------
# 7.  MAIN
# ---------------------------------------------------------------
def main():
    print("\n" + "="*60)
    print("  DNP3 ANOMALY DETECTION - START")
    print("="*60)

    X_train, X_test, y_train_raw, y_test_raw, feature_names = load_and_preprocess()
    y_tr_bin, y_te_bin, y_tr_mc, y_te_mc, le = make_labels(y_train_raw, y_test_raw)
    mc_labels  = list(le.classes_)
    bin_labels = ["NORMAL", "ATTACK"]

    scaler     = StandardScaler()
    X_tr_sc    = scaler.fit_transform(X_train)
    X_te_sc    = scaler.transform(X_test)

    # ============================================================
    #  PHASE 1 : BINARY CLASSIFICATION
    # ============================================================
    print("\n\n" + "#"*60)
    print("  PHASE 1 : BINARY CLASSIFICATION  (NORMAL vs ATTACK)")
    print("#"*60)

    ml_bin = run_ml(X_tr_sc, X_te_sc, y_tr_bin, y_te_bin, "binary", bin_labels)
    dl_bin = run_dl(X_tr_sc, X_te_sc, y_tr_bin, y_te_bin, "binary", bin_labels)

    df_bin = pd.DataFrame(ml_bin + dl_bin)
    df_bin.to_csv(os.path.join(RESULTS, "binary_results.csv"), index=False)
    plot_comparison(df_bin, "binary")
    plot_f1_vs_time(df_bin, "binary")

    print("\n-- BINARY RESULTS --")
    print(df_bin.to_string(index=False))

    # ============================================================
    #  PHASE 2 : MULTICLASS CLASSIFICATION
    # ============================================================
    print("\n\n" + "#"*60)
    print("  PHASE 2 : MULTICLASS CLASSIFICATION  (11 classes)")
    print("#"*60)

    ml_mc = run_ml(X_tr_sc, X_te_sc, y_tr_mc, y_te_mc, "multiclass", mc_labels)
    dl_mc = run_dl(X_tr_sc, X_te_sc, y_tr_mc, y_te_mc, "multiclass", mc_labels)

    df_mc = pd.DataFrame(ml_mc + dl_mc)
    df_mc.to_csv(os.path.join(RESULTS, "multiclass_results.csv"), index=False)
    plot_comparison(df_mc, "multiclass")
    plot_f1_vs_time(df_mc, "multiclass")

    print("\n-- MULTICLASS RESULTS --")
    print(df_mc.to_string(index=False))

    # ============================================================
    #  FINAL SUMMARY
    # ============================================================
    print("\n\n" + "="*60)
    print("  FINAL SUMMARY")
    print("="*60)

    summary_cols = ["model", "accuracy", "precision", "recall", "f1", "train_sec"]

    print("\nBINARY (sorted by F1):")
    print(df_bin[summary_cols].sort_values("f1", ascending=False).to_string(index=False))

    print("\nMULTICLASS (sorted by F1):")
    print(df_mc[summary_cols].sort_values("f1", ascending=False).to_string(index=False))

    best_bin = df_bin.loc[df_bin["f1"].idxmax()]
    best_mc  = df_mc.loc[df_mc["f1"].idxmax()]
    print("\nBest Binary     : %s  (F1=%.4f)" % (best_bin["model"], best_bin["f1"]))
    print("Best Multiclass : %s  (F1=%.4f)" % (best_mc["model"], best_mc["f1"]))
    print("\nResults saved to: %s" % RESULTS)
    print("="*60)


if __name__ == "__main__":
    main()
