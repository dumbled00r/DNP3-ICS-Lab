#!/bin/sh
# Train + evaluate the model under several feature-selection modes and
# print a one-line summary per mode. Useful for picking the best.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TRAIN=${TRAIN:-/var/log/dnp3guard/dataset/MyDataset_Training_Balanced.csv}
TEST=${TEST:-/var/log/dnp3guard/dataset/MyDataset_Testing_Balanced.csv}
PY=${PYTHON:-python3}

OUT_TMP=/tmp/sweep_features
mkdir -p "$OUT_TMP"

for mode in all variance smart-30 smart-40 smart-50 importance-30 importance-40 top-30 top-40; do
    echo
    echo "===== $mode ====="
    $PY "$ROOT/export_model.py" \
        --features "$mode" \
        --train "$TRAIN" --test "$TEST" --out "$OUT_TMP/$mode" \
        2>/dev/null \
        | grep -E "features:|test acc"
done
echo
echo "Pick the best mode and re-export with --out /usr/local/dnp3guard/"
