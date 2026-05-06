#!/bin/sh
# capture.sh + predict_pcap.py in one step.
#   ./run.sh <iface> <seconds>
set -eu
IFACE=${1:?iface}
DURATION=${2:?seconds}
TS=$(date +%Y%m%d_%H%M%S)
PCAP_DIR=${PCAP_DIR:-/var/log/dnp3guard/pcaps}
mkdir -p "$PCAP_DIR"
PCAP="$PCAP_DIR/run_${TS}.pcap"

DIR=$(cd "$(dirname "$0")" && pwd)
sh "$DIR/capture.sh" "$IFACE" "$DURATION" "$PCAP"

PYTHON=${PYTHON:-python3}
MODEL=${MODEL:-/usr/local/dnp3guard/model.joblib}
"$PYTHON" "$DIR/predict_pcap.py" "$PCAP" --model "$MODEL"
