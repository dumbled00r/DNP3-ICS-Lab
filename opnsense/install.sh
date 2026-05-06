#!/bin/sh
# dnp3guard installer for OPNsense (FreeBSD).
# Assumes Python + all deps (cicflowmeter, scapy, scikit-learn, joblib,
# requests, optionally xgboost) are already installed system-wide.
# Run as root.  Idempotent.

set -eu
PREFIX=/usr/local/dnp3guard
SRC_DIR=$(cd "$(dirname "$0")" && pwd)

echo "[dnp3guard] files"
mkdir -p "$PREFIX"
install -m 0755 "$SRC_DIR/dnp3guard.py"      "$PREFIX/dnp3guard.py"
install -m 0755 "$SRC_DIR/live_predict.py"   "$PREFIX/live_predict.py"
install -m 0755 "$SRC_DIR/dnp3guard_live.sh" "$PREFIX/dnp3guard_live.sh"
install -m 0755 "$SRC_DIR/install.sh"        "$PREFIX/install.sh"
[ -f "$PREFIX/dnp3guard.conf" ] || install -m 0600 "$SRC_DIR/dnp3guard.conf.sample" "$PREFIX/dnp3guard.conf"
install -m 0755 "$SRC_DIR/dnp3guard.rc"      /usr/local/etc/rc.d/dnp3guard

echo "[dnp3guard] enable + start"
sysrc dnp3guard_enable=YES >/dev/null
service dnp3guard restart || service dnp3guard start

echo "[dnp3guard] done. Edit $PREFIX/dnp3guard.conf and place model.joblib next to it."
