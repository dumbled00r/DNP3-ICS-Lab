#!/bin/sh
# dnp3guard installer for OPNsense (FreeBSD).
# Run as root.  Idempotent.  Pass --reinstall after firmware upgrades.

set -eu
PREFIX=/usr/local/dnp3guard
VENV=$PREFIX/venv
SRC_DIR=$(cd "$(dirname "$0")" && pwd)

echo "[dnp3guard] pkg install base deps"
ASSUME_ALWAYS_YES=yes pkg install -y \
  python311 py311-pip py311-sqlite3 \
  py311-numpy py311-scipy py311-scikit-learn py311-pandas

echo "[dnp3guard] venv"
mkdir -p "$PREFIX"
[ -d "$VENV" ] || python3.11 -m venv --system-site-packages "$VENV"
"$VENV/bin/pip" install --upgrade pip wheel
"$VENV/bin/pip" install \
  "cicflowmeter>=0.3.0" \
  "scapy>=2.5.0" \
  "joblib>=1.3" \
  "requests>=2.31"

echo "[dnp3guard] files"
install -m 0755 "$SRC_DIR/dnp3guard.py"      "$PREFIX/dnp3guard.py"
install -m 0755 "$SRC_DIR/install.sh"        "$PREFIX/install.sh"
[ -f "$PREFIX/dnp3guard.conf" ] || install -m 0600 "$SRC_DIR/dnp3guard.conf.sample" "$PREFIX/dnp3guard.conf"
install -m 0755 "$SRC_DIR/dnp3guard.rc"      /usr/local/etc/rc.d/dnp3guard

echo "[dnp3guard] enable + start"
sysrc dnp3guard_enable=YES >/dev/null
service dnp3guard restart || service dnp3guard start

echo "[dnp3guard] done. Edit $PREFIX/dnp3guard.conf and place model.joblib next to it."
