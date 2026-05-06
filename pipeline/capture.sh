#!/bin/sh
# Capture DNP3 traffic on a given interface for N seconds, then exit.
#   ./capture.sh <iface> <seconds> <output.pcap>
# Example: ./capture.sh igb1 60 /tmp/run01.pcap
set -eu
IFACE=${1:?iface}
DURATION=${2:?seconds}
OUT=${3:?output.pcap}
BPF=${BPF:-"tcp port 20000"}

echo "[+] tcpdump -i $IFACE -w $OUT  ($BPF)  for ${DURATION}s"
tcpdump -i "$IFACE" -w "$OUT" -G "$DURATION" -W 1 -nn "$BPF"
echo "[+] saved $OUT"
ls -lh "$OUT"
