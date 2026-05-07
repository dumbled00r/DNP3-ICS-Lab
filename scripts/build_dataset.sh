#!/bin/sh
# Build a labelled DNP3 flow dataset that mirrors the original UOWM dataset.
#
# Per class:
#   1. start outstation_real (proper response sizes per request type)
#   2. run master_session for $DURATION seconds:
#         continuous class-1 polls + periodic class-0 + periodic attack frame
#         reconnects every ~5s -> multiple flows per class
#   3. tcpdump captures TCP/$PORT traffic during the session
#   4. cicflowmeter -> per-class CSV
# Then label_and_split.py merges + 80/20 splits.

set -eu
IFACE=${IFACE:-lo0}
PORT=${PORT:-20000}
OUT=${OUT:-/var/log/dnp3guard/dataset}
DURATION=${DURATION:-90}            # default per-class capture window
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PYTHON=${PYTHON:-python3}
LAB="$ROOT/lab"

mkdir -p "$OUT/pcap" "$OUT/csv"

ECHO_PID=""
start_outstation() {
    [ -n "$ECHO_PID" ] && kill "$ECHO_PID" 2>/dev/null
    sleep 0.3
    $PYTHON "$LAB/outstation_real.py" --port "$PORT" \
        >>/tmp/outstation_real.log 2>&1 &
    ECHO_PID=$!
    sleep 0.5
    if ! python3 -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', $PORT)); s.close()" 2>/dev/null; then
        echo "[!] outstation failed; tail of log:"; tail -5 /tmp/outstation_real.log; exit 1
    fi
}
trap 'kill $ECHO_PID 2>/dev/null' EXIT INT TERM
echo "[+] starting outstation_real on :$PORT"
start_outstation

run_class() {
    LABEL=$1; CMD=$2
    PCAP="$OUT/pcap/$LABEL.pcap"
    CSV="$OUT/csv/$LABEL.csv"
    # NORMAL gets a longer capture window to match the inflated session duration
    CAP_DUR=$DURATION
    [ "$LABEL" = "NORMAL" ] && CAP_DUR=$((DURATION * 3))
    echo
    echo "==== $LABEL  (${CAP_DUR}s) ===="
    rm -f "$PCAP" "$CSV"
    start_outstation

    tcpdump -i "$IFACE" -w "$PCAP" -G "$CAP_DUR" -W 1 -nn "tcp port $PORT" \
        >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 1
    sh -c "$CMD" || true
    wait $TCPDUMP_PID 2>/dev/null || true
    echo "    pcap: $(ls -lh "$PCAP" 2>/dev/null | awk '{print $5}')"

    timeout 300 cicflowmeter -f "$PCAP" -c "$CSV" >/dev/null 2>&1 || \
        echo "    [!] cicflowmeter timed out / failed for $LABEL"
    LINES=$(wc -l <"$CSV" 2>/dev/null || echo 0)
    echo "    flows: $((LINES - 1))"
}

# Baseline params for attack classes — SAME timing distribution across all
# 5 (master_session randomizes per session), only --attack-fc differs.
# attack-every=6 ensures every short flow contains several attack frames.
ATK="$PYTHON $LAB/master_session.py --host 127.0.0.1 --port $PORT --duration $DURATION \
     --reconnect 5 --c1-period 0.012 --c0-every 30 --attack-every 6"

# NORMAL gets 3x the duration so its flow count matches attack volume,
# fixing the previous class imbalance (116 NORMAL vs 399 attack).
NRM_DUR=$((DURATION * 3))
NRM="$PYTHON $LAB/master_session.py --host 127.0.0.1 --port $PORT --duration $NRM_DUR \
     --reconnect 5 --c1-period 0.012 --c0-every 30"

run_class NORMAL              "$NRM"
run_class COLD_RESTART        "$ATK --attack-fc 0x0D"
run_class WARM_RESTART        "$ATK --attack-fc 0x0E"
run_class INIT_DATA           "$ATK --attack-fc 0x0F"
run_class STOP_APP            "$ATK --attack-fc 0x12"
run_class DISABLE_UNSOLICITED "$ATK --attack-fc 0x15"
# Recon attacks have intrinsically distinct shapes (different scripts)
run_class DNP3_INFO           "$PYTHON $LAB/attacks/dnp3_info.py --host 127.0.0.1 --rounds 60 --interval 0.15"
run_class DNP3_ENUMERATE      "$PYTHON $LAB/attacks/dnp3_enumerate.py --host 127.0.0.1 --start 0 --end 80"

echo
echo "[+] labelling + splitting"
$PYTHON "$ROOT/scripts/label_and_split.py" --csv-dir "$OUT/csv" --out-dir "$OUT"

echo
echo "[+] dataset ready at $OUT"
ls -la "$OUT"/*.csv 2>/dev/null
