#!/bin/sh
# Build a labelled DNP3 flow dataset on YOUR lab topology.
#
# Per class:
#   1. start tcpdump on $IFACE filtering tcp/$PORT
#   2. run the matching attack/normal script for $DURATION seconds
#   3. close pcap; cicflowmeter -> per-class CSV
# Then label_and_split.py merges + adds Label + 80/20 splits.
#
# Run on OPNsense (or any Linux/BSD with tcpdump + cicflowmeter + python3).
#
# Vars (override on the command line):
#   IFACE=lo0 PORT=20000 OUT=/var/log/dnp3guard/dataset \
#   DURATION=60 sh scripts/build_dataset.sh

set -eu
IFACE=${IFACE:-lo0}
PORT=${PORT:-20000}
OUT=${OUT:-/var/log/dnp3guard/dataset}
DURATION=${DURATION:-60}          # seconds of capture per class
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PYTHON=${PYTHON:-python3}

mkdir -p "$OUT/pcap" "$OUT/csv"

# --- start the smart outstation (background) -------------------------------
echo "[+] starting outstation_smart on :$PORT"
$PYTHON "$ROOT/lab/outstation_smart.py" --port "$PORT" >/tmp/outstation_smart.log 2>&1 &
ECHO_PID=$!
trap 'kill $ECHO_PID 2>/dev/null' EXIT INT TERM
sleep 1

run_class() {
    LABEL=$1; CMD=$2
    PCAP="$OUT/pcap/$LABEL.pcap"
    CSV="$OUT/csv/$LABEL.csv"
    echo
    echo "==== $LABEL  (${DURATION}s) ===="
    rm -f "$PCAP" "$CSV"

    tcpdump -i "$IFACE" -w "$PCAP" -G "$DURATION" -W 1 -nn "tcp port $PORT" \
        >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 1

    sh -c "$CMD" || true

    wait $TCPDUMP_PID 2>/dev/null || true
    echo "    pcap: $(ls -lh "$PCAP" | awk '{print $5}')"

    # cicflowmeter can be slow on pcaps with hundreds of short flows
    # (DNP3_ENUMERATE in particular). Cap it at 5 minutes per class.
    timeout 300 cicflowmeter -f "$PCAP" -c "$CSV" >/dev/null 2>&1 || \
        echo "    [!] cicflowmeter timed out / failed for $LABEL"
    LINES=$(wc -l <"$CSV" 2>/dev/null || echo 0)
    echo "    flows: $((LINES - 1))"
}

# --- per-class commands -----------------------------------------------------
# Each command should produce a noticeable burst of traffic for $DURATION sec.
LAB="$ROOT/lab"
HOST=127.0.0.1
PYHOST="--host $HOST"

# loop attack scripts heavily so we get hundreds of flows per window
loop() {
    SCRIPT=$1; INTERVAL=${2:-0.3}; COUNT=${3:-200}
    echo "$PYTHON $LAB/attacks/$SCRIPT $PYHOST --count $COUNT --interval $INTERVAL"
}

run_class NORMAL              "$PYTHON $LAB/normal.py $PYHOST --duration $DURATION --cadence 0.3 --reconnect"
run_class COLD_RESTART        "$(loop cold_restart.py)"
run_class WARM_RESTART        "$(loop warm_restart.py)"
run_class DISABLE_UNSOLICITED "$(loop disable_unsolicited.py)"
run_class INIT_DATA           "$(loop init_data.py)"
run_class STOP_APP            "$(loop stop_app.py)"
run_class DNP3_INFO           "$PYTHON $LAB/attacks/dnp3_info.py $PYHOST --rounds 30 --interval 0.3"
run_class DNP3_ENUMERATE      "$PYTHON $LAB/attacks/dnp3_enumerate.py $PYHOST --start 0 --end 50"

echo
echo "[+] labelling + splitting"
$PYTHON "$ROOT/scripts/label_and_split.py" --csv-dir "$OUT/csv" --out-dir "$OUT"

echo
echo "[+] dataset ready at $OUT"
ls -la "$OUT"/*.csv 2>/dev/null
