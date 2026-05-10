#!/bin/sh
# Build a labelled DNP3 flow dataset covering all 9 UOWM classes.
#
# Classes generated:
#   NORMAL, COLD_RESTART, WARM_RESTART, INIT_DATA, STOP_APP,
#   DISABLE_UNSOLICITED, DNP3_INFO, DNP3_ENUMERATE, MITM_DOS, REPLAY
#
# Per class:
#   1. Start appropriate outstation (real or blackhole)
#   2. tcpdump captures TCP/$PORT traffic
#   3. Attack / master script runs for $DURATION seconds
#   4. cicflowmeter -> per-class CSV
# Then label_and_split.py merges + 80/20 splits.
#
# Run on OPNsense / Linux as root:
#   sh scripts/build_dataset.sh
#   DURATION=120 OUT=/var/log/dnp3guard/dataset sh scripts/build_dataset.sh
#
# For cross-platform (including Windows) use build_dataset.py instead.

set -eu
IFACE=${IFACE:-lo0}
PORT=${PORT:-20000}
OUT=${OUT:-/var/log/dnp3guard/dataset}
DURATION=${DURATION:-90}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PYTHON=${PYTHON:-python3}
LAB="$ROOT/lab"

mkdir -p "$OUT/pcap" "$OUT/csv"

OUTSTATION_PID=""
BACKEND_PID=""      # extra process for relay mode

_wait_port() {
    local i=0
    while [ $i -lt 20 ]; do
        $PYTHON -c "import socket; s=socket.socket(); s.settimeout(0.5); s.connect(('127.0.0.1', $PORT)); s.close()" 2>/dev/null && return 0
        sleep 0.3; i=$((i+1))
    done
    echo "[!] outstation did not open $PORT in 6s"; return 1
}

_stop_all() {
    [ -n "$OUTSTATION_PID" ] && kill "$OUTSTATION_PID" 2>/dev/null
    [ -n "$BACKEND_PID"    ] && kill "$BACKEND_PID"    2>/dev/null
    OUTSTATION_PID=""; BACKEND_PID=""
    sleep 0.3
}

start_outstation() {
    _stop_all
    $PYTHON "$LAB/outstation_real.py" --host 127.0.0.1 --port "$PORT" \
        >>/tmp/outstation_real.log 2>&1 &
    OUTSTATION_PID=$!
    _wait_port || { echo "[!] real outstation failed; abort"; exit 1; }
}

start_blackhole() {
    _stop_all
    $PYTHON "$LAB/outstation_blackhole.py" --host 127.0.0.1 --port "$PORT" \
        >>/tmp/outstation_blackhole.log 2>&1 &
    OUTSTATION_PID=$!
    _wait_port || { echo "[!] blackhole outstation failed; abort"; exit 1; }
}

start_relay() {
    # real outstation on PORT+1, relay proxy on PORT
    _stop_all
    BACKEND_PORT=$((PORT + 1))
    $PYTHON "$LAB/outstation_real.py" --host 127.0.0.1 --port "$BACKEND_PORT" \
        >>/tmp/outstation_real.log 2>&1 &
    BACKEND_PID=$!
    sleep 0.5
    $PYTHON "$LAB/outstation_relay.py" \
        --host 127.0.0.1 --port "$PORT" \
        --backend-port "$BACKEND_PORT" \
        --delay 0.015 --jitter 0.008 \
        >>/tmp/outstation_relay.log 2>&1 &
    OUTSTATION_PID=$!
    _wait_port || { echo "[!] relay outstation failed; abort"; exit 1; }
}

trap '_stop_all; exit 0' EXIT INT TERM

# ---- generic capture-and-flow helper ----------------------------------------
# run_class LABEL "master cmd" [real|blackhole] [override_duration]
run_class() {
    LABEL=$1; CMD=$2; OST_MODE=${3:-real}; CAP_DUR=${4:-$DURATION}
    PCAP="$OUT/pcap/$LABEL.pcap"
    CSV="$OUT/csv/$LABEL.csv"
    rm -f "$PCAP" "$CSV"

    echo
    echo "========================================================================"
    echo "  CLASS: $LABEL   outstation=$OST_MODE   window=${CAP_DUR}s"
    echo "========================================================================"

    case "$OST_MODE" in
        blackhole) start_blackhole ;;
        relay)     start_relay     ;;
        *)         start_outstation;;
    esac

    tcpdump -i "$IFACE" -w "$PCAP" -G "$CAP_DUR" -W 1 -nn "tcp port $PORT" \
        >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 1

    sh -c "$CMD" || true
    wait $TCPDUMP_PID 2>/dev/null || true

    SZ=$(ls -lh "$PCAP" 2>/dev/null | awk '{print $5}'); echo "  pcap: ${SZ:-0}"

    timeout 300 cicflowmeter -f "$PCAP" -c "$CSV" >/dev/null 2>&1 \
        || echo "  [!] cicflowmeter timed out / failed for $LABEL"

    LINES=$(wc -l <"$CSV" 2>/dev/null || echo 0)
    echo "  flows: $((LINES - 1))"
}

# ---- baseline params --------------------------------------------------------
# All FC-injection classes use the SAME timing distribution so the model is
# forced to learn from attack content, not timing orchestration artefacts.
# attack-every=6 ensures every short flow contains multiple attack frames.
ATK="$PYTHON $LAB/master_session.py --host 127.0.0.1 --port $PORT \
     --duration $DURATION --reconnect 5 --c1-period 0.012 \
     --c0-every 30 --attack-every 6"

NRM_DUR=$((DURATION * 3))
NRM="$PYTHON $LAB/master_session.py --host 127.0.0.1 --port $PORT \
     --duration $NRM_DUR --reconnect 5 --c1-period 0.012 --c0-every 30"

# MITM_DOS: normal master against blackhole outstation.
# Produces near-zero backward bytes (no DNP3 responses from outstation).
MITM="$PYTHON $LAB/master_session.py --host 127.0.0.1 --port $PORT \
      --duration $DURATION --reconnect 5 --c1-period 0.012 --c0-every 30"

# REPLAY: rapid burst replay against real outstation.
# Produces very low IAT, high packet rate, short burst flows.
REPLAY="$PYTHON $LAB/attacks/replay_sim.py --host 127.0.0.1 --port $PORT \
        --duration $DURATION --burst-size 25 --burst-interval 0.001 --burst-gap 0.8"

# ---- class capture ----------------------------------------------------------
#         label                 master / attack cmd          outstation  duration
run_class NORMAL                "$NRM"                       real        $NRM_DUR
run_class COLD_RESTART          "$ATK --attack-fc 0x0D"      real
run_class WARM_RESTART          "$ATK --attack-fc 0x0E"      real
run_class INIT_DATA             "$ATK --attack-fc 0x0F"      real
run_class STOP_APP              "$ATK --attack-fc 0x12"      real
run_class DISABLE_UNSOLICITED   "$ATK --attack-fc 0x15"      real
run_class DNP3_INFO \
    "$PYTHON $LAB/attacks/dnp3_info.py --host 127.0.0.1 --rounds 60 --interval 0.15" \
    real
run_class DNP3_ENUMERATE \
    "$PYTHON $LAB/attacks/dnp3_enumerate.py --host 127.0.0.1 --start 0 --end 80" \
    real
run_class MITM_DOS              "$MITM"                      blackhole
run_class REPLAY                "$REPLAY"                    real
# ARP_POISONING: relay adds 15±8ms response latency -> higher IAT vs NORMAL
ARP="$PYTHON $LAB/master_session.py --host 127.0.0.1 --port $PORT \
     --duration $DURATION --reconnect 5 --c1-period 0.012 --c0-every 30"
run_class ARP_POISONING         "$ARP"                       relay

# ---- label + split ----------------------------------------------------------
echo
echo "[+] labelling + 80/20 split (--collapse merges 5 FC classes -> DNP3_COMMAND_INJECTION)"
$PYTHON "$ROOT/scripts/label_and_split.py" \
    --csv-dir "$OUT/csv" --out-dir "$OUT" --collapse

echo
echo "[+] dataset ready at $OUT"
ls -la "$OUT"/*.csv 2>/dev/null

echo
echo "Next step — train the model:"
echo "  python3 export_model.py \\"
echo "    --train $OUT/MyDataset_Training_Balanced.csv \\"
echo "    --test  $OUT/MyDataset_Testing_Balanced.csv \\"
echo "    --features smart-30"
