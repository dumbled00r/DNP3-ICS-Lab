#!/bin/sh
# Capture vmx0 training data for all 9 UOWM classes with a remote attacker.
#
# Per class:
#   1. Print the exact command to run on the attacker box
#   2. Wait for ENTER to confirm attacker is running
#   3. Capture vmx0 pcap for the capture window
#   4. cicflowmeter -> per-class CSV
# Then label_and_split.py (with --collapse) merges + 80/20 splits.
#
# MITM_DOS / REPLAY use a local simulation instead of real ARP poisoning:
#   MITM_DOS : OPNsense starts outstation_blackhole.py; attacker runs
#              master_session.py normally -> produces near-zero bwd bytes
#   REPLAY   : OPNsense starts outstation_real.py; attacker runs
#              replay_sim.py -> produces burst-IAT flows
#
# Run on OPNsense (as root):
#   ATTACKER_HOST=10.8.0.2 OPNSENSE_IP=192.168.150.34 sh scripts/capture_remote.sh

set -eu
IFACE=${IFACE:-vmx0}
PORT=${PORT:-20000}
DURATION=${DURATION:-90}
OPNSENSE_IP=${OPNSENSE_IP:-192.168.150.34}
ATTACKER_HOST=${ATTACKER_HOST:-10.8.0.2}
OUT=${OUT:-/var/log/dnp3guard/dataset_vmx0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PYTHON=${PYTHON:-python3}
LAB="$ROOT/lab"

mkdir -p "$OUT/pcap" "$OUT/csv"

# ---- outstation management --------------------------------------------------
OUTSTATION_PID=""

OUTSTATION_PID=""
BACKEND_PID=""

stop_outstation() {
    [ -n "$OUTSTATION_PID" ] && kill "$OUTSTATION_PID" 2>/dev/null
    [ -n "$BACKEND_PID"    ] && kill "$BACKEND_PID"    2>/dev/null
    OUTSTATION_PID=""; BACKEND_PID=""
    sleep 0.5
}

start_outstation() {
    stop_outstation
    $PYTHON "$LAB/outstation_real.py" --host 0.0.0.0 --port "$PORT" \
        >/tmp/outstation_real.log 2>&1 &
    OUTSTATION_PID=$!
    sleep 1
    echo "[+] outstation_real started (pid=$OUTSTATION_PID)"
}

start_blackhole() {
    stop_outstation
    $PYTHON "$LAB/outstation_blackhole.py" --host 0.0.0.0 --port "$PORT" \
        >/tmp/outstation_blackhole.log 2>&1 &
    OUTSTATION_PID=$!
    sleep 1
    echo "[+] outstation_blackhole started (pid=$OUTSTATION_PID)"
}

start_relay() {
    stop_outstation
    BACKEND_PORT=$((PORT + 1))
    $PYTHON "$LAB/outstation_real.py" --host 127.0.0.1 --port "$BACKEND_PORT" \
        >/tmp/outstation_real.log 2>&1 &
    BACKEND_PID=$!
    sleep 0.5
    $PYTHON "$LAB/outstation_relay.py" --host 0.0.0.0 --port "$PORT" \
        --backend-port "$BACKEND_PORT" --delay 0.015 --jitter 0.008 \
        >/tmp/outstation_relay.log 2>&1 &
    OUTSTATION_PID=$!
    sleep 1
    echo "[+] outstation_relay started on :$PORT -> 127.0.0.1:$BACKEND_PORT"
}

trap 'stop_outstation; service dnp3guard start 2>/dev/null || true' EXIT INT TERM

# Stop live detector so it doesn't race on vmx0
service dnp3guard stop 2>/dev/null || true
pkill -f outstation_ 2>/dev/null || true
sleep 1

# ---- capture helper ---------------------------------------------------------
run_class() {
    LABEL=$1
    ATTACK_HINT=$2        # short description printed to operator
    ATTACKER_CMD=$3       # command to run ON THE ATTACKER BOX
    OST_MODE=${4:-real}   # real or blackhole
    CAP_DUR=${5:-$DURATION}

    PCAP="$OUT/pcap/$LABEL.pcap"
    CSV="$OUT/csv/$LABEL.csv"
    rm -f "$PCAP" "$CSV"

    echo
    echo "========================================================================"
    echo "  CLASS: $LABEL   outstation=$OST_MODE   window=${CAP_DUR}s"
    echo "========================================================================"
    echo
    echo "  ON THE ATTACKER ($ATTACKER_HOST), run:"
    echo
    echo "    $ATTACKER_CMD"
    echo
    printf "  Press ENTER once the attacker command is running... "
    read _

    case "$OST_MODE" in
        blackhole) start_blackhole ;;
        relay)     start_relay     ;;
        *)         start_outstation;;
    esac

    tcpdump -i "$IFACE" -w "$PCAP" -G "$CAP_DUR" -W 1 -nn "tcp port $PORT" \
        >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    echo "  capturing on $IFACE for ${CAP_DUR}s ..."
    wait $TCPDUMP_PID 2>/dev/null || true

    SZ=$(ls -lh "$PCAP" 2>/dev/null | awk '{print $5}'); echo "  pcap: ${SZ:-0}"

    timeout 300 cicflowmeter -f "$PCAP" -c "$CSV" >/dev/null 2>&1 \
        || echo "  [!] cicflowmeter timed out / failed for $LABEL"

    LINES=$(wc -l <"$CSV" 2>/dev/null || echo 0)
    echo "  flows: $((LINES - 1))"
}

NRM_DUR=$((DURATION * 3))

# ---- all 9 classes ----------------------------------------------------------

run_class NORMAL \
    "steady class-1 polling" \
    "python lab/master_session.py --host $OPNSENSE_IP --port $PORT --duration $NRM_DUR --reconnect 5 --c1-period 0.012 --c0-every 30" \
    real $NRM_DUR

run_class COLD_RESTART \
    "FC 0x0D cold_restart injection" \
    "python lab/master_session.py --host $OPNSENSE_IP --port $PORT --duration $DURATION --reconnect 5 --c1-period 0.012 --c0-every 30 --attack-every 6 --attack-fc 0x0D" \
    real

run_class WARM_RESTART \
    "FC 0x0E warm_restart injection" \
    "python lab/master_session.py --host $OPNSENSE_IP --port $PORT --duration $DURATION --reconnect 5 --c1-period 0.012 --c0-every 30 --attack-every 6 --attack-fc 0x0E" \
    real

run_class INIT_DATA \
    "FC 0x0F initialize_data injection" \
    "python lab/master_session.py --host $OPNSENSE_IP --port $PORT --duration $DURATION --reconnect 5 --c1-period 0.012 --c0-every 30 --attack-every 6 --attack-fc 0x0F" \
    real

run_class STOP_APP \
    "FC 0x12 stop_appl injection" \
    "python lab/master_session.py --host $OPNSENSE_IP --port $PORT --duration $DURATION --reconnect 5 --c1-period 0.012 --c0-every 30 --attack-every 6 --attack-fc 0x12" \
    real

run_class DISABLE_UNSOLICITED \
    "FC 0x15 disable_unsolicited injection" \
    "python lab/master_session.py --host $OPNSENSE_IP --port $PORT --duration $DURATION --reconnect 5 --c1-period 0.012 --c0-every 30 --attack-every 6 --attack-fc 0x15" \
    real

run_class DNP3_INFO \
    "attribute enumeration (g0v240)" \
    "python lab/attacks/dnp3_info.py --host $OPNSENSE_IP --rounds 80 --interval 0.2" \
    real

run_class DNP3_ENUMERATE \
    "link-address sweep 0..80" \
    "python lab/attacks/dnp3_enumerate.py --host $OPNSENSE_IP --start 0 --end 80" \
    real

# MITM_DOS simulation:
# OPNsense runs outstation_blackhole (no responses).
# Attacker runs master_session normally — it polls but gets no replies.
# Flow features: near-zero backward bytes, short flows (recv timeout fires).
run_class MITM_DOS \
    "normal polling against blackhole (MITM simulation — no outstation responses)" \
    "python lab/master_session.py --host $OPNSENSE_IP --port $PORT --duration $DURATION --reconnect 5 --c1-period 0.012 --c0-every 30" \
    blackhole

# REPLAY simulation:
# OPNsense runs real outstation.
# Attacker sends pre-captured DNP3 frames in rapid bursts.
# Flow features: very low IAT, high packet rate, short flow duration.
run_class REPLAY \
    "burst replay of pre-captured DNP3 read frames" \
    "python lab/attacks/replay_sim.py --host $OPNSENSE_IP --port $PORT --duration $DURATION --burst-size 25 --burst-interval 0.001 --burst-gap 0.8" \
    real

# ARP_POISONING simulation:
# OPNsense starts outstation_relay (relay adds 15±8ms latency to responses).
# Attacker runs normal master_session against OPNsense:PORT.
# Flow features: slightly higher Flow IAT Mean / Bwd IAT vs NORMAL.
run_class ARP_POISONING \
    "normal polling (outstation_relay adds 15ms latency — MITM relay simulation)" \
    "python lab/master_session.py --host $OPNSENSE_IP --port $PORT --duration $DURATION --reconnect 5 --c1-period 0.012 --c0-every 30" \
    relay

# ---- label + split ----------------------------------------------------------
echo
echo "[+] labelling + splitting (collapsed FC injection classes)"
$PYTHON "$ROOT/scripts/label_and_split.py" \
    --csv-dir "$OUT/csv" --out-dir "$OUT" --collapse

echo
echo "[+] dataset ready at $OUT"
ls -la "$OUT"/*.csv 2>/dev/null

echo
echo "Next: retrain with your vmx0 flows (optionally combined with original dataset)"
echo "  python3 export_model.py \\"
echo "    --train $OUT/MyDataset_Training_Balanced.csv \\"
echo "    --test  $OUT/MyDataset_Testing_Balanced.csv \\"
echo "    --features smart-30"
echo
echo "  Or hybrid (lab + original):"
echo "  python3 export_model.py \\"
echo "    --train data_sample/CICFlowMeter_Training_Balanced.csv \\"
echo "            $OUT/MyDataset_Training_Balanced.csv \\"
echo "    --test  data_sample/CICFlowMeter_Testing_Balanced.csv \\"
echo "            $OUT/MyDataset_Testing_Balanced.csv \\"
echo "    --collapse --features smart-30"
echo "  service dnp3guard start"
