#!/bin/sh
# Capture vmx0 training data with the attacker on a remote host.
#
# Per class:
#   1. Print the exact command to run on the attacker box
#   2. Wait for ENTER to confirm attacker is running
#   3. Capture vmx0 pcap for $DURATION+5 seconds
#   4. cicflowmeter -> per-class CSV
# Then label_and_split.py (with --collapse) merges + 80/20 splits.
#
# Run on OPNsense:
#   ATTACKER_HOST=10.8.0.2 OPNSENSE_IP=192.168.150.34 sh scripts/capture_remote.sh

set -eu
IFACE=${IFACE:-vmx0}
PORT=${PORT:-20000}
DURATION=${DURATION:-90}
OPNSENSE_IP=${OPNSENSE_IP:-192.168.150.34}
OUT=${OUT:-/var/log/dnp3guard/dataset_vmx0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PYTHON=${PYTHON:-python3}
LAB="$ROOT/lab"

mkdir -p "$OUT/pcap" "$OUT/csv"

# Stop the live detector so it doesn't race on vmx0
service dnp3guard stop 2>/dev/null || true
pkill -f outstation_ 2>/dev/null || true
sleep 1

# Listen on 0.0.0.0:20000 for the whole run
echo "[+] starting outstation_real on 0.0.0.0:$PORT"
$PYTHON "$LAB/outstation_real.py" --host 0.0.0.0 --port "$PORT" \
    >/tmp/outstation_real.log 2>&1 &
ECHO_PID=$!
trap 'kill $ECHO_PID 2>/dev/null; service dnp3guard start 2>/dev/null || true' EXIT INT TERM
sleep 1

run_class() {
    LABEL=$1; ATTACK_ARG=$2
    PCAP="$OUT/pcap/$LABEL.pcap"
    CSV="$OUT/csv/$LABEL.csv"
    CAP_DUR=$DURATION
    [ "$LABEL" = "NORMAL" ] && CAP_DUR=$((DURATION * 3))
    echo
    echo "===================================================================="
    echo "  CLASS: $LABEL    capture window: ${CAP_DUR}s"
    echo "===================================================================="
    echo
    echo "  ON THE ATTACKER, run:"
    echo
    if [ "$LABEL" = "DNP3_INFO" ]; then
        echo "    python lab/attacks/dnp3_info.py --host $OPNSENSE_IP --rounds 80 --interval 0.2"
    elif [ "$LABEL" = "DNP3_ENUMERATE" ]; then
        echo "    python lab/attacks/dnp3_enumerate.py --host $OPNSENSE_IP --start 0 --end 80"
    else
        echo "    python lab/master_session.py --host $OPNSENSE_IP --port $PORT --duration $CAP_DUR --reconnect 5 $ATTACK_ARG"
    fi
    echo
    printf "  Press ENTER once the attacker command is running... "
    read _
    rm -f "$PCAP" "$CSV"

    tcpdump -i "$IFACE" -w "$PCAP" -G "$CAP_DUR" -W 1 -nn "tcp port $PORT" \
        >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    echo "  capturing on $IFACE for ${CAP_DUR}s ..."
    wait $TCPDUMP_PID 2>/dev/null || true
    echo "  pcap: $(ls -lh "$PCAP" 2>/dev/null | awk '{print $5}')"

    timeout 300 cicflowmeter -f "$PCAP" -c "$CSV" >/dev/null 2>&1 || \
        echo "  [!] cicflowmeter timed out / failed for $LABEL"
    LINES=$(wc -l <"$CSV" 2>/dev/null || echo 0)
    echo "  flows: $((LINES - 1))"
}

#         label                 master_session arg
run_class NORMAL                 ""
run_class COLD_RESTART           "--attack-every 6 --attack-fc 0x0D"
run_class WARM_RESTART           "--attack-every 6 --attack-fc 0x0E"
run_class INIT_DATA              "--attack-every 6 --attack-fc 0x0F"
run_class STOP_APP               "--attack-every 6 --attack-fc 0x12"
run_class DISABLE_UNSOLICITED    "--attack-every 6 --attack-fc 0x15"
run_class DNP3_INFO              ""
run_class DNP3_ENUMERATE         ""

echo
echo "[+] labelling + splitting (collapsed FC injection classes)"
$PYTHON "$ROOT/scripts/label_and_split.py" --csv-dir "$OUT/csv" --out-dir "$OUT" --collapse

echo
echo "[+] dataset ready at $OUT"
ls -la "$OUT"/*.csv 2>/dev/null
echo
echo "Next: retrain"
echo "  python3 export_model.py --features smart-30 \\"
echo "      --train $OUT/MyDataset_Training_Balanced.csv \\"
echo "      --test  $OUT/MyDataset_Testing_Balanced.csv \\"
echo "      --out   /usr/local/dnp3guard/"
echo "  service dnp3guard start"
