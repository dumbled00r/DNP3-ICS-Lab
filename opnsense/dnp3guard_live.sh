#!/bin/sh
# Supervisor: launch multimodal DNP3 detection.
#
# Two complementary processes share verdicts.log:
#   pkt_inspect.py  -- per-packet payload inspection (<1 ms latency)
#                      detects: COMMAND_INJECTION (FC byte), DNP3_RECON (ctrl=0xC9)
#   live_predict.py -- per-flow ML (2-15 s latency, flow-feature based)
#                      detects: MITM_DOS, REPLAY, ARP_POISONING
#   cicflowmeter    -- feeds per-flow CSV to live_predict.py
#
# Designed to be invoked by /usr/local/etc/rc.d/dnp3guard via daemon(8).
#
# Env (override via /etc/rc.conf or sysrc):
#   DNP3_IFACE            default: vmx0
#   DNP3_CSV              default: /var/log/dnp3guard/live.csv
#   DNP3_MODEL            default: /usr/local/dnp3guard/model.joblib
#   DNP3_LOG              default: /var/log/dnp3guard/verdicts.log
#   DNP3_PORT             default: 20000
#   DNP3_SCAN_THRESHOLD   default: 40  (ctrl=0xC9 pkts/window -> DNP3_RECON)
#   DNP3_SCAN_WINDOW      default: 10  (seconds)

set -eu
PATH="/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:$PATH"
export PATH

IFACE=${DNP3_IFACE:-vmx0}
CSV=${DNP3_CSV:-/var/log/dnp3guard/live.csv}
MODEL=${DNP3_MODEL:-/usr/local/dnp3guard/model.joblib}
VLOG=${DNP3_LOG:-/var/log/dnp3guard/verdicts.log}
PYTHON=${DNP3_PYTHON:-/usr/local/bin/python3}
EVE_JSON=${DNP3_EVE:-/var/log/suricata/eve.json}
EVE_TTL=${DNP3_EVE_TTL:-60}
PORT=${DNP3_PORT:-20000}
SCAN_THRESH=${DNP3_SCAN_THRESHOLD:-40}
SCAN_WIN=${DNP3_SCAN_WINDOW:-10}
DNP3GUARD_DIR=${DNP3GUARD_DIR:-/usr/local/dnp3guard}
PAYLOAD_MODEL=${DNP3_PAYLOAD_MODEL:-$DNP3GUARD_DIR/payload_model.joblib}

mkdir -p "$(dirname "$CSV")" "$(dirname "$VLOG")"
: >"$CSV"

PKT_PID=""
CFM_PID=""

_cleanup() {
    [ -n "$PKT_PID" ] && kill "$PKT_PID" 2>/dev/null || true
    [ -n "$CFM_PID" ] && kill "$CFM_PID" 2>/dev/null || true
    exit 0
}
trap '_cleanup' INT TERM HUP

# ---- payload inspector (runs in background) ---------------------------------
PKT_ARGS="--iface $IFACE --port $PORT --log $VLOG \
    --scan-threshold $SCAN_THRESH --scan-window $SCAN_WIN"
[ -f "$PAYLOAD_MODEL" ] && PKT_ARGS="$PKT_ARGS --payload-model $PAYLOAD_MODEL"

# shellcheck disable=SC2086
"$PYTHON" "$DNP3GUARD_DIR/pkt_inspect.py" $PKT_ARGS \
    >>/var/log/dnp3guard/pkt_inspect.log 2>&1 &
PKT_PID=$!
echo "[dnp3guard] pkt_inspect pid=$PKT_PID iface=$IFACE port=$PORT"

# ---- cicflowmeter (runs in background) --------------------------------------
CICFLOWMETER=${CICFLOWMETER:-$(command -v cicflowmeter || echo /usr/local/bin/cicflowmeter)}
"$CICFLOWMETER" -i "$IFACE" -c "$CSV" >>/var/log/dnp3guard/cicflowmeter.log 2>&1 &
CFM_PID=$!
echo "[dnp3guard] cicflowmeter pid=$CFM_PID iface=$IFACE csv=$CSV"

# ---- flow ML tailer (foreground — daemon(8) reaps it) -----------------------
EVE_FLAGS=""
[ -f "$EVE_JSON" ] && EVE_FLAGS="--eve-json $EVE_JSON --eve-ttl $EVE_TTL"
exec "$PYTHON" "$DNP3GUARD_DIR/live_predict.py" \
    --csv "$CSV" --model "$MODEL" --log "$VLOG" $EVE_FLAGS
