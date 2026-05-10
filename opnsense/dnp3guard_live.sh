#!/bin/sh
# Supervisor: launch cicflowmeter live capture + Python tailer.
# Designed to be invoked by /usr/local/etc/rc.d/dnp3guard via daemon(8).
#
# Env (override via /etc/rc.conf or sysrc):
#   DNP3_IFACE   default: vmx0
#   DNP3_CSV     default: /var/log/dnp3guard/live.csv
#   DNP3_MODEL   default: /usr/local/dnp3guard/model.joblib
#   DNP3_LOG     default: /var/log/dnp3guard/verdicts.log

set -eu
# daemon(8) starts with a minimal PATH; make sure pip-installed scripts and
# python's bin dir are findable.
PATH="/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:$PATH"
export PATH
IFACE=${DNP3_IFACE:-vmx0}
CSV=${DNP3_CSV:-/var/log/dnp3guard/live.csv}
MODEL=${DNP3_MODEL:-/usr/local/dnp3guard/model.joblib}
VLOG=${DNP3_LOG:-/var/log/dnp3guard/verdicts.log}
PYTHON=${DNP3_PYTHON:-/usr/local/bin/python3}
EVE_JSON=${DNP3_EVE:-/var/log/suricata/eve.json}
EVE_TTL=${DNP3_EVE_TTL:-60}

mkdir -p "$(dirname "$CSV")" "$(dirname "$VLOG")"
: >"$CSV"

# clean up child on exit/signal
trap 'kill $CFM_PID 2>/dev/null; exit 0' INT TERM HUP

CICFLOWMETER=${CICFLOWMETER:-$(command -v cicflowmeter || echo /usr/local/bin/cicflowmeter)}
"$CICFLOWMETER" -i "$IFACE" -c "$CSV" >>/var/log/dnp3guard/cicflowmeter.log 2>&1 &
CFM_PID=$!
echo "[dnp3guard] cicflowmeter pid=$CFM_PID iface=$IFACE csv=$CSV"

# tailer in foreground — daemon(8) reaps it for us
EVE_FLAGS=""
[ -f "$EVE_JSON" ] && EVE_FLAGS="--eve-json $EVE_JSON --eve-ttl $EVE_TTL"
exec "$PYTHON" /usr/local/dnp3guard/live_predict.py \
    --csv "$CSV" --model "$MODEL" --log "$VLOG" $EVE_FLAGS
