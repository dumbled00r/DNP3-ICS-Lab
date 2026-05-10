#!/bin/sh
# Configure Suricata on OPNsense for DNP3 logging + DNP3Guard rule set.
#
# Run as root on the OPNsense box.
# Prerequisites: Suricata already installed via OPNsense package (pkg).
#
# What this does:
#   1. Patches suricata.yaml to enable the DNP3 app-layer parser on port 20000
#   2. Ensures eve.json emits 'alert' and 'dnp3' event types
#   3. Installs the dnp3guard.rules file
#   4. Soft-reloads Suricata (SIGHUP)
#
# After running, test with:
#   tail -f /var/log/suricata/eve.json | python3 -c "
#     import sys,json
#     for l in sys.stdin:
#         e=json.loads(l)
#         if e.get('event_type') in ('alert','dnp3'): print(e)"

set -eu
SRC_DIR=$(cd "$(dirname "$0")" && pwd)
SURI_YAML=${SURI_YAML:-/usr/local/etc/suricata/suricata.yaml}
SURI_RULES_DIR=${SURI_RULES_DIR:-/usr/local/etc/suricata/rules}
EVE_LOG=${EVE_LOG:-/var/log/suricata/eve.json}

# ---- 1. Install the rule file -----------------------------------------------
echo "[suricata] installing dnp3guard.rules"
install -m 0644 "$SRC_DIR/suricata_dnp3.rules" "$SURI_RULES_DIR/dnp3guard.rules"

# ---- 2. Enable DNP3 app-layer parser on port 20000 --------------------------
# We sed-patch the yaml in place only if our marker isn't already there.
if grep -q 'dnp3guard-patched' "$SURI_YAML" 2>/dev/null; then
    echo "[suricata] yaml already patched, skipping"
else
    echo "[suricata] patching $SURI_YAML"
    cp "$SURI_YAML" "${SURI_YAML}.bak.$(date +%s)"

    # --- DNP3 app-layer block (insert after 'protocols:' block if not present)
    # We use a Python one-liner because POSIX sed has no multi-line insert on BSD.
    python3 - "$SURI_YAML" <<'PYEOF'
import sys, re

path = sys.argv[1]
text = open(path).read()

# Enable DNP3 parser + port 20000 if not already configured
dnp3_block = """
    # dnp3guard-patched
    dnp3:
      enabled: yes
      detection-ports:
        dp: 20000
"""

if 'dnp3:' not in text:
    # Insert after the 'protocols:' header inside app-layer section
    text = re.sub(
        r'(app-layer:\s*\n\s*protocols:\s*\n)',
        r'\1' + dnp3_block,
        text, count=1
    )

# Ensure eve-log emits alert + dnp3 event types
# Find the first eve-log types list and add dnp3 if missing
if "- dnp3" not in text:
    text = re.sub(
        r'(types:\s*\n(\s+- alert\b[^\n]*\n))',
        r'\1\2'.replace(r'\2', '        - dnp3\n'),
        text, count=1
    )
    # simpler fallback: append after first "- alert" under types:
    text = re.sub(
        r'(\s+- alert\n)(?!\s+- dnp3)',
        r'\1        - dnp3\n',
        text, count=1
    )

# Add dnp3guard.rules to rule-files if not present
if 'dnp3guard.rules' not in text:
    text = re.sub(
        r'(rule-files:\s*\n)',
        r'\1 - dnp3guard.rules\n',
        text, count=1
    )

open(path, 'w').write(text)
print("  suricata.yaml patched OK")
PYEOF
fi

# ---- 3. Verify eve.json path is writable ------------------------------------
EVE_DIR=$(dirname "$EVE_LOG")
mkdir -p "$EVE_DIR"
echo "[suricata] eve.json dir: $EVE_DIR"

# ---- 4. Reload Suricata -------------------------------------------------------
echo "[suricata] reloading rules (SIGHUP)"
if service suricata status >/dev/null 2>&1; then
    # OPNsense Suricata rc.d
    service suricata reload || service suricata restart
else
    echo "[suricata] service not running; start it from OPNsense GUI or:"
    echo "  service suricata start"
fi

echo "[suricata] done."
echo ""
echo "Next steps:"
echo "  1. Confirm DNP3 events appear in $EVE_LOG:"
echo "       tail -f $EVE_LOG | grep dnp3"
echo ""
echo "  2. Set DNP3_EVE in OPNsense rc.conf for live_predict.py integration:"
echo "       sysrc dnp3guard_eve=$EVE_LOG"
echo "       sysrc dnp3guard_eve_ttl=60"
echo "       service dnp3guard restart"
echo ""
echo "  3. To test suppression: send a cold_restart while Suricata + dnp3guard"
echo "       are both running; verdicts.log should show SUPPRESS not ALERT-AI."
