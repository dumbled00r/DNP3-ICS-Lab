# dnp3guard — layered DNP3 detection on OPNsense

Two complementary detection layers running on the same OPNsense box:

| Layer | Tool | Response time | Catches |
|-------|------|--------------|---------|
| Signature (rules) | Suricata | < 1 ms (per-packet) | Known attack FCs: cold/warm restart, stop_appl, init_data, disable_unsolicited |
| ML anomaly | cicflowmeter + live_predict.py | 2–15 s (flow end) | Novel anomalies, info-gathering patterns, abnormal timing / volume |

Suricata and the AI detector cooperate: AI reads Suricata's `eve.json` and
**suppresses** any alert for a flow Suricata already caught, so you get one
clean alert per attack, not two.

---

## Files

| Path | Purpose |
|------|---------|
| `dnp3guard.py` | OPNsense API helper (alias block after ML verdict) |
| `live_predict.py` | CSV tailer: scores completed flows, logs ALERT / SUPPRESS |
| `eve_watcher.py` | Background thread that tails `eve.json` for Suricata correlation |
| `dnp3guard_live.sh` | Supervisor: starts cicflowmeter + live_predict.py |
| `dnp3guard.rc` | FreeBSD rc.d service wrapper |
| `dnp3guard.conf.sample` | Config template (iface, model path, API creds, alias) |
| `suricata_dnp3.rules` | Suricata rules (drop command-injection FCs, alert recon) |
| `suricata_setup.sh` | One-shot: installs rules + patches suricata.yaml + reloads |
| `install.sh` | One-shot: installs dnp3guard daemon + optionally runs suricata_setup |

---

## Step 1 — train the model (on your workstation)

### Option A — original dataset only

```sh
python export_model.py --features smart-30 --collapse
```

### Option B — hybrid (original + your own vmx0 lab capture)

First capture lab flows on the OPNsense box (needs remote attacker):
```sh
# on OPNsense (root)
ATTACKER_HOST=10.8.0.2 OPNSENSE_IP=192.168.150.34 sh scripts/capture_remote.sh
```

Then train on both:
```sh
python export_model.py \
  --train data_sample/CICFlowMeter_Training_Balanced.csv \
          /var/log/dnp3guard/dataset_vmx0/MyDataset_Training_Balanced.csv \
  --test  data_sample/CICFlowMeter_Testing_Balanced.csv \
          /var/log/dnp3guard/dataset_vmx0/MyDataset_Testing_Balanced.csv \
  --collapse --features smart-30
```

Copy the artifact to OPNsense:
```sh
scp artifacts/model.joblib root@<opnsense-ip>:/usr/local/dnp3guard/model.joblib
```

---

## Step 2 — install dnp3guard daemon

```sh
# on OPNsense (root), from this directory
sh install.sh
```

Optionally configure interface, model path etc.:
```sh
vi /usr/local/dnp3guard/dnp3guard.conf
```

Key `sysrc` overrides (persist across reboots):
```sh
sysrc dnp3guard_iface=em0          # your LAN iface
sysrc dnp3guard_eve=/var/log/suricata/eve.json   # Suricata eve.json
sysrc dnp3guard_eve_ttl=60         # seconds to keep Suricata alerts in cache
```

---

## Step 3 — enable Suricata DNP3 detection

```sh
# on OPNsense (root)
sh /usr/local/dnp3guard/suricata_setup.sh
```

This:
1. Copies `suricata_dnp3.rules` to `/usr/local/etc/suricata/rules/`
2. Patches `suricata.yaml` to enable the DNP3 app-layer parser on port 20000
   and add `dnp3` event type to `eve-log`
3. Reloads Suricata

Verify:
```sh
tail -f /var/log/suricata/eve.json | grep '"event_type":"alert"'
```

---

## Step 4 — OPNsense firewall alias (ML block)

1. Firewall → Aliases → add **`dnp3_blocklist`** (type: Host(s), empty)
2. Firewall → Rules → LAN → add a **block** rule, Source = `dnp3_blocklist`,
   place it **above** the DNP3 allow rules
3. System → Access → Users → create `dnp3guard` user with API key,
   grant **Firewall: Alias: Edit** permission
4. Put the key/secret into `/usr/local/dnp3guard/dnp3guard.conf`

---

## How the two layers coordinate

```
network packet
      │
      ▼
 [Suricata inline]
  • DNP3 parser sees FC in each packet
  • cold_restart / warm_restart / stop_appl etc. → DROP + log to eve.json
  • Info-gather threshold → ALERT + log to eve.json
      │ (passed flows continue)
      ▼
 [cicflowmeter live capture]
  • Accumulates per-flow statistics (IAT, pkt sizes, flags …)
  • Emits one CSV row when flow ends or hits timeout
      │
      ▼
 [live_predict.py]
  • Loads row, predicts label with XGBoost model
  • If verdict == NORMAL → log "ok" info line, done
  • If verdict != NORMAL:
      ├─ check EveWatcher (5-tuple in Suricata cache within TTL?)
      │     YES → log "SUPPRESS AI=<verdict> sig=<id>" (avoid double-alert)
      │     NO  → log "ALERT-AI <verdict>"  ← novel anomaly
      └─ if ALERT-AI → push src IP to OPNsense dnp3_blocklist alias
```

### Why suppress?

Suricata drops the packet (or alerts) within < 1 ms; AI verdict comes 2–15 s
later after the flow ends. Without suppression you'd get two alerts for every
Suricata-visible attack, making the log noisy and the SIEM harder to tune.

With suppression: Suricata catches the FC-based attacks precisely; AI alerts
only for flows that slipped past all signatures (unusual timing, odd object
patterns, lateral movement without a bad FC).

---

## Surviving firmware upgrades

OPNsense firmware upgrades wipe `/usr/local` Python packages.
After any upgrade:

```sh
sh /usr/local/dnp3guard/install.sh
service dnp3guard restart
```

Suricata rules in `/usr/local/etc/suricata/rules/` usually survive
(they are managed by the IDS package, not the base firmware).

---

## Inline mode reality check

This is **near-real-time**, not per-packet for the AI layer. A flow is scored
when it ends or hits the cicflowmeter idle timeout (default 15 s). DNP3 polls
are short-lived, so command-injection attacks get an AI verdict within a few
seconds — but Suricata's rule layer drops the packet before the AI even sees
the flow end.

For the attack types where we want fast blocking (restart, stop, init_data),
Suricata is the enforcement layer. AI covers subtler patterns that don't
trigger any rule.
