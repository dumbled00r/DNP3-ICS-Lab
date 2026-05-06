# DNP3 ICS Lab — Deployment Runbook

End-to-end steps to bring up live DNP3 anomaly detection on OPNsense, using
the model trained from `dnp3_anomaly_detection.py` and the `data_sample/`
CICFlowMeter dataset.

---

## Architecture (recap)

```
master-pi  ──DNP3──▶  outstation-pi
              ▲
              │  (mirrored / passing through)
              ▼
         OPNsense  ──▶  dnp3guard (sniff + score + block)
                          │
                          └──▶ Firewall alias `dnp3_blocklist`
                               (referenced by a top-of-list block rule)
```

`dnp3guard` runs as a FreeBSD `rc.d` service under `/usr/local/dnp3guard/`,
using the system-wide Python install. It sniffs DNP3 with scapy, builds
CICFlowMeter features live, scores each completed flow with the trained
sklearn pipeline, and on a non-`NORMAL` verdict pushes the source IP into
the OPNsense alias.

---

## Phase A — train + export (workstation)

```powershell
cd d:\BKCSLab\DNP3\ics_lab
conda activate DATN

# (optional) full benchmark — produces results/, takes a while
python dnp3_anomaly_detection.py

# always run this — produces the artifacts that ship to OPNsense
python export_model.py --model xgb
```

Output: `artifacts/model.joblib` and `artifacts/features.txt`.

**Choose `--model rf` instead of `xgb` if `pip install xgboost` is painful on
OPNsense** — RandomForest needs only numpy/scikit-learn, both available via
FreeBSD `pkg`.

---

## Phase B — install dnp3guard on OPNsense

On the OPNsense box (root shell):

```sh
git clone https://github.com/dumbled00r/DNP3-ICS-Lab
cd DNP3-ICS-Lab/opnsense
sh install.sh
```

`install.sh` is idempotent — rerun any time, also after firmware upgrades
(which wipe pip-installed files).

Then ship the artifacts up from your workstation:

```powershell
scp d:\BKCSLab\DNP3\ics_lab\artifacts\model.joblib   root@OPNSENSE_IP:/usr/local/dnp3guard/
scp d:\BKCSLab\DNP3\ics_lab\artifacts\features.txt   root@OPNSENSE_IP:/usr/local/dnp3guard/
```

If you used `--model xgb`, install the runtime system-wide on OPNsense:

```sh
pip install xgboost
```

---

## Phase C — OPNsense web UI (one-time)

1. **Firewall → Aliases → Add**
   - Name: `dnp3_blocklist`
   - Type: `Host(s)`
   - Content: empty
   - Save + Apply.

2. **Firewall → Rules → LAN → Add** (drag to top, above any DNP3 allow rule)
   - Action: `Block`
   - Source: `Single host or alias` → `dnp3_blocklist`
   - Destination: `any`
   - Save + Apply.

3. **System → Access → Users → Add**
   - Username: `dnp3guard`
   - Generate API key + secret, save the `apikey.txt`.
   - Effective Privileges: add `Firewall: Alias: Edit`.

---

## Phase D — configure + start

Edit `/usr/local/dnp3guard/dnp3guard.conf`:

```ini
[capture]
iface          = igb1            # check `ifconfig` for the LAN nic
bpf            = tcp port 20000
flow_timeout   = 15

[model]
path           = /usr/local/dnp3guard/model.joblib
features_file  = /usr/local/dnp3guard/features.txt
benign_label   = NORMAL

[opnsense_api]
base_url       = https://127.0.0.1
key            = <from apikey.txt>
secret         = <from apikey.txt>
verify_tls     = false
alias_name     = dnp3_blocklist
block_ttl_sec  = 3600
```

Start the service:

```sh
service dnp3guard restart
tail -f /var/log/dnp3guard.log
```

Expect a startup line like `dnp3guard starting; iface=igb1` followed by
`model loaded; N features`.

---

## Phase E — smoke test

From the master Pi:

```sh
cd ~/DNP3-ICS-Lab/lab
python3 attacks/cold_restart.py --count 3
```

Within ~15 s (the configured flow timeout) you should see:

- `BLOCK <master-ip> reason=COLD_RESTART` in `/var/log/dnp3guard.log`
- the master IP appear in **Firewall → Diagnostics → Aliases →
  `dnp3_blocklist`**
- the next attack attempt drops at the firewall.

After `block_ttl_sec` seconds the entry auto-removes (`UNBLOCK` in log).

---

## Common failures

| Symptom                                          | Fix                                                                    |
|--------------------------------------------------|------------------------------------------------------------------------|
| Empty log, no flows scoring                      | Wrong `iface` or BPF — confirm DNP3 is on TCP/20000 and the LAN nic.   |
| `model.joblib must be the dict produced by ...`  | You shipped an old artifact — re-run `python export_model.py`.         |
| `xgboost` install fails on OPNsense              | Re-export with `--model rf`; ship the new `model.joblib`.              |
| API 401 in log                                   | API user missing `Firewall: Alias: Edit`, or wrong key/secret.         |
| Firmware upgrade removed deps                    | Reinstall global pip deps, then `sh /usr/local/dnp3guard/install.sh`.  |
| `'super' object has no attribute __sklearn_tags__` during export | sklearn ≥1.6 calls `__sklearn_tags__` on every Pipeline op, missing in xgboost <3. Fix: `pip install -U "xgboost>=2.1"` in the training env. |
| VarianceThreshold feature-name warning           | Cosmetic; suppressed in current `export_model.py`.                     |

---

## Latency reality check

This is **near-real-time**, not per-packet inline. A flow scores when it
ends or hits the cicflowmeter timeout (15 s in the config). For DNP3
control commands (write / restart / init_data) this is usually fine —
the attacker is blocked before they can iterate. For ARP / MITM detection
the same flow-end latency applies.

Per-packet sub-ms blocking would need a different model trained on
per-packet features, not the CICFlowMeter dataset.
