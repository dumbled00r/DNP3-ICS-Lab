# dnp3guard — on-OPNsense DNP3 ML inference

Runs the trained CICFlowMeter-feature model **directly on OPNsense** (FreeBSD).
Sniffs the LAN interface, builds CIC flows live with `cicflowmeter`, scores
each completed flow, and on a malicious verdict pushes the offending source IP
into an OPNsense alias used by a permanent block rule.

## Why this layout

OPNsense is FreeBSD. Python deps are installed system-wide (out of band,
by you). Only the daemon, config, model, and rc.d script live under
`/usr/local/dnp3guard/`.

## One-time install (on the OPNsense box, as root)

Prereq: Python 3 + the deps installed system-wide (`cicflowmeter`,
`scapy`, `scikit-learn`, `joblib`, `requests`, optionally `xgboost`).

```sh
sh install.sh
```

`install.sh` only:
1. Drops `dnp3guard.py` + config + `rc.d` script in place
2. `sysrc dnp3guard_enable=YES && service dnp3guard start`

If your `python3` lives somewhere other than `/usr/local/bin/python3`,
override via `sysrc dnp3guard_python=/path/to/python3`.

## Files

| Path                                     | Purpose                                |
|------------------------------------------|----------------------------------------|
| `/usr/local/dnp3guard/dnp3guard.py`      | live capture + scoring + block daemon  |
| `/usr/local/dnp3guard/dnp3guard.conf`    | iface, model path, API creds, alias    |
| `/usr/local/dnp3guard/model.joblib`      | your trained sklearn/lightgbm pipeline |
| `/usr/local/etc/rc.d/dnp3guard`          | service wrapper                        |
| `/var/log/dnp3guard.log`                 | verdicts                               |

## OPNsense side, manual once

1. Firewall → Aliases → add `dnp3_blocklist` (type: Host(s), empty).
2. Firewall → Rules → LAN → add a block rule with **Source = dnp3_blocklist**
   above your DNP3 allow rules.
3. System → Access → Users → create `dnp3guard` user with API key, grant
   permission `Firewall: Alias: Edit`.
4. Put the API key/secret into `dnp3guard.conf`.

## Inline mode reality check

This is **near-real-time**, not per-packet inline. A flow scores when it
ends or hits the cicflowmeter timeout (default lowered to 15s in our
config). DNP3 polls are short, so for command-injection attacks (write,
restart, init_data) you get a verdict within a few seconds. ARP/MITM
detection inherits the same flow-timeout latency.

## Surviving firmware upgrades

Firmware upgrades wipe non-pkg Python files. After every upgrade,
reinstall whichever of your global pip deps got removed, then:

```sh
sh /usr/local/dnp3guard/install.sh
service dnp3guard restart
```
