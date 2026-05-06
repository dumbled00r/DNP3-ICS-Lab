# dnp3guard — on-OPNsense DNP3 ML inference

Runs the trained CICFlowMeter-feature model **directly on OPNsense** (FreeBSD).
Sniffs the LAN interface, builds CIC flows live with `cicflowmeter`, scores
each completed flow, and on a malicious verdict pushes the offending source IP
into an OPNsense alias used by a permanent block rule.

## Why this layout

OPNsense is FreeBSD — `pip` works inside a venv but firmware upgrades wipe
`/usr/local/lib/python*/site-packages` files not owned by `pkg`. We isolate
everything under `/usr/local/dnp3guard/` and reinstall on upgrade via a
`post-upgrade` hook.

## One-time install (on the OPNsense box, as root)

```sh
fetch -o - https://<your-host>/install.sh | sh         # or scp install.sh && sh install.sh
```

`install.sh` does:
1. `pkg install -y python311 py311-pip py311-numpy py311-scipy py311-scikit-learn py311-pandas`
2. Creates venv at `/usr/local/dnp3guard/venv`
3. `pip install cicflowmeter scapy joblib requests`
4. Drops `dnp3guard.py` + config + `rc.d` script in place
5. `sysrc dnp3guard_enable=YES && service dnp3guard start`

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

OPNsense upgrades wipe pip-installed files. After every upgrade run:

```sh
/usr/local/dnp3guard/install.sh --reinstall
```

Or add it to `/usr/local/etc/rc.syshook.d/start/99-dnp3guard` (an OPNsense
syshook that runs after upgrade boots).
