# pipeline/ — pcap → features → predictions

Offline / batch path. Use this for:
- validating the trained model on captured traffic
- replaying old pcaps through the model
- scheduled "capture every N minutes, score, alert" jobs

For continuous live scoring, use `opnsense/dnp3guard.py` instead — same model,
no pcap intermediate.

## Files

| File              | Purpose                                            |
|-------------------|----------------------------------------------------|
| `capture.sh`      | tcpdump for N seconds on an interface              |
| `predict_pcap.py` | pcap → cicflowmeter CSV → model → labelled CSV     |
| `run.sh`          | capture + predict in one shot                      |

## Requirements

```sh
pip install "git+https://github.com/hieulw/cicflowmeter@main" \
            joblib pandas numpy scikit-learn xgboost
```

The `cicflowmeter` package on PyPI is an older fork — for production
install directly from the **hieulw** GitHub repo, which matches the
column schema of `data_sample/`.

**hieulw/cicflowmeter requires Python ≥ 3.12.** OPNsense `install.sh`
already uses `pkg install python312`. For local Windows testing on a
Python 3.11 conda env, the PyPI version is fine as a fallback —
`predict_pcap.py` zero-fills any missing columns.

If you prefer the upstream layout:

```sh
git clone https://github.com/hieulw/cicflowmeter
cd cicflowmeter && uv sync && source .venv/bin/activate
```

On OPNsense, deps are installed system-wide. `xgboost` is only needed if
the model was exported with `--model xgb`.

## Usage

### One-off, on a pcap you already have

```sh
python predict_pcap.py /tmp/run01.pcap --model artifacts/model.joblib
```

Outputs alongside the pcap:
- `run01_flows.csv`     — raw cicflowmeter features
- `run01_predicted.csv` — same + `predicted_label` column

And prints a class-count summary.

### Capture + predict (e.g. on OPNsense)

```sh
sh run.sh igb1 60                       # capture 60s on igb1, then score
```

Set `BPF`, `PCAP_DIR`, `MODEL`, `PYTHON` env vars to override defaults.

### Reuse an existing flows CSV

```sh
python predict_pcap.py /tmp/run01.pcap --skip-extract
```

## Scheduling (cron)

On OPNsense (System → Settings → Cron) or `/etc/crontab`:

```
*/5 * * * * root /root/DNP3-ICS-Lab/pipeline/run.sh igb1 290 >>/var/log/dnp3guard/cron.log 2>&1
```

(290 s window inside a 5-min cron tick leaves headroom for prediction.)

## Common issues

| Symptom                                          | Fix                                                                       |
|--------------------------------------------------|---------------------------------------------------------------------------|
| `cicflowmeter: command not found`                | `pip install "git+https://github.com/hieulw/cicflowmeter@master"` system-wide. |
| `N feature(s) missing from cicflowmeter output`  | Cosmetic if N is small — those features are zero-filled. Investigate if a core feature is missing (column name mismatch between cicflowmeter version and training data). |
| Empty CSV / 0 flows                              | BPF filter wrong, or no DNP3 traffic on that iface during the window.     |
| All flows predicted NORMAL during an attack run  | Attack happened in a different time window than the capture, or the flow didn't terminate before tcpdump exited. Increase capture duration. |
| `tcpdump is not available` on Windows            | cicflowmeter shells out to tcpdump for BPF. Either install Wireshark (provides `tcpdump.exe`) and add it to PATH, or run the pipeline on OPNsense / a Pi where tcpdump is native. Production target is FreeBSD/Linux anyway. |
