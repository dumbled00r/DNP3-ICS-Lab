# Build your own DNP3 flow dataset

End-to-end pipeline to capture, label, train, and deploy on **your** lab
topology — replacing the paper's pretrained model that doesn't transfer.

## Why

The original `data_sample/` was captured with a specific opendnp3 outstation
on a specific network. Loopback IATs (µs) differ from lab network IATs (ms),
TCP windows differ, response sizes differ. Even when our generated traffic
contains identical DNP3 application bytes, the *flow features* land in a
different region of feature space and the original model misclassifies them.

The fix is to train on captures **from your own lab**, with your own
outstation, your own network paths.

## Steps

### 1. Capture + label

On OPNsense (or any host running the outstation + having tcpdump +
cicflowmeter):

```sh
cd ~/DNP3-ICS-Lab
sh scripts/build_dataset.sh
```

Defaults: `IFACE=lo0`, `PORT=20000`, `DURATION=60s` per class. Override:

```sh
IFACE=vmx0 DURATION=120 sh scripts/build_dataset.sh
```

Per class, the orchestrator:
1. Starts `outstation_echo` on `:$PORT` (or you can swap in `lab/outstation.py`)
2. Captures a pcap on `$IFACE` for `$DURATION` seconds
3. Drives the corresponding attack/normal script in parallel
4. Closes the pcap and runs cicflowmeter offline against it

Then `label_and_split.py` adds the `Label` column, renames hieulw's
snake_case columns to data_sample's Title Case, shuffles, and emits:

```
$OUT/MyDataset_Training_Balanced.csv   (80%)
$OUT/MyDataset_Testing_Balanced.csv    (20%)
```

Default `$OUT=/var/log/dnp3guard/dataset`.

### 2. Train on the new data

```sh
# on OPNsense, or scp the CSVs back to your workstation
python3 export_model.py \
    --train /var/log/dnp3guard/dataset/MyDataset_Training_Balanced.csv \
    --test  /var/log/dnp3guard/dataset/MyDataset_Testing_Balanced.csv \
    --features smart-40 \
    --out   /usr/local/dnp3guard/
```

Prints test accuracy + macro-F1. Compare against the paper's model:

```sh
python3 validate_model.py        # if you point its TEST_CSV to your CSV
```

### 3. Deploy

Already in place — `dnp3guard` autoloads `/usr/local/dnp3guard/model.joblib`
on every restart:

```sh
service dnp3guard restart
tail -f /var/log/dnp3guard/verdicts.log
```

## Sanity checks

- **Per-class flow counts** are printed at the end of `build_dataset.sh`.
  Aim for ≥ 100 flows per class. If a class has < 30, increase `DURATION`
  or the `--count` for that attack in `build_dataset.sh`.
- **NORMAL volume** should be ≥ all attack classes combined (or use
  class-weighting in training). Otherwise the model biases toward attacks.
- **Inspect a CSV manually**:
  `head -1 /var/log/dnp3guard/dataset/csv/COLD_RESTART.csv` — confirm
  cicflowmeter columns are present.

## When to rebuild

Anything that changes flow shape: new outstation implementation, network
re-cabling, MTU change, TCP window tuning, kernel upgrade affecting timing.
Or simply periodically as a sanity check.
