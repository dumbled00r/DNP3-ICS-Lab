"""End-to-end local model test on Windows.

  - Start outstation_echo in a thread (TCP/20000 loopback)
  - For each attack class, monkey-patch dnp3.send_tcp to record bytes both
    directions, run the attack script, then synthesize a realistic pcap
    (TCP handshake -> data -> teardown) from the recorded exchanges.
  - Run cicflowmeter on each per-class pcap, score with the trained model,
    print expected vs predicted.

No pcap capture infrastructure required (no tcpdump, no Npcap loopback).
"""
from __future__ import annotations
import importlib, runpy, socket, subprocess, sys, threading, time
from pathlib import Path

import joblib, numpy as np, pandas as pd
from scapy.all import IP, TCP, wrpcap

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "lab"))
sys.path.insert(0, str(ROOT / "pipeline"))

from predict_pcap import CIC_RENAME            # column rename map
import dnp3 as dnp3_mod                         # lab/dnp3.py

OUT_DIR = ROOT / "artifacts" / "local_test"
OUT_DIR.mkdir(parents=True, exist_ok=True)
HOST = "127.0.0.1"
PORT = 20000


# ---------- echo outstation ----------
def echo_outstation():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT)); s.listen(16); s.settimeout(0.5)
    while not _stop.is_set():
        try:
            c, _ = s.accept()
        except socket.timeout:
            continue
        threading.Thread(target=_echo_loop, args=(c,), daemon=True).start()
    s.close()

def _echo_loop(c):
    c.settimeout(2.0)
    try:
        while True:
            data = c.recv(4096)
            if not data: break
            c.sendall(data)
    except (OSError, socket.timeout):
        pass
    finally:
        c.close()


# ---------- recording send_tcp ----------
RECORDS: list[tuple] = []        # (t, direction, bytes)

def recording_send_tcp(payload: bytes, host: str, port: int, timeout: float = 5.0):
    s = socket.create_connection((host, port), timeout=timeout)
    sport = s.getsockname()[1]
    t0 = time.time()
    RECORDS.append((t0, "syn", b"", sport))
    s.sendall(payload)
    RECORDS.append((time.time(), "fwd", payload, sport))
    try:
        reply = s.recv(4096)
    except socket.timeout:
        reply = b""
    if reply:
        RECORDS.append((time.time(), "bwd", reply, sport))
    s.close()
    RECORDS.append((time.time(), "fin", b"", sport))
    return reply


# ---------- pcap synthesis ----------
def records_to_pcap(records, out_pcap: Path):
    """Translate (t,dir,bytes,sport) events into TCP/IP packets with proper
    handshake + FIN. Group by sport (one TCP flow per attack request)."""
    by_sport: dict[int, list] = {}
    for r in records:
        by_sport.setdefault(r[3], []).append(r)

    pkts = []
    for sport, evs in by_sport.items():
        seq = 1000; ack = 1
        # SYN
        t_syn = evs[0][0]
        pkts.append((t_syn,                IP(src=HOST,dst=HOST)/TCP(sport=sport,dport=PORT,flags="S",seq=seq)))
        pkts.append((t_syn + 0.0001,       IP(src=HOST,dst=HOST)/TCP(sport=PORT,dport=sport,flags="SA",seq=ack,ack=seq+1)))
        pkts.append((t_syn + 0.0002,       IP(src=HOST,dst=HOST)/TCP(sport=sport,dport=PORT,flags="A",seq=seq+1,ack=ack+1)))
        seq += 1; ack += 1
        for ev in evs[1:]:
            t, kind, data, _ = ev
            if kind == "fwd":
                pkts.append((t, IP(src=HOST,dst=HOST)/TCP(sport=sport,dport=PORT,flags="PA",seq=seq,ack=ack)/data))
                seq += len(data)
                pkts.append((t+0.0001, IP(src=HOST,dst=HOST)/TCP(sport=PORT,dport=sport,flags="A",seq=ack,ack=seq)))
            elif kind == "bwd":
                pkts.append((t, IP(src=HOST,dst=HOST)/TCP(sport=PORT,dport=sport,flags="PA",seq=ack,ack=seq)/data))
                ack += len(data)
                pkts.append((t+0.0001, IP(src=HOST,dst=HOST)/TCP(sport=sport,dport=PORT,flags="A",seq=seq,ack=ack)))
            elif kind == "fin":
                pkts.append((t, IP(src=HOST,dst=HOST)/TCP(sport=sport,dport=PORT,flags="FA",seq=seq,ack=ack)))
                pkts.append((t+0.0001, IP(src=HOST,dst=HOST)/TCP(sport=PORT,dport=sport,flags="FA",seq=ack,ack=seq+1)))
                pkts.append((t+0.0002, IP(src=HOST,dst=HOST)/TCP(sport=sport,dport=PORT,flags="A",seq=seq+1,ack=ack+1)))
    pkts.sort(key=lambda x: x[0])
    out = []
    for t, p in pkts:
        p.time = t
        out.append(p)
    wrpcap(str(out_pcap), out)
    return len(out)


# ---------- model + predict ----------
def load_model():
    art = joblib.load(ROOT / "artifacts" / "model.joblib")
    return art["pipeline"], art["label_encoder"], art["features"]

def score_pcap(pcap: Path, pipe, le, feats):
    csv = pcap.with_suffix(".csv")
    if csv.exists(): csv.unlink()
    # locate the cicflowmeter CLI shipped alongside this venv's python
    import os
    scripts = Path(sys.executable).parent
    candidates = [
        scripts / ("cicflowmeter.exe" if os.name == "nt" else "cicflowmeter"),
        scripts / "Scripts" / "cicflowmeter.exe",   # some Windows layouts
    ]
    cfm = next((c for c in candidates if c.exists()), None)
    if cfm is None:
        raise SystemExit("cicflowmeter CLI not found in venv Scripts/. "
                         "pip install -U git+https://github.com/hieulw/cicflowmeter")
    r = subprocess.run([str(cfm), "-f", str(pcap), "-c", str(csv)],
                       capture_output=True, text=True)
    if r.returncode:
        print(f"[!] cicflowmeter stderr:\n{r.stderr[:500]}")
    if r.returncode or not csv.exists() or csv.stat().st_size == 0:
        return ["<no flows>"], 0
    df = pd.read_csv(csv).rename(columns=CIC_RENAME)
    if df.empty: return ["<empty>"], 0
    for c in feats:
        if c not in df.columns: df[c] = 0
    X = df[feats].replace([np.inf,-np.inf],0).fillna(0).astype(np.float32)
    yhat = le.inverse_transform(pipe.predict(X))
    return list(yhat), len(yhat)


# ---------- runner ----------
ATTACKS = [
    ("cold_restart",        "COLD_RESTART"),
    ("warm_restart",        "WARM_RESTART"),
    ("disable_unsolicited", "DISABLE_UNSOLICITED"),
    ("init_data",           "INIT_DATA"),
    ("stop_app",            "STOP_APP"),
]

_stop = threading.Event()

def main():
    th = threading.Thread(target=echo_outstation, daemon=True)
    th.start(); time.sleep(0.5)

    # monkey-patch the send_tcp every attack uses
    real = dnp3_mod.send_tcp
    dnp3_mod.send_tcp = recording_send_tcp

    pipe, le, feats = load_model()

    print(f"\n{'attack':<22}{'flows':>6}  {'predicted'}")
    print("-" * 60)
    for mod_name, expected in ATTACKS:
        RECORDS.clear()
        # run the attack script as __main__ with a scripted argv
        sys.argv = [f"{mod_name}.py", "--host", HOST, "--count", "5", "--interval", "0.2"]
        try:
            runpy.run_module(f"attacks.{mod_name}", run_name="__main__")
        except SystemExit:
            pass
        time.sleep(0.5)
        pcap = OUT_DIR / f"{mod_name}.pcap"
        n = records_to_pcap(list(RECORDS), pcap)
        verdicts, k = score_pcap(pcap, pipe, le, feats)
        from collections import Counter
        cnt = Counter(verdicts)
        print(f"{expected:<22}{k:>6}  {dict(cnt)}")

    dnp3_mod.send_tcp = real
    _stop.set(); th.join(timeout=2)


if __name__ == "__main__":
    main()
