#!/usr/bin/env python3
"""Cross-platform DNP3 dataset builder -- all 10 classes matching original UOWM dataset.

Classes generated:
  NORMAL, COLD_RESTART, WARM_RESTART, INIT_DATA, STOP_APP,
  DISABLE_UNSOLICITED, DNP3_INFO, DNP3_ENUMERATE,
  MITM_DOS, REPLAY, ARP_POISONING

Simulation strategy for network attacks (no second machine required):
  MITM_DOS     -- master polls against outstation_blackhole (no responses)
                 -> near-zero backward bytes, short flows
  REPLAY       -- replay_sim.py blasts pre-built DNP3 frames in rapid bursts
                 -> very low IAT, high pkt rate, short flow duration
  ARP_POISONING-- outstation_relay.py sits between master and real outstation,
                 adds 15+-8 ms per response -> higher Flow IAT Mean / Bwd IAT

Platform requirements:
  All platforms : Python >= 3.10, cicflowmeter (hieulw fork), scapy
  Windows       : Npcap (https://npcap.com) + run as Administrator
  Linux         : run as root (or CAP_NET_RAW)
  OPNsense/BSD  : run as root; uses tcpdump when available

Usage:
  python scripts/build_dataset.py
  python scripts/build_dataset.py --out /var/log/dnp3guard/dataset
  python scripts/build_dataset.py --duration 90 --collapse
  python scripts/build_dataset.py --only MITM_DOS,REPLAY,ARP_POISONING
  python scripts/build_dataset.py --iface lo0 --port 20000

Outputs (in --out dir):
  pcap/<CLASS>.pcap
  csv/<CLASS>.csv
  MyDataset_Training_Balanced.csv
  MyDataset_Testing_Balanced.csv
"""
from __future__ import annotations
import argparse, os, platform, shutil, socket, subprocess, sys, threading, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB  = ROOT / "lab"
sys.path.insert(0, str(ROOT / "scripts"))


# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------

def _sys() -> str:
    return platform.system()


def default_loopback() -> str:
    s = _sys()
    if s == "Windows": return r"\Device\NPF_Loopback"
    if s == "Darwin":  return "lo0"
    return "lo"   # Linux; FreeBSD/OPNsense uses lo0 -- override via --iface


def find_python() -> str:
    return sys.executable


def find_cicflowmeter() -> str:
    cfm = shutil.which("cicflowmeter")
    if cfm:
        return cfm
    p = Path(sys.executable).parent / (
        "cicflowmeter.exe" if _sys() == "Windows" else "cicflowmeter")
    if p.exists():
        return str(p)
    raise SystemExit(
        "cicflowmeter not found.\n"
        "Install: pip install git+https://github.com/hieulw/cicflowmeter "
        "--ignore-requires-python")


TCPDUMP = shutil.which("tcpdump")


def wait_port(host: str, port: int, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


# ---------------------------------------------------------------------------
# Packet capture (tcpdump preferred, scapy fallback for Windows)
# ---------------------------------------------------------------------------

def _capture_tcpdump(iface: str, port: int, duration: int, pcap: Path) -> None:
    subprocess.run(
        [TCPDUMP, "-i", iface, "-w", str(pcap),
         "-G", str(duration), "-W", "1", "-nn",
         f"tcp port {port}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _capture_scapy(iface: str, port: int, duration: float, pcap: Path) -> None:
    try:
        from scapy.all import AsyncSniffer, wrpcap
    except ImportError:
        raise SystemExit(
            "scapy required on Windows: pip install scapy\n"
            "Also install Npcap from https://npcap.com and run as Administrator.")
    sn = AsyncSniffer(iface=iface, filter=f"tcp port {port}", store=True)
    sn.start()
    time.sleep(duration)
    sn.stop()
    wrpcap(str(pcap), sn.results or [])


def capture_pcap(iface: str, port: int, duration: int, pcap: Path) -> None:
    if TCPDUMP:
        _capture_tcpdump(iface, port, duration, pcap)
    else:
        _capture_scapy(iface, port, float(duration), pcap)


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------

def start_proc(cmd: list[str]) -> subprocess.Popen:
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


def kill_proc(p: subprocess.Popen | None) -> None:
    if p is None:
        return
    try:
        p.terminate()
        p.wait(timeout=3)
    except (subprocess.TimeoutExpired, OSError):
        try:
            p.kill()
        except OSError:
            pass


def run_cicflowmeter(cfm: str, pcap: Path, csv: Path, timeout: int = 300) -> bool:
    try:
        r = subprocess.run([cfm, "-f", str(pcap), "-c", str(csv)],
                           timeout=timeout,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        print("    [!] cicflowmeter timed out")
        return False


# ---------------------------------------------------------------------------
# Class definitions
# ---------------------------------------------------------------------------

def build_class_list(python: str, port: int, dur: int) -> list[tuple]:
    """Return list of (label, outstation_mode, master_cmd, cap_dur).

    outstation_mode values:
      "real"      -- outstation_real.py on :port
      "blackhole" -- outstation_blackhole.py on :port (no responses)
      "relay"     -- outstation_real.py on :port+1 + outstation_relay.py on :port
    """
    ATK = [python, str(LAB / "master_session.py"),
           "--host", "127.0.0.1", "--port", str(port),
           "--duration", str(dur),
           "--reconnect", "5",
           "--c1-period", "0.012",
           "--c0-every", "30",
           "--attack-every", "6"]

    NRM_DUR = dur * 3
    NRM = [python, str(LAB / "master_session.py"),
           "--host", "127.0.0.1", "--port", str(port),
           "--duration", str(NRM_DUR),
           "--reconnect", "5", "--c1-period", "0.012", "--c0-every", "30"]

    # MITM_DOS: normal master against blackhole -> near-zero bwd bytes
    MITM = [python, str(LAB / "master_session.py"),
            "--host", "127.0.0.1", "--port", str(port),
            "--duration", str(dur),
            "--reconnect", "5", "--c1-period", "0.012", "--c0-every", "30"]

    # REPLAY: rapid burst of pre-captured frames -> very low IAT
    REPLAY = [python, str(LAB / "attacks" / "replay_sim.py"),
              "--host", "127.0.0.1", "--port", str(port),
              "--duration", str(dur),
              "--burst-size", "25", "--burst-interval", "0.001", "--burst-gap", "0.8"]

    # ARP_POISONING: relay adds 15+-8 ms -> higher Flow IAT Mean
    ARP = [python, str(LAB / "master_session.py"),
           "--host", "127.0.0.1", "--port", str(port),
           "--duration", str(dur),
           "--reconnect", "5", "--c1-period", "0.012", "--c0-every", "30"]

    return [
        ("NORMAL",              "real",      NRM,                             NRM_DUR),
        ("COLD_RESTART",        "real",      ATK+["--attack-fc","0x0D"],      dur),
        ("WARM_RESTART",        "real",      ATK+["--attack-fc","0x0E"],      dur),
        ("INIT_DATA",           "real",      ATK+["--attack-fc","0x0F"],      dur),
        ("STOP_APP",            "real",      ATK+["--attack-fc","0x12"],      dur),
        ("DISABLE_UNSOLICITED", "real",      ATK+["--attack-fc","0x15"],      dur),
        ("DNP3_INFO",           "real",
         [python, str(LAB/"attacks"/"dnp3_info.py"),
          "--host","127.0.0.1","--rounds","60","--interval","0.15"],          dur),
        ("DNP3_ENUMERATE",      "real",
         [python, str(LAB/"attacks"/"dnp3_enumerate.py"),
          "--host","127.0.0.1","--start","0","--end","80"],                   dur),
        ("MITM_DOS",            "blackhole", MITM,                            dur),
        ("REPLAY",              "real",      REPLAY,                          dur),
        ("ARP_POISONING",       "relay",     ARP,                             dur),
    ]


# ---------------------------------------------------------------------------
# Per-class capture
# ---------------------------------------------------------------------------

def run_class(label: str, ost_mode: str, master_cmd: list[str], cap_dur: int,
              port: int, iface: str, cfm: str,
              pcap_dir: Path, csv_dir: Path, python: str) -> None:
    pcap = pcap_dir / f"{label}.pcap"
    csv  = csv_dir  / f"{label}.csv"
    for f in (pcap, csv):
        if f.exists():
            f.unlink()

    print(f"\n{'='*64}")
    print(f"  CLASS: {label}   outstation={ost_mode}   window={cap_dur}s")
    print(f"{'='*64}")

    # ---- start appropriate outstation(s) ------------------------------------
    ost_main: subprocess.Popen | None = None
    ost_back: subprocess.Popen | None = None   # only used in relay mode

    if ost_mode == "blackhole":
        ost_main = start_proc([python, str(LAB/"outstation_blackhole.py"),
                               "--host", "127.0.0.1", "--port", str(port)])
        if not wait_port("127.0.0.1", port, 10):
            print(f"  [!] blackhole outstation failed; skipping {label}")
            kill_proc(ost_main)
            return

    elif ost_mode == "relay":
        backend_port = port + 1
        ost_back = start_proc([python, str(LAB/"outstation_real.py"),
                               "--host", "127.0.0.1", "--port", str(backend_port)])
        if not wait_port("127.0.0.1", backend_port, 10):
            print(f"  [!] backend outstation failed; skipping {label}")
            kill_proc(ost_back)
            return
        ost_main = start_proc([python, str(LAB/"outstation_relay.py"),
                               "--host", "127.0.0.1", "--port", str(port),
                               "--backend-port", str(backend_port),
                               "--delay", "0.015", "--jitter", "0.008"])
        if not wait_port("127.0.0.1", port, 10):
            print(f"  [!] relay outstation failed; skipping {label}")
            kill_proc(ost_main)
            kill_proc(ost_back)
            return

    else:   # "real"
        ost_main = start_proc([python, str(LAB/"outstation_real.py"),
                               "--host", "127.0.0.1", "--port", str(port)])
        if not wait_port("127.0.0.1", port, 10):
            print(f"  [!] real outstation failed; skipping {label}")
            kill_proc(ost_main)
            return

    # ---- start capture in a background thread --------------------------------
    cap_thread = threading.Thread(
        target=capture_pcap, args=(iface, port, cap_dur, pcap), daemon=True)
    time.sleep(0.3)
    cap_thread.start()
    time.sleep(0.5)

    # ---- run attack / master -------------------------------------------------
    master = start_proc(master_cmd)
    master.wait()
    cap_thread.join(timeout=cap_dur + 15)

    # ---- stop outstation(s) --------------------------------------------------
    kill_proc(ost_main)
    kill_proc(ost_back)

    sz = pcap.stat().st_size if pcap.exists() else 0
    print(f"  pcap : {sz // 1024} KB")

    # ---- run cicflowmeter ----------------------------------------------------
    print(f"  cicflowmeter ... ", end="", flush=True)
    ok = run_cicflowmeter(cfm, pcap, csv)
    rows = 0
    if csv.exists():
        try:
            rows = max(0, len(csv.read_text(errors="replace").splitlines()) - 1)
        except OSError:
            pass
    print(f"{'OK' if ok else 'FAILED'}  flows={rows}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Generate full DNP3 dataset (10 classes) on loopback.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument("--out",      default=str(ROOT / "dataset"),
                    help="output directory (default: <repo>/dataset)")
    ap.add_argument("--port",     type=int, default=20000)
    ap.add_argument("--duration", type=int, default=90,
                    help="per-class capture window in seconds (NORMAL=3x, default 90)")
    ap.add_argument("--iface",    default=None,
                    help="capture interface (auto-detect loopback if omitted)")
    ap.add_argument("--collapse", action="store_true",
                    help="collapse 5 FC-injection classes -> DNP3_COMMAND_INJECTION "
                         "in the final Training/Testing CSVs")
    ap.add_argument("--skip-merge", action="store_true",
                    help="skip label_and_split; produce per-class CSVs only")
    ap.add_argument("--only", default="",
                    help="comma-separated subset of class labels to run "
                         "(e.g. --only MITM_DOS,REPLAY,ARP_POISONING)")
    a = ap.parse_args()

    out      = Path(a.out)
    pcap_dir = out / "pcap"
    csv_dir  = out / "csv"
    pcap_dir.mkdir(parents=True, exist_ok=True)
    csv_dir.mkdir(parents=True, exist_ok=True)

    iface  = a.iface or default_loopback()
    python = find_python()
    cfm    = find_cicflowmeter()

    only = {c.strip().upper() for c in a.only.split(",") if c.strip()}

    print(f"\n[build_dataset] platform={_sys()}  iface={iface}")
    print(f"[build_dataset] port={a.port}  duration={a.duration}s/class")
    print(f"[build_dataset] output: {out}")
    if not TCPDUMP:
        print("[build_dataset] tcpdump not found; will use scapy (requires Npcap on Windows)")

    classes = build_class_list(python, a.port, a.duration)
    if only:
        classes = [(l, o, c, d) for l, o, c, d in classes if l in only]
        if not classes:
            raise SystemExit(f"--only filter matched no classes: {only}")

    for label, ost_mode, master_cmd, cap_dur in classes:
        run_class(label, ost_mode, master_cmd, cap_dur,
                  a.port, iface, cfm, pcap_dir, csv_dir, python)

    if not a.skip_merge:
        print(f"\n[build_dataset] labelling + 80/20 split ...")
        merge_cmd = [python,
                     str(ROOT / "scripts" / "label_and_split.py"),
                     "--csv-dir", str(csv_dir),
                     "--out-dir", str(out)]
        if a.collapse:
            merge_cmd.append("--collapse")
        subprocess.run(merge_cmd, check=True)

    print(f"\n[build_dataset] done.  Output: {out}/")
    total = 0
    for f in sorted(out.glob("*.csv")):
        try:
            rows = max(0, len(f.read_text(errors="replace").splitlines()) - 1)
        except OSError:
            rows = 0
        print(f"  {f.name}: {rows} rows")
        total += rows
    if total:
        print(f"\n  Total rows in final CSVs: {total}")

    print()
    print("Next step -- train the model:")
    collapse_flag = "--collapse " if a.collapse else ""
    print(f"  python export_model.py \\")
    print(f"    --train {out}/MyDataset_Training_Balanced.csv \\")
    print(f"    --test  {out}/MyDataset_Testing_Balanced.csv \\")
    print(f"    --features smart-30 {collapse_flag}")
    print()
    print("  Or hybrid with original dataset:")
    print(f"  python export_model.py \\")
    print(f"    --train data_sample/CICFlowMeter_Training_Balanced.csv \\")
    print(f"            {out}/MyDataset_Training_Balanced.csv \\")
    print(f"    --test  data_sample/CICFlowMeter_Testing_Balanced.csv \\")
    print(f"            {out}/MyDataset_Testing_Balanced.csv \\")
    print(f"    {collapse_flag}--features smart-30")


if __name__ == "__main__":
    main()
