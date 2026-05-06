import argparse
import logging
import subprocess
import sys
import time
from pathlib import Path


LOG_FORMAT = "%(asctime)s [%(levelname)s] [DNP3Scenario] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run(attacks: list[str]) -> None:
    outstation_path = PROJECT_ROOT / "dnp3" / "outstation.py"
    master_path = PROJECT_ROOT / "dnp3" / "master.py"
    attacks_dir = PROJECT_ROOT / "dnp3" / "attacks"

    logger.info("Starting DNP3 outstation...")
    outstation_proc = subprocess.Popen([sys.executable, str(outstation_path)])
    time.sleep(2.0)

    logger.info("Starting normal DNP3 master...")
    master_proc = subprocess.Popen([sys.executable, str(master_path)])
    time.sleep(5.0)

    try:
        if "all" in attacks or "spoof" in attacks:
            logger.info("Starting spoofed master in parallel (Ctrl+C to stop)...")
            spoof_proc = subprocess.Popen(
                [sys.executable, str(attacks_dir / "master_spoof.py")],
            )
            time.sleep(10.0)
            spoof_proc.terminate()

        if "all" in attacks or "proxy" in attacks:
            logger.info("Starting data modification proxy on port 21000...")
            proxy_proc = subprocess.Popen(
                [sys.executable, str(attacks_dir / "data_modification.py")],
            )
            time.sleep(3.0)

            logger.info("Restarting master to connect via proxy (port 21000)...")
            master_proc.terminate()
            master_proc = subprocess.Popen(
                [sys.executable, str(master_path), "--port", "21000"],
            )
            time.sleep(10.0)

        if "all" in attacks or "replay" in attacks:
            logger.info("Recording frames for replay attack...")
            subprocess.run(
                [
                    sys.executable,
                    str(attacks_dir / "replay_attack.py"),
                    "record",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "20000",
                    "--duration",
                    "5",
                    "--output",
                    "dnp3_frames.log",
                ],
                check=False,
            )

            logger.info("Stopping normal master and launching replay attack...")
            master_proc.terminate()
            replay_proc = subprocess.Popen(
                [
                    sys.executable,
                    str(attacks_dir / "replay_attack.py"),
                    "replay",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "20000",
                    "--input",
                    "dnp3_frames.log",
                ],
            )
            replay_proc.wait()

        logger.info("DNP3 scenario finished. Press Ctrl+C to stop outstation/proxy.")
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        logger.info("Stopping DNP3 scenario...")
    finally:
        try:
            master_proc.terminate()
        except Exception:
            pass
        try:
            outstation_proc.terminate()
        except Exception:
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run DNP3 scenario with selectable attack types.",
    )
    parser.add_argument(
        "--attacks",
        nargs="+",
        choices=["spoof", "proxy", "replay", "all"],
        default=["all"],
        help="Chọn kiểu tấn công DNP3: spoof, proxy, replay, hoặc all (mặc định: all).",
    )
    args = parser.parse_args()

    run(args.attacks)

