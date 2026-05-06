import argparse
import logging
import subprocess
import sys
import time
from pathlib import Path


LOG_FORMAT = "%(asctime)s [%(levelname)s] [ModbusScenario] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run(attacks: list[str]) -> None:
    server_path = PROJECT_ROOT / "modbus" / "server.py"
    client_path = PROJECT_ROOT / "modbus" / "client.py"
    attacks_dir = PROJECT_ROOT / "modbus" / "attacks"

    logger.info("Starting Modbus server...")
    server_proc = subprocess.Popen([sys.executable, str(server_path)])
    time.sleep(2.0)

    logger.info("Starting Modbus client...")
    client_proc = subprocess.Popen([sys.executable, str(client_path)])
    time.sleep(5.0)

    try:
        if "all" in attacks or "dos" in attacks:
            logger.info("Running DoS attack for 20 seconds...")
            subprocess.Popen(
                [sys.executable, str(attacks_dir / "dos.py"), "--duration", "20"],
            )
            time.sleep(25.0)

        if "all" in attacks or "cmd" in attacks:
            logger.info("Running command injection attack (Ctrl+C to stop)...")
            cmd_inj_proc = subprocess.Popen(
                [sys.executable, str(attacks_dir / "command_injection.py"), "--iterations", "0"],
            )
            time.sleep(15.0)
            cmd_inj_proc.terminate()

        if "all" in attacks or "sniff" in attacks:
            logger.info("Starting reconnaissance sniffer (run separately if needed)...")
            logger.info(
                "Example (may require sudo): python %s --iface lo --count 50",
                attacks_dir / "sniff_recon.py",
            )

        logger.info("Modbus scenario finished. Press Ctrl+C to stop server/client.")
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        logger.info("Stopping Modbus scenario...")
    finally:
        client_proc.terminate()
        server_proc.terminate()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run Modbus scenario with selectable attack types.",
    )
    parser.add_argument(
        "--attacks",
        nargs="+",
        choices=["dos", "cmd", "sniff", "all"],
        default=["all"],
        help="Chọn kiểu tấn công Modbus: dos, cmd, sniff, hoặc all (mặc định: all).",
    )
    args = parser.parse_args()

    run(args.attacks)

