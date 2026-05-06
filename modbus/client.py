import json
import logging
import time
from pathlib import Path

from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ConnectionException


LOG_FORMAT = "%(asctime)s [%(levelname)s] [ModbusClient] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODBUS_CONFIG_PATH = PROJECT_ROOT / "config" / "modbus.json"


def load_config() -> dict:
    if MODBUS_CONFIG_PATH.is_file():
        with MODBUS_CONFIG_PATH.open("r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError as exc:
                logger.error("Failed to parse %s: %s", MODBUS_CONFIG_PATH, exc)
    # fallback defaults aligned with the plan
    return {
        "server": {"host": "127.0.0.1", "port": 5020},
        "client": {"host": "127.0.0.1", "port": 5020, "poll_interval_s": 1.0},
    }


def safe_read_holding_registers(client: ModbusTcpClient, address: int, count: int = 10) -> None:
    try:
        if not client.connect():
            raise ConnectionException("Unable to connect to Modbus server")

        response = client.read_holding_registers(address=address, count=count, slave=1)
        if response.isError():
            logger.error("Read error: %s", response)
        else:
            logger.info("Read holding registers[%d..%d]: %s", address, address + count - 1, response.registers)
    finally:
        client.close()


def safe_write_single_register(client: ModbusTcpClient, address: int, value: int) -> None:
    try:
        if not client.connect():
            raise ConnectionException("Unable to connect to Modbus server")

        response = client.write_register(address=address, value=value, slave=1)
        if response.isError():
            logger.error("Write error at %d: %s", address, response)
        else:
            logger.info("Wrote holding register[%d] = %d", address, value)
    finally:
        client.close()


def main() -> None:
    cfg = load_config()
    client_cfg = cfg.get("client", {})

    host = client_cfg.get("host", "127.0.0.1")
    port = int(client_cfg.get("port", 5020))
    interval = float(client_cfg.get("poll_interval_s", 1.0))

    logger.info("Starting Modbus TCP client polling %s:%s every %.2fs", host, port, interval)

    address = 0
    count = 10
    toggle_value = 123

    while True:
        client = ModbusTcpClient(host=host, port=port)
        try:
            safe_read_holding_registers(client, address=address, count=count)
        except ConnectionException as exc:
            logger.error("Connection failed: %s", exc)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Unexpected error during read: %s", exc)

        # Example occasional write to demonstrate bidirectional traffic
        client = ModbusTcpClient(host=host, port=port)
        try:
            safe_write_single_register(client, address=0, value=toggle_value)
            toggle_value = 10 if toggle_value != 10 else 123
        except ConnectionException as exc:
            logger.error("Connection failed during write: %s", exc)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Unexpected error during write: %s", exc)

        time.sleep(interval)


if __name__ == "__main__":
    main()

