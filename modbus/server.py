import json
import logging
import threading
import time
from pathlib import Path
from typing import List

from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.server import StartTcpServer


LOG_FORMAT = "%(asctime)s [%(levelname)s] [ModbusServer] %(message)s"
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


def build_data_store(initial_values: List[int]) -> ModbusServerContext:
    """
    Create a simple data store with a sequence of holding registers representing sensors.
    """
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0] * 10),
        co=ModbusSequentialDataBlock(0, [0] * 10),
        hr=ModbusSequentialDataBlock(0, initial_values),
        ir=ModbusSequentialDataBlock(0, [0] * 10),
        zero_mode=True,
    )
    return ModbusServerContext(slaves=store, single=True)


def sensor_simulation(context: ModbusServerContext, interval: float = 1.0) -> None:
    """
    Periodically update holding registers to simulate changing sensor values.
    """
    slave_id = 0x00
    address = 0
    count = 10

    while True:
        time.sleep(interval)
        values = list(context[slave_id].getValues(3, address, count))
        new_values = [(v + 1) % 1000 for v in values]
        context[slave_id].setValues(3, address, new_values)
        logger.info("Updated holding registers: %s", new_values)


def start_sensor_thread(context: ModbusServerContext, interval: float = 1.0) -> None:
    thread = threading.Thread(
        target=sensor_simulation,
        args=(context, interval),
        daemon=True,
        name="modbus-sensor-simulation",
    )
    thread.start()


def main() -> None:
    cfg = load_config()
    server_cfg = cfg.get("server", {})
    host = server_cfg.get("host", "127.0.0.1")
    port = int(server_cfg.get("port", 5020))

    logger.info("Starting Modbus TCP server on %s:%s", host, port)

    context = build_data_store(initial_values=[10 + i for i in range(10)])
    start_sensor_thread(context, interval=1.0)

    identity = ModbusDeviceIdentification()
    identity.VendorName = "ICS Lab"
    identity.ProductCode = "MODBUSLAB"
    identity.ProductName = "ICS Lab Modbus Server"
    identity.MajorMinorRevision = "1.0"

    try:
        # StartTcpServer is blocking; sensor thread runs in background.
        StartTcpServer(context=context, identity=identity, address=(host, port))
    except KeyboardInterrupt:
        logger.info("Server interrupted by user, shutting down.")


if __name__ == "__main__":
    main()

