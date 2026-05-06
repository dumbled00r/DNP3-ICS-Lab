import argparse
import logging

from scapy.all import sniff, TCP, IP  # type: ignore[import]


LOG_FORMAT = "%(asctime)s [%(levelname)s] [ModbusRecon] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)


# Callback xử lý từng gói tin bắt được: trích IP nguồn/đích, port và độ dài payload để phục vụ mục đích trinh sát.
def packet_callback(pkt) -> None:  # type: ignore[no-untyped-def]
    if not pkt.haslayer(TCP):
        return

    ip = pkt[IP]
    tcp = pkt[TCP]
    payload_len = len(bytes(tcp.payload))

    logger.info(
        "Observed Modbus TCP packet %s:%d -> %s:%d payload_len=%d",
        ip.src,
        tcp.sport,
        ip.dst,
        tcp.dport,
        payload_len,
    )


 # Hàm cấu hình và khởi chạy trình sniff Scapy với BPF filter theo cổng Modbus, gọi packet_callback cho mỗi gói.
def run_sniffer(
    interface: str,
    port: int,
    count: int,
) -> None:
    logger.info(
        "Starting reconnaissance sniffer on interface=%s for tcp port %d",
        interface,
        port,
    )
    bpf_filter = f"tcp port {port}"
    sniff(
        iface=interface or None,
        filter=bpf_filter,
        prn=packet_callback,
        store=False,
        count=count if count > 0 else 0,
    )


 # Hàm main phân tích tham số CLI và chạy sniffer với interface, cổng, số lượng gói mong muốn.
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Passive Modbus reconnaissance sniffer using Scapy.",
    )
    parser.add_argument(
        "--iface",
        default="lo",
        help="Interface to sniff on (default: lo for localhost).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5020,
        help="Modbus TCP port to filter on.",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = infinite until Ctrl+C).",
    )
    args = parser.parse_args()

    run_sniffer(
        interface=args.iface,
        port=args.port,
        count=args.count,
    )


if __name__ == "__main__":
    main()

