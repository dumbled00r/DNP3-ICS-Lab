# DNP3 ICS Lab — Dataset Generation

Replicates the 11 traffic classes in `data_sample/` on a small Raspberry Pi
testbed. OPNsense + Suricata captures pcap on the wire; CICFlowMeter then
extracts flow features.

## Topology

```
                        +-----------------+
                        |  OPNsense + IDS |  (pcap capture, port mirror)
                        +--------+--------+
                                 |
        +----------------+-------+--------+----------------+
        |                |                                 |
  master-pi          outstation-pi                    attacker-pi
  192.168.10.10      192.168.10.20                    192.168.10.30
  runs:              runs:                            runs:
   - normal.py        - outstation.py                  - arp_poisoning.py
   - all FC attacks                                    - mitm_dos.py
                                                       - replay.py
                                                       - dnp3_enumerate.py
                                                       - dnp3_info.py
```

DNP3 over TCP, port 20000. Master link address 1, outstation 10.

## Per-Pi setup

```bash
sudo apt update && sudo apt install -y python3-pip tcpdump tcpreplay
pip3 install -r requirements.txt
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))   # for scapy on attacker-pi
```

## Run order (per capture session)

1. Outstation Pi: `python3 outstation.py`
2. Master Pi:    `python3 normal.py --duration 600`   (always running while you record any class)
3. Start Suricata pcap recording on OPNsense.
4. On the appropriate Pi, run **one** attack script for the class you want to label.
5. Stop pcap. Tag the time window with the class name. Run CICFlowMeter on the pcap.

Each script prints its start/stop timestamps in ISO-8601 — use those to slice flows.

## Class → script map

| Class               | Pi          | Script                          |
|---------------------|-------------|---------------------------------|
| NORMAL              | master      | `normal.py`                     |
| DISABLE_UNSOLICITED | master      | `attacks/disable_unsolicited.py`|
| WARM_RESTART        | master      | `attacks/warm_restart.py`       |
| COLD_RESTART        | master      | `attacks/cold_restart.py`       |
| STOP_APP            | master      | `attacks/stop_app.py`           |
| INIT_DATA           | master      | `attacks/init_data.py`          |
| DNP3_ENUMERATE      | attacker    | `attacks/dnp3_enumerate.py`     |
| DNP3_INFO           | attacker    | `attacks/dnp3_info.py`          |
| REPLAY              | attacker    | `attacks/replay.py`             |
| ARP_POISONING       | attacker    | `attacks/arp_poisoning.py`      |
| MITM_DOS            | attacker    | `attacks/mitm_dos.py`           |

All scripts share defaults via `lab/config.py`. Override on the CLI.
