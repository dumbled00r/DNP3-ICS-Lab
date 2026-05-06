"""Run a DNP3 outstation (slave) target on the outstation Pi.

Uses dnp3-python (opendnp3 wrapper). Listens on 0.0.0.0:20000, link addr 10.
Master link addr is 1.

  python3 outstation.py
"""
import argparse, time
from dnp3_python.dnp3station.outstation_new import MyOutStationNew

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=20000)
    p.add_argument("--outstation-addr", type=int, default=10)
    p.add_argument("--master-addr", type=int, default=1)
    a = p.parse_args()

    o = MyOutStationNew(
        outstation_ip=a.host, port=a.port,
        masterstation_id_to_outstation=a.master_addr,
        outstation_id_to_masterstation=a.outstation_addr,
    )
    o.start()
    print(f"[outstation] up on {a.host}:{a.port} addr={a.outstation_addr}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        o.shutdown()

if __name__ == "__main__":
    main()
