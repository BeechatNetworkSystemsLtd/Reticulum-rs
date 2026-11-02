#!/usr/bin/env python3
"""Broadcast partner for Rust PLAIN-destination interop tests."""
import argparse, time
import RNS

APP_NAME = "example_utilities"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--send", default=None, help="text to broadcast then exit")
    parser.add_argument("--listen-secs", type=float, default=30.0)
    args = parser.parse_args()

    reticulum = RNS.Reticulum(args.config)
    dest = RNS.Destination(None, RNS.Destination.IN, RNS.Destination.PLAIN,
                           APP_NAME, "broadcast", "public_information")
    print(f"[PYI] destination {dest.hash.hex()}", flush=True)

    if args.send:
        time.sleep(0.5)
        packet = RNS.Packet(dest, args.send.encode("utf-8"))
        packet.send()
        print(f"[PYI] sent {len(args.send)} bytes", flush=True)
        time.sleep(1.0)
        return

    def cb(data, packet):
        print(f"[PYI] received {data.decode('utf-8')}", flush=True)

    dest.set_packet_callback(cb)
    time.sleep(args.listen_secs)

main()
