#!/usr/bin/env python3
"""Interop endpoints driven by the Rust middle test.

Roles:
  destination — announces an echo destination, accepts a link, echoes data.
  initiator   — waits for the announce, links, sends data, expects the echo.
"""
import argparse
import os
import sys
import tempfile
import time

import RNS

APP_NAME = "example_utilities"

parser = argparse.ArgumentParser()
parser.add_argument("--role", required=True, choices=["destination", "initiator"])
parser.add_argument("--listen", type=int, required=True)
parser.add_argument("--forward", type=int, required=True)
args = parser.parse_args()

configdir = os.path.join(tempfile.mkdtemp(), "config")
os.makedirs(os.path.join(configdir, "storage"), exist_ok=True)
with open(os.path.join(configdir, "config"), "w") as f:
    f.write(
        f"""[reticulum]
  enable_transport = No
  share_instance = No

[interfaces]
  [[Endpoint]]
    type = UDPInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = {args.listen}
    forward_ip = 127.0.0.1
    forward_port = {args.forward}
"""
    )

reticulum = RNS.Reticulum(configdir=configdir, loglevel=6)


def destination_role():
    identity = RNS.Identity(create_keys=True)
    destination = RNS.Destination(
        identity, RNS.Destination.IN, RNS.Destination.SINGLE, APP_NAME, "middle", "echo"
    )

    def link_established(link):
        print("LINK-ESTABLISHED", flush=True)

        def receiver(data, packet):
            try:
                RNS.Packet(link, data).send()
                print("ECHO-SENT", flush=True)
            except Exception as e:
                print(f"echo failed: {e}", flush=True)

        link.set_packet_callback(receiver)

    destination.set_link_established_callback(link_established)
    destination.announce()
    print("DESTINATION-ANNOUNCED", flush=True)


def initiator_role():
    def announce_received(destination_hash, announced_identity, app_data):
        print(f"ANNOUNCE-RECEIVED {RNS.hexrep(destination_hash, delimit=False)}", flush=True)
        destination = RNS.Destination(
            announced_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            APP_NAME,
            "middle",
            "echo",
        )

        def link_established(link):
            print("LINK-ESTABLISHED", flush=True)

            def receiver(data, packet):
                print("ECHO-RECEIVED", flush=True)
                print("DONE", flush=True)

            link.set_packet_callback(receiver)
            RNS.Packet(link, b"ping through rust middle").send()
            print("PING-SENT", flush=True)

        RNS.Link(destination, established_callback=link_established)

    RNS.Transport.register_announce_handler(
        type(
            "H",
            (),
            {
                "received_announce": staticmethod(announce_received),
                "aspect_filter": None,
            },
        )()
    )


if args.role == "destination":
    destination_role()
else:
    initiator_role()

while True:
    time.sleep(1)
