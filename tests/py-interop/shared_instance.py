#!/usr/bin/env python3
"""Shared-instance interop partner for tests/python_shared_instance.rs.

Depending on whether a shared instance is already listening on the
configured TCP port, this script either *becomes* the shared instance
(when started standalone) or *connects* to it as a local client
(`RNS.Reticulum` share_instance semantics).

It announces a SINGLE destination every two seconds with a fixed app data
blob and reports received announces on stdout:

    SENT_ANNOUNCE <destination hash hex>
    GOT_ANNOUNCE <destination hash hex> <app data>

Used by the Rust tests to verify both directions of the local
shared-instance protocol (HDLC framing over TCP).
"""
import sys
import time

import RNS


class Partner:
    # RNS.Transport.register_announce_handler only registers handlers
    # exposing an `aspect_filter` attribute; None means "all announces"
    aspect_filter = None

    def __init__(self, config_dir: str):
        self.reticulum = RNS.Reticulum(configdir=config_dir)
        self.identity = RNS.Identity()
        self.destination = RNS.Destination(
            self.identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            "test",
            "shared",
        )
        RNS.Transport.register_announce_handler(self)

    # RNS.Transport announce handler interface
    def received_announce(self, destination_hash, announced_identity, app_data):
        try:
            app_data = app_data.decode("utf-8")
        except Exception:
            app_data = repr(app_data)
        print(
            f"GOT_ANNOUNCE {RNS.hexrep(destination_hash, delimit=False)} {app_data}",
            flush=True,
        )

    def run(self, duration: float):
        deadline = time.time() + duration
        while time.time() < deadline:
            self.destination.announce(app_data=b"python-shared-instance")
            print(
                f"SENT_ANNOUNCE {RNS.hexrep(self.destination.hash, delimit=False)}",
                flush=True,
            )
            time.sleep(2)


if __name__ == "__main__":
    config_dir = sys.argv[1]
    duration = float(sys.argv[2]) if len(sys.argv) > 2 else 20.0
    Partner(config_dir).run(duration)
