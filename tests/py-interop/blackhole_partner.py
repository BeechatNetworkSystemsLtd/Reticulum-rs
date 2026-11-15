#!/usr/bin/env python3
"""Blackhole interop partner.

publish mode: a Python node with `publish_blackhole` that blackholes one
identity (fixed for the test) and answers `/list` requests.

Usage: blackhole_partner.py publish <listen> <forward> <victim-hex>

fetch mode: links to a Rust node's `rnstransport.info.blackhole`
destination, requests `/list` and verifies the Python dict shape.

Usage: blackhole_partner.py fetch <listen> <forward> <publisher-identity-hex> <victim-hex> <until> <reason>
"""
import os
import sys
import tempfile
import time

import RNS

MODE = sys.argv[1]
LISTEN, FORWARD = int(sys.argv[2]), int(sys.argv[3])

configdir = os.path.join(tempfile.mkdtemp(), "config")
os.makedirs(os.path.join(configdir, "storage"), exist_ok=True)
with open(os.path.join(configdir, "config"), "w") as f:
    f.write(
        f"""[reticulum]
  enable_transport = Yes
  share_instance = No
  publish_blackhole = {"Yes" if MODE == "publish" else "No"}

[interfaces]
  [[To Rust]]
    type = UDPInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = {LISTEN}
    forward_ip = 127.0.0.1
    forward_port = {FORWARD}
"""
    )

reticulum = RNS.Reticulum(configdir=configdir, loglevel=8)

if MODE == "publish":
    VICTIM = bytes.fromhex(sys.argv[4])
    UNTIL = float(sys.argv[5])
    REASON = sys.argv[6]

    # The publisher's transport identity is random per run; the Rust
    # side learns it from this line before starting the updater.
    RNS.Transport.blackhole_identity(VICTIM, until=UNTIL, reason=REASON)
    print("PUBLISHER-ID " + RNS.Transport.identity.hash.hex(), flush=True)
    print("PUBLISH-READY", flush=True)

    while True:
        time.sleep(1)

elif MODE == "fetch":
    PUBLISHER = bytes.fromhex(sys.argv[4])
    VICTIM = bytes.fromhex(sys.argv[5])
    UNTIL = float(sys.argv[6])
    REASON = sys.argv[7]

    destination_hash = RNS.Destination.hash_from_name_and_identity(
        "rnstransport.info.blackhole", PUBLISHER
    )

    if not RNS.Transport.await_path(destination_hash, timeout=25):
        print("FETCH-FAIL no path", flush=True)
        sys.exit(1)

    remote_identity = RNS.Identity.recall(destination_hash)
    destination = RNS.Destination(
        remote_identity,
        RNS.Destination.OUT,
        RNS.Destination.SINGLE,
        "rnstransport",
        "info",
        "blackhole",
    )

    link = RNS.Link(destination)

    # Wait for activation, then request from the main thread (blocking
    # inside the established callback would stall the transport thread).
    deadline = time.time() + 45
    while not link.status == RNS.Link.ACTIVE and time.time() < deadline:
        time.sleep(0.1)

    if not link.status == RNS.Link.ACTIVE:
        print("FETCH-FAIL link never activated", flush=True)
        sys.exit(1)

    receipt = link.request("/list")
    if receipt:
        while not receipt.concluded() and time.time() < deadline:
            time.sleep(0.1)

    response = receipt.get_response()
    link.teardown()
    if not isinstance(response, dict):
        print("FETCH-FAIL response is not a dict: %r" % (response,), flush=True)
        sys.exit(1)

    entry = response.get(VICTIM)
    if not isinstance(entry, dict):
        print("FETCH-FAIL victim missing from list", flush=True)
        sys.exit(1)

    if entry.get("source") != PUBLISHER:
        print("FETCH-FAIL source mismatch: %r" % (entry.get("source"),), flush=True)
        sys.exit(1)

    until = entry.get("until")
    if abs((until or 0) - UNTIL) > 1.0:
        print("FETCH-FAIL until mismatch: %r" % (until,), flush=True)
        sys.exit(1)

    if entry.get("reason") != REASON:
        print("FETCH-FAIL reason mismatch: %r" % (entry.get("reason"),), flush=True)
        sys.exit(1)

    # Merge like Python's own updater would.
    added = 0
    for identity_hash in response:
        if identity_hash not in RNS.Transport.blackholed_identities:
            RNS.Transport.blackholed_identities[identity_hash] = response[identity_hash]
            added += 1

    print("FETCH-OK added=%d" % added, flush=True)
    time.sleep(2)
    sys.exit(0)
