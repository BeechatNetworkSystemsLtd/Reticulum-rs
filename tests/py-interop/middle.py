#!/usr/bin/env python3
"""Interop middle node: a PYTHON RNS transport node with two UDP
interfaces routing between two Rust endpoints.

Usage: middle.py <listen_a> <forward_a> <listen_c> <forward_c>
"""
import os
import sys
import tempfile
import time

import RNS

LISTEN_A, FORWARD_A, LISTEN_C, FORWARD_C = (int(x) for x in sys.argv[1:5])

configdir = os.path.join(tempfile.mkdtemp(), "config")
os.makedirs(os.path.join(configdir, "storage"), exist_ok=True)
with open(os.path.join(configdir, "config"), "w") as f:
    f.write(
        f"""[reticulum]
  enable_transport = Yes
  share_instance = No

[interfaces]
  [[To Rust A]]
    type = UDPInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = {LISTEN_A}
    forward_ip = 127.0.0.1
    forward_port = {FORWARD_A}

  [[To Rust C]]
    type = UDPInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = {LISTEN_C}
    forward_ip = 127.0.0.1
    forward_port = {FORWARD_C}
"""
    )

reticulum = RNS.Reticulum(configdir=configdir, loglevel=8)

print("MIDDLE-READY", flush=True)

while True:
    time.sleep(1)
