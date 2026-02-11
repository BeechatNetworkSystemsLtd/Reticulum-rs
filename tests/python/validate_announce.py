#!/usr/bin/env python3
import sys
import RNS

if len(sys.argv) < 2:
    sys.stderr.write("usage: validate_announce.py <packet_hex>\n")
    sys.exit(1)

raw = bytes.fromhex(sys.argv[1])
packet = RNS.Packet(None, raw)

if not packet.unpack():
    sys.stderr.write("failed to unpack packet\n")
    sys.exit(2)

if RNS.Identity.validate_announce(packet):
    sys.stdout.write("ok")
    sys.exit(0)

sys.stderr.write("announce validation failed\n")
sys.exit(3)
