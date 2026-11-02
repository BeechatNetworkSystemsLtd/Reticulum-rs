#!/usr/bin/env python3
"""Interop partner for Rust identity/persistence tests over UDP.

Mirrors `Examples/Echo.py` and `Examples/Ratchets.py`:

  --mode echo-server    : IN SINGLE destination with ratchets enabled and
                          PROVE_ALL; announces and prints received packet shas
  --mode echo-client    : sends an encrypted packet to a destination (hex arg)
                          and waits for the delivery proof
  --mode ratchet-server : IN SINGLE destination that rotates its ratchet on
                          every announce and prints the current ratchet id
"""
import argparse, hashlib, os, tempfile, threading, time
import RNS

APP_NAME = "example_utilities"
LINK_WAIT = 15.0

def log(msg):
    print(f"[PYI] {msg}", flush=True)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def echo_server(args):
    if os.environ.get("PYI_VERBOSE"):
        RNS.loglevel = RNS.LOG_DEBUG
    reticulum = RNS.Reticulum(args.config)
    identity = RNS.Identity()
    dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                           APP_NAME, "identity", "echo")

    # Examples/Ratchets.py server behaviour: enable ratchets on the
    # destination and prove all incoming packets.
    ratchet_dir = tempfile.mkdtemp(prefix="rns-py-ratchets-")
    dest.enable_ratchets(os.path.join(ratchet_dir, f"{dest.hexhash}.ratchets"))
    dest.set_proof_strategy(RNS.Destination.PROVE_ALL)

    def packet_received(data, packet):
        try:
            log(f"received sha {sha(data)}")
            log(f"received len {len(data)}")
            log(f"received ratchet {'set' if packet.ratchet_id else 'none'}")
        except Exception as e:
            log(f"callback error {e}")

    dest.set_packet_callback(packet_received)
    dest.announce()
    log(f"destination {dest.hash.hex()}")
    log(f"ratchet {RNS.Identity.current_ratchet_id(dest.hash).hex()}")

    deadline = time.time() + args.timeout
    while time.time() < deadline:
        time.sleep(0.05)

def echo_client(args):
    if os.environ.get("PYI_VERBOSE"):
        RNS.loglevel = RNS.LOG_DEBUG
    reticulum = RNS.Reticulum(args.config)
    dest_hash = bytes.fromhex(args.destination)
    RNS.Transport.request_path(dest_hash)
    deadline = time.time() + LINK_WAIT
    while (not RNS.Transport.has_path(dest_hash)) and time.time() < deadline:
        time.sleep(0.1)
    if not RNS.Transport.has_path(dest_hash):
        log("no path"); return

    identity = RNS.Identity.recall(dest_hash)
    if identity == None:
        log("no identity"); return

    dest = RNS.Destination(identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
                           APP_NAME, "identity", "echo")
    if dest.hash != dest_hash:
        log(f"hash mismatch {dest.hash.hex()}"); return

    ratchet = RNS.Identity.get_ratchet(dest.hash)
    log(f"ratchet-known {RNS.Identity.current_ratchet_id(dest.hash).hex() if ratchet else 'none'}")

    payload = os.urandom(args.size)
    log(f"sending sha {sha(payload)}")

    state = {}

    def delivered(receipt):
        state["delivered"] = True
        log(f"delivered sha {sha(payload)}")

    def timed_out(receipt):
        state["failed"] = True
        log("delivery timed out")

    packet = RNS.Packet(dest, payload)
    receipt = packet.send()
    receipt.set_delivery_callback(delivered)
    receipt.set_timeout_callback(timed_out)

    deadline = time.time() + args.timeout
    while "delivered" not in state and "failed" not in state and time.time() < deadline:
        time.sleep(0.05)

    if "delivered" not in state:
        log("not delivered")

def ratchet_server(args):
    if os.environ.get("PYI_VERBOSE"):
        RNS.loglevel = RNS.LOG_DEBUG
    reticulum = RNS.Reticulum(args.config)
    identity = RNS.Identity()
    dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                           APP_NAME, "identity", "ratchet")

    ratchet_dir = tempfile.mkdtemp(prefix="rns-py-ratchets-")
    dest.enable_ratchets(os.path.join(ratchet_dir, f"{dest.hexhash}.ratchets"))
    dest.set_proof_strategy(RNS.Destination.PROVE_ALL)
    # Rotate the ratchet on every announce so the Rust side has to track
    # ratchet updates from announces (Examples/Ratchets.py logic).
    dest.ratchet_interval = 0

    def packet_received(data, packet):
        try:
            log(f"received sha {sha(data)}")
            log(f"received ratchet {'set' if packet.ratchet_id else 'none'}")
        except Exception as e:
            log(f"callback error {e}")

    dest.set_packet_callback(packet_received)
    log(f"destination {dest.hexhash}")

    def announce_loop():
        while True:
            dest.announce()
            log(f"ratchet {RNS.Identity.current_ratchet_id(dest.hash).hex()}")
            time.sleep(args.announce_interval)

    threading.Thread(target=announce_loop, daemon=True).start()

    deadline = time.time() + args.timeout
    while time.time() < deadline:
        time.sleep(0.05)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--destination", default=None)
    parser.add_argument("--size", type=int, default=64)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--announce-interval", type=float, default=4.0)
    args = parser.parse_args()
    {"echo-server": echo_server,
     "echo-client": echo_client,
     "ratchet-server": ratchet_server,
    }[args.mode](args)
