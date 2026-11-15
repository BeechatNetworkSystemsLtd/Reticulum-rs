#!/usr/bin/env python3
"""Interop partner for Rust resource/request tests over UDP.

Modes:
  --mode resource-server  : announce destination, accept link, receive a resource, echo it back as a resource
  --mode resource-client  : connect to destination (hex arg), send N bytes as a resource
  --mode request-server   : announce destination, register "echo" request handler returning data
  --mode request-client   : connect, send request "echo" with payload, print response hex
"""
import argparse, os, time
import RNS

APP_NAME = "example_utilities"
LINK_WAIT = 15.0

def log(msg):
    print(f"[PYI] {msg}", flush=True)

def resource_server(args):
    reticulum = RNS.Reticulum(args.config)
    identity = RNS.Identity()
    dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                           APP_NAME, "interop", "resource")
    log(f"destination {dest.hash.hex()}")
    received = {}

    def resource_concluded(resource):
        try:
            data = resource.data.read() if hasattr(resource.data, "read") else resource.data
            received["data"] = data
            log(f"resource complete {len(data)} bytes")
        except Exception as e:
            log(f"resource read error {e}")

    def link_established(link):
        log("link established")
        link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
        link.set_resource_concluded_callback(resource_concluded)

    dest.set_link_established_callback(link_established)
    dest.announce()

    deadline = time.time() + args.timeout
    while time.time() < deadline:
        if "data" in received:
            log(f"received hex {received['data'].hex()[:128]}")
            log(f"received sha {__import__('hashlib').sha256(received['data']).hexdigest()}")
            break
        time.sleep(0.05)

def resource_client(args):
    reticulum = RNS.Reticulum(args.config)
    dest_hash = bytes.fromhex(args.destination)
    RNS.Transport.request_path(dest_hash)
    deadline = time.time() + LINK_WAIT
    while (not RNS.Transport.has_path(dest_hash)) and time.time() < deadline:
        time.sleep(0.1)
    if not RNS.Transport.has_path(dest_hash):
        log("no path"); return
    identity = RNS.Identity.recall(dest_hash)
    dest = RNS.Destination(identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
                           APP_NAME, "interop", "resource")
    if dest.hash != dest_hash:
        log(f"hash mismatch {dest.hash.hex()}"); return
    link = RNS.Link(dest)
    deadline = time.time() + LINK_WAIT
    while link.status != RNS.Link.ACTIVE and time.time() < deadline:
        time.sleep(0.05)
    if link.status != RNS.Link.ACTIVE:
        log("link failed"); return
    log("link established")

    payload = os.urandom(args.size)
    log(f"sending sha {__import__('hashlib').sha256(payload).hexdigest()}")

    def concluded(resource):
        log(f"concluded status {resource.status}")

    resource = RNS.Resource(payload, link, callback=concluded, auto_compress=False)
    deadline = time.time() + args.timeout
    while resource.status < RNS.Resource.COMPLETE and time.time() < deadline:
        time.sleep(0.05)
    log(f"final status {resource.status}")

def request_server(args):
    reticulum = RNS.Reticulum(args.config)
    identity = RNS.Identity()
    dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                           APP_NAME, "interop", "request")
    log(f"destination {dest.hash.hex()}")

    def echo(path, data, request_id, remote_identity, requested_at):
        log(f"request {path} with {len(data)} bytes")
        return data

    dest.register_request_handler("echo", response_generator=echo, allow=RNS.Destination.ALLOW_ALL)
    dest.announce()
    time.sleep(args.timeout)

def request_client(args):
    reticulum = RNS.Reticulum(args.config)
    dest_hash = bytes.fromhex(args.destination)
    RNS.Transport.request_path(dest_hash)
    deadline = time.time() + LINK_WAIT
    while (not RNS.Transport.has_path(dest_hash)) and time.time() < deadline:
        time.sleep(0.1)
    if not RNS.Transport.has_path(dest_hash):
        log("no path"); return
    identity = RNS.Identity.recall(dest_hash)
    dest = RNS.Destination(identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
                           APP_NAME, "interop", "request")
    link = RNS.Link(dest)
    deadline = time.time() + LINK_WAIT
    while link.status != RNS.Link.ACTIVE and time.time() < deadline:
        time.sleep(0.05)
    if link.status != RNS.Link.ACTIVE:
        log("link failed"); return
    log("link established")

    payload = os.urandom(args.size)
    log(f"requesting sha {__import__('hashlib').sha256(payload).hexdigest()}")

    done = {}
    def response(receipt):
        done["resp"] = receipt.response
    def failed(receipt):
        done["failed"] = True

    receipt = link.request("echo", payload, response_callback=response, failed_callback=failed, timeout=30)
    deadline = time.time() + 30
    while "resp" not in done and "failed" not in done and time.time() < deadline:
        time.sleep(0.05)
    if "resp" in done:
        log(f"response sha {__import__('hashlib').sha256(done['resp']).hexdigest()}")
        log(f"response len {len(done['resp'])}")
    else:
        log("request failed")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--destination", default=None)
    parser.add_argument("--size", type=int, default=10000)
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args()
    {"resource-server": resource_server,
     "resource-client": resource_client,
     "request-server": request_server,
     "request-client": request_client}[args.mode](args)
