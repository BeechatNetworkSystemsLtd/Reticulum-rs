#!/usr/bin/env python3
"""Buffer stream partner for Rust buffer-stream interop tests.

--mode writer: wait for link, write N bytes as a stream to the peer, close.
--mode reader: wait for link, read the incoming stream until EOF, print sha.
"""
import argparse, hashlib, sys, time
import RNS
import RNS.Buffer

# Verbose RNS logging to stdout for interop debugging.
RNS.loglevel = RNS.LOG_NOTICE
def _rlog(msg, *a, **k):
    print(f"[RNS] {msg}", flush=True)
RNS.log = _rlog

APP_NAME = "example_utilities"
LINK_WAIT = 20.0

def log(msg):
    print(f"[PYI] {msg}", flush=True)

def get_link(dest_hash_hex, config):
    reticulum = RNS.Reticulum(config)
    dest_hash = bytes.fromhex(dest_hash_hex)
    RNS.Transport.request_path(dest_hash)
    deadline = time.time() + LINK_WAIT
    while (not RNS.Transport.has_path(dest_hash)) and time.time() < deadline:
        time.sleep(0.1)
    if not RNS.Transport.has_path(dest_hash):
        log("no path"); sys.exit(1)
    identity = RNS.Identity.recall(dest_hash)
    dest = RNS.Destination(identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
                           APP_NAME, "buffer", "stream")
    link = RNS.Link(dest)
    deadline = time.time() + LINK_WAIT
    while link.status != RNS.Link.ACTIVE and time.time() < deadline:
        time.sleep(0.05)
    if link.status != RNS.Link.ACTIVE:
        log("link failed"); sys.exit(1)
    log("link established")
    return link

def writer(args):
    link = get_link(args.destination, args.config)
    channel = link.get_channel()
    deadline = time.time() + 5
    while not channel.is_ready_to_send() and time.time() < deadline:
        time.sleep(0.05)

    data = bytes(range(256)) * ((args.size + 255) // 256)
    writer = RNS.Buffer.create_writer(1, channel)
    # RawChannelWriter.write returns the number of bytes actually sent;
    # the caller must retry the remainder (Python semantics).
    sent = 0
    while sent < len(data):
        sent += writer.write(data[sent:])
    writer.flush()
    writer.close()
    log(f"wrote {len(data)} bytes sha {hashlib.sha256(data).hexdigest()}")
    data_len = len(data)
    import builtins; builtins.DATA_LEN = data_len
    time.sleep(2)

def reader(args):
    reticulum = RNS.Reticulum(args.config)
    identity = RNS.Identity()
    dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                           APP_NAME, "buffer", "stream")
    log(f"destination {dest.hash.hex()}")

    received = {}

    def link_established(link):
        log("link established")
        channel = link.get_channel()
        reader = RNS.Buffer.create_reader(2, channel)

        def pump():
            import io
            buf = io.BytesIO()
            deadline = time.time() + args.timeout
            while time.time() < deadline:
                chunk = reader.read1(4096)
                if chunk:
                    buf.write(chunk)
                elif reader.raw._eof:
                    break
                else:
                    time.sleep(0.05)
            data = buf.getvalue()
            received["data"] = data
            log(f"read {len(data)} bytes sha {hashlib.sha256(data).hexdigest()}")

        import threading
        threading.Thread(target=pump, daemon=True).start()

    dest.set_link_established_callback(link_established)
    dest.announce()

    deadline = time.time() + args.timeout
    while time.time() < deadline:
        if "data" in received:
            break
        time.sleep(0.05)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--mode", required=True, choices=["writer", "reader"])
    parser.add_argument("--destination", default=None)
    parser.add_argument("--size", type=int, default=20000)
    parser.add_argument("--timeout", type=float, default=45.0)
    args = parser.parse_args()
    {"writer": writer, "reader": reader}[args.mode](args)
