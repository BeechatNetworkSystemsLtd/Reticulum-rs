#!/usr/bin/env python3
import sys
import time
import RNS

class _StubDestination:
    def __init__(self, destination_hash: bytes):
        self.hash = destination_hash
        self.type = RNS.Destination.SINGLE

def _build_random_hash() -> bytes:
    random_part = RNS.Identity.get_random_hash()[:5]
    time_part = int(time.time()).to_bytes(5, "big")
    return random_part + time_part

def _build_ratchet_bytes(enable: bool) -> bytes:
    if not enable:
        return b""
    ratchet = RNS.Identity._generate_ratchet()
    return RNS.Identity._ratchet_public_bytes(ratchet)

def main() -> None:
    if len(sys.argv) < 4:
        sys.stderr.write(
            "usage: create_announce.py <priv_hex> <app_name> <aspect> [ratchet_flag] [app_data_hex]\n"
        )
        sys.exit(1)

    priv_hex = sys.argv[1]
    app_name = sys.argv[2]
    aspect = sys.argv[3]
    ratchet_flag = sys.argv[4] if len(sys.argv) > 4 else "0"
    app_data_hex = sys.argv[5] if len(sys.argv) > 5 else ""

    identity = RNS.Identity.from_bytes(bytes.fromhex(priv_hex))
    destination_hash = RNS.Destination.hash(identity, app_name, aspect)
    name_hash = RNS.Identity.full_hash(
        RNS.Destination.expand_name(None, app_name, aspect).encode("utf-8")
    )[: RNS.Identity.NAME_HASH_LENGTH // 8]

    random_hash = _build_random_hash()
    ratchet_bytes = _build_ratchet_bytes(ratchet_flag == "1")
    app_data = bytes.fromhex(app_data_hex) if app_data_hex else b""

    signed_data = (
        destination_hash
        + identity.get_public_key()
        + name_hash
        + random_hash
        + ratchet_bytes
        + app_data
    )
    signature = identity.sign(signed_data)

    announce_data = (
        identity.get_public_key()
        + name_hash
        + random_hash
        + ratchet_bytes
        + signature
        + app_data
    )

    context_flag = RNS.Packet.FLAG_SET if ratchet_bytes else RNS.Packet.FLAG_UNSET
    packet = RNS.Packet(
        _StubDestination(destination_hash),
        announce_data,
        RNS.Packet.ANNOUNCE,
        context_flag=context_flag,
    )
    packet.pack()
    sys.stdout.write(packet.raw.hex())

if __name__ == "__main__":
    main()
