#!/usr/bin/env python3
"""Generate golden fixtures for the Rust identity/persistence parity tests.

Run with PYTHONPATH pointing at the Python Reticulum checkout:

    PYTHONPATH=/path/to/Reticulum python3 tests/fixtures/gen_identity_fixtures.py

Everything random is pinned (fixed keys, fixed ephemeral keys, fixed IVs,
fixed announce random hashes and timestamps) so the Rust port can verify
byte-exact wire and storage compatibility.
"""
import hashlib
import json
import os
import struct
import sys
import tempfile

import RNS
from RNS.vendor import umsgpack as umsgpack

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)))

# --- fixed material -------------------------------------------------------

IDENTITY_PRV_HEX = (
    "f8953ffaf607627e615603ff1530c82c434cf87c07179dd7689ea776f30b964c"
    "fb7ba6164af00c5111a45e69e57d885e1285f8dbfe3a21e95ae17cf676b0f8b7"
)
SECOND_PRV_HEX = (
    "d85d036245436a3c33d3228affae06721f8203bc364ee0ee7556368ac62add65"
    "0ebf8f926abf628da9d92baaa12db89bd6516ee92ec29765f3afafcb8622d697"
)
APP_NAME = "example_utilities"
ASPECT = "parity"

RATCHET_PRV = bytes.fromhex(
    "a457d1c7f88b5cf3dcb1b0f3a3e1d5a30a1eef04b32b6812c4b6aee5b3210544"
)
RATCHET_PRV_2 = bytes.fromhex(
    "1122334455667788112233445566778811223344556677881122334455667788"
)
EPHEMERAL_PRV = bytes.fromhex(
    "9988776655443322119988776655443322119988776655443322119988776655"
)
FERNET_IV = bytes.fromhex("00112233445566778899aabbccddeeff")

# The Rust `Hash::new_from_rand` pins hash SHA-256(IV || IV); Python's
# `get_random_hash` is pinned to the same value so announce random hashes
# match byte for byte.
ANNOUNCE_RANDOM_HASH = hashlib.sha256(FERNET_IV + FERNET_IV).digest()[:10]
ANNOUNCE_TIMESTAMP = 1735689600  # 2025-01-01T00:00:00Z
KNOWN_TIME = 1735689601.5
RATCHET_RECEIVED = 1735689602.25


def pinned_identity(prv_hex):
    identity = RNS.Identity(create_keys=False)
    identity.load_private_key(bytes.fromhex(prv_hex))
    return identity


def pin_rng():
    """Pin os.urandom inside the Token module to a fixed IV."""
    token_mod = sys.modules["RNS.Cryptography.Token"]
    original_urandom = token_mod.os.urandom
    token_mod.os.urandom = lambda n: (FERNET_IV + b"\x5a" * n)[:n]
    return lambda: setattr(token_mod.os, "urandom", original_urandom)


def pin_ephemeral(identity_module):
    """Pin X25519PrivateKey.generate to a fixed ephemeral key."""
    real = identity_module.X25519PrivateKey

    class Fixed:
        # Keep the real classmethods available: `Identity.decrypt` uses
        # `X25519PrivateKey.from_private_bytes` for ratchets.
        from_private_bytes = staticmethod(real.from_private_bytes)

        @staticmethod
        def generate():
            return real.from_private_bytes(EPHEMERAL_PRV)

    identity_module.X25519PrivateKey = Fixed
    return lambda: setattr(identity_module, "X25519PrivateKey", real)


def pin_ratchet_generation():
    """Pin Identity._generate_ratchet to fixed keys."""
    keys = [RATCHET_PRV, RATCHET_PRV_2]
    state = {"i": 0}

    def fixed():
        key = keys[min(state["i"], len(keys) - 1)]
        state["i"] += 1
        return key

    real = RNS.Identity._generate_ratchet
    RNS.Identity._generate_ratchet = staticmethod(fixed)
    return lambda: setattr(RNS.Identity, "_generate_ratchet", real)


def pin_announce_randomness():
    """Pin announce random hashes and timestamps."""
    real_random_hash = RNS.Identity.get_random_hash
    import time as _time

    real_time = _time.time

    class FixedTime:
        @staticmethod
        def time():
            return ANNOUNCE_TIMESTAMP

    RNS.Identity.get_random_hash = staticmethod(lambda: ANNOUNCE_RANDOM_HASH)
    _time.time = FixedTime.time
    return lambda: (
        setattr(RNS.Identity, "get_random_hash", real_random_hash),
        setattr(_time, "time", real_time),
    )


def main():
    meta = {}

    # ------------------------------------------------------------------
    # Reticulum instance with a scratch storage dir (never used for the
    # fixtures themselves, which are written explicitly below).
    # ------------------------------------------------------------------
    scratch = tempfile.mkdtemp()

    # Minimal config: no interface discovery, no shared instance, transport
    # disabled, so the generator stays hermetic.
    os.makedirs(os.path.join(scratch, "storage"), exist_ok=True)
    with open(os.path.join(scratch, "config"), "w") as config:
        config.write("[reticulum]\n")
        config.write("  discover_interfaces = No\n")
        config.write("  enable_transport = No\n")
        config.write("  share_instance = No\n")
        config.write("  [interfaces]\n")

    RNS.Reticulum(configdir=scratch, loglevel=RNS.LOG_CRITICAL)

    identity = pinned_identity(IDENTITY_PRV_HEX)
    peer_identity = pinned_identity(SECOND_PRV_HEX)
    meta["identity_prv_hex"] = IDENTITY_PRV_HEX
    meta["identity_hash_hex"] = identity.hash.hex()
    meta["peer_prv_hex"] = SECOND_PRV_HEX
    meta["peer_hash_hex"] = peer_identity.hash.hex()

    # ------------------------------------------------------------------
    # 1. Identity files (raw private/public key bytes)
    # ------------------------------------------------------------------
    with open(os.path.join(OUT, "identity_private.bin"), "wb") as f:
        f.write(identity.get_private_key())
    with open(os.path.join(OUT, "identity_public.bin"), "wb") as f:
        f.write(identity.get_public_key())
    with open(os.path.join(OUT, "peer_public.bin"), "wb") as f:
        f.write(peer_identity.get_public_key())

    # ------------------------------------------------------------------
    # 2. Known destinations file
    # ------------------------------------------------------------------
    destination = RNS.Destination(
        identity, RNS.Destination.IN, RNS.Destination.SINGLE, APP_NAME, ASPECT
    )
    announce = destination.announce(app_data=b"known destinations fixture", send=False)
    announce.pack()

    peer_destination = RNS.Destination(
        peer_identity, RNS.Destination.IN, RNS.Destination.SINGLE, APP_NAME, "peer"
    )
    peer_announce = peer_destination.announce(send=False)
    peer_announce.pack()

    known = {
        destination.hash: [
            KNOWN_TIME,
            announce.packet_hash,
            identity.get_public_key(),
            b"known destinations fixture",
            0,
        ],
        peer_destination.hash: [
            KNOWN_TIME + 1,
            peer_announce.packet_hash,
            peer_identity.get_public_key(),
            None,
            KNOWN_TIME + 2,
        ],
    }

    # A retained destination (uses == -1) and a never-used ratchet destination
    retained_hash = bytes.fromhex("00112233445566778899aabbccddeeff")
    known[retained_hash] = [
        KNOWN_TIME + 3,
        bytes(range(32)),
        peer_identity.get_public_key(),
        b"",
        -1,
    ]

    packed_known = umsgpack.packb(known)
    with open(os.path.join(OUT, "known_destinations.bin"), "wb") as f:
        f.write(packed_known)
    meta["known_destinations"] = {
        destination.hash.hex(): {
            "time": KNOWN_TIME,
            "packet_hash": announce.packet_hash.hex(),
            "public_key": identity.get_public_key().hex(),
            "app_data": b"known destinations fixture".hex(),
            "uses": 0,
        },
        peer_destination.hash.hex(): {
            "time": KNOWN_TIME + 1,
            "packet_hash": peer_announce.packet_hash.hex(),
            "public_key": peer_identity.get_public_key().hex(),
            "app_data": None,
            "uses": KNOWN_TIME + 2,
        },
        retained_hash.hex(): {
            "time": KNOWN_TIME + 3,
            "packet_hash": bytes(range(32)).hex(),
            "public_key": peer_identity.get_public_key().hex(),
            "app_data": "",
            "uses": -1,
        },
    }

    # ------------------------------------------------------------------
    # 3. Ratchet storage files
    # ------------------------------------------------------------------
    ratchet_pub = RNS.Identity._ratchet_public_bytes(RATCHET_PRV)
    ratchet_data = {"ratchet": ratchet_pub, "received": RATCHET_RECEIVED}
    with open(os.path.join(OUT, "ratchet.bin"), "wb") as f:
        f.write(umsgpack.packb(ratchet_data))
    meta["ratchet"] = {
        "destination_hash": destination.hash.hex(),
        "public_hex": ratchet_pub.hex(),
        "private_hex": RATCHET_PRV.hex(),
        "received": RATCHET_RECEIVED,
        "id_hex": RNS.Identity._get_ratchet_id(ratchet_pub).hex(),
    }

    # Destination ratchet file (private keys, signed by the destination)
    ratchets_path = os.path.join(OUT, "destination_ratchets.bin")
    peer_destination.ratchets = [RATCHET_PRV, RATCHET_PRV_2]
    peer_destination.ratchets_path = ratchets_path
    peer_destination._persist_ratchets()

    # ------------------------------------------------------------------
    # 4. Announce with ratchet (packed packet) and plain announce
    # ------------------------------------------------------------------
    unpin_randomness = pin_announce_randomness()
    unpin_ratchets = pin_ratchet_generation()

    ratchet_destination = RNS.Destination(
        identity, RNS.Destination.IN, RNS.Destination.SINGLE, APP_NAME, "ratcheted"
    )
    ratchet_destination.ratchets = []
    ratchet_destination.latest_ratchet_time = 0
    ratchet_destination.ratchets_path = os.path.join(scratch, "ratcheted.ratchets")

    ratchet_announce = ratchet_destination.announce(
        app_data=b"ratchet announce fixture", send=False
    )
    ratchet_announce.pack()
    with open(os.path.join(OUT, "announce_ratchet.bin"), "wb") as f:
        f.write(ratchet_announce.raw)
    meta["announce_ratchet"] = {
        "destination_hash": ratchet_announce.destination_hash.hex(),
        "context_flag": ratchet_announce.context_flag,
        "ratchet_pub_hex": RNS.Identity._ratchet_public_bytes(RATCHET_PRV).hex(),
        "app_data": b"ratchet announce fixture".hex(),
        "name": ratchet_destination.name,
    }

    plain_announce = destination.announce(app_data=b"plain announce fixture", send=False)
    plain_announce.pack()
    with open(os.path.join(OUT, "announce_plain.bin"), "wb") as f:
        f.write(plain_announce.raw)
    meta["announce_plain"] = {
        "destination_hash": plain_announce.destination_hash.hex(),
        "context_flag": plain_announce.context_flag,
        "app_data": b"plain announce fixture".hex(),
        "name": destination.name,
    }

    unpin_ratchets()
    unpin_randomness()

    # ------------------------------------------------------------------
    # 5. SINGLE-destination encryption tokens (static key and ratchet)
    # ------------------------------------------------------------------
    unpin_rng = pin_rng()
    unpin_ephemeral = pin_ephemeral(sys.modules["RNS.Identity"])

    plaintext = b"the quick brown fox jumps over the lazy dog"
    encryptor = RNS.Identity(create_keys=False)
    encryptor.load_public_key(identity.get_public_key())
    static_token = encryptor.encrypt(plaintext)
    with open(os.path.join(OUT, "encrypt_static.bin"), "wb") as f:
        f.write(static_token)

    ratchet_token = encryptor.encrypt(plaintext, ratchet=ratchet_pub)
    with open(os.path.join(OUT, "encrypt_ratchet.bin"), "wb") as f:
        f.write(ratchet_token)

    meta["encrypt"] = {
        "plaintext_hex": plaintext.hex(),
        "static_token_len": len(static_token),
        "ratchet_token_len": len(ratchet_token),
        "ephemeral_prv_hex": EPHEMERAL_PRV.hex(),
        "ephemeral_pub_hex": RNS.Cryptography.X25519PrivateKey.from_private_bytes(
            EPHEMERAL_PRV
        )
        .public_key()
        .public_bytes()
        .hex(),
    }

    # Round-trip sanity: the pinned identity must decrypt both tokens.
    assert identity.decrypt(static_token) == plaintext
    assert identity.decrypt(ratchet_token, ratchets=[RATCHET_PRV]) == plaintext

    unpin_ephemeral()
    unpin_rng()

    # ------------------------------------------------------------------
    # 6. Proof vectors: explicit and implicit proofs of a fixed packet hash
    # ------------------------------------------------------------------
    packet_hash = bytes.fromhex(
        "5d1a5f2e6e20b7c9db3b10c8d4e2b6dbac9d81f2f0a54c3e0f7d2f9bb1a3ea17"
    )
    meta["proof"] = {
        "packet_hash_hex": packet_hash.hex(),
        "explicit_hex": (packet_hash + identity.sign(packet_hash)).hex(),
        "implicit_hex": identity.sign(packet_hash).hex(),
    }

    meta["known_destinations_order"] = [h.hex() for h in known.keys()]

    with open(os.path.join(OUT, "identity_fixtures.json"), "w") as f:
        json.dump(meta, f, indent=2, sort_keys=True)

    print("fixtures written to", OUT)


if __name__ == "__main__":
    main()
