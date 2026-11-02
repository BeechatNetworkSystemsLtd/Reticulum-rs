#!/usr/bin/env python3
"""Generate golden test vectors for the Rust LXMF port.

Run from anywhere with:

    PYTHONPATH=/path/to/Reticulum:/path/to/LXMF \
        python3 fixtures/generate.py

The script is deterministic: all identities, timestamps, stamps and
tickets are fixed values, so the output (golden.json) is stable.
"""

import json
import os
import sys

import RNS
import RNS.vendor.umsgpack as msgpack

import LXMF
from LXMF.LXMF import APP_NAME, FIELD_EMBEDDED_LXMS, FIELD_TELEMETRY, FIELD_FILE_ATTACHMENTS, \
    FIELD_THREAD, FIELD_IMAGE, FIELD_REPLY_TO, FIELD_REACTION, FIELD_TICKET, FIELD_CUSTOM_TYPE, \
    FIELD_CUSTOM_DATA, FIELD_NON_SPECIFIC, FIELD_DEBUG
from LXMF.LXMessage import LXMessage
import LXMF.LXStamper as LXStamper

# Fixed identities from the Reticulum python test suite
# (Reticulum repository: tests/identity.py)
FIXED_KEYS = [
    ("f8953ffaf607627e615603ff1530c82c434cf87c07179dd7689ea776f30b964cfb7ba6164af00c5111a45e69e57d885e1285f8dbfe3a21e95ae17cf676b0f8b7", "650b5d76b6bec0390d1f8cfca5bd33f9"),
    ("d85d036245436a3c33d3228affae06721f8203bc364ee0ee7556368ac62add650ebf8f926abf628da9d92baaa12db89bd6516ee92ec29765f3afafcb8622d697", "1469e89450c361b253aefb0c606b6111"),
    ("8893e2bfd30fc08455997caf7abb7a6341716768dbbf9a91cc1455bd7eeaf74cdc10ec72a4d4179696040bac620ee97ebc861e2443e5270537ae766d91b58181", "e5fe93ee4acba095b3b9b6541515ed3e"),
    ("b82c7a4f047561d974de7e38538281d7f005d3663615f30d9663bad35a716063c931672cd452175d55bcdd70bb7aa35a9706872a97963dc52029938ea7341b39", "1333b911fa8ebb16726996adbe3c6262"),
    ("08bb35f92b06a0832991165a0d9b4fd91af7b7765ce4572aa6222070b11b767092b61b0fd18b3a59cae6deb9db6d4bfb1c7fcfe076cfd66eea7ddd5f877543b9", "d13712efc45ef87674fb5ac26c37c912"),
]

SOURCE_KEY_HEX = FIXED_KEYS[0][0]
DEST_KEY_HEX = FIXED_KEYS[1][0]
PN_KEY_HEX = FIXED_KEYS[2][0]

FIXED_TS = 1735689600.5

FIXED_STAMP = bytes.fromhex(
    "00112233445566778899aabbccddeeff"
    "00112233445566778899aabbccddeeff")

FIXED_TICKET = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
FIXED_TICKET_EXPIRY = 2000000000.0

FIXED_THREAD_ID = bytes.fromhex(
    "61d194b5da8ddba5a1f8788a12f21c68"
    "e1cf738f6c03621d78b6a1105f8a9b41")

STAMP_MESSAGE_ID = bytes.fromhex(
    "3fc2c8fb7ae15ecfd5b1c4d05b7614f0"
    "11e5c11f24cdddd58ba4514a2f96c4db")

PN_TRANSIENT_ID = bytes.fromhex(
    "7a9e3f11d20c58b9e6a1f0c4d5e6f708"
    "192a3b4c5d6e7f8091a2b3c4d5e6f708")

PEERING_ID = bytes.fromhex(
    "00aa11bb22cc33dd44ee55ff66001122"
    "33445566778899aabbccddeeff001122")


def val_to_json(obj):
    """Convert a python msgpack-compatible value to a JSON-safe tagged tree."""
    if obj is None:
        return ["nil"]
    if isinstance(obj, bool):
        return ["bool", obj]
    if isinstance(obj, int):
        return ["int", obj]
    if isinstance(obj, float):
        return ["float", obj]
    if isinstance(obj, str):
        return ["str", obj]
    if isinstance(obj, (bytes, bytearray)):
        return ["bin", bytes(obj).hex()]
    if isinstance(obj, list):
        return ["list", [val_to_json(e) for e in obj]]
    if isinstance(obj, tuple):
        return ["list", [val_to_json(e) for e in obj]]
    if isinstance(obj, dict):
        return ["map", [[val_to_json(k), val_to_json(v)] for k, v in obj.items()]]
    raise TypeError(f"Cannot encode {type(obj)} as msgpack value")


def destination_for(identity):
    return RNS.Destination(identity, RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, "delivery")


def make_message(name, src_id, dst_id, title, content, fields, stamp=None,
                 stamp_cost=None, defer_stamp=True, desired_method=None):
    dst = destination_for(dst_id)
    src = destination_for(src_id)
    lxm = LXMessage(destination=dst, source=src, content=content, title=title,
                    fields=fields, desired_method=desired_method)
    lxm.timestamp = FIXED_TS
    if stamp is not None:
        lxm.stamp = stamp
        lxm.stamp_cost = stamp_cost if stamp_cost is not None else 8
        lxm.defer_stamp = False
    elif stamp_cost is not None:
        lxm.stamp_cost = stamp_cost
        lxm.defer_stamp = defer_stamp
    lxm.pack()
    return lxm


def message_fixture(name, lxm, fields_json, stamp=None, ticket=None):
    return {
        "name": name,
        "destination_hash": lxm.destination_hash.hex(),
        "source_hash": lxm.source_hash.hex(),
        "title": lxm.title.hex(),
        "content": lxm.content.hex(),
        "fields": fields_json,
        "timestamp": lxm.timestamp,
        "stamp": stamp.hex() if stamp else None,
        "ticket": ticket.hex() if ticket else None,
        "packed": lxm.packed.hex(),
        "packed_size": lxm.packed_size,
        "hash": lxm.hash.hex(),
        "signature": lxm.signature.hex(),
        "method": lxm.method,
        "representation": lxm.representation,
        "transport_encrypted": lxm.transport_encrypted,
        "transport_encryption": lxm.transport_encryption,
    }


def main():
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden.json")

    src_id = RNS.Identity.from_bytes(bytes.fromhex(SOURCE_KEY_HEX))
    dst_id = RNS.Identity.from_bytes(bytes.fromhex(DEST_KEY_HEX))
    pn_id = RNS.Identity.from_bytes(bytes.fromhex(PN_KEY_HEX))

    src_dest = destination_for(src_id)
    dst_dest = destination_for(dst_id)
    pn_dest = RNS.Destination(pn_id, RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, "propagation")

    golden = {
        "app_name": APP_NAME,
        "identities": {
            "source": {
                "private_hex": SOURCE_KEY_HEX,
                "hash": src_id.hash.hex(),
                "public_hex": src_id.get_public_key().hex(),
                "delivery_destination_hash": src_dest.hash.hex(),
            },
            "destination": {
                "private_hex": DEST_KEY_HEX,
                "hash": dst_id.hash.hex(),
                "public_hex": dst_id.get_public_key().hex(),
                "delivery_destination_hash": dst_dest.hash.hex(),
            },
            "propagation_node": {
                "private_hex": PN_KEY_HEX,
                "hash": pn_id.hash.hex(),
                "public_hex": pn_id.get_public_key().hex(),
                "propagation_destination_hash": pn_dest.hash.hex(),
            },
        },
        "constants": {
            "delivery_name_hash": RNS.Destination.hash_from_name_and_identity("lxmf.delivery", dst_id)[:0].hex()
                                  if False else None,  # placeholder, filled below
        },
    }
    del golden["constants"]

    # -- messages ---------------------------------------------------------
    messages = []

    # 1. small plain message
    fields = {}
    lxm = make_message("small", src_id, dst_id, "Test Title", "Hello from the LXMF Rust port!", fields)
    messages.append(message_fixture("small", lxm, val_to_json(fields)))

    # 2. empty message
    lxm = make_message("empty", src_id, dst_id, "", "", {})
    messages.append(message_fixture("empty", lxm, val_to_json({})))

    # 3. message with many field types
    fields = {
        FIELD_EMBEDDED_LXMS: bytes.fromhex("deadbeef") * 4,
        FIELD_TELEMETRY: {0x00: bytes.fromhex("74656d70"), 0x01: 21.5, 0x02: 3},
        FIELD_FILE_ATTACHMENTS: [["report.txt", bytes.fromhex("6c6f72656d20697073756d")]],
        FIELD_IMAGE: [0x01, bytes.fromhex("ffd8ffe000104a46494600")],
        FIELD_THREAD: FIXED_THREAD_ID,
        FIELD_REPLY_TO: FIXED_THREAD_ID,
        FIELD_REACTION: {0x00: FIXED_THREAD_ID, 0x01: "👍".encode("utf-8")},
        FIELD_CUSTOM_TYPE: "application/x-test",
        FIELD_CUSTOM_DATA: bytes.fromhex("00ff00ff00ff"),
        FIELD_NON_SPECIFIC: 24680,
        FIELD_DEBUG: {"debug_key": True, "rounds": 4},
    }
    lxm = make_message("fields", src_id, dst_id, "Fields", "With fields", fields)
    messages.append(message_fixture("fields", lxm, val_to_json(fields)))

    # 4. large message (forces RESOURCE representation for direct delivery)
    large_content = "x" * 600
    fields = {FIELD_CUSTOM_TYPE: "large"}
    lxm = make_message("large", src_id, dst_id, "Large", large_content, fields)
    messages.append(message_fixture("large", lxm, val_to_json(fields)))

    # 5. message with a pre-generated (fixed) stamp included in the payload
    fields = {}
    lxm = make_message("stamp", src_id, dst_id, "Stamped", "With stamp", fields,
                       stamp=FIXED_STAMP, stamp_cost=8)
    messages.append(message_fixture("stamp", lxm, val_to_json(fields), stamp=FIXED_STAMP))

    # 6. message with a ticket field and ticket-derived stamp
    ticket_fields = {FIELD_TICKET: [FIXED_TICKET_EXPIRY, FIXED_TICKET]}
    lxm = make_message("ticket", src_id, dst_id, "Ticket", "With ticket", ticket_fields)
    ticket_stamp = RNS.Identity.truncated_hash(FIXED_TICKET + lxm.message_id)
    # re-pack with the ticket stamp applied
    lxm2 = make_message("ticket", src_id, dst_id, "Ticket", "With ticket", ticket_fields,
                        stamp=ticket_stamp)
    messages.append(message_fixture("ticket", lxm2, val_to_json(ticket_fields),
                                    stamp=ticket_stamp, ticket=FIXED_TICKET))

    golden["messages"] = messages

    # -- packed container ---------------------------------------------------
    # Mirrors what write_to_directory() persists for a packed message
    # (state is GENERATING since the message has not been sent yet).
    container_lxm = make_message(
        "small", src_id, dst_id, "Test Title", "Hello from the LXMF Rust port!", {})
    golden["packed_container"] = {
        "message": "small",
        "bytes": container_lxm.packed_container().hex(),
    }

    # -- stamps -------------------------------------------------------------
    stamps = []
    for cost in (8, 10, 12):
        stamp, value = LXStamper.generate_stamp(STAMP_MESSAGE_ID, cost)
        wb = LXStamper.stamp_workblock(STAMP_MESSAGE_ID)
        stamps.append({
            "message_id": STAMP_MESSAGE_ID.hex(),
            "expand_rounds": LXStamper.WORKBLOCK_EXPAND_ROUNDS,
            "cost": cost,
            "stamp": stamp.hex(),
            "value": value,
            "workblock_len": len(wb),
            "workblock_hash": RNS.Identity.full_hash(wb).hex(),
        })

    # propagation-node stamp (WORKBLOCK_EXPAND_ROUNDS_PN)
    stamp, value = LXStamper.generate_stamp(PN_TRANSIENT_ID, 8, expand_rounds=LXStamper.WORKBLOCK_EXPAND_ROUNDS_PN)
    wb = LXStamper.stamp_workblock(PN_TRANSIENT_ID, expand_rounds=LXStamper.WORKBLOCK_EXPAND_ROUNDS_PN)
    stamps.append({
        "message_id": PN_TRANSIENT_ID.hex(),
        "expand_rounds": LXStamper.WORKBLOCK_EXPAND_ROUNDS_PN,
        "cost": 8,
        "stamp": stamp.hex(),
        "value": value,
        "workblock_len": len(wb),
        "workblock_hash": RNS.Identity.full_hash(wb).hex(),
    })

    # peering key (WORKBLOCK_EXPAND_ROUNDS_PEERING)
    stamp, value = LXStamper.generate_stamp(PEERING_ID, 12, expand_rounds=LXStamper.WORKBLOCK_EXPAND_ROUNDS_PEERING)
    stamps.append({
        "message_id": PEERING_ID.hex(),
        "expand_rounds": LXStamper.WORKBLOCK_EXPAND_ROUNDS_PEERING,
        "cost": 12,
        "stamp": stamp.hex(),
        "value": value,
    })
    golden["stamps"] = stamps

    # -- paper message ------------------------------------------------------
    paper = {}
    lxm = LXMessage(destination=dst_dest, source=src_dest, content="Paper message",
                    title="Paper", desired_method=LXMessage.PAPER)
    lxm.timestamp = FIXED_TS
    lxm.pack()
    paper = {
        "destination_hash": lxm.destination_hash.hex(),
        "source_hash": lxm.source_hash.hex(),
        "title": lxm.title.hex(),
        "content": lxm.content.hex(),
        "fields": val_to_json({}),
        "timestamp": lxm.timestamp,
        "paper_packed": lxm.paper_packed.hex(),
        "transient_id": RNS.Identity.full_hash(lxm.paper_packed).hex(),
        "uri": lxm.as_uri(),
        "method": lxm.method,
        "representation": lxm.representation,
    }
    golden["paper"] = paper

    # -- propagation packed -------------------------------------------------
    lxm = LXMessage(destination=dst_dest, source=src_dest, content="Propagated message",
                    title="Prop", desired_method=LXMessage.PROPAGATED)
    lxm.timestamp = FIXED_TS
    lxm.pack()
    # Recreate with a fixed transport timestamp for the wrapper list
    lxmf_data = lxm.propagation_packed
    prop = {
        "destination_hash": lxm.destination_hash.hex(),
        "transient_id": lxm.transient_id.hex(),
        "packed": lxm.packed.hex(),
        "propagation_packed": lxmf_data.hex(),
        "propagation_lxmf_data": (lxm.packed[:LXMessage.DESTINATION_LENGTH] + lxm._LXMessage__pn_encrypted_data).hex(),
        "method": lxm.method,
        "representation": lxm.representation,
    }
    golden["propagation"] = prop

    # -- peer data ------------------------------------------------------------
    class StubRouter:
        identity = None
        propagation_entries = {}

    from LXMF.LXMPeer import LXMPeer
    peer = LXMPeer(StubRouter(), bytes.fromhex(golden["identities"]["propagation_node"]["propagation_destination_hash"]))
    peer.alive = True
    peer.last_heard = FIXED_TS
    peer.peering_timebase = 1735689600
    peer.sync_strategy = LXMPeer.STRATEGY_PERSISTENT
    peer.peering_key = [FIXED_STAMP, 12]
    peer.metadata = {0x01: b"Test Node"}
    peer.link_establishment_rate = 1024.0
    peer.sync_transfer_rate = 512.5
    peer.propagation_transfer_limit = 256.0
    peer.propagation_sync_limit = 1024
    peer.propagation_stamp_cost = 16
    peer.propagation_stamp_cost_flexibility = 3
    peer.peering_cost = 18
    peer.last_sync_attempt = FIXED_TS
    peer.offered = 12
    peer.outgoing = 8
    peer.incoming = 3
    peer.rx_bytes = 12345
    peer.tx_bytes = 67890

    handled = [
        bytes.fromhex("11" * 32),
        bytes.fromhex("22" * 32),
    ]
    unhandled = [bytes.fromhex("33" * 32)]

    # LXMPeer stores handled/unhandled state in router.propagation_entries,
    # so for the wire-format fixture we serialise the same dictionary
    # structure that to_bytes() produces, with explicit id lists.
    dictionary = {
        "peering_timebase": peer.peering_timebase,
        "alive": peer.alive,
        "metadata": peer.metadata,
        "last_heard": peer.last_heard,
        "sync_strategy": peer.sync_strategy,
        "peering_key": peer.peering_key,
        "destination_hash": peer.destination_hash,
        "link_establishment_rate": peer.link_establishment_rate,
        "sync_transfer_rate": peer.sync_transfer_rate,
        "propagation_transfer_limit": peer.propagation_transfer_limit,
        "propagation_sync_limit": peer.propagation_sync_limit,
        "propagation_stamp_cost": peer.propagation_stamp_cost,
        "propagation_stamp_cost_flexibility": peer.propagation_stamp_cost_flexibility,
        "peering_cost": peer.peering_cost,
        "last_sync_attempt": peer.last_sync_attempt,
        "offered": peer.offered,
        "outgoing": peer.outgoing,
        "incoming": peer.incoming,
        "rx_bytes": peer.rx_bytes,
        "tx_bytes": peer.tx_bytes,
        "handled_ids": handled,
        "unhandled_ids": unhandled,
    }
    peer_bytes = msgpack.packb(dictionary)

    golden["peer"] = {
        "bytes": peer_bytes.hex(),
        "fields": val_to_json(dictionary),
    }

    # -- announce app data ------------------------------------------------------
    delivery_app_data = msgpack.packb(["Display Name".encode("utf-8"), 12, [LXMF.SF_COMPRESSION]])
    legacy_delivery_app_data = b"Legacy Name"
    pn_app_data = msgpack.packb([
        False,
        1735689600,
        True,
        256,
        1024,
        [16, 3, 18],
        {0x01: b"Test Node"},
    ])
    golden["announce_app_data"] = {
        "delivery": delivery_app_data.hex(),
        "delivery_display_name": "Display Name",
        "delivery_stamp_cost": 12,
        "delivery_compression_support": True,
        "legacy_delivery": legacy_delivery_app_data.hex(),
        "legacy_delivery_display_name": "Legacy Name",
        "legacy_delivery_stamp_cost": None,
        "propagation_node": pn_app_data.hex(),
        "pn_valid": True,
        "pn_name": "Test Node",
        "pn_stamp_cost": 16,
        "pn_timebase": 1735689600,
        "pn_node_state": True,
        "pn_transfer_limit": 256,
        "pn_sync_limit": 1024,
        "pn_stamp_cost_flexibility": 3,
        "pn_peering_cost": 18,
    }

    with open(out_path, "w") as f:
        json.dump(golden, f, indent=2, sort_keys=False)

    print(f"Wrote {out_path}")
    print(f"  messages:  {len(messages)}")
    print(f"  stamps:    {len(stamps)}")


if __name__ == "__main__":
    main()
