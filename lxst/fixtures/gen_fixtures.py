#!/usr/bin/env python3
"""Generate byte-exact reference fixtures from the Python LXST package.

Produces `fixtures/reference.json` consumed by the Rust integration test
`tests/reference_fixtures.rs`, so the Rust port can be verified against the
Python implementation byte for byte.

Usage:
    python3 fixtures/gen_fixtures.py [--out fixtures/reference.json]

Requires: numpy, and the Reticulum + LXST packages on PYTHONPATH:

    PYTHONPATH=/path/to/Reticulum:/path/to/LXST python3 fixtures/gen_fixtures.py

`pycodec2` (needed to import LXST.Codecs) is optional; a stub is installed
when missing since no Codec2 fixture is generated here.
"""
import argparse
import json
import os
import sys
import types

# --- optional pycodec2 stub (only needed for the LXST.Codecs import) -------
try:
    import pycodec2  # noqa: F401
except ImportError:
    stub = types.ModuleType("pycodec2")

    class _C2:  # pragma: no cover - never instantiated here
        def __init__(self, mode):
            raise RuntimeError("pycodec2 not available")

    stub.Codec2 = _C2
    sys.modules["pycodec2"] = stub

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for candidate in (
    os.path.join(REPO_ROOT, "..", "Reticulum"),
    os.environ.get("RETICULUM_PY", ""),
):
    if candidate and os.path.isdir(os.path.join(candidate, "RNS")):
        sys.path.insert(0, os.path.normpath(candidate))
        break

import numpy as np  # noqa: E402
from RNS.vendor import umsgpack as mp  # noqa: E402

from LXST.Codecs import (  # noqa: E402
    CODEC2, NULL, OPUS, RAW, Null, Raw, codec_header_byte, codec_type,
)
from LXST.Network import FIELD_SIGNALLING, FIELD_FRAMES  # noqa: E402


def frame_1ch():
    return np.array([[0.5], [-0.25], [0.0], [0.125], [-0.9]], dtype="float32")


def frame_2ch():
    return np.array(
        [
            [0.5, -0.5],
            [0.25, -0.25],
            [0.125, -0.125],
            [0.0, 0.0],
            [-1.0, 1.0],
        ],
        dtype="float32",
    )


def frame_3ch():
    rng = np.random.default_rng(1337)
    return rng.uniform(-1.0, 1.0, (7, 3)).astype("float32")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "reference.json"))
    args = parser.parse_args()

    out = {
        "version": 1,
        "codec_headers": {
            "raw": RAW,
            "opus": OPUS,
            "codec2": CODEC2,
            "null": NULL,
        },
        "codec_type_map": {
            "0x00": codec_type(0x00) is not None,
            "0x01": codec_type(0x01) is not None,
            "0x02": codec_type(0x02) is not None,
            "0xff": codec_type(0xff) is not None,
            "0x7f": codec_type(0x7f) is not None,
        },
        "raw_encode": [],
        "raw_decode": [],
        "bitdepth_map": {},
        "channel_clamp": {},
        "null_passthrough": {},
        "msgpack": [],
    }

    frames = {"1ch": frame_1ch(), "2ch": frame_2ch(), "3ch": frame_3ch()}

    # Input frames as float32 bytes so consumers can reconstruct them
    # exactly (the 3-channel frame comes from a seeded RNG).
    out["inputs"] = {
        name: {
            "float32_hex": np.ascontiguousarray(frame, dtype="float32").tobytes().hex(),
            "frames": int(frame.shape[0]),
            "channels": int(frame.shape[1]),
        }
        for name, frame in frames.items()
    }


    # ---- Raw encode for every bitdepth x channel count -------------------
    for name, frame in frames.items():
        for bitdepth in (16, 32, 64, 128):
            codec = Raw(channels=frame.shape[1], bitdepth=bitdepth)
            encoded = codec.encode(frame)
            out["raw_encode"].append(
                {
                    "frame": name,
                    "bitdepth": bitdepth,
                    "channels": frame.shape[1],
                    "hex": encoded.hex(),
                    "len": len(encoded),
                }
            )

    # ---- default construction --------------------------------------------
    codec = Raw()
    encoded = codec.encode(frame_2ch())
    out["raw_encode"].append(
        {"frame": "2ch", "bitdepth": 16, "channels": 2, "hex": encoded.hex(),
         "len": len(encoded), "note": "channels=None adopts frame channels, default bitdepth 16"}
    )

    # ---- channel adaptation ----------------------------------------------
    more = np.array([[0.5, -0.5, 0.25]], dtype="float32")
    fewer = np.array([[0.5]], dtype="float32")
    out["inputs"]["adapt_down"] = {
        "float32_hex": more.tobytes().hex(), "frames": 1, "channels": 3,
    }
    out["inputs"]["adapt_up"] = {
        "float32_hex": fewer.tobytes().hex(), "frames": 1, "channels": 1,
    }
    out["raw_encode"].append(
        {"frame": "adapt_down", "bitdepth": 32, "channels": 2,
         "hex": Raw(channels=2, bitdepth=32).encode(more).hex(),
         "len": len(Raw(channels=2, bitdepth=32).encode(more))}
    )
    out["raw_encode"].append(
        {"frame": "adapt_up", "bitdepth": 32, "channels": 3,
         "hex": Raw(channels=3, bitdepth=32).encode(fewer).hex(),
         "len": len(Raw(channels=3, bitdepth=32).encode(fewer))}
    )

    # ---- bitdepth selection thresholds ------------------------------------
    for bitdepth in (0, 15, 16, 31, 32, 63, 64, 127, 128, 256):
        codec = Raw(channels=1, bitdepth=bitdepth)
        out["bitdepth_map"][str(bitdepth)] = {
            "dtype": codec.dtype,
            "header_bitdepth": codec.header_bitdpeth,
        }

    # ---- channel clamping --------------------------------------------------
    out["channel_clamp"] = {
        "0": Raw(channels=0, bitdepth=32).channels,
        "1": Raw(channels=1, bitdepth=32).channels,
        "32": Raw(channels=32, bitdepth=32).channels,
        "33": Raw(channels=33, bitdepth=32).channels,
        "99": Raw(channels=99, bitdepth=32).channels,
    }

    # ---- decode round-trip (dtype of decoded frames) -----------------------
    for bitdepth in (16, 32, 64, 128):
        codec = Raw(channels=2, bitdepth=bitdepth)
        encoded = codec.encode(frame_2ch())
        decoded = Raw().decode(encoded)
        out["raw_decode"].append(
            {
                "bitdepth": bitdepth,
                "decoded_dtype": str(decoded.dtype),
                "decoded_shape": list(decoded.shape),
                "decoded_hex": decoded.tobytes().hex(),
            }
        )

    # ---- Null codec --------------------------------------------------------
    null = Null()
    out["null_passthrough"] = {
        "encode_hex": null.encode(frame_1ch()).tobytes().hex(),
        "encode_note": "Null.encode returns its argument unchanged (numpy float32 buffer)",
    }

    # ---- msgpack wire frames ------------------------------------------------
    raw_frame = Raw(channels=1, bitdepth=32).encode(frame_1ch())
    out["msgpack"].append(
        {
            "name": "frame_single",
            "hex": mp.packb({FIELD_FRAMES: raw_frame}).hex(),
            "note": "Packetizer frame packet: {0x01: bytes}",
        }
    )
    out["msgpack"].append(
        {
            "name": "signal_single",
            "hex": mp.packb({FIELD_SIGNALLING: [2]}).hex(),
            "note": "SignallingReceiver.signal: {0x00: [signal]}",
        }
    )
    out["msgpack"].append(
        {
            "name": "signal_multi",
            "hex": mp.packb({FIELD_SIGNALLING: [0, 1, 2]}).hex(),
        }
    )
    out["msgpack"].append(
        {
            "name": "signal_not_list",
            "hex": mp.packb({FIELD_SIGNALLING: 2}).hex(),
            "note": "receivers wrap a bare signal into a list",
        }
    )
    out["msgpack"].append(
        {
            "name": "frames_list",
            "hex": mp.packb({FIELD_FRAMES: [raw_frame, raw_frame]}).hex(),
            "note": "LinkSource also accepts a list of frames",
        }
    )
    out["msgpack"].append(
        {
            "name": "bin_size_boundaries",
            "hex": mp.packb({FIELD_FRAMES: b"\x40" * 255}).hex()[:16],
            "note": "bin8 at 255 bytes: 81 01 c4 ff ..",
        }
    )
    out["msgpack"].append(
        {
            "name": "bin_size_boundary_256",
            "hex": mp.packb({FIELD_FRAMES: b"\x40" * 256}).hex()[:16],
            "note": "bin16 at 256 bytes: 81 01 c5 01 00 ..",
        }
    )
    out["msgpack"].append(
        {
            "name": "unknown_key_ignored",
            "hex": mp.packb({0x05: "hi", FIELD_FRAMES: raw_frame}).hex(),
            "note": "unknown keys must be ignored by receivers",
        }
    )
    out["msgpack"].append(
        {
            "name": "not_a_map",
            "hex": mp.packb([1, 2, 3]).hex(),
            "note": "non-dict payloads decode to an empty message",
        }
    )

    with open(args.out, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
