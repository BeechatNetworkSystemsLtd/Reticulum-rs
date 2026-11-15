# lxst

A Rust port of [LXST](https://github.com/markqvist/LXST) — low-latency audio
streaming, calls and telephony over
[Reticulum](https://reticulum.network), built on the `reticulum` and
`reticulum-core` crates of this workspace.

## Modules

| Python module          | Rust module                       |
|------------------------|-----------------------------------|
| `LXST/__init__.py`     | `lxst::APP_NAME`                  |
| `Common.py`            | [`common`] (`nop`, `AudioFrame`)  |
| `Codecs/`              | [`codecs`]                        |
| `Network.py`           | [`network`]                       |
| `Pipeline.py`          | [`pipeline`]                      |
| `Sources.py`           | [`sources`]                       |
| `Sinks.py`             | [`sinks`]                         |
| `Mixer.py`             | [`mixer`]                         |
| `Filters.py`           | [`filters`]                       |
| `Processing.py`        | [`processing`]                    |
| `Generators.py`        | [`generators`]                    |
| `Call.py`              | [`call`]                          |
| `Primitives/`          | **not ported** (OS audio/hardware)|
| `Platforms/`           | **not ported** (OS audio backends)|

Not ported from Python: microphone/speaker device backends (`Platforms/*`,
`soundcard`), the vendored `pyogg`/`pydub` helpers (`Codecs/libs/*`), and the
`Telephone`/`FilePlayer`/`FileRecorder` primitives that depend on them.
`Primitives/Telephony.py` signalling codes live in
[`network::Signal`](crate::network::Signal); the profile tables were codec
dependent and are folded into the codecs.

## Wire format (byte-compatible with Python LXST)

Every LXST payload carried in a Reticulum packet is a **msgpack map** with
integer keys, packed exactly like `RNS.vendor.umsgpack.packb`:

```text
{0x00: [signal, ...]}   signalling: fixarray of positive fixint codes
{0x01: frame}           audio frame: bin (or fixarray of bins for several)
```

* map keys are encoded as **positive fixint** bytes (`0x00`, `0x01`)
* frame payloads are **bin** containers (`0xc4`/`0xc5`/`0xc6` for
  len < 256 / < 65536 / beyond)
* signals must be `< 0x80` (fixint range); the Python packer cannot express
  larger codes, so this port rejects them on receive
* unknown map keys are ignored; a non-map payload decodes to an empty
  message (both mirror the Python receivers)

Every audio frame is `[codec_header_byte] ++ codec_payload`, where the codec
header byte comes from the registry:

| codec    | header | inner frame format                                   |
|----------|--------|-------------------------------------------------------|
| `Raw`    | `0x00` | one byte `bitdepth << 6 \| (channels-1)`, then samples |
| `Opus`   | `0x01` | a raw Opus packet (no inner header)                    |
| `Codec2` | `0x02` | one mode header byte, then packed Codec2 frames        |
| `Null`   | `0xFF` | no packet mapping (Python raises `TypeError`)          |

`Raw` sample formats by header bit-depth index:

| index | nominal bits | numpy dtype | Rust             |
|-------|--------------|-------------|------------------|
| 0     | 16           | float16     | `half::f16`      |
| 1     | 32           | float32     | `f32`            |
| 2     | 64           | float64     | `f64`            |
| 3     | 128          | float128    | x87 80-bit (see `codecs::raw`) |

`float128`: numpy's `float128` on x86-64 is the x87 80-bit extended format
in a 16-byte container whose trailing 6 bytes are **uninitialised padding**.
This port writes the same 10 value bytes and zeroes the padding.

## Features

| feature  | default | dependency                | notes                          |
|----------|---------|---------------------------|--------------------------------|
| `opus`   | no      | `audiopus` (libopus)      | needs `pkg-config Opus` or autotools |
| `codec2` | no      | `codec2` (pure Rust)      | only modes 2400 and 3200 exist upstream |

The default build has **no native/C dependencies** and provides the `Raw`
and `Null` codecs, the whole DSP layer and the full wire protocol.

## Examples

Answer a call and stream audio:

```no_run
use std::sync::Arc;
use lxst::call::{call_transport, CallEndpoint};
use lxst::codecs::CodecType;
use rand_core::OsRng;
use reticulum::identity::PrivateIdentity;

#[tokio::main]
async fn main() {
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport = call_transport(&identity, "lxst");
    let (mut endpoint, mut events) =
        CallEndpoint::new(transport.clone(), identity).await.unwrap();
    endpoint.announce().await;

    while let Some(event) = events.recv().await {
        match event {
            lxst::call::CallEvent::IncomingCall(link_id) => {
                let link = transport.find_in_link(&link_id).await.unwrap();
                let _handle = endpoint
                    .answer(link, CodecType::Raw, Some(48_000), Some(1))
                    .await
                    .unwrap();
            }
            lxst::call::CallEvent::Frame(_, frame) => {
                // decoded remote audio
            }
            _ => {}
        }
    }
}
```

## Fixtures

`fixtures/gen_fixtures.py` regenerates `fixtures/reference.json` from the
Python LXST package; the Rust integration tests in `tests/` verify the port
byte for byte against it:

```sh
PYTHONPATH=../Reticulum:../LXST python3 fixtures/gen_fixtures.py
cargo test -p lxst
```

## Known gaps / TODOs

* **Opus/Codec2 numerics** are ported but not byte-verified against Python
  (the Python codecs need `pyogg`/`pycodec2`, unavailable here); the framing
  around them is verified.
* `Codec2` modes other than 2400/3200 are unsupported by the upstream Rust
  crate and fail with `CodecError::Unsupported`.
* The Python `Telephone` state machine (ringing, dial/busy tones, ringtones,
  profile switching, allow/block lists, auto-answer) is not ported; it needs
  OS audio.
* Resampling is linear interpolation; Python delegates to pydub (which uses
  ffmpeg for non-trivial ratios). For integer-ratio conversions the results
  agree closely, but they are not guaranteed bit-identical.
* The Python `Mixer.unmute()` has a bug (it assigns `muted = unmute`, so
  `unmute()` keeps the mixer muted). This port implements the intended
  behaviour and documents the divergence.
* In-band signalling scheduling (the recurring TODO in Python `Network.py`)
  is not implemented, matching Python.
