# Reticulum-rs — Feature-Parity Implementation Plan

Target: bring `Reticulum-rs` (workspace v0.1.0) to functional parity with Python
`Reticulum` 1.5.5 (`1.5.5`, `RNS/` ≈ 13.2k lines).

This document inventories every gap identified by comparing the two codebases,
and turns it into a phased, dependency-ordered work plan. Every work item lists
the Python reference (file + functions/constants), the planned Rust target
files, design notes grounded in the actual wire formats, tests, and acceptance
criteria.

---

## Table of contents

1. [Ground rules & architecture conventions](#1-ground-rules--architecture-conventions)
2. [Current-state inventory](#2-current-state-inventory)
3. [Phase 0 — Foundations & prerequisites](#3-phase-0--foundations--prerequisites)
4. [Phase 1 — Identity & persistence parity](#4-phase-1--identity--persistence-parity)
5. [Phase 2 — Destination & Link API parity](#5-phase-2--destination--link-api-parity)
6. [Phase 3 — Resource transfer](#6-phase-3--resource-transfer)
7. [Phase 4 — Buffer streams](#7-phase-4--buffer-streams)
8. [Phase 5 — Interface expansion](#8-phase-5--interface-expansion)
9. [Phase 6 — Transport parity](#9-phase-6--transport-parity)
10. [Phase 7 — Reticulum instance & daemon parity](#10-phase-7--reticulum-instance--daemon-parity)
11. [Phase 8 — Utilities (`rn*` tools)](#11-phase-8--utilities-rn-tools)
12. [Phase 9 — Testing, CI & documentation](#12-phase-9--testing-ci--documentation)
13. [Phase 10 — Beyond RNS parity: LXMF & LXST](#13-phase-10--beyond-rns-parity-lxmf--lxst)
14. [Dependency graph](#14-dependency-graph)
15. [Milestones & suggested ordering](#15-milestones--suggested-ordering)
16. [Risk register](#16-risk-register)
17. [Open questions](#17-open-questions)
18. [Appendix A — Python ↔ Rust file map](#appendix-a--python--rust-file-map)
19. [Appendix B — Wire-format cheat sheet](#appendix-b--wire-format-cheat-sheet)

---

## 1. Ground rules & architecture conventions

These rules apply to every work item and should be decided up front, since they
constrain all later designs.

### 1.1 Wire compatibility is the #1 requirement

Every protocol-visible feature (announces, path requests, links, channel
envelopes, resources, requests, IFAC, shared-instance frames, tunnel packets)
must byte-match what Python Reticulum 1.5.5 puts on the wire. Verification is
done by extending the existing Python-interop harness (`tests/python.rs`,
feature `python-tests`, `RETICULUM_TEST_PYTHON_DIR`) — see [Phase 9](#12-phase-9--testing-ci--documentation).

*MessagePack note:* Python uses `RNS/vendor/umsgpack`; the workspace already
depends on `rmp 0.8`. `rmp` is wire-compatible with msgpack for the value types
Reticulum uses, and `path_requests.rs` already relies on this. Keep a single
helper module (`reticulum-core/src/serde.rs`, extend as needed) that owns all
cross-language (de)serialization so quirks are fixed in one place.

### 1.2 Crate & module layout stays as-is

| Crate | Role | Constraints |
|---|---|---|
| `reticulum-core` | Pure protocol logic: crypto, identities, packets, destinations, links | Must stay `no_std`-friendly (`std`/`no_std`/`embassy-time` features already exist). No tokio, no sockets, no filesystem. I/O via traits (buffers, RNG, clock, storage). |
| `reticulum` | Async runtime: `Transport`, interfaces, `Channel`, resources, shared-instance client/server | tokio-based (feature-gate anything platform-specific). |
| `reticulum-daemon` | Binary: config, daemon | Config in TOML; keeps the Python-config converter. |

New top-level modules planned in `reticulum`: `resource/`, `storage/`,
`iface/auto.rs`, `iface/local.rs`, `iface/serial.rs`, `iface/kiss.rs`,
`iface/rnode.rs`, `iface/i2p.rs`, `iface/pipe.rs`, `discovery.rs`.

### 1.3 Concurrency model

Follow the existing `transport.rs` pattern:

* One `TransportHandler` behind `Arc<Mutex<…>>`, background tokio tasks driven
  by `TimerConfig` values in a `select! { cancel, sleep }` loop.
* Application-facing APIs are `async fn` on the facade structs; events flow out
  through `tokio::sync::broadcast` channels (announce events, link events,
  received data). New event types (resource status, request receipts, path
  events) get their own broadcast channels — do **not** pollute the existing
  ones.
* No Python-style threads/watchdog loops; every timer becomes a task.

### 1.4 Platform-specific interfaces behind feature flags

Serial/RNode need `tokio-serial`; I2P spawns a `sam3` TCP connection or the
`i2pd`/Java-I2P control interface; BLE (future) needs `btleplug`. Each becomes
a non-default cargo feature (`iface-serial`, `iface-rnode`, `iface-i2p`, …) so
the default build (and embedded users of `reticulum-core`) stay dependency-free.

### 1.5 Definition of done (applies to every item)

1. Implementation merged with unit tests.
2. If protocol-visible: an interop test against Python (`python-tests` feature)
   and/or a scripted Python `Examples/` run added to the matrix.
3. Public API documented with doc examples (crate docs already follow this
   style).
4. `cargo clippy --workspace --all-targets --all-features` clean; CI workflow
   extended if new features were added.

---

## 2. Current-state inventory

Legend: ✅ done (parity or near-parity), 🟡 partial (exists but incomplete),
❌ missing.

| Python (`RNS/…`) | Lines | Rust status | Notes |
|---|---|---|---|
| `Cryptography/*` (Ed25519, X25519, HKDF, Fernet token, AES) | — | ✅ `reticulum-core/src/crypt/fernet.rs`, `identity.rs` | dalek-based; verified by link tests |
| `Identity.py` | 956 | 🟡 | Keys/derive/sign/verify ✅; **ratchets ❌**, known-destinations store ❌, file persistence ❌ |
| `Packet.py` | 576 | ✅ `reticulum-core/src/packet.rs` | all contexts/types incl. resource constants |
| `Destination.py` | 691 | 🟡 | SINGLE in/out ✅; **PLAIN ❌, GROUP ❌**, proof strategies ❌ (TODO at `destination.rs:314`), requests ❌ |
| `Link.py` | 1500 | 🟡 | establishment/proofs/RTT/keepalive/identify/teardown/MTU field ✅; **requests/responses ❌**, resource hooks ❌ |
| `Channel.py` | 606 | ✅ `src/channel.rs` | windowing, sequences, receipts ported |
| `Resource.py` | 1367 | ❌ | only packet-context constants exist |
| `Buffer.py` | 371 | ❌ | `buffer.rs` is a byte-buffer helper, not link streams |
| `Transport.py` | 3706 | 🟡 | announces, paths, dedup cache, link relay, rate limit, retransmit ✅; **expiry ❌, announce caps/egress control 🟡 (simplistic), tunnels ❌, blackholes ❌, cache requests ❌, remote mgmt ❌, path stats ❌** |
| `Discovery.py` | 864 | ❌ | |
| `Reticulum.py` | 1997 | 🟡 | daemon with identity persistence, config parity (warn-not-fail), SIGINT/SIGTERM shutdown; **shared-instance API ❌, RPC ❌, stats 🟡 (iface snapshot only)** |
| `Interfaces/`: TCP client/server, UDP | — | ✅ `src/iface/{tcp_client,tcp_server,udp}.rs`, HDLC ✅ | |
| `Interfaces/`: Auto, Local, Serial, KISS, AX.25 KISS, RNode(+Multi), I2P, Pipe, Backbone, Weave, Android | ~8000 | ❌ | daemon config *parses* some types but logs "not yet supported" |
| IFAC (netname/netkey auth) | (Interface.py, Transport.py) | ❌ | flag bit parsed (`IfacFlag`), never computed/validated |
| `Utilities/rnsd.py` | — | 🟡 `reticulum-daemon` | identity persistence + restart stability ✅, `--version` ✅; no shared instance, no control/RPC |
| `Utilities/` rnstatus, rnpath, rnprobe, rnsh, rncp, rnx, rnid, rnir, rnodeconf, rnpkg | — | 🟡 `reticulum-utils` (`rn` binary) | rnid ✅ (generate/save/inspect), rnpath ✅ (lookup + table, local), rnstatus 🟡 (local only; iface stats minimal), rncp ✅ (send/serve/fetch, Python-interop send both ways); rnprobe/rnsh/rnx/rnir/rnodeconf/rnpkg ❌ |
| Stale docs | — | 🟡 | README mentions `proto/kaonic` + `kaonic_client.rs` which don't exist in-tree |

---

## 3. Phase 0 — Foundations & prerequisites

Nothing here is user-visible protocol; everything later depends on it.

### 0.1 Unify time handling in `reticulum-core` *(S)*

* Python refs: `time.time()` usage throughout.
* Rust: `reticulum-core/src/time.rs` (74 lines) already exists as the `no_std`
  clock shim. Extend it with a monotonic `Instant`-like facade so resource
  timers (Phase 3) and transport timers work in both `std` and `embassy-time`
  builds without further churn.
* Acceptance: resource/transport code written against `time::now()` /
  `time::monotonic()` compiles under both `std` and `no_std+embassy-time`
  feature sets in CI.

### 0.2 Storage abstraction layer *(M)*

* Python refs: `Identity.save_known_destinations` / `load_known_destinations`,
  `Identity.persist_data`, `RNS.Reticulum.storagepath`, per-identity
  `to_file`/`from_file`.
* Rust target: new `reticulum-core/src/storage.rs` trait + `reticulum/src/storage/`
  implementations:
  ```rust
  pub trait Storage {
      fn read(&self, path: &str) -> Result<Vec<u8>, RnsError>;
      fn write(&self, path: &str, data: &[u8]) -> Result<(), RnsError>;
      fn list(&self, path: &str) -> Result<Vec<String>, RnsError>;
      fn remove(&self, path: &str) -> Result<(), RnsError>;
  }
  // reticulum: FsStorage(configdir-based), MemoryStorage (tests, embedded)
  ```
  This keeps `reticulum-core` `no_std` clean while Phases 1/7 get real
  persistence.
* Acceptance: trait + two impls + tests; used later by Phases 1 and 7.

### 0.3 Interface trait redesign *(M — blocking for Phase 5 & 6)*

* Python refs: `Interfaces/Interface.py` (`get_hash`, `announce_cap`,
  `optimise_mtu`, `hold_announce`, `process_held_announces`, announce/pr
  frequency trackers, `mode`, `bitrate`, `online`, rssi/snr/q…).
* Rust target: `src/iface.rs`. Today the `Interface` trait is just
  `fn mtu() -> usize` and `InterfaceManager` only tracks tx senders. Extend to
  a shared per-interface state struct:
  ```rust
  pub struct InterfaceState {          // held in InterfaceManager, one per iface
      pub address: AddressHash,
      pub name: String,
      pub kind: InterfaceKind,         // for stats & config reporting
      pub mode: InterfaceMode,         // AccessPoint / Gateway / Roaming / Boundary (Reticulum.py option)
      pub bitrate: u64,                // configured or measured
      pub announce_cap: f32,           // default from Reticulum::ANNOUNCE_CAP (0.9 * ...; see Python)
      pub ifac_size: Option<usize>,    // Phase 5.1
      pub online: bool,
      pub stats: InterfaceStats,       // counters; rssi/snr/q as Option<i32> where radio
  }
  pub trait Interface { fn state(&self) -> InterfaceState; fn detach(&mut self); }
  ```
  Also add `InterfaceManager::set/get/detach` so transport and utilities can
  query interfaces (needed by Phase 6 egress control and `rnstatus`).
* Acceptance: existing TCP/UDP ifaces migrated without behavior change; tests
  still green.

### 0.4 Error & packet API polish *(S)*

* Fold new failure modes into `reticulum-core/src/error.rs` (`RnsError::Resource`,
  `Storage`, `Request`, `Iface`), finish the `destination.rs` TODO at line 314
  (prove strategy) plumbing required by Phase 2.3, and keep packet
  encode/decode errors descriptive for fuzzing (Phase 9).

### 0.5 Interop harness upgrade *(M)*

* Extend `tests/python.rs` harness (currently: announce, link client/server,
  identify) with:
  * generic "spawn python script with config dir, drive rust peer, assert"
    helpers (already partly there — generalize);
  * a `PythonNode` builder producing isolated config dirs (storage paths,
    interfaces on ephemeral ports) from templates in
    `tests/rns-py-configs/`;
  * dump/replay of raw frames (`PI_*`-style trace env var exists:
    `PACKET_TRACE`) for golden-file wire tests.
* Acceptance: a new interop test can be added in ≤ 50 lines.

---

## 4. Phase 1 — Identity & persistence parity

Python ref: `RNS/Identity.py` (956 lines).

### 1.1 Identity file persistence *(S)*

* Python: `Identity.to_file/pub_to_file/from_file/from_bytes`, hex-encoded
  key files under `storagepath/identities`.
* Rust: `PrivateIdentity::{to_file, from_file, pub_to_file}` via the Phase 0.2
  `Storage` trait; hex format must match Python exactly (`identity.rs` already
  has `new_from_hex_string`/`to_hex_string`, so this is mostly I/O + tests).
* Tests: round-trip; read a file produced by Python `rnid`; Python reads a
  file produced by Rust.
* Acceptance: daemon identity survives restart (used by Phase 7.4).

### 1.2 Known-destinations store *(M)*

* Python: `Identity.remember/recall/recall_app_data`,
  `save_known_destinations/load_known_destinations` (msgpack file
  `storagepath/known_destinations`), `_retain_destination_data`,
  `clean_known_destinations`.
* Rust: new `reticulum/src/storage/known_destinations.rs`:
  ```rust
  pub struct KnownDestinations { /* addr hash -> (pub key, app data, last seen, uses) */ }
  ```
  * `Transport::handle_announce` populates it (hook into the existing
    `AnnounceEvent` path);
  * periodic save (like `__persist_data`) as a `TimerConfig`-driven task;
  * `Transport::recall(destination_hash)` public API for apps (parity with
    `RNS.Identity.recall`).
* Wire detail: the persisted msgpack structure must stay readable by (and
  writable for) Python Reticulum — replicate the exact dict layout from
  `Identity.save_known_destinations` (keys: destination hash →
  `[public key, app data, ...]` as Python builds it — copy from source).
* Tests: round-trip; cross-load a `known_destinations` file produced by Python.
* Acceptance: Rust node remembers known destinations and app data across
  restarts; announce validation can use recalled keys.

### 1.3 Announce ratchets *(M)*

* Python: `Identity._generate_ratchet`, `_remember_ratchet`,
  `get_ratchet`, `current_ratchet_id`, `_clean_ratchets`,
  `validate_announce(..., ratchets)`, and `Ratchets.py` example.
* What it does (1.4.x): each destination announces an ephemeral X25519
  "ratchet" key in the signed announce blob; senders encrypt SINGLE-destination
  packets (see Phase 2.2/2.4 crypto) to `identity_key || ratchet_key` so the
  receiver can decrypt while rotating keys forward.
* Rust:
  * `reticulum-core/src/identity.rs`: add `Ratchet` (X25519 static secret +
    id), `ratchet_id()` (= first byte of hash of pub key, per Python
    `_get_ratchet_id`), remember-queue with age bounds;
  * `SingleInputDestination::announce` gains the ratchet field (announce blob
    layout per `Identity.validate_announce`);
  * `DestinationAnnounce::validate` records ratchets for recalled use.
* Persistence: ratchets are part of the known-destinations file in Python —
  store alongside Phase 1.2 data.
* Tests: unit (generate/remember/clean); interop with Python
  `Examples/Ratchets.py`-style flow once Phase 2.4 lands.
* Acceptance: Rust can send announce-encrypted packets to Python
  `Destination.encrypt` users and vice versa.

### 1.4 Destination-data retention *(S)*

* Python: `Reticulum._retain_destination_data/_unretain/_used_destination_data`
  gate what gets persisted.
* Rust: small ref-count map in `TransportHandler` consumed by Phase 1.2 saver.
  Acceptance: retained destinations survive `clean_known_destinations`
  (age-based pruning ported from Python).

---

## 5. Phase 2 — Destination & Link API parity

Python refs: `RNS/Destination.py`, `RNS/Link.py`, parts of `Transport.py`.

### 2.1 PLAIN destinations *(M)*

* Python: `Destination.PLAIN` (type `0b10` — enum already exists in
  `packet.rs`), used with a null identity; packets encrypted with an ephemeral
  X25519 key whose public part is prepended to the payload
  (`Identity.encrypt` with generated ephemeral key).
* Rust:
  * enable the commented-out `encrypt/decrypt` impls in
    `reticulum-core/src/destination.rs` (lines ~192–215) — the crypto
    primitives (`DerivedKey::new_from_ephemeral_key`, Fernet token) already
    exist;
  * add `PlainInput/PlainOutputDestination` (or parameterize
    `Destination<EmptyIdentity, …>` which already exists) with name-hash
    addressing (`DestinationName::new_from_hash_slice` already present);
  * `handle_data` in `transport.rs`: route `DestinationType::Plain` to a new
    broadcast event (currently plain-type data packets are ignored).
* Tests: unit encrypt/decrypt; interop with Python `Examples/Broadcast.py`.
* Acceptance: Rust ↔ Python broadcast (plain) chat works both directions.

### 2.2 GROUP destinations *(S)*

* Python: type exists (`GROUP = 0x01`, `GroupIdentity`), but crypto for group
  in the Python reference is effectively a reserved placeholder (group key =
  shared hash-based key; no full group encryption scheme shipped).
* Rust: keep `DestinationType::Group` parseable (already is), implement
  name-hash addressing identical to PLAIN, and document parity == "same as
  Python today". No invented crypto.
* Acceptance: packets with group destination type from Python are not dropped;
  addressing matches Python naming rules.

### 2.3 Proof strategies *(S)*

* Python: `Destination.PROVE_NONE/PROVE_APP/PROVE_ALL`,
  `set_proof_strategy`, default `PROVE_ALL`; link requests require proofs.
* Rust: `destination.rs:308 handle_packet` currently proves unconditionally
  (TODO marker). Add `ProofStrategy` to `SingleInputDestination`
  (`set_proof_strategy`), gate packet proof generation (`PROVE_APP` = only when
  app data present), keep link-request proofs unconditional.
* Tests: unit matrix; interop: Python `Link.py` example still establishes.
* Acceptance: strategies behave as documented in Python docstrings.

### 2.4 SINGLE-destination packet encryption (announce crypto) *(M)*

* Python: `Identity.encrypt(plaintext, ratchet)` / `Identity.decrypt(...)`
  using the derived Fernet token; used by `Destination` IN/OUT packet paths
  (`Destination.encrypt/decrypt`).
* Rust: finish the `encrypt/decrypt` methods on destinations, wiring
  ratchets (Phase 1.3) on the receiver side and ratchet-id lookup on the
  sender side. The `Packet` layer stays untouched — this is payload-level
  crypto inside `PacketContext::None` data to SINGLE destinations.
* Tests: unit; interop with Python `Examples/Echo.py` (single destination,
  encrypted).
* Acceptance: bidirectional single-destination encrypted exchange with Python.

### 2.5 Announce handler API parity *(S)*

* Python: `Transport.register_announce_handler(AnnounceHandler(aspects))`,
  deregister, aspect filtering.
* Rust: today `recv_announces()` broadcasts everything to one channel. Add
  `Transport::subscribe_announces(aspects: &[&str])` returning a filtered
  receiver (keep the unfiltered one).
* Acceptance: aspect filters behave like Python's `aspect_filter`.

### 2.6 Link callbacks / ingress & identification parity *(M)*

* Python: `Link.set_link_established_callback`, `set_packet_callback`,
  `resource callbacks`, `set_remote_identified_handler`,
  `set_resource_concluded`, etc.; `Destination.set_link_established_callback`,
  `accepts_links`.
* Rust: `LinkEvent` enum + broadcast channels exist; add:
  * `LinkEvent::RemoteIdentified { identity }` (identify already implemented —
    emit event);
  * per-link packet callbacks via `events_for_link` (exists) — document and
    test;
  * `SingleInputDestination::accepts_links(bool)` gating link requests in
    `handle_link_request` (Python: `accepts_links`).
* Acceptance: API parity list in docs; tests for each event.

### 2.7 Requests & responses over links *(L)*

* Python: `Link.request(path, data, response_callback, failed_callback,
  progress_callback, timeout, max_response_size)`; wire format (Link.py:486):
  ```python
  request_path_hash = truncated_hash(path.encode("utf-8"))
  packed_request    = umsgpack.packb([time.time(), request_path_hash, data])
  request_id        = truncated_hash(packed_request)
  ```
  If `len(packed_request) <= link.mdu` → plain packet, else a **Resource**
  transfer carrying the packed request (depends on Phase 3). Responses are
  `[request_id, response_data]` msgpack, also resource-backed when large.
  Server side: `Destination.register_request_parser`/`set_request_policy`
  (`ALLOW_NONE/ALL/LIST`) and `Link.register_request_handler(path, handler)`.
* Rust (staged so it's usable before Phase 3 completes):
  1. Small-packet requests (fits MDU) — full implementation now:
     * `Link::request(path, data) -> RequestReceipt` with broadcast events
       (`RequestEvent::{Response, Failed, Progress}`);
     * `Link::register_request_handler(path, handler)` on the inbound side;
     * msgpack via `rmp` in the shared serde helper; timestamps as f64
       seconds to match `time.time()`;
     * timeout default = `rtt * traffic_timeout_factor +
       Resource::RESPONSE_MAX_GRACE_TIME * 1.125` (constant pulled from
       Phase 3 module even before transfer lands).
  2. Resource-backed requests — enabled in Phase 3.7.
* Tests: unit; interop with Python `Examples/Request.py` (both roles).
* Acceptance: Rust client ↔ Python server and Python client ↔ Rust server
  request/response round-trips, including >MDU payloads once Phase 3 lands.

### 2.8 Link MTU discovery *(M)*

* Python: `Reticulum.link_mtu_discovery()`, MTU negotiation in link proofs
  (`Link.MTU`/`mtu`), `optimise_mtu` on interfaces.
* Rust: the proof already carries a 3-byte MTU field
  (`link.rs:LINK_MTU_SIZE`, `MTU_PROOF_LEN`) — finish negotiation: initiator
  proposes min(its iface MTU), responder echoes final MTU, both sides clamp
  packet sizing; config gate in Phase 7.2.
* Tests: unit negotiation matrix; interop with Python with discovery on/off.
* Acceptance: MTU discovered links carry larger packets when the path allows.

---

## 6. Phase 3 — Resource transfer

Python ref: `RNS/Resource.py` (1367 lines) + `Link.py` resource hooks. This is
the single largest missing feature and the keystone for `rncp`/`rnsh`/requests
(2.7.2).

### 3.1 Module scaffold & advertisement format *(M)*

* New crate module `reticulum/src/resource/mod.rs` (+ `advertisement.rs`,
  `outbound.rs`, `inbound.rs`, `watchdog.rs`).
* Port all constants verbatim from `Resource.py:48–110` (WINDOW=4, WINDOW_MIN=2,
  WINDOW_MAX_SLOW=10, WINDOW_MAX_VERY_SLOW=4, WINDOW_MAX_FAST=75, WINDOW_MAX=75,
  FAST_RATE_THRESHOLD, RATE_FAST=(50_000/8) B/s, RATE_VERY_SLOW=(2_000/8) B/s,
  WINDOW_FLEXIBILITY=4, MAPHASH_LEN=4, SDU=Packet.MDU, RANDOM_HASH_SIZE=4,
  MAX_EFFICIENT_SIZE=1 MiB−1, METADATA_MAX_SIZE=16 MiB−1,
  AUTO_COMPRESS_MAX_SIZE=64 MiB, PART_TIMEOUT_FACTOR=4,
  PART_TIMEOUT_FACTOR_AFTER_RTT=2, PROOF_TIMEOUT_FACTOR=3, HMU_WAIT_FACTOR=3.5,
  MAX_RETRIES=16, MAX_ADV_RETRIES=4, SENDER_GRACE_TIME=10.0,
  PROCESSING_GRACE=1.0, RETRY_GRACE_TIME=0.25, PER_RETRY_DELAY=0.5,
  HASHMAP_IS_NOT_EXHAUSTED=0x00 / 0xFF) and status enum
  (`NONE/QUEUED/ADVERTISED/TRANSFERRING/AWAITING_PROOF/ASSEMBLING/COMPLETE/
  FAILED/CORRUPT/REJECTED`).
* Advertisement wire format (msgpack dict, keys exactly as Python
  `ResourceAdvertisement.pack`): `t` transfer size, `d` data size, `n` parts,
  `h` resource hash, `r` random hash, `o` original/first-segment hash, `m`
  hashmap slice, `c` compressed, `e` encrypted, `s` split, `x` has-metadata,
  `i` segment index, `l` total segments, `q` request id, `u` is-request,
  `p` is-response, `f` flags byte — plus the `OVERHEAD = 134` /
  `HASHMAP_MAX_LEN = floor((Link.MDU − OVERHEAD)/MAPHASH_LEN)` /
  `COLLISION_GUARD_SIZE = 2*WINDOW_MAX + HASHMAP_MAX_LEN` computation.
* Acceptance: `ResourceAdvertisement::pack/unpack` round-trips and parses a
  capture produced by Python.

### 3.2 Outbound (sender) side *(L)*

* Python refs: `Resource.__init__` (splitting into `SDU`-sized parts, optional
  BZ2 compression when `auto_compress` and size ≤ AUTO_COMPRESS_MAX_SIZE,
  segmenting beyond MAX_EFFICIENT_SIZE), `advertise`,
  `__prepare_next_segment`, `request` (respond to part requests),
  `validate_proof`, `watchdog_job`, `update_eifr`.
* Rust design:
  * `Resource::new(data: DataSource, link: Arc<Mutex<Link>>, opts)` where
    `DataSource` = `Bytes | &File` (async streaming for files, mirroring
    Python's file-handle support);
  * splitting/hashing is CPU-bound → `tokio::task::spawn_blocking`
    (or chunked async loop) producing the part-hashmap
    (`full_hash(part + random_hash)[:4]` per `get_map_hash`);
  * state machine driven by link payload events: on
    `ResourceRequest` → serve requested parts from a windowed queue; on
    `ResourceProof` → `validate_proof`, advance segments, emit status events;
  * `watchdog` task (1 s tick like Python `WATCHDOG_MAX_SLEEP`) implementing
    retry/timeouts using the constants above.
* Tests: unit with loopback link harness (existing tests/channels.rs
  pattern); interop: Python `Examples/Filetransfer.py`/`Resource.py` as
  receiver.

### 3.3 Inbound (receiver) side *(L)*

* Python refs: `Resource.accept(advertisement_packet, callback,
  progress_callback, request_id)`, `receive_part`, `request_next`,
  `hashmap_update`, `assemble`, `prove`, `cancel`, `reject`.
* Rust design:
  * `Resource::accept(packet) -> ResourceHandle` after advertisement
    validation (size checks, max parts, request id match when solicited);
  * part-request engine with window growth/shrink per `update_eifr`
    (expected-in-flight-rate) algorithm — port the rate math exactly;
  * collision-guard window (`COLLISION_GUARD_SIZE`) around the requested
    map region; hashmap updates (`ResourceHashUpdate` context) when the map
    has holes;
  * assembly + full-hash verification, `ResourceProof` context packet with
    signature data as Python `prove`;
  * streaming to `Storage`/`Bytes` sink; progress events on a new
    `broadcast::Sender<ResourceEvent>`.
* Tests: interop with Python sender at small (1 part), medium (multi-window),
  large (multi-segment >1 MiB) sizes; simulated loss (drop N% in a test iface)
  exercises retries.
* Acceptance: `rncp`-scale transfers Rust↔Python in both directions.

### 3.4 Compression *(S)*

* Python: BZ2 when beneficial (`auto_compress`), flag `c` in advertisement.
* Rust: `bzip2` crate behind default feature `bz2` (or `compress-bzip2`);
  decompress always available. Choose based on measured benefit like Python
  (`bz2` then compare sizes).
* Tests: round-trip; interop both directions with compressed flag.

### 3.5 Encryption & metadata *(M)*

* Python: resource `encrypted` flag (link-level encryption already covers
  payloads; flag preserved for parity), optional `metadata` (`x` flag,
  `METADATA_MAX_SIZE`) transferred as a small pre-resource.
* Rust: carry both flags; implement metadata transfer; document encrypted
  flag semantics identical to Python.

### 3.6 Watchdog/timers parity *(M)*

Port the full retry/time-out decision table (`watchdog_job`: adv retries,
part timeouts scaled by measured RTT (`PART_TIMEOUT_FACTOR_AFTER_RTT`),
HMU waits, grace times). All timers in `TimerConfig` overridables.

### 3.7 Integration points *(M)*

* `Link` additions (Python `Link.py`): `register_outgoing_resource`,
  `register_incoming_resource`, `ready_for_new_resource`,
  `resource_concluded`, `cancel_outgoing_resource`; `Transport::handle_data`
  routes `PacketContext::Resource*` packets into the resource engine per link.
* Enable resource-backed `Link::request`/responses from 2.7.2 (responses > MDU
  become resources; `is_response` advertisement flag).
* Acceptance: `Examples/Request.py` with large response passes interop.

---

## 7. Phase 4 — Buffer streams

Python ref: `RNS/Buffer.py` (371 lines): `Buffer.create_reader/
create_writer` on links & channels implementing stream I/O on top of
reliable channel envelopes.

* Rust: `reticulum/src/buffer_stream.rs` — async `tokio::io::AsyncRead` /
  `AsyncWrite` adapters over a `Channel<StreamFrame>`:
  ```rust
  pub struct BufferReader { /* wrapped channel rx */ }
  pub struct BufferWriter { /* channel tx, chunking at CHANNEL_MDU */ }
  impl AsyncRead for BufferReader { … } impl AsyncWrite for BufferWriter { … }
  ```
  Message type: system-range (0xff00–0xffff) channel message carrying
  `(seq, chunk)` frames, matching Python's `SystemMessage`-adjacent scheme —
  replicate the exact envelope Python uses for buffer traffic before
  finalizing the wire type.
* Tests: unit pipe throughput; interop with Python `Examples/Buffer.py`.
* Acceptance: Rust reader consumes a Python writer's stream and vice versa.

---

## 8. Phase 5 — Interface expansion

Order within the phase matters for adoption: Auto and Local first (they make
interop testing dramatically easier), then serial-family, then RNode/I2P.

### 5.1 IFAC — Interface Access Codes *(M)*

* Python refs: `Interfaces/Interface.py` + `Reticulum._add_interface`
  (`ifac_size`, `ifac_netname`, `ifac_netkey`), IFAC packet fields
  (`Packet.IFAC` in `Packet.py`), `Transport.outbound/inbound` IFAC
  encode/decode & `PACKET_IFAC_MIN_SIZE`.
* Rust: 
  * `reticulum-core/src/packet.rs` already parses `IfacFlag`; complete the
    IFAC field (HMAC-based access code over the packet, netname+netkey →
    HKDF-derived key);
  * `InterfaceState.ifac_size` (Phase 0.3) drives encode;
  * `TransportHandler::send` inserts IFAC for authenticated interfaces,
    inbound path validates and drops mismatches.
* Config (daemon): parse `ifac_size`, `ifac_netname`, `ifac_netkey` per
  interface.
* Tests: unit (known-answer vectors generated from Python); interop: a
  Python↔Rust TCP link with IFAC enabled.
* Acceptance: IFAC-protected interfaces exchange traffic; without the key,
  packets are dropped on both sides.

### 5.2 AutoInterface *(L)*

* Python refs: `Interfaces/AutoInterface.py` (~600 lines): UDP multicast
  beacons on `ff{temporary|permanent}{scope}::{group_id}` derived from
  `group_id` (default `"reticulum"`), discovery port default **29716**
  (`DEFAULT_DISCOVERY_PORT`, unicast discovery = port+1), peer probing,
  multicast echo tracking, IPv6 requirements.
* Rust: `src/iface/auto.rs` behind default feature `iface-auto`:
  * `socket2` for IPv6 multicast join on all suitable interfaces;
  * beacon announce/parse matching Python's packed beacon data (replicate
    byte layout from `AutoInterface.py` job loop);
  * spawn per-peer `TcpClient`-style transports? — no: peers exchange raw
    datagrams after discovery (Python uses UDP unicast data channel);
  * hooks into Discovery (Phase 6.7) for interface discovery mode if enabled.
* Tests: loopback two-node test with two distinct IPv6 link-local scopes on
  loopback (CI-friendly per Python's own test approach), manual real-hw test
  script.
* Acceptance: two Rust nodes auto-peer; a Rust node auto-peers with a Python
  node on the same LAN.

### 5.3 LocalInterface + shared instance server *(L)*

* Python refs: `Interfaces/LocalInterface.py` (+ `BackboneInterface.py` base):
  TCP server on `127.0.0.1:{shared_instance_port}` (default **37428**;
  daemon config already parses this), clients = local client interfaces using
  the same HDLC framing (`hdlc.rs` already exists), abstract-unix-socket mode
  (`\0rns/…`) when available, interface announce cap/aggregation, client-side
  shared-instance connection for the **library API** (`Reticulum.get_shared_instance`
  model).
* Rust:
  * `src/iface/local.rs`: `LocalServer` (accept loop, per-client HDLC reader,
    route to `InterfaceManager`) + `LocalClient` (connects to a shared
    instance like Python's `LocalClientInterface`, with ` AF_UNIX` variant
    under unix cfg);
  * `reticulum::Reticulum` facade (Phase 7) exposes
    `connect_shared_instance(addr)` for apps — this is how Python utilities
    talk to `rnsd`.
  * ingress/egress limits from `Interface.py` (`should_ingress_limit` etc.)
    ported in Phase 6.2.
* Tests: Rust daemon + Rust client util (Phase 8 `rnstatus`) over local
  interface; interop: Python `rnstatus` against Rust daemon (requires Phase
  7.3 RPC/destination parity for stats, else degrade gracefully).
* Acceptance: local client traffic flows through the daemon; Python client
  can attach to the Rust daemon and exchange packets.

### 5.4 Serial + KISS + AX.25 KISS *(M)*

* Python refs: `SerialInterface.py`, `KISSInterface.py` (preamble/tail/
  persistence/slottime CSMA params), `AX25KISSInterface.py`.
* Rust: `src/iface/serial.rs`, `src/iface/kiss.rs` behind feature
  `iface-serial` (dep `tokio-serial`): KISS framing (FEND/FESC/TFEND/TFESC —
  straightforward after HDLC experience), CSMA timing from config, AX.25
  callsign/SSID encoding (Python `_pack_ax25`-style helpers).
* Tests: unit framing; loopback via `socat` pty pair in CI (works on Linux);
  manual hardware test script.
* Acceptance: `rnstatus` shows serial/KISS ifaces; packets flow over a pty
  bridge between two Rust nodes.

### 5.5 RNodeInterface (+ RNodeMulti) *(L)*

* Python refs: `RNodeInterface.py` (~1600 lines): serial LoRa radio with its
  command protocol (probe, set frequency/bandwidth/txpower/SF/CR, CRC, flow
  control), RSSI/SNR stats, `RNodeMultiInterface.py` sub-interface multiplexing.
* Rust: `src/iface/rnode.rs` feature `iface-rnode`: port the command state
  machine (constants block verbatim), expose `InterfaceStats { rssi, snr, q }`
  (Phase 0.3), support `flow_control`. Multi-interface (multiple virtual
  sub-interfaces over one radio) second.
* Tests: unit command framing against recorded byte streams from Python
  sessions; manual hardware checklist.
* Acceptance: Rust node on an RNode exchanges packets with a Python RNode
  node at matching radio params.

### 5.6 I2PInterface *(L)*

* Python refs: `I2PInterface.py`: spawns/uses i2prouter (Java I2P or i2pd),
  SAMv3 session (`7656`), connectable inbound sessions, b32 addresses, peers
  list.
* Rust: `src/iface/i2p.rs` feature `iface-i2p`: SAMv3 protocol over TCP
  (handshake, session create, streams; mirrors of Python's helper commands),
  no bundled router (require external i2pd), config `connectable`, `peers`.
* Tests: unit SAM message framing; integration behind an env-gated test with
  a running i2pd in CI container (optional job).
* Acceptance: Rust↔Python over I2P transport.

### 5.7 PipeInterface / subprocess *(S)*

* Python ref: `PipeInterface.py` (spawn command, exchange framed packets on
  stdin/stdout), `util/*.py`.
* Rust: `src/iface/pipe.rs` using `tokio::process`. Tests with `cat`-style
  echo script. Acceptance: two nodes via a pipe program.

### 5.8 BackboneInterface & WeaveInterface *(M, lower priority)*

* Python refs: `BackboneInterface.py` (multiplexed internal backbone used by
  Local + Weave), `WeaveInterface.py` (LAN mesh weave protocol). Implement
  after 5.3 shares its code.

### 5.9 Interface statistics collection *(S, prerequisite 0.3)*

Port counters: `rssi/snr/q` (radio ifaces), `sent/received` counters,
airtime estimates, `bitrate`, `announce frequency` trackers used by egress
control (6.2) and reported by `rnstatus` (8.1).

---

## 9. Phase 6 — Transport parity

Python ref: `RNS/Transport.py` (3706 lines). Existing Rust covers the happy
path; this phase closes the behavioral gaps that matter on real networks.

### 6.1 Path table upgrades *(M)*

* Python refs: path table entries `[timestamp, received_via, hops, expires,
  random_blobs, receiving_interface, packet_hash]`, `PATHFINDER_E` (1 week
  expiry), `DESTINATION_TIMEOUT` (unused 1 week), `mark_path_unresponsive/
  responsive/unknown`, `expire_path`, `path_is_unresponsive`, blocking via
  `retract_path`/`drop_path`, `Transport.timebase_from_random_blobs`.
* Rust: extend `src/transport/path_table.rs` (currently `{received_from,
  hops, iface}` only) with `timestamp`, `expires`, `random_blobs` (from
  announces), `packet_hash`; add expiry sweep to the existing cleanup task
  (`packet_cache_cleanup` loop); public APIs mirroring Python:
  `Transport::{expire_path, mark_path_unresponsive, drop_path, hops_to,
  next_hop, next_hop_interface}` (several already partially exist on
  `path_table`).
* Announce random blobs: capture from validated announces (blob layout per
  `Identity.validate_announce`) — pairs with Phase 1.3.
* Tests: unit expiry/upgrade-policy; interop: announce → wait → expire →
  re-announce round trip with Python.
* Acceptance: stale paths are dropped after `PATHFINDER_E`; unresponsive
  marking prevents black-holing link attempts (Python semantics).

### 6.2 Announce queueing & egress control *(L)*

* Python refs: `Interface.hold_announce/process_held_announces` with
  ingress caps (`ic_max_held_announces`, `ic_burst_hold`, `ic_burst_freq*`,
  `ic_pr_burst_freq*`, `ic_new_time`, `ic_burst_penalty`,
  `ic_held_release_interval`), egress control (`egress_control` config,
  `ec_pr_freq`), `announce_cap` airtime limiting (retransmit deferral when
  `tx_time/announce_cap` exceeds budget — Transport.py:1277+),
  `PATHFINDER_R/G/RW` retransmit timing with random window.
* Rust: replace/augment `src/transport/announce_table.rs` +
  `announce_limits.rs` with a full `announce_queue` module implementing:
  * per-interface held-announce queues with burst/rate parameters (defaults
    from Python `Reticulum._default_*` methods);
  * airtime-based deferral using interface `bitrate` (Phase 0.3);
  * retransmit randomization (`PATHFINDER_RW = 0.5 s`).
* Config surface: daemon `[[reticulum]]` options + per-interface overrides
  (Phase 7.2).
* Tests: unit timing sims (tokio `start_paused`); interop: announce storm
  from Python side, assert Rust retransmits within cap.
* Acceptance: behavior matches Python under a scripted announce flood
  (compare retransmit counts within tolerance).

### 6.3 Path request parity *(M)*

* Python refs: `Transport.path_request` (tags, `PATH_REQUEST_TIMEOUT`,
  gate timeouts `PATH_REQUEST_GATE_TIMEOUT=120 s`, grace `PATH_REQUEST_GRACE`
  0.4 s / roaming `PATH_REQUEST_RG` 1.5 s, min interval
  `PATH_REQUEST_MI=20 s`, `request_path`/`await_path`,
  `Transport.path_requests` accounting, circular-request suppression with
  requestor transport ids — the Rust `path_requests.rs` already implements
  `generate/decode/generate_recursive` and discovery dedupe; finish the
  timing gates and `await_path` async API (`Transport::await_path(hash,
  timeout)`).
* Tests: unit gates; interop multihop path request via Python middle node
  (extend `tests/hop_test.rs`).
* Acceptance: `await_path` resolves with Python transport nodes in the
  middle; no request storms under repeated unknown-destination sends.

### 6.4 Tunnel support *(M)*

* Python refs: `Transport.synthesize_tunnel`, `tunnel_synthesize_handler`
  (PLAIN destination `rnstransport/tunnel/synthesize`, registered at
  Transport.py:264 — `Transport.APP_NAME = "rnstransport"`, aspects
  `"tunnel", "synthesize"`), `handle_tunnel`, `void_tunnel_interface`, tunnel
  path restore logic (Transport.py:2366–2478), `TUNNEL_TIMEOUT`.
* Rust: new `src/transport/tunnels.rs`:
  * fixed PLAIN destination handler for synthesize packets (reuses Phase
    2.1) — validation: `len == KEYSIZE/8 + HASHLENGTH/8 + TRUNCATED_HASHLENGTH/8
    + SIGLENGTH/8`, signature over `pub_key||iface_hash||random_hash`;
  * tunnel table `[tunnel_id, iface, paths, expires]`, restore-on-reappear
    algorithm ported verbatim (hops/timebase checks);
  * hook: interfaces with `wants_tunnel` (Phase 5.5 RNodeMulti uses this).
* Tests: unit with synthetic tunnel packets; interop scripted from Python.
* Acceptance: paths survive tunnel re-establishment like Python.

### 6.5 Blackholes *(M)*

* Python refs: `Reticulum.blackhole_identity/unblackhole/
  get_blackholed_identities/is_blackholed`, `publish_blackhole_enabled`,
  `blackhole_sources`, `blackhole_update_interval`, `Discovery.BlackholeUpdater`,
  announce/app-data propagation of blackhole lists in Transport inbound
  filtering.
* Rust: `src/transport/blackholes.rs` (identity set + TTLs + config), filter
  in `handle_announce`/`handle_data`, updater task interval, publish opt-in.
* Tests: unit; interop with Python publishing a blackhole.
* Acceptance: blackholed identities' announces/paths are ignored.

### 6.6 Network Discovery *(L)*

* Python refs: `RNS/Discovery.py` (864 lines): `InterfaceAnnouncer`
  (announce own interfaces over fixed destination with stamp values),
  `InterfaceAnnounceHandler`, `InterfaceDiscovery` (discover + autoconnect
  to advertised interfaces when `enable_discovery`/`discovery_*` config set),
  `BlackholeUpdater`, graph pathfinding analytics.
* Rust: `src/discovery.rs` behind feature `discovery`: announcer task,
  handler registration on the fixed discovery destination, discovered
  interface table, `autoconnect` policy engine (mode/transport gates from
  config), blackhole updater wiring (6.5).
* Config: daemon `[discovery]` section parity (Phase 7.2).
* Tests: unit policy; interop with Python discovery-enabled node.
* Acceptance: Rust discovers and (optionally) autoconnects to Python-advertised
  interfaces; announces its own per config.

### 6.7 Remote management & probe destination *(M)*

* Python refs: `Reticulum.remote_management_enabled`, `probe_destination_enabled`,
  `Transport.remote_status_handler`, `remote_path_handler`, fixed probe
  destination request handlers (status/path/… paths per source).
* Rust: fixed inbound destination when enabled in config; request handlers
  registered via Phase 2.7 machinery exposing: instance status, path table,
  drop-path commands — mirroring Python's handler paths exactly.
* Tests: interop: Python `rnprobe`/`rnstatus --remote` against Rust daemon.
* Acceptance: remote queries answered compatibly.

### 6.8 Packet cache requests *(S)*

* Python refs: `Transport.should_cache`, `cache_request`,
  `cache_request_packet`, `get_cached_packet`, `has_cached_packet` —
  retrieval of previously seen packets by hash (used for proofs/announces).
* Rust: extend `src/transport/packet_cache.rs` (64 lines today: dedupe only)
  with type-aware caching + `PacketContext::CacheRequest` handling in
  `handle_data`.
* Acceptance: cache request returns the packet Python would return.

---

## 10. Phase 7 — Reticulum instance & daemon parity

Python refs: `RNS/Reticulum.py` (1997 lines), `Utilities/rnsd.py`.

### 7.1 `reticulum::Reticulum` facade *(M)*

A high-level instance object owning config, storage, identity, transport,
local-interface server, and RPC — matching what Python apps get from
`RNS.Reticulum(configdir)`:
```rust
let reticulum = Reticulum::new(ReticulumConfig::load(configdir)?)?;
let destination = reticulum.register_destination(name, identity).await?;
reticulum.shared_instance_addr();      // for local clients
reticulum.rpc_client();                 // Phase 7.3
```
This is the seam used by Phase 8 utilities.

### 7.2 Config parity *(M)*

* Python refs: `Reticulum.__apply_config` (~180 options): `enable_transport`,
  `share_instance`, `shared_instance_port`, `instance_control_port`,
  `instance_name`, `panic_on_interface_error`, `storagepath`,
  `require_if_time_sync`…, logging section, per-interface options incl.
  `mode`, `ifac_*`, `configured_bitrate`, `autoconnect_interface_mode`,
  discovery section, `link_mtu_discovery`, `remote_management`,
  `probe_destination`, announce/egress-control knobs (`ic_*`, `ec_*`, `ar_*`).
* Rust: extend `reticulum-daemon/src/config.rs` (already has TOML schema +
  converter for a subset) to parse every option; unknown options → warn (as
  Python does) not fail. The converter (`convert-config`) must learn new keys
  so Python configs migrate losslessly.
* Acceptance: golden Python config from `docs/manual` converts and runs.

### 7.3 Shared-instance RPC & control *(L)*

* Python refs: `Reticulum.rpc_loop` / `get_rpc_client`
  (`multiprocessing.connection` on `instance_control_port`, default 37429):
  commands used by utilities — `get_interface_stats`, `get_path_table`,
  `get_rate_table`, `drop_path`, `drop_all_via`, `drop_announce_queues`,
  `get_next_hop_if_name`, `get_first_hop_timeout`, `get_link_count`,
  `get_packet_rssi/snr/q`, `halt/resume/reload_interface`,
  `blackhole_*`, `_retain_*` …
* Rust: `reticulum/src/rpc.rs`: length-prefixed msgpack server on
  `127.0.0.1:instance_control_port` implementing the same command set with
  Python-compatible wire payloads (Python uses pickle via
  `multiprocessing.connection` — replicate its framing/protocol or provide a
  msgpack bridge; **decide via spike**, see Open Questions). Provide
  `RpcClient` for the Rust utilities.
* Acceptance: Python `rnstatus` (which uses these APIs) renders a Rust
  daemon's stats (stretch: full protocol compatibility), Rust utilities work
  against both daemons.

### 7.4 Daemon hardening & lifecycle *(M)*

* Persist identity (Phase 1.1) under `storagepath` (config dir), load on
  start; announce registered destinations on startup; SIGTERM/SIGINT clean
  shutdown (exists), plus `panic_on_interface_error` behavior, interface
  respawn policy, `enable_transport` semantics (already), storage cleanup
  tasks (`__clean_caches`), `instance_name`.
* Acceptance: restart identity stability; `rnid`-style address stays.

### 7.5 Docs truth pass *(S)*

Fix README: remove non-existent `proto/kaonic`, `kaonic_client.rs`
references; document feature flags matrix, config migration, supported
interfaces. (Discrepancy found during the audit.)

---

## 11. Phase 8 — Utilities (`rn*` tools)

All live in a new `reticulum-utils` (or `rn` multi-call binary) crate so they
share one clap shell, mirroring Python's `Utilities/`. Most depend on Phases
7.1/7.3 (attach to shared instance) — several also work standalone.

| Tool | Python ref | Depends on | Estimate | Notes |
|---|---|---|---|---|
| `rnstatus` | `Utilities/rnstatus.py` | 7.1/7.3 (+5.9) | M | iface stats, path table, link counts; remote mode |
| `rnpath` | `Utilities/rnpath.py` | 6.1/6.3 | S | `hops_to`, `next_hop`, request path, wait |
| `rnprobe` | `Utilities/rnprobe.py` | 6.7 (probe dest) | S | RTT probes via probe destination |
| `rnid` | `Utilities/rnid.py` | 1.1 | S | generate/inspect identities |
| `rnir` | `Utilities/rnir.py` | 1.1/1.2 | S | identity request over network |
| `rnsh` | `Utilities/rnsh/` | 3, 2.7 | L | remote shell: links + requests + resources |
| `rncp` | `Utilities/rncp.py` | 3 (resources), 1.2 | L | file transfer tool; the flagship validation of Phase 3 |
| `rnx` | `Utilities/rnx.py` | 2.7, 3 | L | remote command execution |
| `rnodeconf` | `Utilities/rnodeconf.py` | 5.5 | XL | RNode firmware config tool; huge, schedule last / optional |
| `rnpkg` | `Utilities/rnpkg.py` | 3 | L | package manager over Reticulum; optional |

Order: `rnid` → `rnpath` → `rnstatus` → `rnprobe` → `rnsh`/`rncp` → rest.

---

## 12. Phase 9 — Testing, CI & documentation

### 9.1 Interop test matrix *(M, continuous)*

Extend `tests/` with a matrix runner; each row = feature × direction
(Rust→Py, Py→Rust) × role (client/server). Minimum set:

| Test | Python fixture | Covers |
|---|---|---|
| announce/link/identify (exist) | `Examples/{Announce,Link,Identify}.py` | baseline |
| broadcast | `Examples/Broadcast.py` | 2.1 |
| echo | `Examples/Echo.py` | 2.4 |
| request small/large | `Examples/Request.py` | 2.7, 3.7 |
| channel | `Examples/Channel.py` | regression |
| buffer | `Examples/Buffer.py` | Phase 4 |
| filetransfer | `Examples/Filetransfer.py`, `Speedtest.py` | 3 |
| ratchets | `Examples/Ratchets.py` | 1.3 |
| ifac | generated configs | 5.1 |
| multihop + path expiry | scripted `rnsd` chain | 6.1/6.3 |
| shared instance | Python client ↔ Rust daemon | 5.3, 7.3 |

### 9.2 Fuzz & property tests *(M)*

`cargo-fuzz` targets for `Packet::from_bytes` (well-formedness, no panics),
resource advertisement, channel envelopes, path-request payloads. The Python
side can generate corpora (write received bytes to disk via a small tap).

### 9.3 Benchmarks *(S)*

Criterion benches: packet encode/decode, crypto ops, resource part-hash
throughput, channel throughput. Track regressions for the embedded story.

### 9.4 CI *(S)*

Extend `.github/workflows`: build matrix with new feature flags
(`iface-serial`, `iface-rnode`, `iface-i2p`, `discovery`, `bz2`), `no_std`
core check (exists), clippy, fmt, interop job (exists — extend), fuzz smoke
job, doc-tests.

---

## 13. Phase 10 — Beyond RNS parity: LXMF & LXST

> **Scope note.** LXMF and LXST are **not** part of the Python `Reticulum`
> repository — they are separate packages (`markqvist/lxmf`, `markqvist/LXST`)
> layered on top of RNS, so they are outside the strict parity scope of
> Phases 0–9. This phase covers them as a deliberate extension: they are the
> de-facto application layer of the ecosystem (messaging, voice) and the
> primary consumers of the primitives built in Phases 1–3. The in-workspace
> reference for LXMF behavior is the `columba/` Kotlin port
> (`rns-api/.../RnsLxmf.kt`, `LxmfFields.kt`; external repos `reticulum-kt` /
> `LXMF-kt` mirror the Python sources). **The Python sources are not checked
> out in this workspace — clone both repos before starting and re-verify all
> wire-format claims below against them.**

### 10.A LXMF — messaging layer (`lxmf` package → `lxmf-rs` crate) *(XL)*

What LXMF consists of (per `Reticulum/docs/markdown/software.md` §LXMF and
the columba surface):

* **LXMessage** — msgpack-packed, Ed25519-signed message envelope: source &
  destination identity hashes, timestamp, title, content, optional `fields`
  map (reactions `FIELD_REACTION 0x40`, stamps, attachments, ratchet keys —
  see `columba/.../LxmfFields.kt` for the field ids).
* **LXMRouter** — inbound destination `lxmf/delivery`, announce handling,
  outbound delivery state machine with three delivery methods.
* **Delivery methods**:
  1. **Direct** — establish `Link` to recipient, deliver (small = link data
     packets; large = **RNS Resource** over the link), await delivery proof,
     retry with backoff. → needs 2.6, Phase 3.
  2. **Opportunistic** — single encrypted packet to the destination identity
     (no link), using announce ratchets for forward secrecy. → needs 1.3, 2.4.
  3. **Propagated** — store-and-forward via **LXMF propagation nodes**
     (destination `lxmf/propagation`): message store with age limits,
     dedup by time-token, sync protocol over a link (request/response of
     message batches), `want`-lists, auto-sync tasks. → needs 2.7, 3, 0.2.
* **Ratchets** — per-destination key ratchets carried in message fields for
  forward secrecy (LXMF-level, distinct from RNS announce ratchets).
* **Paper messages** — offline-encoded messages (QR/text URI form; pure
  encoding, no networking).

Work items:

| # | Item | Size | Depends on |
|---|---|---|---|
| 10.A.1 | Clone `markqvist/lxmf` + `markqvist/LXST` next to `Reticulum/`; wire into the interop harness (Phase 0.5 pattern); audit this phase against them | S | — |
| 10.A.2 | `LXMessage` envelope: msgpack pack/unpack, signatures, field map — wire-identical to Python | M | 0.5 |
| 10.A.3 | `LXMRouter` core: `lxmf/delivery` destination, announce subscription, inbound dispatch, outbound queue | M | M2 |
| 10.A.4 | Direct delivery + retries + proofs (resource-backed for large payloads/attachments) | M | M3 |
| 10.A.5 | Opportunistic delivery with ratchets | M | 1.3, 2.4 |
| 10.A.6 | Propagation node (server side): message store on the `Storage` trait, age limits, dedup | L | 0.2, 3 |
| 10.A.7 | Propagation client: node announce discovery, sync protocol, auto-sync, `tryPropagationOnFail` (see `RnsLxmf.kt`) | L | 2.7, 10.A.6 |
| 10.A.8 | LXMF ratchets (forward secrecy) | M | 10.A.2 |
| 10.A.9 | Paper-message encoding | S | 10.A.2 |
| 10.A.10 | Interop tests vs Python lxmf in both roles (direct, opportunistic, propagation) | M | all |

Acceptance: a `lxmf-rs` client exchanges messages with a Python LXMF client
(Nomad Network / Sideband-class flows) in all three delivery modes, including
attachments over Resources and propagation-node sync.

### 10.B LXST — real-time streaming / voice (`LXST` package → `lxst-rs` crate) *(L)*

Per `docs/markdown/software.md` §LXST: a "real-time streaming format and
delivery protocol … zero-conf stream routing, end-to-end encryption and
Forward Secrecy", powering voice/telephony (`rnphone`, LXST Phone, and voice
calls in Sideband/columba). Its transport foundation — the **Channel API —
already exists in Reticulum-rs** (`src/channel.rs`, windowing included), so
the RNS-side blocker is smaller than for LXMF; codecs are payload, not
protocol.

Work items:

| # | Item | Size | Depends on |
|---|---|---|---|
| 10.B.1 | Clone & port stream/call wire formats from `markqvist/LXST` (with 10.A.1) | S | — |
| 10.B.2 | Call signaling: setup/accept/reject/teardown over Links (request/response) | M | 2.7 |
| 10.B.3 | Stream transport over `Channel` messages (real-time frames; sequencing via channel sequence numbers) | M | Channel ✅, 2.8 |
| 10.B.4 | Audio codec integration (Codec2 / Opus) behind feature flags — out of RNS scope, payload handling only | M | 10.B.3 |
| 10.B.5 | Jitter buffer + mic/playback abstraction traits (embedded-friendly, the Phase 0.2 pattern) | M | 10.B.4 |
| 10.B.6 | Interop vs Python `rnphone` | M | all |

Acceptance: a Rust node completes a voice call against a Python `rnphone`
peer with stable audio over a simulated (lossy) transport.

### Sequencing

* 10.B can start right after **M2** (links/requests + channels exist) — it is
  the cheapest end-to-end validation of the Channel API against the reference
  ecosystem.
* 10.A is gated on **M3 (Resources)** for attachments and propagation sync;
  10.A.2/10.A.3/10.A.9 can start earlier.
* New crates `lxmf-rs` and `lxst-rs` depend only on the public `reticulum`
  crate — fully outside `reticulum-core`'s `no_std` concerns.

---

## 14. Dependency graph

```text
0.1 time ─┐
0.2 storage ─┬─► 1.1 identity files ─► 7.4 daemon persistence
             ├─► 1.2 known destinations ─► 1.3 ratchets ─┐
             │                                          ├─► 2.4 single pkt crypto
0.3 iface trait/state ─┬─► 5.x all interfaces            │
                       ├─► 5.1 IFAC                     │
                       └─► 6.2 egress control ─► 6.1 path table upgrades ─► 6.3 path requests ─► 6.4 tunnels
2.1 plain destinations ─┬─► 6.4 tunnels (synthesize dest)
                        └─► 6.6 discovery
2.7 requests (small) ──► 3.7 resource-backed requests ──► 8. rnsh/rnx/rnpkg
3. resources ──────────► 8. rncp  ;  4. buffer streams (after channels+links)
3. resources ──────────► 10.A lxmf (attachments, propagation sync)
1.3 ratchets + 2.4 ───► 10.A.5 opportunistic lxmf delivery
2.7 requests + channel(✅) ──► 10.B lxst (call signaling + streams)
5.3 local iface ─► 7.3 shared instance RPC ─► 8. rnstatus/rnprobe/…
6.5 blackholes ─► 6.6 discovery
7.2 config parity ─► nearly everything config-gated
```

Critical path: **0.2 → 1.x → 2.x → 3 (resources) → 8 (rncp)** for the
"big-visible-feature" narrative, with **0.3 → 5.3 → 7.3** as the parallel
"daemon ecosystem" path.

---

## 15. Milestones & suggested ordering

Estimates: S ≤ 1 wk, M 1–3 wk, L 3–6 wk, XL > 6 wk for one experienced Rust
engineer; many items parallelize.

| Milestone | Contents | Outcome |
|---|---|---|
| **M1 — Foundations** | Phase 0 (all) | traits/storage/iface-state/test harness ready |
| **M2 — Persistence & crypto parity** | 1.1, 1.2, 2.1–2.6, 2.4 | plain/broadcast, encrypted SINGLE packets, callbacks, strategies; identities & known dests persist |
| **M3 — Resources & requests** | 3.1–3.7, 2.7 | `rncp`-class transfers Python↔Rust; full request/response |
| **M4 — Daemon ecosystem** | 5.3, 7.1–7.4, 0.3-complete | shared instance, RPC, persisted identity, config parity; `rnstatus`/`rnpath`/`rnid` |
| **M5 — Interfaces** | 5.1, 5.2, 5.4, 5.7 | IFAC, Auto, serial/KISS, pipe |
| **M6 — Transport hardening** | 6.1–6.3, 6.8, 2.8 | real-network routing behavior parity |
| **M7 — Advanced transport** | 6.4–6.7 | tunnels, blackholes, discovery, remote mgmt |
| **M8 — Radio & overlays** | 5.5, 5.6, 5.8 | RNode, I2P, backbone/weave |
| **M9 — Tools & polish** | Phase 8 remainder, 4, 9 | rnsh/rnx, streams, fuzz/benches/docs |
| **M10 — Application layer (extension)** | 10.B early (after M2), 10.A after M3 | `lxst-rs` voice calls and `lxmf-rs` messaging incl. propagation — interop with Python lxmf/rnphone |

Buffer streams (Phase 4) are small and can slot anywhere after M3; schedule
with M9 for team-load leveling.

---

## 16. Risk register

| # | Risk | Impact | Mitigation |
|---|---|---|---|
| R1 | msgpack edge mismatches (`umsgpack` vs `rmp`: int widths, bin vs str, ext types) | interop failures on resources/requests | single serde helper (0.5/1.2); corpus tests from Python captures |
| R2 | Resource state machine complexity (windowing/EIFR math, segmentation) | transfers stall/corrupt | port Python tests verbatim; lossy-iface simulator; golden captures |
| R3 | RPC protocol is Python `multiprocessing.connection` (pickle-based) | Python utils may never fully talk to Rust daemon | spike early (7.3); worst case: Rust implements the subset used by rnstatus/rnpath with pickle framing behind a feature flag |
| R4 | `no_std` core discipline vs new features wanting OS services | breaks embedded users | keep all new core code behind `Storage`/clock traits; CI `no_std` build per PR (exists) |
| R5 | RNode/I2P hardware & external router dependencies in CI | untested merges | unit-test recorded byte streams; hardware tests manual + release checklist |
| R6 | Feature-flag sprawl | confusing builds | document matrix (7.5); a `full` meta-feature |
| R7 | Python upstream drift (1.5.x) | chasing target | pin interop Python version in CI; scheduled refresh job |
| R8 | Announce ratchet + announce crypto interactions with existing Rust announce validation | subtle wire bugs | property tests vs Python `Identity.validate_announce` |
| R9 | LXMF/LXST Python sources not in workspace; Phase 10 details grounded in docs + `columba` Kotlin surface only | rework of 10.x wire formats | clone repos first (10.A.1); treat Phase 10 format notes as provisional; audit line-by-line like Phases 0–9 |

---

## 17. Open questions

1. **RPC wire format (7.3):** emulate `multiprocessing.connection` framing +
   pickle (via `serde-pickle`?) for full Python-utility compat, or define a
   msgpack RPC and ship Rust utilities? Recommendation: spike pickle
   emulation; fallback to msgpack with feature flag.
2. **Resource file streaming API:** expose `tokio::fs`-based `DataSource`
   only, or also a synchronous/embedded variant via `Storage` (0.2)?
   Recommendation: both; embedded one behind `no_std`-compatible trait.
3. **Compression feature default:** bundle `bzip2` (C dependency) in default
   build or feature-gate? Recommendation: feature-gate; decompress always on
   to avoid un-receivable resources.
4. **Group destinations:** Python ships essentially placeholders — confirm we
   mirror exactly and add no novel semantics (parity-only).
5. **Tunnel synthesize destination:** confirmed from source — PLAIN
   destination `rnstransport/tunnel/synthesize`
   (`Transport.APP_NAME = "rnstransport"`, Transport.py:61/264/2380).
   Fixed hash must be computed at runtime like Python does for fixed
   destinations.
6. **Interface stats fidelity:** do we mirror Python's `get_interface_stats`
   dict shape for RPC compat, or a typed API + adapter? Recommendation:
   typed API + `Into<serde_json::Value>` adapter mirroring Python keys.
7. **BLE interface:** Python has `Android/BLEInterface` under Android utils;
   out of scope unless requested — confirm with stakeholders.

---

## Appendix A — Python ↔ Rust file map

| Python | Rust (existing → planned) |
|---|---|
| `Cryptography/*` | `reticulum-core/src/crypt/*` ✅ |
| `Identity.py` | `identity.rs` ✅ + `storage/identity_files.rs`, `identity.rs` ratchets, `storage/known_destinations.rs` |
| `Packet.py` | `packet.rs` ✅ (+ IFAC field completion) |
| `Destination.py` | `destination.rs` (+ plain/group modules, proof strategy, request registry) |
| `Link.py` | `destination/link.rs` (+ request machinery `link/request.rs`) |
| `Channel.py` | `channel.rs` ✅ |
| `Resource.py` | `resource/{mod,advertisement,outbound,inbound,watchdog}.rs` |
| `Buffer.py` | `buffer_stream.rs` |
| `Transport.py` | `transport.rs` + `transport/{path_table,announce_table,announce_queue,tunnels,blackholes,cache}.rs`, `discovery.rs` |
| `Discovery.py` | `discovery.rs` |
| `Reticulum.py` | `reticulum/src/instance.rs`, `rpc.rs`, daemon `config.rs` |
| `Interfaces/*.py` | `src/iface/*` (auto, local, serial, kiss, rnode, i2p, pipe, backbone, weave) |
| `Utilities/*.py` | `reticulum-utils` crate (rnstatus, rnpath, …) |
| *(separate repo)* `lxmf` | `lxmf-rs` crate (Phase 10.A) |
| *(separate repo)* `LXST` | `lxst-rs` crate (Phase 10.B) |

## Appendix B — Wire-format cheat sheet

* **Link request/proof, LR proof, RTT, keepalive (0xFF req / 0xFE resp), link
  close, identify** — already byte-compatible; regression-protect with
  existing tests.
* **Path request payload** — msgpack list `[destination_hash, requestor_transport_id,
  time, tag, discovery?]` (see `path_requests.rs::generate` ↔ Python
  `Transport.path_request`); keep tag/discovery field order identical.
* **Resource advertisement** — msgpack dict keys `t d n h r o m c e s x i l q
  u p f` (Resource.py:1300+); flags byte `f = x<<5 | p<<4 | u<<3 | s<<2 |
  c<<1 | e`.
* **Part requests** — msgpack `[map_hash, want_all(i.e. collision-guard window
  start), mode, flagged hashes…]` per `Resource.request`; **hashmap update** —
  `[segment, hashmap_bytes]`; **proof** — msgpack with signature over
  assembled data hash (see `Resource.prove`).
* **Link request (RPC) payload** — `umsgpack.packb([time.time(),
  truncated_hash(path), data])`; response — `umsgpack.packb([request_id,
  response])`; request ids are `truncated_hash(packed_request)` (16-byte
  truncated SHA-256).
* **Channel envelope** — `[type:u16][sequence:u16][len:u16][payload]` within
  `PacketContext::Channel` (already implemented).
* **IFAC** — HKDF(netname, netkey) → HMAC truncated to `ifac_size` over
  packet prefix; flag bit in header (see `Interface.py`/`Transport.outbound`).
* **AutoInterface beacon** — multicast UDP on derived group; replicate exact
  packed peer-data bytes from `AutoInterface.py` before implementing.
* **Shared instance frames** — HDLC-framed packets over TCP
  `127.0.0.1:37428` (server) / abstract-UNIX `\0rns/…`; control RPC on 37429.

> When implementing each item, **read the corresponding Python function and
> port constants byte-for-byte**; this cheat sheet is a map, not a spec.
>
> **Phase 10 caveat:** no LXMF/LXST wire formats are listed here because the
> Python sources (`markqvist/lxmf`, `markqvist/LXST`) are not in this
> workspace. Step 10.A.1 (clone + audit) must precede any Phase 10 wire-format
> work.

---

## Progress log (updated by implementation work)

| Item | Status |
|---|---|
| 0.4 error/packet polish | ✅ `RnsError::ResourceMsg/Resource/Storage/Request/Iface/Unsupported`, protocol constants corrected (HEADER_MAXSIZE=35 → MDU 464, LINK_MDU 431) |
| 2.8 Link MTU discovery | ✅ `Link::signalling_bytes`, MTU parsed from link requests/proofs, `link.mtu()/mdu()/sdu()` |
| 3.1 Resource advertisement format | ✅ byte-exact vs Python (`tests/fixtures_msgpack.json` golden vectors) |
| 3.2 Outbound resource | ✅ windowed part serving, hashmap updates, retries, progress |
| 3.3 Inbound resource | ✅ accept/reject, EIFR/window management, assembly, proof, cancel |
| 3.4 Compression | ✅ bzip2 behind default `bz2` feature, decompression guards |
| 3.5 Metadata + encrypted flags | ✅ 3-byte size prefix, metadata extraction on assembly |
| 3.6 Watchdog/timers | ✅ transport resource watchdog task with retry table |
| 3.7 Integration | ✅ `Transport::send_resource(_with_options)`, resource events |
| 2.7 Requests & responses | ✅ packet + resource-backed both directions, handler registry, `await_request_response` |
| Python interop (resources/requests) | ✅ `tests/python_resources.rs`: Rust→Py and Py→Rust resource transfer (60–80 KB) and request/response incl. resource-backed responses |
| Python test-suite parity | ✅ `tests/parity.rs`: SHA-256 vectors, fixed identity hashes, known signature, valid/invalid announce, fixed destination hash |
| LXMF crate | ✅ new `lxmf/` crate (byte-exact message format, stamps, peers, router) + resource-backed delivery |
| LXST crate | ✅ new `lxst/` crate (audio codecs, wire protocol, pipelines, calls) |
| 2.3 Proof strategies | ✅ `ProofStrategy::{None,App,All}`, destination setter, link proof gating |
| 2.2 GROUP destinations | ✅ name-hash addressing + transport routing (no invented crypto, parity) |
| 2.5 Announce handlers | ✅ `AnnounceEvent::matches_aspect`, `Transport::subscribe_announces` |
| 2.6 accepts_links | ✅ `Destination::set_accepts_links`, link-request gating |
| 4 Buffer streams | ✅ `src/buffer_stream.rs`: StreamDataMessage wire format (SMT_STREAM_DATA), AsyncRead/AsyncWrite reader/writer, compression heuristic |
| 6.1 Path expiry | ✅ timestamps, PATHFINDER_E expiry sweep, mark/drop path APIs |
| 6.5 Blackholes | ✅ `transport/blackholes.rs` with pack/merge list, announce filtering, clean task |
| 6.2/6.3/6.8 transport control | ✅ `src/iface/control.rs` (modes, ic_* ingress limits, held/queued announces, announce cap, PR ingress/egress gates) wired into transport egress (`InterfaceManager::send`), announce ingress limiting, Python-parity `handle_path_request`, `await_path`, announce packet cache + CACHE_REQUEST |
| python.rs harness fix | ✅ PYTHONPATH + absolute config for the Python example partners |

Remaining phases (identity persistence, ratchets, plain/group destinations,
interfaces, tunnels/blackholes/discovery, daemon/RPC, `rn*` utilities,
buffer streams) are still open; see the phase descriptions above.

---

## Progress log (final consolidated state)

| Item | Status |
|---|---|
| 0.x foundations | ✅ storage trait (`src/storage/`), interface stats, protocol constants |
| 1.1 Identity files | ✅ hex save/load, Python-compatible layout |
| 1.2 Known destinations | ✅ msgpack byte-exact `known_destinations` file, recall APIs, announce hooks |
| 1.3 Announce ratchets | ✅ context_flag bit, ratchet rotation, 30-day store, Python interop |
| 1.4 Retention/cleaning | ✅ dirty-tracked autosave + clean with expiry |
| 2.1 PLAIN destinations | ✅ + Python broadcast interop both directions |
| 2.2 GROUP destinations | ✅ parseable + name-hash addressing (no invented crypto, parity) |
| 2.3 Proof strategies | ✅ PROVE_NONE/APP/ALL for link + SINGLE packets, receipts |
| 2.4 SINGLE-packet crypto | ✅ ratchet-aware encrypt/decrypt, byte-exact vs Python |
| 2.5 Announce handlers | ✅ `subscribe_announces`, `AnnounceEvent::matches_aspect` |
| 2.6 Link callbacks/accepts_links | ✅ `set_accepts_links` gating, RemoteIdentified events |
| 2.7 Requests & responses | ✅ packet + resource-backed, Python interop both directions |
| 2.8 Link MTU discovery | ✅ signalling bytes in LR/proof, `mtu/mdu/sdu` |
| 3.x Resources | ✅ full engine incl. compression/metadata/segmentation; Python interop 60–80 KB both directions |
| 4 Buffer streams | ✅ `src/buffer_stream.rs`, SMT_STREAM_DATA wire format, AsyncRead/Write, Python interop |
| 5.2 AutoInterface | ✅ feature `iface-auto` (Linux-only; hash-token beacons, reverse peering, AutoPeer data) |
| 5.3 LocalInterface + shared instance | ✅ default feature; TCP 37428 + abstract-unix; Python interop both directions |
| 5.4 Serial + KISS + AX.25 | ✅ feature `iface-serial` (framing, CSMA commands, flow control, beacon; pty tests) |
| 5.7 PipeInterface | ✅ feature `iface-pipe` (shlex, respawn; `/bin/cat` tests) |
| 5.9 Interface statistics | ✅ counters + `Transport::interface_stats()` |
| 6.1 Path table upgrades | ✅ timestamps, PATHFINDER_E expiry, unresponsive marking, drop APIs, snapshot |
| 6.2 Announce queueing & egress control | ✅ `iface/control.rs`: per-interface ingress control (ic_* burst detection, held announces with penalty/release), announce cap airtime budgeting with queued announces, mode-based announce forwarding policy (internal/roaming/boundary), `PATHFINDER_RW` random retransmit window, `PATHFINDER_R` retries |
| 6.3 Path request parity | ✅ full `path_request` branch order (local response / known path with grace+roaming grace / local-client forwarding / mode-gated recursive search with ingress+egress PR limiting / local-client fan-out), `await_path` async API, `PATH_REQUEST_TIMEOUT`/MI pending-request tracking, discovery-request dedupe with tag reuse |
| 6.8 Packet cache requests | ✅ announce packet cache by hash, `CACHE_REQUEST` context handling (replay + link answer) |
| 5.5 RNode + RNodeMulti | ✅ `iface/rnode.rs` (feature `iface-rnode`): full RNode KISS command codec (detect burst, radio config incl. u32 frequency/bandwidth BE, airtime locks, radio state; stats rx/tx/RSSI(-157)/SNR(×0.25 + quality)/battery/temp; READY flow control; leave/reset/blink/random), detection + firmware >= 1.52 gate + echo validation (±100 Hz tolerance), serial + TCP device links; RNodeMulti with CMD_SEL_INT prefixing, 12 vport data commands and per-vport spawned peers (wants_tunnel); daemon serial/tcp config incl. airtime locks and `[[subinterfaces]]`; end-to-end tests against a mock RNode device bridging two hosts |
| 5.6 I2P | ✅ `iface/i2p.rs` (feature `iface-i2p`): SAMv3 spoken directly (HELLO/SESSION CREATE transient/STREAM CONNECT/ACCEPT, per-op fresh sockets like vendored i2plib), I2pPeer (HDLC-framed stream, initiator reconnect + `wants_tunnel` tunnel synthesis, spawned mode with IFAC inheritance), I2pServer (connectable session, accept loop spawning peers, b32 derivation), daemon `peers`/`connectable`/`sam_address` config; end-to-end test against a mock SAM bridge splicing streams |
| 5.8 Backbone | ✅ `iface/backbone.rs`: BackboneServer (spawned peers with inherited access codes + control params) + BackboneClient (reconnect, tunnel synthesis request) over HDLC/TCP, FastFlapTable parity (threshold/grace/expiry accounting, blocked-IP gate, 60s expiry job), daemon server/client config incl. fast-flapping options; Weave remains hardware-gated (device protocol, no wire parity surface without the radio) |
| 7.1 `Reticulum` facade | ✅ `reticulum::reticulum::Reticulum`: instance lifecycle over a `Transport` (transport_enabled, interface manager/stats, path/tunnel tables, has_path/hops_to/request_path/await_path, identity hash, add_destination/announce, enable remote-management/probe/blackhole-publishing) — the embeddable equivalent of Python `RNS.Reticulum` |
| 6.6 Network discovery | ✅ new `reticulum-discovery` crate (avoids the reticulum↔lxmf cycle): `InterfaceAnnouncer` (periodic due-interface announces on `rnstransport.discovery.interface` with LXMF work-function stamps at discovery expand rounds=20), `InterfaceDiscovery` (announce validation against required stamp value, msgpack `InterfaceInfo` with field checks, staleness-tracked table, TCP autoconnect with dedupe + cap, `list_discovered_interfaces` semantics), `BlackholeUpdater` (links to source `rnstransport.info.blackhole` destinations, pulls `/list`, merges identities); daemon wires `discoverable`/`announce_interval`/`discovery_*`/`reachable_on` |
| 6.7 Remote management & probe | ✅ `transport/management.rs`: `rnstransport.remote.management` SINGLE destination with `/status` (interface stats + link counts) and `/path` ("table"/"rates") request handlers gated by the link-identified allow list; `rnstransport.probe` destination (no links, PROVE_ALL) for rnprobe; `rnstransport.info.blackhole` `/list` publishing; daemon config `remote_management`/`probe_destination` |
| 5.1 IFAC | ✅ `iface/ifac.rs`: HKDF-SHA256 key derivation from netname/netkey over `IFAC_SALT` (byte-exact vs Python), truncated-signature access codes with HKDF masking/unmasking per packet, IFAC flag handling; wired into udp/tcp_client/auto/serial/kiss/pipe/local workers + tcp_server inheritance to spawned connections; daemon parses `mode`/`configured_bitrate`/`ifac_size`/`networkname`/`passphrase`; Python interop over an IFAC-protected TCP link both directions + unprotected-packet rejection |
| 6.4 Tunnels | ✅ `transport/tunnels.rs`: signed synthesize packets on fixed PLAIN dest `rnstransport.tunnel.synthesize` (176-byte wire format, remote transport identity signature validation), tunnel table with path association, void/restore on re-appearance (Python restore rules: unknown/expired/worse-path checks), `TUNNEL_TIMEOUT` expiry, `Transport::synthesize_tunnel`/`void_tunnel`/`tunnel_table_snapshot`, iface `tunnel_id`/`wants_tunnel` |
| 6.5 Blackholes | ✅ `transport/blackholes.rs`, identity-hash announce filtering, pack/merge lists |
| 7.2/7.4 Daemon config & lifecycle | ✅ config parity for new interfaces + shared-instance keys, identity persistence |
| 8 `rn*` utilities | ✅ `reticulum-utils` crate: rnid/rnpath/rnstatus/rncp/rnprobe/rnx/rnsh/rnodeconf/rnir/rnpkg (`rn probe --loopback` measures proof RTTs; rnx serves Python-shaped `[command,timeout,o_limit,e_limit,stdin] -> [executed,retval,stdout,...]` requests over links; rnsh runs channel-based exec sessions; rnodeconf probes device info + validates radio config; rnir/rnpkg match the reference stubs) |
| 7.3 shared-instance RPC | ✅ resolved: the reference's local RPC is the plain HDLC-framed packet exchange (implemented, 5.3) plus the link-based `/status`/`/path`/`/list` management handlers (6.7) — no pickle protocol exists in the current reference to port |
| no_std status | **`reticulum-core` is fully no_std** (verified: builds and links as `#![no_std]` for Cortex-M4 `thumbv7em-none-eabihf` with an external heap; entropy injected via `_with_rng` APIs or `std`-gated `OsRng` conveniences; portable atomics; `ZeroRng` for decrypt-only paths). **The `reticulum` main crate is std-only by design** (tokio, interfaces, storage; its `no-default-features` check passes but it has no `#![no_std]` goal — embedded users take `reticulum-core` directly). `lxmf`/`lxst`/utils/daemon/discovery are std-only. |
| 9.1 Hardware test ladder | ✅ `docs/hardware-testing.md`: unit → emulator (`rn node-sim`, faithful device-side protocol incl. frequency quantization + flow control + telemetry) → mock bridges → hardware-in-the-loop (`tests/hardware_rnode.rs` env-gated via `RETICULUM_HW_RNODE[_TCP]`) → over-the-air checklist. **Fully validated on real hardware**: a Heltec V3 was brought up as a working RNode (official fw 1.86, provisioned identity, radio ONLINE — live RSSI telemetry, real LoRa TX) — root cause of the earlier offline radio was the missing `CMD_FW_HASH` image-hash provisioning step, found by instrumenting the actual firmware (BT was never at fault); `tests/hardware_rnode.rs` 4/4 green against the radio, and the corrected `RADIO_STATE` constants (0x01/0x00) are what make the radio-state echo validation pass |
| 9.2 Fuzz/property tests | ✅ `fuzz/` cargo-fuzz targets (packet deserialize, announce validation, tunnel synthesis, IFAC strip, HDLC decode — nightly/cargo-fuzz) + stable-runnable `tests/fuzz_properties.rs` driving the same decoders with deterministic pseudo-random corpora; found and fixed a real panic: `Packet::deserialize` sliced beyond the 2 KiB payload buffer for oversized hostile inputs (now `RnsError::OutOfMemory`) |
| 9.3 Benchmarks | ✅ criterion `benches/hot_paths.rs`: announce validation, IFAC wrap/unwrap, packet serialize, announce emission timestamp, HDLC framing |
| LXMF crate | ✅ byte-exact message format, stamps, peers, router + resource-backed delivery |
| LXST crate | ✅ codecs, wire protocol, pipelines, calls |

## Progress log — intermediary link routing & full E2E interop (latest)

| Area | Status |
| --- | --- |
| Link-request proof authentication | ✅ `transport/link_table.rs`: intermediary link entries (`IDX_LT_*` parity), LRPROOF validation via recalled identity over `link_id‖pub‖sig_pub‖signalling`, hop/interface gating, validated relay toward the initiator, path rebalancing (sequential rebalance-then-relay like Python), 6s/hop proof timeout, 900s validated-link lifetime, 5s cull cadence, retried LRs refresh entries |
| Bidirectional intermediary link routing | ✅ directional `outbound_iface_for` (same-interface links accept either hop count; differing interfaces forward on the opposite interface with exact hop match); link data, keepalives, message proofs, resource proofs and channel packets all relay; forwarding preserves the original header bytes and rewrites only the hop count (Python `new_raw = raw[0:1] + hops + raw[2:]`) |
| Python-parity relay semantics | ✅ path-table relay re-addressing (multi-hop → HEADER_2/TRANSPORT via next hop; last hop → HEADER_1/BROADCAST stripped), LRs addressed via the known path, unaddressed remote-dest LRs/data no longer relayed on a path-table hit (Python `transport_id` gate), LR MTU signalling stripped onto non-MTU interfaces, packet-hash insertion deferred for link-table packets and LRPROOFs, blind re-broadcast of received packets removed (every relayed class handled explicitly) |
| Path responses through Rust transports | ✅ grace-delayed responses are queued until actually retransmitted (a 1s tick inside the 400ms grace window used to silently drop them) — Python clients now learn paths through Rust middles |
| Pending-link recovery | ✅ establishment timeout closes the link, expires the failed path on client instances and re-requests it (Python Link watchdog + `Transport.jobs`) |
| E2E interop matrix | ✅ `tests/python_middle.rs` (4 tests): Rust↔Python-middle↔Rust announce/LR/proof/bidirectional data; Python endpoints ↔ Rust middle (announce, LR re-address, LRPROOF, ping/echo); 80KB resource + request/response through the Python middle; Python request client/server through the Rust middle. Live-program validation: rncp 300KB/500KB through a Python `rnsd` middle both directions, **Python rncp client↔server with the Rust `rs-rnsd` daemon as the only transport: 2MB @ ~79Mbps, sha256-verified** |
| rnsh wire protocol | ✅ real Python rnsh protocol (msgpack messages `0xac00`–`0xac07`, StreamData 2-byte header, identify→VersionInfo→ExecuteCommand→streamed output→CommandExited); `rn sh -c "cmd"` → Rust client → Rust `rs-rnsd` middle → Python rnsh listener verified live (command execution + output streaming). Empty closed stdin advertises no pipe (Python's listener kills the child 50ms after stdin EOF, which loses fast-command output otherwise) |

## Progress log — Python 1.5.0 parity (latest)

Reference pulled to 1.5.0+5 (b123a756, was 1.4.2/b48b96e6). Upstream Rust
fork merged (LinkRequest forwarding-loop fixes, `TransportConfig` broadcast
flag removal — routing capability is `retransmit` now).

| Area | Status |
| --- | --- |
| Discovery wire format | ✅ **was wire-incompatible** (string keys vs Python's integer keys — Rust↔Python interface discovery never actually interopped); now the exact Python integer-key msgpack map (0x00 type … 0xFF name), verified bidirectionally against real Python 1.5.0 pack+validation |
| Discovery implementation identity | ✅ `TRANSPORT_IMPL` (0xFD, "reticulum-rs") + `TRANSPORT_VERS` (0xFC, crate version) packed per the 1.5.0 requirement |
| Operator LXMF address | ✅ `OP_ADDR` (0xF0) packed from `discovery_lxmf_address` interface config; validated on receive (nil or 16-byte bin) |
| Discovery autoconnect hardening | ✅ `.onion` targets and invalid IPs (127.0.0.1, 0.0.0.0) never auto-connect |
| Protocol violations | ✅ per-interface counters (`protocol_violations`, `ifac_violations`, `packet_filter_hits`) with Python's violation conditions: PLAIN/GROUP data with hops > 1, PLAIN/GROUP announces |
| Early packet filter | ✅ Python `packet_filter` semantics hooked at ingress before processing |
| Excessive hop rejection | ✅ outbound packets with hops > PATHFINDER_M-1 dropped (`Transport._outbound` parity) |
| In-flight PR batching | ✅ discovery path requests batch requesting interfaces; the path response fans out to every batched requestor (Python 1.5.0 batching semantics) |
| Interface traffic stats | ✅ announce/path-request counts + announce bytes on `InterfaceStats` (Python `arxb/atxb/arxc/atxc/prxc/ptxc`) |
| rnstatus | ✅ Announces / PRs / Violations columns (per-interface traffic stats parity) |

Follow-up round (all three gaps closed):
- `link_mtu_discovery` config (daemon key + `TransportConfig` setter):
  link requests signal the next-hop hardware MTU when enabled and the
  interface supports MTU negotiation (TCP/backbone/local/auto kinds),
  else the protocol MTU — exactly Python's gate. iface_hw_mtu lookup
  added per kind (262144 TCP/local, 1048576 backbone, 1196 auto).
- Prioritized inbound queues (Python `InboundQueues`): four bounded
  per-class queues (data 4096, announce 256, PR 256, IL 128) drained in
  class order with drop counters; configurable via `qlen_in_data` /
  `qlen_in_announce` / `qlen_in_pr` / `qlen_in_il`; queue-pressure
  snapshot in `rnstatus`.
- Adaptive timeouts: `Transport::lowest_interface_bitrate()` /
  `medium_path_timeout()` (2*(MTU*8/bitrate)+6s) with rnpath/rncp
  using it as the establishment timeout floor (Python parity), and
  `extra_link_proof_timeout` added to link establishment on slow
  interfaces.

## Remaining open (documented, lower priority)

* WeaveInterface — requires WeaveMesh radio hardware; the WDCL device
  protocol (discover/handshake over the radio's serial link) has no
  wire surface testable without the device; keep using the Python
  stack or upstream tooling for Weave radios
* Blackhole discovery persistence to storage (in-memory table today)
* rnodeconf firmware flashing / EEPROM provisioning — device bootstrap
  and esptool-class flashing stay with the upstream `rnodeconf`
  (device-info probing and radio config validation are ported)
