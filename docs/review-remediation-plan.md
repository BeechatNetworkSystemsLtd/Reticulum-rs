# Review Remediation Plan

This plan addresses all 29 review findings: 15 P1 findings and 14 P2
findings. Work is ordered by security impact and by dependencies between
shared transport, persistence, interface, and application-level changes.

## 1. Restore CI and establish regression coverage

- Rewrite the loop in `tests/python_buffer.rs` to return the channel tuple
  directly, removing the overwritten initialization that fails Clippy under
  `RUSTFLAGS=-D warnings`.
- Add a negative regression test for each security or protocol defect before
  or alongside its fix.
- Keep changes grouped by behavior so every code change and test remains
  traceable to a review finding.

## 2. Close authentication and malformed-input vulnerabilities

### rnsh authentication

- Add an explicit identity allowlist and `allow_all` option to
  `reticulum-utils/src/rnsh.rs`; default to deny-all.
- Add matching repeatable `--allowed` and explicit `--allow-all` CLI options.
- Make the client load a stable private identity and identify over the link
  before sending commands.
- Execute commands only after the listener has verified `remote_identity` and
  found it in the allowlist, unless `allow_all` was explicitly selected.
- Test authorized, unauthorized, unidentified, and explicit allow-all
  sessions.

### rncp authentication

- In `reticulum-utils/src/rncp.rs`, make `allow_all` depend solely on
  `no_auth`; an empty authenticated allowlist must deny every identity.
- Test that an empty allowlist rejects both uploads and fetch requests, while
  `--no-auth` remains the explicit opt-in for unrestricted access.

### Resource request parsing

- In `src/resource/manager.rs`, validate the minimum normal-request and
  exhausted-map request lengths before taking any slices.
- Return an empty `ResourceTx` for malformed requests without mutating
  resource state.
- Test empty, one-byte, truncated exhausted-map, short-hash, and valid
  requests.

### SINGLE proof parsing

- In `src/transport.rs`, accept only the exact 64-byte implicit and 96-byte
  explicit proof forms before parsing a signature.
- Replace the signature parsing `expect` with ordinary invalid-proof handling.
- Test every short length, invalid intermediate lengths, and both valid proof
  forms while a receipt is pending.

### Link MTU validation

- Define one minimum safe link MTU from the header, IFAC, token-overhead, and
  AES block-size constants.
- Reject nonzero negotiated MTUs below that minimum in link requests.
- Apply the same lower bound to local MTU setters and make `mdu()` and `sdu()`
  defensively safe.
- Test zero/default signalling, the minimum valid MTU, and values below the
  minimum in debug and release-compatible code paths.

### IFAC bounds

- Add an `IFAC_MAX_SIZE` of 64 bytes in `src/iface/ifac.rs`.
- Make IFAC derivation return `InvalidArgument` for larger values and
  propagate the error through interface configuration instead of panicking.
- Test 1-byte and 64-byte IFACs, plus rejection of 65 bytes and configuration
  values above 512 bits.

### Packet payload bounds

- Reject PLAIN data above `PACKET_PROTOCOL_MDU` before writing to the packet
  buffer.
- Introduce a canonical SINGLE plaintext MDU that accounts for the packet
  header, IFAC, encryption token, block padding, and ephemeral public key.
- Reject SINGLE data above that MDU before encryption.
- Test each boundary at `MDU`, `MDU + 1`, and well beyond the scratch-buffer
  capacity; rejected sends must emit no packet.

## 3. Secure identity persistence

- Centralize private-identity creation and writing in
  `reticulum-utils/src/common.rs`.
- On Unix, use owner-only mode `0600` at creation time and normalize
  permissions when rewriting an existing identity.
- Replace the direct rnsh and rnx identity writers with the common helper.
- Preserve portable behavior on non-Unix platforms without pretending Unix
  mode bits are available.
- Add Unix tests under a permissive umask verifying daemon, rnsh, rnx, and
  utility-created identities remain owner-only.

## 4. Correct transport API and routing semantics

### Async-safe accessors

- Remove the `blocking_lock()` calls from `Transport` accessors.
- Keep immutable transport identity and the shared blackhole handle directly
  on `Transport`, allowing synchronous cloning without locking the Tokio
  handler mutex.
- In `destination_accepts_links`, clone the destination handle while holding
  the handler lock, release it, and then await the destination lock.
- Add a Tokio-runtime regression test that calls all affected accessors and
  proves they do not panic.

### Proof strategy default

- Change `ProofStrategy::default()` to `None` in
  `reticulum-core/src/destination.rs`.
- Keep explicit `All` configuration for probe and any other destination that
  intentionally proves every packet.
- Test the constructor default and explicit overrides.

### Announce filtering

- Redesign `subscribe_announces` to receive the application name and complete
  aspects needed to derive expected destination hashes.
- Compute each expected destination hash using the announced identity and
  forward only matching events; an empty filter continues to forward all
  announces.
- Update interface discovery to subscribe specifically to
  `rnstransport.discovery.interface`.
- Test matching and unrelated announces from the same and different
  identities.

### Unresponsive paths

- Exclude unresponsive entries from route lookup, next-hop selection, inbound
  forwarding, and outbound packet routing.
- Allow a fresh equal-hop announce to replace an unresponsive entry even when
  eager rerouting is disabled.
- Keep diagnostic table iteration able to report the retained unresponsive
  entry.
- Test marking, route suppression, equal-hop recovery, and explicit
  responsiveness restoration.

## 5. Repair persistence behavior

### Destination ratchet signatures

- At both destination-ratchet persistence sites in `src/transport.rs`, sign
  with the destination's private identity instead of the transport identity.
- Test a destination whose identity differs from the transport identity
  across initial empty-file persistence, ratchet rotation, and reload.

### Daemon storage lifecycle

- Construct the daemon transport with `FsStorage` rooted at
  `<config-directory>/storage`.
- Call `load_known_destinations()` before interfaces begin receiving traffic
  or management and discovery destinations announce.
- Ensure normal persistence hooks continue saving known destinations and
  remote ratchets to the same backend.
- Add a restart test proving recalled identities, application data, and
  remote ratchets survive construction of a new daemon transport.

### Atomic replacement on Windows

- Refactor `FsStorage::write` around a unique same-directory temporary file.
- On Unix, replace the destination with `rename`.
- On Windows, use replacement-capable platform APIs such as `ReplaceFileW` or
  `MoveFileExW` with replacement semantics.
- Clean temporary files on error and avoid a shared fixed `.tmp` name that
  races concurrent writers.
- Add repeated-write tests and run them in a Windows CI job.

## 6. Fix management and migration configuration

### Management keys and allowlist

- Add serde aliases so `enable_remote_management` populates
  `remote_management` and `respond_to_probes`/`enable_remote_probe` populate
  `probe_destination`.
- Add `remote_management_allowed`, accepting both TOML arrays and
  Python-style comma-separated strings.
- Parse and validate every configured identity hash, call
  `remote_management_allow` for each, and only then enable the management
  destination.
- Test standard Python keys, native Rust keys, invalid hashes, an empty
  deny-all list, and an authorized management request.

### I2P peer lists

- Give I2P `peers` a string-or-array deserializer.
- Split Python-style comma-separated values, trim whitespace, and discard
  empty entries while retaining support for native TOML arrays.
- Test direct parsing and the full Python-config migration path.

### String-valued migration keys

- Replace the incomplete sequence of `quote_if_needed` calls with explicit
  schema sets for string-valued and list-valued keys.
- Preserve the complete right-hand value, spaces, escaping, and inline
  comments instead of retaining only the first whitespace-delimited token.
- Cover at least `group_id`, `discovery_scope`, `multicast_address_type`,
  `command`, `reachable_on`, `sam_address`, `tcp`, network names and
  passphrases, device lists, I2P peers, and management identities.
- Add a realistic migration fixture containing every affected interface
  field and require the converted result to deserialize as `Config`.

### TCP RNode endpoints

- Introduce one endpoint-normalization helper: an explicit `tcp` field wins;
  otherwise, a `port` beginning with `tcp://` becomes a TCP endpoint and all
  other values remain serial paths.
- Apply the same normalization to RNode and RNodeMulti configuration.
- Test a migrated standard Python RNode entry and explicit native TOML forms.

## 7. Repair I2P and RNode protocol behavior

### I2P SAM session lifetime

- Store the socket that issued `SESSION CREATE` inside `SamSession` for the
  session's entire lifetime.
- Strengthen the SAM mock so closing the control socket invalidates the
  session ID.
- Test stream connect, stream accept, and session teardown behavior.

### RNode radio state

- Change `RADIO_STATE_ON` to `0x01` and `RADIO_STATE_OFF` to `0x00`.
- Update configuration and validation expectations and add exact frame tests.

### RNodeMulti transmit selection

- For every virtual-port transmission, send `CMD_SEL_INT(index)` followed by
  a normal `CMD_DATA` frame.
- Retain per-port data commands for receive parsing only.
- Add a strict writer transcript test covering multiple virtual ports.

### RNode reconnection

- Replace the single and multi-interface `join!` pump arrangements with
  coordinated `select!` lifetimes.
- When the reader, writer, or cancellation completes, stop the sibling
  immediately, mark the interface offline, and enter reconnection.
- Keep the single-interface transmit receiver outside the reconnect loop so
  it is not consumed with `take().unwrap()`.
- Test read-side EOF while transmit is idle, write failure while read is
  pending, cancellation, and a successful second connection.

### RNode flow control

- Store `flow_control` on `RnodeInterface` and pass the parsed daemon setting
  into the constructed interface.
- When enabled, wait for readiness before sending and set
  `interface_ready = false` after every successful transmission.
- Permit the next frame only after the parser receives another `CMD_READY`.
- Test two queued transmissions, proving the second remains blocked until
  the ready frame arrives; also test unrestricted behavior when flow control
  is disabled.

## 8. Isolate shared-transport application events

### LXMF delivery links

- Track link IDs activated specifically for the local LXMF delivery
  destination.
- Enable resource acceptance and message proofs only for those links.
- Filter completed resource events by exact link ID and remove tracked IDs
  when links close.
- Test a transport containing both an LXMF delivery destination and an
  unrelated inbound destination; unrelated resources must never be parsed or
  emitted as LXMF messages.

### LXST endpoint and active-call links

- Filter incoming activation and close events by the call endpoint's
  destination hash.
- Make `Transport::events_for_link` actually forward only the requested link
  ID.
- Retain an explicit `id == active_link_id` guard in the active-call task as
  defense in depth.
- Test unrelated activation, data, and close events while a call is pending
  and while another call is active.

## 9. Verification and acceptance gates

Run focused tests after each workstream, followed by the repository's full CI
matrix:

```bash
cargo fmt --all -- --check

RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets
RUSTFLAGS="-D warnings" cargo clippy -p reticulum --all-targets --all-features
RUSTFLAGS="-D warnings" cargo clippy -p reticulum-core \
  --no-default-features --features embassy-time

cargo test --workspace --all-targets
cargo test --workspace --all-targets --features python-tests -- --no-capture
cargo test -p reticulum-core --all-targets \
  --no-default-features --features embassy-time
cargo test -p reticulum --features bz2 --test resource_transfer
```

The work is complete only when:

- all 29 findings have regression coverage;
- the exact warnings-as-errors Clippy commands pass;
- unauthorized rnsh, rncp, and management peers are rejected;
- malformed network inputs cannot panic transport or interface tasks;
- mixed-destination tests show no LXMF or LXST cross-application traffic;
- daemon identity knowledge and ratchets survive restart;
- strict SAM and RNode protocol mocks pass; and
- repeated filesystem replacement passes on Windows.
