# Review Remediation Plan — 2026-08-20

## Objective

Address all eight findings from the current review while preserving Criterion
benchmark coverage, Python interoperability coverage, and the public resource
API. Five findings share the split-resource lifecycle, so those fixes should be
implemented and tested as one coherent workstream rather than as unrelated line
changes.

The worktree was clean when this plan was prepared. The affected behavior is in
the committed `main` checkout at `f39c2af`.

## Finding map

| ID | Priority | Area | Primary files | Required outcome |
|---|---:|---|---|---|
| F1 | P1 | Criterion in CI | `.github/workflows/ci.yml`, `Cargo.toml` | Libtest arguments never reach the harness-free Criterion executable, while the benchmark still compiles in CI. |
| F2 | P1 | Python test gating | `tests/python_middle.rs` | A checkout without the Python Reticulum source can run the default test suite. |
| F3 | P1 | rncp split completion | `reticulum-utils/src/rncp.rs`, `src/resource/manager.rs` | `rn cp` waits for proof of the final segment, fails promptly when a later segment fails, and only then closes the link. |
| F4 | P2 | Split response/event state | `src/resource/manager.rs` | The final assembled buffer remains available to response decoding, and metadata from segment one reaches the final event. |
| F5 | P2 | Metadata segment boundaries | `src/resource/outbound.rs` | Every byte in the metadata-prefixed logical stream is sent exactly once. |
| F6 | P2 | Outbound option propagation | `src/resource/outbound.rs`, `src/resource/manager.rs` | Later segments retain compression, timeout, and request/response semantics. |
| F7 | P1 | Abandoned split assemblies | `src/resource/manager.rs` | Failed, corrupt, or cancelled split transfers release accumulated bytes without deleting valid in-progress assemblies. |
| F8 | P2 | Blackhole source attribution | `reticulum-discovery/src/lib.rs`, `src/transport/blackholes.rs` | Fetched entries are attributed to the publishing identity and expire as remote entries without replacing locally sourced entries. |

### Plan-review refinements

The following adjacent requirements were identified while reviewing this plan
and are mandatory parts of the corresponding phases:

| ID | Priority | Requirement |
|---|---:|---|
| G1 | P1 | Watchdog failures for later segments must include their advertisement so rncp can correlate them through `original_hash` and fail immediately. |
| G2 | P2 | Split assembly state must retain first-segment metadata and attach it to the final event. |
| G3 | P2 | Discovery must reuse `Blackholes::merge_list`, and that helper must not replace a locally sourced entry with a remote source. |
| G4 | Nit | Sender completion events must use segment-weighted `resource.progress()` rather than hard-coded `1.0`. |
| G5 | Nit | Criterion 0.5.1 accepts `--nocapture`; the present failure is specifically `--no-capture`, but target separation remains the chosen durable fix. |

## Cross-cutting resource invariants

The split-resource changes should enforce these invariants explicitly:

1. The outbound logical stream is exactly
   `[3-byte metadata length][metadata][payload]` when metadata exists, and just
   `[payload]` otherwise.
2. Segment ranges form a contiguous, non-overlapping partition of that stream:
   segment `n` covers
   `((n - 1) * MAX_EFFICIENT_SIZE)..min(n * MAX_EFFICIENT_SIZE, total_size)`.
3. `original_hash` identifies the complete logical transfer; `hash` identifies
   one segment. Code waiting for a logical transfer must not assume all segment
   events use the first segment's `hash` field.
4. A `Complete` event for a non-final segment means only that the segment was
   proved. Logical transfer completion requires
   `advertisement.segment_index == advertisement.total_segments`.
5. The complete receive buffer has one clear ownership path on the final
   segment. Removing it from `split_assembly` must not make it unavailable to
   response decoding, the resource event, or request dispatch.
6. Metadata decoded from segment one is logical-transfer state. It remains with
   the accumulated bytes until the final event, even though later
   `IncomingResource` values have `metadata: None`.
7. A successful non-final segment keeps its accumulated bytes. A terminally
   failed, corrupt, rejected, or cancelled split transfer drops them.
8. Later outbound segments inherit every behavior-affecting option from segment
   one. Metadata bytes themselves are not prepended again because they already
   live in `original_stream`.
9. Every production event for a segment carries enough advertisement state to
   recover `original_hash`, segment index, and total segment count. Non-final
   progress is segment-weighted and remains below `1.0`.

## Phase 1 — Restore reliable default and CI test entry points

### 1.1 Gate `python_middle` with the existing feature

Files:

- `tests/python_middle.rs`

Changes:

- Add `#![cfg(feature = "python-tests")]` at the top of the integration test,
  before its module documentation, matching `tests/python.rs`,
  `tests/python_resources.rs`, and the other Python interoperability targets.
- Keep `python_dir()` strict when the feature is enabled. CI explicitly checks
  out Python Reticulum and sets `RETICULUM_TEST_PYTHON_DIR`, so silently skipping
  enabled interoperability tests would hide configuration failures.

Regression checks:

- With `RETICULUM_TEST_PYTHON_DIR` unset, run the default workspace tests and
  confirm `python_middle` builds as an empty gated target rather than executing
  its four tests.
- With `python-tests` enabled and the environment configured, confirm all four
  middle-node interoperability tests are still discovered and run.

### 1.2 Separate libtest targets from Criterion

Files:

- `.github/workflows/ci.yml`
- `Cargo.toml` only for confirmation; retain `harness = false` for `hot_paths`

Changes:

- Replace the first CI invocation's `--all-targets` selection with explicit
  non-benchmark targets, for example:

  ```bash
  cargo test --workspace --lib --bins --tests --examples \
    --features="python-tests" -- --no-capture
  ```

- Add a separate compile-only benchmark command with no libtest arguments:

  ```bash
  cargo bench --workspace --no-run
  ```

  The existing Clippy `--all-targets` command also compiles benchmarks, but the
  explicit bench command makes the intended CI coverage visible and prevents a
  future test-target edit from dropping it.
- Do not change the Criterion benchmark to the libtest harness. Criterion's
  generated `main` requires `harness = false`.
- Record the exact observed nuance: Criterion 0.5.1 accepts the one-word
  `--nocapture`, while the current CI supplies libtest's hyphenated
  `--no-capture`. Do not use the spelling change as the fix; it would leave
  libtest-specific arguments coupled to a harness-free executable and could
  regress with other arguments later.

Regression checks:

- Reproduce the new test command locally and confirm `--no-capture` reaches only
  libtest executables.
- Run `cargo bench --workspace --no-run` and confirm `hot_paths` compiles without
  executing benchmark measurements.
- Retain `cargo test --workspace --all-targets` as the default-suite gate in
  Phase 6. Plain `cargo test` passes `--test` to Criterion, which runs its quick
  smoke mode successfully; only the CI command that forwards `--no-capture`
  needs target separation.

## Phase 2 — Correct outbound split construction and option inheritance

These changes should land together because a large metadata-bearing rncp test
exercises both the byte boundary and option propagation defects.

### 2.1 Use one canonical segment-range calculation

Files:

- `src/resource/outbound.rs`

Changes:

- Make `OutgoingResource::new()` and `prepare_next_segment()` both use
  `segment_range()` (or one equivalent private helper) as the single source of
  segment boundaries.
- Remove the `first_read_size = MAX_EFFICIENT_SIZE - metadata_size` adjustment
  from `prepare_next_segment()`. `original_stream` already includes the metadata
  prefix and metadata, and segment one already consumes bytes through
  `MAX_EFFICIENT_SIZE`; therefore segment two must begin at
  `MAX_EFFICIENT_SIZE`, not `MAX_EFFICIENT_SIZE - metadata_size`.
- Update the comments to describe ranges in the actual metadata-prefixed stream
  and eliminate the contradictory statement that the first segment
  "additionally" begins with metadata.
- Preserve the existing total-segment calculation based on the complete stream
  length.

Unit coverage in `src/resource/outbound.rs`:

- No metadata: verify coverage for sizes `MAX_EFFICIENT_SIZE - 1`, exactly
  `MAX_EFFICIENT_SIZE`, `MAX_EFFICIENT_SIZE + 1`, and more than two segments.
- With nonzero metadata size: verify the ranges are still `0..MAX`,
  `MAX..2*MAX`, and so on, with neither overlap nor gaps.
- Concatenate all selected slices and assert exact equality with the original
  metadata-prefixed stream. This catches both duplication and omission.

### 2.2 Make option inheritance an `OutgoingResource` responsibility

Files:

- `src/resource/outbound.rs`
- `src/resource/manager.rs`

Changes:

- Retain the original behavior-affecting settings on `OutgoingResource`. At
  minimum this requires the original `auto_compress` value; the resource already
  stores its effective `timeout`, `request_id`, and `is_response` values.
- Prefer changing `prepare_next_segment(&self, link)` so it internally derives
  the next segment's options instead of accepting a caller-supplied
  `ResourceOptions`. That makes it impossible for `ResourceManager` to reset
  options accidentally.
- Construct the next segment with:

  - the original `auto_compress` value;
  - `timeout: Some(self.timeout)` so an explicit caller timeout, or the first
    segment's already-derived effective timeout, remains identical;
  - the existing `request_id` and `is_response` values;
  - `metadata: None`, because metadata bytes are already present once in
    `original_stream`; and
  - the existing `has_metadata` and `metadata_size` structural fields passed to
    `new_segment()` for advertisement and receive-side parsing.

- Remove the `ResourceOptions { ..Default::default() }` reconstruction in
  `ResourceManager::handle_proof()` and call the self-contained next-segment
  preparation method.

Unit coverage:

- Build a split outbound resource with `auto_compress = false` and a distinctive
  explicit timeout, prepare segment two, and assert both values are unchanged.
- Build a split response and assert segment two retains `request_id` and
  `is_response`.
- Under the default `bz2` feature, use compressible data and verify that a
  no-compress transfer never sets the compressed flag on any segment.

Integration coverage in `tests/split_resource.rs`:

- Strengthen the existing test, which currently counts sender-side completion
  events but does not validate receiver bytes.
- Send more than `MAX_EFFICIENT_SIZE` bytes with non-empty metadata and
  `auto_compress = false`.
- Subscribe on the receiver, wait for the final event, and assert:

  - received payload equals the source byte-for-byte;
  - metadata equals the original metadata exactly;
  - exactly the expected segment indices were advertised;
  - the final event is the only split event carrying complete data; and
  - sender events reach the final segment before the test declares success.

Use deterministic poorly-compressible data so the test exercises the actual
multi-segment wire path regardless of compression heuristics.

## Phase 3 — Fix assembly ownership, cleanup, and terminal events

### 3.1 Preserve final data and first-segment metadata

Files:

- `src/resource/manager.rs`
- `tests/resource_transfer.rs`

Changes:

- Replace the raw `HashMap<Hash, Vec<u8>>` value with a small split-assembly
  state value containing at least:

  ```rust
  struct SplitAssembly {
      data: Vec<u8>,
      metadata: Option<Vec<u8>>,
  }
  ```

  Keep it keyed by `original_hash` as today. If link ownership is added for the
  cleanup work below, include it in this state rather than creating a second map.
- Refactor `assemble_completed()` so appending/removing a split assembly produces
  one local final assembly value instead of looking the state up twice.
- On segment one, store `resource.metadata.clone()` in the split assembly when
  the inbound decoder extracts it. Later segments must preserve that value
  instead of replacing it with their own `None` metadata.
- On a non-final segment, append to the state's data and leave the final
  assembly absent.
- On the final segment, append first and then remove the map entry into
  a local final assembly. Do not perform a second lookup after removal and do
  not use `unwrap_or_default()` to turn a violated assembly invariant into an
  empty response.
- Use that retained final state for all final consumers:

  - clone or borrow `data` for `ResourceEvent.data`;
  - attach the retained metadata to the final `ResourceEvent.metadata`;
  - pass `data` to `unpack_response()` when `is_response` is true;
  - insert the decoded response into `completed_responses` for late awaiters;
  - emit `RequestEvent::Response`; and
  - return `data` for inbound request dispatch.

- Keep non-split behavior unchanged and keep the split map empty after a
  successful final segment.
- If the final state is unexpectedly missing, emit/log an explicit failed or
  corrupt outcome instead of attempting to decode an empty vector or dropping
  metadata silently.

Regression coverage:

- Add a request/response integration case whose packed response exceeds
  `MAX_EFFICIENT_SIZE` (the existing 300,000-byte case is only resource-backed,
  not split).
- Await it through `Transport::await_request_response()` and assert the exact
  deterministic payload is returned.
- Include a late-await variant, or delay awaiting, to prove the decoded final
  payload is also inserted into `completed_responses` before broadcast delivery.
- Assert the final resource event carries both the complete packed resource and
  metadata captured from segment one, and that the corresponding
  `split_assembly` entry is gone after success in a focused manager-level test.

### 3.2 Remove abandoned split assemblies without deleting valid partials

Files:

- `src/resource/manager.rs`

Changes:

- Before `cleanup()` retains only active resources, collect the
  `original_hash` of incoming split resources whose terminal status is
  `Failed`, `Corrupt`, or `Rejected`, then remove those keys from
  `split_assembly`.
- Ensure initiator cancellation, receiver watchdog exhaustion, and assembly
  corruption all flow through one terminal-state cleanup rule. If any path can
  remove an `IncomingResource` without calling the common cleanup, invoke the
  same small helper at that path.
- Do not remove an assembly merely because a non-final segment is `Complete`;
  completed segment records are expected to be discarded while their bytes are
  retained for the next segment.
- Keep successful final cleanup in `assemble_completed()`, where the completed
  buffer is removed for delivery.
- Consider recording link ownership with assembly state if cleanup is expanded
  to link teardown later. It is not necessary to broaden this patch, but the
  cleanup implementation must never remove an unrelated active assembly.

Manager-level regression coverage:

- Seed/produce a completed non-final segment, run `cleanup()`, and assert its
  accumulated bytes remain.
- Mark the following segment `Failed`, run `cleanup()`, and assert both the
  incoming resource and accumulated buffer are removed.
- Repeat for `Corrupt` and the initiator-cancel path.
- Run the cleanup twice to prove it is idempotent.
- Use distinct original hashes to prove abandoning one transfer does not remove
  another transfer's assembly.

### 3.3 Make terminal events correlatable and progress truthful

Files:

- `src/resource/manager.rs`

Changes:

- Change the watchdog's `failed_events` staging value so it retains a
  `ResourceAdvertisement` alongside link ID, segment hash, status, and progress.
  Build it with `OutgoingResource::advertisement()` for sender failures and
  `IncomingResource::advertisement_of()` for receiver failures.
- Populate `ResourceEvent.advertisement` for failures emitted by
  `ResourceManager::check()`. This is required for segment two and later: their
  direct hashes differ from the initial hash returned to rncp, so
  `advertisement.original_hash` is the only safe correlation key.
- Audit all other terminal paths (`handle_proof`, `handle_cancel`,
  `handle_reject`, and assembly corruption) and require an advertisement when a
  concrete resource exists. Pre-advertisement construction failures may remain
  outside the event stream.
- In `handle_proof()`, replace the hard-coded `progress: 1.0` with the completed
  resource's `progress()` value. Capture it after proof validation so a
  non-final completion reports its segment-weighted fraction and the final
  completion reports exactly `1.0`.
- Keep the segment's own hash in `ResourceEvent.hash`; the advertisement adds
  logical identity without changing existing per-segment event semantics.

Regression coverage:

- Force/check a watchdog failure for segment two and assert the emitted event
  contains segment `2/N`, the original hash, and the second segment's own hash.
- Verify the same event correlates to the initial transfer hash through its
  advertisement and is reported as a terminal error by the rncp helper.
- Assert completion progress is monotonic, below `1.0` for every non-final
  segment, and exactly `1.0` for the final segment.

## Phase 4 — Make rncp wait for logical completion

Files:

- `reticulum-utils/src/rncp.rs`
- `reticulum-utils/tests/rncp_loopback.rs`

Changes:

- In `wait_for_transfer()`, correlate an event with the requested logical
  transfer using either:

  - the event's direct segment hash for the initial/unsplit resource; or
  - `event.advertisement.original_hash` for later split segments.

  Convert the full hash to `AddressHash` consistently with the value returned by
  `send_resource_with_options()`.
- Treat `ResourceStatus::Complete` as success only when the advertisement says
  the completed segment is final. A non-final completion should update progress
  and continue waiting.
- Continue treating matching `Failed`, `Corrupt`, and `Rejected` events as
  terminal errors. Events from unrelated logical resources on the same
  transport must remain ignored.
- Preserve unsplit compatibility: its advertisement has segment `1/1`. If a
  legacy/internal event lacks an advertisement, only a direct hash match may use
  the unsplit completion or failure fallback.
- Make the advertisement-less later-segment behavior explicit: because neither
  its segment hash nor any attached field identifies the requested logical
  transfer, it must not be guessed or treated as matching. Production watchdog
  events are fixed in Phase 3.3 to carry advertisements; a legacy or malformed
  advertisement-less later failure is ignored and the rncp deadline remains the
  final fallback.
- Close the link in `send()` only after `wait_for_transfer()` returns final
  success, as it already does structurally.

Unit coverage:

- Factor the event correlation/finality checks into small pure helpers.
- Feed a synthetic two-segment event sequence and assert segment `1/2` does not
  complete the wait while `2/2` does.
- Verify the second segment matches by `original_hash` even though its own
  `hash` differs.
- Verify unrelated events and non-final completions are ignored, while matching
  failures are reported.
- Include an advertisement-less `Failed` event whose hash is a later segment's
  hash. Assert it cannot be correlated and is ignored; then verify the same
  event with an advertisement fails immediately. Also verify an
  advertisement-less failure with a direct initial hash still fails.
- Assert progress from a non-final completion remains below 100% and does not
  print the final completion message.

End-to-end coverage:

- Add a loopback rncp send test with a file larger than
  `MAX_EFFICIENT_SIZE`, filename metadata, and `no_compress = true`.
- Assert `rncp::send()` does not return success on the first segment. After it
  returns on the final proof, wait for the listener's asynchronous file write
  and compare source and destination bytes exactly. The protocol guarantees
  final resource assembly/proof, not that the application event consumer has
  completed its filesystem write before the proof reaches the sender.
- Assert the saved path's filename is exactly the advertised source filename
  (for example `payload.bin`) and that no generic `rncp.incoming` fallback file
  appears. This directly covers retention of segment-one metadata through the
  final event.
- This one test should regress F3, F5, G2, and the rncp-facing portion of F6.

## Phase 5 — Attribute remote blackholes to the publisher

Files:

- `reticulum-discovery/src/lib.rs`
- `src/transport/blackholes.rs`

Changes:

- Capture `desc.identity.address_hash` before moving `desc` into
  `transport.link(desc)`.
- Pass that publisher identity hash as the `source` argument when inserting
  every decoded `/list` entry. Do not use `transport.identity_hash()`, which is
  the updater's local identity and is intentionally exempt from expiry.
- Keep identity entries as raw 16-byte hashes; do not re-hash the list values.
- Reuse `Blackholes::merge_list()` for the MessagePack decode and merge instead
  of retaining the hand-written loop in `BlackholeUpdater::update_from()`.
  Acquire the write lock once for the whole response.
- Extend `merge_list()` (or add an equivalently named guarded remote-merge
  variant and make the unguarded form unavailable to remote callers) so it also
  receives the updater's local identity. For each decoded identity:

  - if an existing entry's source equals the local identity, skip it completely
    and preserve its source and timestamp;
  - otherwise insert or renew it with the publisher's source and current time;
    and
  - increment the returned count only when the identity was absent.

  This local-source guard is required for Python parity; it is not optional.
- Keep `Blackholes::with_clock()` as the test seam for expiry and renewal
  behavior.

Regression coverage in `src/transport/blackholes.rs` and
`reticulum-discovery/src/lib.rs`:

- Merge a valid publisher response where local updater identity, publisher
  identity, and blackholed identity are all distinct.
- Advance an injected clock past `BLACKHOLE_TIMEOUT`, call `clean(local_id)`,
  and assert the fetched entry expires. This proves its source is not local.
- Add a control entry sourced locally and assert it remains after the same
  cleanup.
- Merge a remote list containing that locally sourced identity and assert its
  source/timestamp remain local/unchanged rather than being overwritten by the
  publisher.
- Merge the same remote list twice and assert the second merge returns zero but
  renews the timestamp of entries that are remote-sourced.
- Verify malformed values and non-16-byte binary items remain ignored.

## Phase 6 — Verification matrix

Run focused checks while implementing each phase:

```bash
cargo test -p reticulum --lib resource::outbound
cargo test -p reticulum --lib resource::manager
cargo test -p reticulum --test split_resource -- --nocapture
cargo test -p reticulum --test resource_transfer -- --nocapture
cargo test -p reticulum-utils --test rncp_loopback -- --nocapture
cargo test -p reticulum-discovery --lib -- --nocapture
```

Then run the default checkout and CI-equivalent gates:

```bash
cargo fmt --all -- --check

RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets
RUSTFLAGS="-D warnings" cargo clippy -p reticulum --all-targets --all-features
RUSTFLAGS="-D warnings" cargo clippy -p reticulum-core \
  --no-default-features --features="embassy-time"

# Must not require RETICULUM_TEST_PYTHON_DIR.
env -u RETICULUM_TEST_PYTHON_DIR -u PYTHONPATH \
  cargo test --workspace --all-targets

# CI libtest selection; requires the Python checkout configured by CI.
cargo test --workspace --lib --bins --tests --examples \
  --features="python-tests" -- --no-capture

cargo bench --workspace --no-run
cargo test -p reticulum-core --all-targets \
  --no-default-features --features="embassy-time"
cargo test -p reticulum --features bz2 --test resource_transfer
```

For the Python-enabled command, verify the test listing includes the four tests
from `python_middle`; for the default command, verify none of them execute.

## Suggested implementation/commit order

1. **Test entry points:** F1 and F2. This restores a trustworthy baseline and
   prevents unrelated failures from obscuring resource work.
2. **Outbound split invariants:** F5 and F6, with range and option unit tests.
3. **Assembly and event lifecycle:** F4, F7, G1, G2, and G4, with
   split-response, metadata, cleanup, event-correlation, and progress tests.
4. **rncp logical completion:** F3, followed by the large metadata-bearing
   no-compress loopback test that exercises phases 2–4 together.
5. **Discovery attribution:** F8 and its clock-driven expiry test.
6. **Full matrix:** formatting, warnings-as-errors Clippy, default tests,
   Python-enabled tests, benchmark compilation, embedded-time tests, and the bz2
   resource matrix.

Keeping those boundaries makes failures easy to bisect while respecting the
dependency chain: rncp completion is only meaningful after the core split
engine produces correct final segments and events.

## Definition of done

- The CI test job no longer passes `--no-capture` to `hot_paths`, and the
  Criterion target still compiles.
- `cargo test --workspace --all-targets` succeeds without a Python checkout.
- Python-middle tests still run when `python-tests` is enabled.
- A metadata-bearing payload above `MAX_EFFICIENT_SIZE` round-trips byte-for-byte
  with no duplicated boundary bytes.
- `auto_compress = false`, explicit timeout, request ID, and response flag remain
  unchanged on every segment.
- A split response larger than `MAX_EFFICIENT_SIZE` is returned by
  `await_request_response()` and remains available to a late awaiter.
- rncp reports success only after the final segment is assembled and proved;
  the listener subsequently writes the exact complete file under the advertised
  filename from that event.
- A watchdog failure of segment two or later carries its advertisement and
  causes rncp to fail promptly instead of waiting for its overall deadline.
- Sender completion progress stays below 100% until the final segment.
- Failed, corrupt, and cancelled split transfers leave no entry in
  `split_assembly`; valid completed non-final segments still retain their bytes.
- Blackholes fetched from a publisher expire after `BLACKHOLE_TIMEOUT`, while
  locally sourced entries retain the existing non-expiring behavior and cannot
  be reattributed by a remote merge.
- All focused and full verification commands above pass.
