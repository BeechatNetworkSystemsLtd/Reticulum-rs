# Agent Notes

## UniFFI / Kotlin + Swift FFI for Reticulum-rs

A new workspace crate `reticulum-actor` holds the pure-Rust actor engine, and `reticulum-ffi` is the thin UniFFI skin over it.

### Build

```bash
cargo build -p reticulum-actor
cargo build -p reticulum-ffi
```

This produces the C shared library at:

- `target/debug/libreticulum_ffi.so` (Linux)
- `target/debug/libreticulum_ffi.dylib` (macOS)
- `target/debug/reticulum_ffi.dll` (Windows)

#### Mobile build recipes (`Makefile`)

`just` is not installed in this environment, so a `Makefile` is provided as the fallback. If `just` is installed elsewhere, the recipe names map directly.

- `make bindings-android` — builds the `cdylib` for `aarch64-linux-android` and `x86_64-linux-android` with `cargo-ndk`, runs `uniffi-bindgen` for Kotlin into `reticulum-ffi/bindings/kotlin`, and packages per-ABI `.so` files into `reticulum-ffi/bindings/kotlin/jniLibs/`.
- `make bindings-ios` — builds `cdylib`/`staticlib` for the Apple targets (`aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`, `aarch64-apple-darwin`, `x86_64-apple-darwin`), runs `uniffi-bindgen` for Swift into `reticulum-ffi/bindings/swift`, and assembles an `XCFramework`-ish tree under `reticulum-ffi/bindings/xcframework/ReticulumFfi.xcframework/`.
- `make bindings` — runs both `bindings-android` and `bindings-ios`.
- `make test-ffi` — runs `cargo test -p reticulum-actor -p reticulum-ffi` and, if `swiftc` and `kotlinc` are available, type-checks the generated Swift and Kotlin files.

Override variables at the top of the `Makefile` (e.g. `CARGO_NDK`, `ANDROID_TARGETS`, `APPLE_*_TARGETS`) if your toolchain uses different triples or wrappers.

### Test

```bash
cargo test -p reticulum-actor
cargo test -p reticulum-ffi
```

### Acceptance and FFI callback tests (gap closure)

- `reticulum-actor/tests/integration.rs` — two-actor acceptance tests over
  real interfaces (TCP, mock `TransportBridge`, shared instance) covering
  requests, LXMF delivery, propagation sync, LXST calls, resources,
  discovery, and the audio-policy paths. These tests start real actors;
  run them single-threaded when debugging a single flow:
  `cargo test -p reticulum-actor --test integration -- --test-threads=1`.
- `reticulum-ffi/tests/ffi_callbacks.rs` — `AppReconciler` implemented in
  Rust, `listen_for_updates`/`stop_listening` lifecycle, and dispatch
  coverage across the `AppAction` surface.
- `reticulum-actor/tests/perf_floor.rs` — absolute throughput floors that
  fail CI on regressions; `reticulum-actor/benches/actor.rs` holds the
  criterion benchmarks (`cargo bench -p reticulum-actor`).
- `make mobile-smoke` — mobile feature-matrix build check.
- After changing the FFI surface, regenerate and commit the bindings (CI
  fails on drift): `make bindings-android` or the uniffi-bindgen command
  above, then commit `reticulum-ffi/bindings/`.


`reticulum-actor/tests/actor.rs` is the headless lifecycle test, and `reticulum-ffi/tests/ffi_app.rs` exercises the same `Start`/`Stop` flow through the UniFFI surface.

### Generate Kotlin bindings

```bash
cargo run -p uniffi-bindgen -- generate --library target/debug/libreticulum_ffi.so --language kotlin --out-dir reticulum-ffi/bindings/kotlin
```

The generated Kotlin file is written to:

- `reticulum-ffi/bindings/kotlin/com/reticulum/ffi/rust/reticulum_ffi.kt`

#### Convenience recipe

```bash
make bindings-android
```

This builds the Android `cdylib` targets, regenerates the Kotlin binding above, and also copies the per-ABI `.so` files into:

- `reticulum-ffi/bindings/kotlin/jniLibs/arm64-v8a/libreticulum_ffi.so`
- `reticulum-ffi/bindings/kotlin/jniLibs/x86_64/libreticulum_ffi.so`

The `reticulum_ffi.kt` file is the single Kotlin surface for the M1–M5 engine; it grows in place as new records, enums, and objects are added to `reticulum-ffi/src/lib.rs`.

### Android / Kotlin usage

- The generated bindings require [JNA](https://github.com/java-native-access/jna) in the consuming Kotlin/Java project.
- Load `libreticulum_ffi.so` from the app, then use `FfiApp(dataDir)`, `dispatch`, `state`, and `listenForUpdates`.

### Generate Swift bindings

```bash
cargo run -p uniffi-bindgen -- generate --library target/debug/libreticulum_ffi.so --language swift --out-dir reticulum-ffi/bindings/swift
```

The generated Swift files are written to:

- `reticulum-ffi/bindings/swift/ReticulumFfi.swift`
- `reticulum-ffi/bindings/swift/ReticulumFfiFFI.h`
- `reticulum-ffi/bindings/swift/ReticulumFfiFFI.modulemap`

#### Convenience recipe

```bash
make bindings-ios
```

This builds the Apple `cdylib`/`staticlib` targets, regenerates the Swift files above, and assembles an `XCFramework`-ish tree under:

- `reticulum-ffi/bindings/xcframework/ReticulumFfi.xcframework/`

The `ReticulumFfi.swift` file is the single Swift surface for the M1–M5 engine; it grows in place as new records, enums, and objects are added to `reticulum-ffi/src/lib.rs`.

### Verify Swift bindings (Linux)

With a Swift toolchain installed and `PATH` containing `swiftc`:

```bash
# Type-check the generated bindings
swiftc -typecheck \
  -I reticulum-ffi/bindings/swift \
  -import-objc-header reticulum-ffi/bindings/swift/ReticulumFfiFFI.h \
  reticulum-ffi/bindings/swift/ReticulumFfi.swift

# Build and run the full lifecycle check
swiftc -I reticulum-ffi/bindings/swift \
  -import-objc-header reticulum-ffi/bindings/swift/ReticulumFfiFFI.h \
  -L target/debug -lreticulum_ffi \
  reticulum-ffi/bindings/swift/ReticulumFfi.swift \
  reticulum-ffi/bindings/swift/ffi_lifecycle_test.swift \
  -o /tmp/swift-ffi-test

LD_LIBRARY_PATH=target/debug /tmp/swift-ffi-test
```

The test creates an `FfiApp`, dispatches `start`, and waits for a `FullState` with `NodeStatus.running`.

### iOS / macOS / Swift usage

- The `reticulum-ffi` crate builds both a `cdylib` and a `staticlib`, so it can be linked into an iOS/macOS app.
- Add the generated `ReticulumFfi.swift` and the `ReticulumFfiFFI` module map/header to the Xcode project.
- Implement `AppReconciler` and use `FfiApp(dataDir:)`, `dispatch(action:)`, `state()`, and `listenForUpdates(reconciler:)`.

### M1–M5 generated output layout

As the engine surface grows from M1 (interfaces / identity / path) through M5 (resources / discovery / shared instance), the same generated binding files accumulate the new records, enums, and objects. The output layout produced by the recipes above is:

```text
reticulum-ffi/
└── bindings/
    ├── kotlin/
    │   ├── com/reticulum/ffi/rust/
    │   │   └── reticulum_ffi.kt          # M1–M5 Kotlin surface
    │   └── jniLibs/
    │       ├── arm64-v8a/libreticulum_ffi.so
    │       └── x86_64/libreticulum_ffi.so
    ├── swift/
    │   ├── ReticulumFfi.swift            # M1–M5 Swift surface
    │   ├── ReticulumFfiFFI.h
    │   └── ReticulumFfiFFI.modulemap
    └── xcframework/
        └── ReticulumFfi.xcframework/
            ├── ReticulumFfi.swift
            ├── ios-arm64/
            │   ├── libreticulum_ffi.a
            │   ├── Headers/ReticulumFfiFFI.h
            │   └── Modules/module.modulemap
            ├── ios-simulator-arm64/
            │   ├── libreticulum_ffi.a
            │   ├── Headers/ReticulumFfiFFI.h
            │   └── Modules/module.modulemap
            ├── ios-simulator-x86_64/
            │   ├── libreticulum_ffi.a
            │   ├── Headers/ReticulumFfiFFI.h
            │   └── Modules/module.modulemap
            ├── macos-arm64/
            │   ├── libreticulum_ffi.a
            │   ├── Headers/ReticulumFfiFFI.h
            │   └── Modules/module.modulemap
            └── macos-x86_64/
                ├── libreticulum_ffi.a
                ├── Headers/ReticulumFfiFFI.h
                └── Modules/module.modulemap
```

When `lipo` is available, the recipe also creates a universal simulator slice:

- `reticulum-ffi/bindings/xcframework/ReticulumFfi.xcframework/ios-arm64_x86_64-simulator/libreticulum_ffi.a`

### Crate layout

- `reticulum-actor/src/lib.rs` — public re-exports.
- `reticulum-actor/src/types.rs` — engine records/enums (`State`, `Action`, `Update`, `NodeStatus`, etc.).
- `reticulum-actor/src/core.rs` — actor thread, `CoreState`, `Reticulum` integration, and the headless `App` handle.
- `reticulum-ffi/src/lib.rs` — exported UniFFI records, enums, `FfiApp`, `AppReconciler`, and conversion shims from `reticulum-actor` types.
- `uniffi-bindgen/` — helper crate to run `uniffi-bindgen` from the workspace.

### Cardputer firmware

- `firmware/cardputer-idf/` — standalone Reticulum + LXMF chat firmware for the M5Stack Cardputer Advanced (ESP32-S3); see its README for hardware, build/flash commands, and RAM constraints.
- `make card-build`, `make card-flash`, `make card-monitor` — ESP-IDF firmware targets; serial port defaults to `/dev/ttyACM2` (`PORT` override).
