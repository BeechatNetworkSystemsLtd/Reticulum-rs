# Makefile for Reticulum-rs mobile FFI bindings
#
# This is a `just` fallback.  Toolchain/target names below are the standard
# Rust/UniFFI ones; override the variables if your installation uses different
# names (e.g. `arm64-v8a` toolchains or different Apple triples).

SHELL            := /bin/bash

CARGO            ?= cargo
CARGO_NDK        ?= cargo-ndk
XCODEBUILD       ?= xcodebuild
LIPO             ?= lipo
SWIFTC           ?= swiftc
KOTLINC          ?= kotlinc
JNA_JAR          ?= /usr/share/java/jna.jar

UNIFFI_BINDGEN   ?= $(CARGO) run -p uniffi-bindgen --

PROFILE          ?= release

# -----------------------------------------------------------------------------
# Android configuration
# -----------------------------------------------------------------------------

# Target Rust triples for the Android builds.  Override if your NDK uses
# different triples (e.g. armv7-linux-androideabi).
ANDROID_TARGETS  ?= aarch64-linux-android x86_64-linux-android
ANDROID_API      ?= 21

# -----------------------------------------------------------------------------
# Apple configuration
# -----------------------------------------------------------------------------

APPLE_DEVICE_TARGET ?= aarch64-apple-ios
APPLE_SIM_TARGETS   ?= aarch64-apple-ios-sim x86_64-apple-ios
APPLE_MAC_TARGETS   ?= aarch64-apple-darwin x86_64-apple-darwin

# -----------------------------------------------------------------------------
# Output layout
# -----------------------------------------------------------------------------

KOTLIN_OUT       ?= reticulum-ffi/bindings/kotlin
SWIFT_OUT        ?= reticulum-ffi/bindings/swift
XC_FRAMEWORK     ?= reticulum-ffi/bindings/xcframework/ReticulumFfi.xcframework

# -----------------------------------------------------------------------------
# Recipes
# -----------------------------------------------------------------------------

.PHONY: all bindings bindings-android bindings-ios test-ffi build-host

all: bindings

# Host build used by `test-ffi` and as the UniFFI source on Linux CI.
build-host:
	$(CARGO) build -p reticulum-ffi

# Build the cdylib for Android targets and generate Kotlin bindings.
bindings-android:
	@if ! command -v $(CARGO_NDK) >/dev/null 2>&1; then \
		echo "Error: $(CARGO_NDK) is not installed. Install cargo-ndk or set CARGO_NDK."; \
		exit 1; \
	fi
	@for target in $(ANDROID_TARGETS); do \
		echo "=== Building reticulum-ffi for $$target ==="; \
		$(CARGO_NDK) -t $$target --platform $(ANDROID_API) build -p reticulum-ffi --$(PROFILE); \
	done
	@# UniFFI only needs one library to extract the interface; use the first target.
	@first_target=$$(echo $(ANDROID_TARGETS) | awk '{print $$1}'); \
	first_lib="target/$$first_target/$(PROFILE)/libreticulum_ffi.so"; \
	if [ ! -f "$$first_lib" ]; then \
		echo "Error: expected $$first_lib not found."; \
		exit 1; \
	fi; \
	$(UNIFFI_BINDGEN) generate --no-format --library "$$first_lib" --language kotlin --out-dir $(KOTLIN_OUT)
	@# Package the per-ABI .so files into an Android-style jniLibs tree.
	@for target in $(ANDROID_TARGETS); do \
		case "$$target" in \
			aarch64-linux-android) abi=arm64-v8a ;; \
			x86_64-linux-android)  abi=x86_64 ;; \
			*)                     abi="$$target" ;; \
		esac; \
		lib="target/$$target/$(PROFILE)/libreticulum_ffi.so"; \
		mkdir -p "$(KOTLIN_OUT)/jniLibs/$$abi"; \
		cp "$$lib" "$(KOTLIN_OUT)/jniLibs/$$abi/libreticulum_ffi.so"; \
	done
	@echo "Android bindings ready in $(KOTLIN_OUT)"

# Build cdylib/staticlib for Apple targets, generate Swift, and package an
# Xcode-friendly "XCFramework-ish" tree.
bindings-ios:
	@for target in $(APPLE_DEVICE_TARGET) $(APPLE_SIM_TARGETS) $(APPLE_MAC_TARGETS); do \
		echo "=== Building reticulum-ffi for $$target ==="; \
		$(CARGO) build -p reticulum-ffi --target $$target --$(PROFILE); \
	done
	@# Generate the Swift bindings from the first built macOS library found.
	@generated=0; \
	for target in $(APPLE_MAC_TARGETS); do \
		for ext in dylib a; do \
			lib="target/$$target/$(PROFILE)/libreticulum_ffi.$$ext"; \
			if [ -f "$$lib" ]; then \
				$(UNIFFI_BINDGEN) generate --no-format --library "$$lib" --language swift --out-dir $(SWIFT_OUT); \
				generated=1; \
				break 2; \
			fi; \
		done; \
	done; \
	if [ "$$generated" -ne 1 ]; then \
		echo "Error: no macOS library found to generate Swift bindings."; \
		exit 1; \
	fi
	@# Build the XCFramework-ish directory tree.
	@rm -rf "$(XC_FRAMEWORK)"
	@mkdir -p "$(XC_FRAMEWORK)/ios-arm64" \
		"$(XC_FRAMEWORK)/ios-simulator-arm64" \
		"$(XC_FRAMEWORK)/ios-simulator-x86_64" \
		"$(XC_FRAMEWORK)/macos-arm64" \
		"$(XC_FRAMEWORK)/macos-x86_64"
	@cp "target/$(APPLE_DEVICE_TARGET)/$(PROFILE)/libreticulum_ffi.a" \
		"$(XC_FRAMEWORK)/ios-arm64/libreticulum_ffi.a"
	@for target in $(APPLE_SIM_TARGETS); do \
		case "$$target" in \
			aarch64-apple-ios-sim) dst=ios-simulator-arm64 ;; \
			x86_64-apple-ios)      dst=ios-simulator-x86_64 ;; \
			*)                     dst="$$target" ;; \
		esac; \
		cp "target/$$target/$(PROFILE)/libreticulum_ffi.a" \
			"$(XC_FRAMEWORK)/$$dst/libreticulum_ffi.a"; \
	done
	@for target in $(APPLE_MAC_TARGETS); do \
		case "$$target" in \
			aarch64-apple-darwin) dst=macos-arm64 ;; \
			x86_64-apple-darwin)  dst=macos-x86_64 ;; \
			*)                    dst="$$target" ;; \
		esac; \
		cp "target/$$target/$(PROFILE)/libreticulum_ffi.a" \
			"$(XC_FRAMEWORK)/$$dst/libreticulum_ffi.a"; \
	done
	@# Optional universal slices (simulator / macOS) when lipo is available.
	@if command -v $(LIPO) >/dev/null 2>&1; then \
		mkdir -p "$(XC_FRAMEWORK)/ios-arm64_x86_64-simulator"; \
		$(LIPO) -create -output "$(XC_FRAMEWORK)/ios-arm64_x86_64-simulator/libreticulum_ffi.a" \
			"$(XC_FRAMEWORK)/ios-simulator-arm64/libreticulum_ffi.a" \
			"$(XC_FRAMEWORK)/ios-simulator-x86_64/libreticulum_ffi.a" 2>/dev/null || true; \
	fi
	@# Copy the C header, module map, and Swift source into each slice.
	@for d in $(XC_FRAMEWORK)/*/; do \
		[ -d "$$d" ] || continue; \
		mkdir -p "$$d/Headers" "$$d/Modules"; \
		cp "$(SWIFT_OUT)/ReticulumFfiFFI.h"        "$$d/Headers/"; \
		cp "$(SWIFT_OUT)/ReticulumFfiFFI.modulemap" "$$d/Modules/module.modulemap"; \
	done
	@cp "$(SWIFT_OUT)/ReticulumFfi.swift" "$(XC_FRAMEWORK)/"
	@echo "iOS/Swift bindings ready in $(SWIFT_OUT) and $(XC_FRAMEWORK)"

# Run both mobile binding recipes.
bindings: bindings-android bindings-ios

# Run actor + FFI tests and, if the platform toolchains are present, type-check
# the generated Swift and Kotlin files.
test-ffi:
	$(CARGO) test -p reticulum-actor -p reticulum-ffi
	@if command -v $(SWIFTC) >/dev/null 2>&1; then \
		echo "=== Type-checking generated Swift files ==="; \
		swift_sources=$$(find "$(SWIFT_OUT)" -maxdepth 1 -name '*.swift' -type f); \
		$(SWIFTC) -typecheck \
			-I "$(SWIFT_OUT)" \
			-import-objc-header "$(SWIFT_OUT)/ReticulumFfiFFI.h" \
			$$swift_sources; \
	fi
	@if command -v $(KOTLINC) >/dev/null 2>&1; then \
		if [ -f "$(JNA_JAR)" ]; then \
			echo "=== Type-checking generated Kotlin files ==="; \
			kotlin_sources=$$(find "$(KOTLIN_OUT)" -name '*.kt' -type f); \
			$(KOTLINC) -cp "$(JNA_JAR)" -d /tmp/reticulum-kotlin-tc $$kotlin_sources; \
		else \
			echo "Warning: kotlinc found but JNA_JAR=$(JNA_JAR) is missing; skipping Kotlin type-check."; \
		fi; \
	fi


# ─────────────────────────────────────────────────────────────────────────────
# Mobile feature-matrix smoke test
# ─────────────────────────────────────────────────────────────────────────────
# Verifies that every interface feature the mobile bindings advertise actually
# compiles into the FFI library, for each mobile target. Needs cargo-ndk for
# Android and the Apple toolchains for iOS; missing toolchains are skipped
# with a warning so the check can run on any dev machine.

ANDROID_SMOKE_TARGETS ?= aarch64-linux-android x86_64-linux-android
APPLE_SMOKE_TARGETS   ?= aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin

# Feature sets exercised by the mobile clients. The base set must always
# build; each optional capability builds on top of it.
FFI_BASE_FEATURES     ?=
FFI_FEATURE_MATRIX    ?= iface-auto iface-serial iface-i2p iface-rnode

mobile-smoke:
	@echo "=== Mobile feature-matrix smoke test ==="
	@rc=0; 	for feature in none $(FFI_FEATURE_MATRIX); do 		if [ "$$feature" = "none" ]; then feats=""; else feats="$$feature"; fi; 		echo "--- host check: reticulum-ffi [$$feats]"; 		$(CARGO) check -p reticulum-ffi $$( [ -n "$$feats" ] && echo --features $$feats ) || rc=1; 	done; 	if command -v $(CARGO_NDK) >/dev/null 2>&1; then 		for feature in $(FFI_FEATURE_MATRIX); do 			echo "--- android check: reticulum-ffi [--features $$feature]"; 			$(CARGO_NDK) build -p reticulum-ffi --library 				--targets $(ANDROID_SMOKE_TARGETS) 				--features $$feature || rc=1; 		done; 	else 		echo "Warning: cargo-ndk not found; skipping Android matrix."; 	fi; 	if command -v xcrun >/dev/null 2>&1 && xcrun --show-sdk-path --sdk iphoneos >/dev/null 2>&1; then 		for target in $(APPLE_SMOKE_TARGETS); do 			echo "--- apple check: reticulum-ffi [$$target]"; 			rustup target add $$target 2>/dev/null || true; 			$(CARGO) check -p reticulum-ffi --target $$target || rc=1; 		done; 	else 		echo "Warning: Apple toolchains not found; skipping iOS matrix."; 	fi; 	if [ $$rc -ne 0 ]; then echo "=== Mobile smoke FAILED ==="; exit 1; fi; 	echo "=== Mobile smoke OK ==="

.PHONY: mobile-smoke

# -----------------------------------------------------------------------------
# ESP32-C6 modem firmware (M5Stack Unit C6L)
# -----------------------------------------------------------------------------

C6_PORT         ?= /dev/ttyACM1
C6_DIR          := firmware/c6l-modem
C6_ELF          := $(C6_DIR)/target/riscv32imac-unknown-none-elf/release/c6l-modem

c6-build:
	cd $(C6_DIR) && $(CARGO) build --release

# Byte-exact backup of whatever runs on the board today (do this first!).
c6-backup:
	esptool --port $(C6_PORT) --chip esp32c6 read_flash 0x0 0x400000 \
		c6l_backup_$$(date +%Y%m%d_%H%M).bin

# espflash attaches the correct bootloader + partition table.
c6-flash: c6-build
	espflash flash --chip esp32c6 --port $(C6_PORT) $(C6_ELF)

# Host-side verification against the flashed board (KISS detect + radio
# config validation + packet RX log).
c6-verify:
	$(CARGO) run --example rnode_listen --features "iface-rnode,iface-serial" -- \
		--port $(C6_PORT)

# -----------------------------------------------------------------------------
# C6L modem firmware testing
# -----------------------------------------------------------------------------

c6-acceptance:
	python3 firmware/c6l-modem/tests/acceptance.py --port $(C6_PORT)

c6-stability:
	python3 firmware/c6l-modem/tests/stability.py --port $(C6_PORT) --cycles 5

c6-soak:
	bash firmware/c6l-modem/tests/soak.sh $(C6_PORT) 115

c6-test: c6-acceptance c6-stability c6-soak
	@echo "=== all c6l-modem tests passed ==="

# -----------------------------------------------------------------------------
# ESP32-S3 Cardputer Advanced chat firmware
# -----------------------------------------------------------------------------

PORT            ?= /dev/ttyACM2
CARD_DIR        := firmware/cardputer-idf
CARD_ELF        := $(CARD_DIR)/target/xtensa-esp32s3-espidf/release/cardputer-idf

card-build:
	cd $(CARD_DIR) && . /home/lio/export-esp.sh && \
		export LD_LIBRARY_PATH="/home/lio/Android/Sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/linux-x86_64/lib:$$LD_LIBRARY_PATH" && \
		$(CARGO) +esp build --release

card-flash: card-build
	sudo ~/.cargo/bin/espflash flash --port $(PORT) --partition-table $(CARD_DIR)/partitions.csv $(CARD_ELF)

card-monitor:
	sudo ~/.cargo/bin/espflash monitor --port $(PORT)

.PHONY: card-build card-flash card-monitor
