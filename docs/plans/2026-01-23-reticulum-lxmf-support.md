# Reticulum-rs LXMF Support Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add missing Reticulum-rs capabilities required for a full LXMF Rust stack: signing/verifying helpers, destination hash compatibility, delivery receipt hooks, GROUP destination encryption, and packet sizing/fragmentation alignment.

**Architecture:** Extend Reticulum-rs with explicit public APIs that LXMF can call without reaching into internal modules. Implement minimal surface changes first (helpers/wrappers), then add transport callbacks and GROUP encryption primitives, and finally alignment checks for packet sizing/fragmentation.

**Tech Stack:** Rust 2021, existing Reticulum-rs modules (identity, destination, transport, packet, crypt), tests under `tests/`.

---

### Task 1: Public signing/verification helpers for LXMF

**Files:**
- Modify: `src/identity.rs`
- Modify: `src/lib.rs`
- Test: `tests/lxmf_signature.rs`

**Step 1: Write the failing test**

```rust
// tests/lxmf_signature.rs
use reticulum::identity::{Identity, PrivateIdentity};

#[test]
fn lxmf_sign_and_verify_helpers() {
    let signer = PrivateIdentity::new_from_name("lxmf-sign");
    let identity: &Identity = signer.as_identity();
    let data = b"lxmf-data";

    let signature = reticulum::identity::lxmf_sign(&signer, data);
    assert!(reticulum::identity::lxmf_verify(identity, data, &signature));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -q`
Expected: FAIL with missing `lxmf_sign`/`lxmf_verify`.

**Step 3: Write minimal implementation**

```rust
// src/identity.rs
pub fn lxmf_sign(identity: &PrivateIdentity, data: &[u8]) -> [u8; ed25519_dalek::SIGNATURE_LENGTH] {
    identity.sign(data).to_bytes()
}

pub fn lxmf_verify(identity: &Identity, data: &[u8], signature: &[u8]) -> bool {
    let signature = match ed25519_dalek::Signature::from_slice(signature) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    identity.verify(data, &signature).is_ok()
}
```

Ensure `src/lib.rs` re-exports these helpers if needed for the crate public API.

**Step 4: Run test to verify it passes**

Run: `cargo test -q`
Expected: PASS

**Step 5: Commit**

```bash
git add src/identity.rs src/lib.rs tests/lxmf_signature.rs
git commit -m "feat: add lxmf signing helpers"
```

---

### Task 2: Destination hash compatibility helper

**Files:**
- Modify: `src/hash.rs`
- Modify: `src/lib.rs`
- Test: `tests/lxmf_address_hash.rs`

**Step 1: Write the failing test**

```rust
// tests/lxmf_address_hash.rs
use reticulum::hash::{AddressHash, Hash};

#[test]
fn lxmf_address_hash_uses_first_16_bytes() {
    let hash = Hash::new_from_slice(b"hello");
    let addr = reticulum::hash::lxmf_address_hash(&hash);
    assert_eq!(addr.as_slice().len(), 16);
    assert_eq!(addr.as_slice(), &hash.as_slice()[0..16]);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -q`
Expected: FAIL with missing `lxmf_address_hash`.

**Step 3: Write minimal implementation**

```rust
// src/hash.rs
pub fn lxmf_address_hash(hash: &Hash) -> AddressHash {
    AddressHash::new_from_hash(hash)
}
```

Re-export in `src/lib.rs` if required.

**Step 4: Run test to verify it passes**

Run: `cargo test -q`
Expected: PASS

**Step 5: Commit**

```bash
git add src/hash.rs src/lib.rs tests/lxmf_address_hash.rs
git commit -m "feat: add lxmf address hash helper"
```

---

### Task 3: Delivery receipt callbacks in transport

**Files:**
- Modify: `src/transport.rs`
- Modify: `src/lib.rs`
- Test: `tests/lxmf_receipt_callbacks.rs`

**Step 1: Write the failing test**

```rust
// tests/lxmf_receipt_callbacks.rs
use reticulum::transport::{DeliveryReceipt, ReceiptHandler, Transport};

struct Tracker { called: std::sync::Mutex<bool> }
impl ReceiptHandler for Tracker {
    fn on_receipt(&self, _receipt: &DeliveryReceipt) {
        *self.called.lock().unwrap() = true;
    }
}

#[test]
fn transport_emits_delivery_receipt_callback() {
    let handler = Tracker { called: std::sync::Mutex::new(false) };
    let mut transport = Transport::default();
    transport.set_receipt_handler(Box::new(handler));

    // This should trigger the callback in the minimal implementation.
    transport.emit_receipt_for_test(DeliveryReceipt::new([0u8; 32]));

    // Verify callback flag set.
    // (Access via handler in transport or add getter for test.)
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -q`
Expected: FAIL with missing `DeliveryReceipt`, `ReceiptHandler`, or `emit_receipt_for_test`.

**Step 3: Write minimal implementation**

```rust
// src/transport.rs
pub struct DeliveryReceipt { pub message_id: [u8; 32] }
impl DeliveryReceipt { pub fn new(message_id: [u8; 32]) -> Self { Self { message_id } } }

pub trait ReceiptHandler: Send + Sync {
    fn on_receipt(&self, receipt: &DeliveryReceipt);
}

impl Transport {
    pub fn set_receipt_handler(&mut self, handler: Box<dyn ReceiptHandler>) {
        self.receipt_handler = Some(handler);
    }

    pub fn emit_receipt_for_test(&self, receipt: DeliveryReceipt) {
        if let Some(handler) = &self.receipt_handler {
            handler.on_receipt(&receipt);
        }
    }
}
```

Store `receipt_handler` in `Transport` struct (add field) and wire into existing packet receive path later.

**Step 4: Run test to verify it passes**

Run: `cargo test -q`
Expected: PASS

**Step 5: Commit**

```bash
git add src/transport.rs src/lib.rs tests/lxmf_receipt_callbacks.rs
git commit -m "feat: add delivery receipt callbacks"
```

---

### Task 4: GROUP destination encryption helpers

**Files:**
- Modify: `src/destination.rs`
- Modify: `src/lib.rs`
- Test: `tests/lxmf_group_encrypt.rs`

**Step 1: Write the failing test**

```rust
// tests/lxmf_group_encrypt.rs
use reticulum::destination::group_encrypt;

#[test]
fn group_encrypt_roundtrip() {
    let key = [7u8; 16];
    let plaintext = b"hello";
    let ciphertext = group_encrypt(&key, plaintext).unwrap();
    let decoded = reticulum::destination::group_decrypt(&key, &ciphertext).unwrap();
    assert_eq!(decoded, plaintext);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -q`
Expected: FAIL with missing group encryption helpers.

**Step 3: Write minimal implementation**

```rust
// src/destination.rs
pub fn group_encrypt(key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, RnsError> {
    // Placeholder: use existing fernet/aes helper or symmetric crypto module
    crate::crypt::fernet::Fernet::new_from_slices(key, key, rand::thread_rng())
        .encrypt(crate::crypt::fernet::PlainText::from(data), &mut vec![0u8; data.len() + 64])
        .map(|t| t.as_bytes().to_vec())
}

pub fn group_decrypt(key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, RnsError> {
    let token = crate::crypt::fernet::Token::from_slice(data)?;
    let verified = crate::crypt::fernet::Fernet::new_from_slices(key, key, rand::thread_rng()).verify(token)?;
    Ok(verified.as_bytes().to_vec())
}
```

Adjust to use actual symmetric API that exists in Reticulum-rs (might require a small helper in `crypt`).

**Step 4: Run test to verify it passes**

Run: `cargo test -q`
Expected: PASS

**Step 5: Commit**

```bash
git add src/destination.rs src/lib.rs tests/lxmf_group_encrypt.rs
git commit -m "feat: add group encryption helpers"
```

---

### Task 5: Packet size/fragmentation alignment checks

**Files:**
- Modify: `src/packet.rs`
- Modify: `src/transport.rs`
- Test: `tests/lxmf_packet_limits.rs`

**Step 1: Write the failing test**

```rust
// tests/lxmf_packet_limits.rs
use reticulum::packet::Packet;

#[test]
fn packet_fragmentation_respects_limit() {
    let data = vec![0u8; 4096];
    let packets = Packet::fragment_for_lxmf(&data).unwrap();
    assert!(packets.iter().all(|p| p.data.len() <= Packet::LXMF_MAX_PAYLOAD));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -q`
Expected: FAIL with missing `fragment_for_lxmf` or `LXMF_MAX_PAYLOAD`.

**Step 3: Write minimal implementation**

```rust
// src/packet.rs
impl Packet {
    pub const LXMF_MAX_PAYLOAD: usize = 1024; // adjust per Reticulum constraints

    pub fn fragment_for_lxmf(data: &[u8]) -> Result<Vec<Packet>, RnsError> {
        let mut out = Vec::new();
        for chunk in data.chunks(Self::LXMF_MAX_PAYLOAD) {
            let mut packet = Packet::new();
            packet.data = chunk.to_vec();
            out.push(packet);
        }
        Ok(out)
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -q`
Expected: PASS

**Step 5: Commit**

```bash
git add src/packet.rs src/transport.rs tests/lxmf_packet_limits.rs
git commit -m "feat: add lxmf packet limits"
```

---

**Plan complete.**
