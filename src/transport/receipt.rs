use crate::hash::{AddressHash, Hash};
use crate::identity::Identity;
use crate::packet::Packet;
use ed25519_dalek::{Signature, SIGNATURE_LENGTH};
use std::convert::TryInto;
use std::fmt;
use std::sync::{
    atomic::{AtomicBool, AtomicU8, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

type ReceiptCallback = Arc<dyn Fn(PacketReceipt) + Send + Sync>;

#[derive(Clone)]
pub struct PacketReceipt {
    inner: Arc<PacketReceiptInner>,
}

impl fmt::Debug for PacketReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketReceipt")
            .field("hash", &self.hash())
            .field("destination", &self.destination())
            .field("status", &self.status())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketReceiptStatus {
    Sent = 0,
    Delivered = 1,
    Failed = 2,
    Culled = 3,
}

impl From<PacketReceiptStatus> for u8 {
    fn from(value: PacketReceiptStatus) -> Self {
        value as u8
    }
}

impl From<u8> for PacketReceiptStatus {
    fn from(value: u8) -> Self {
        match value {
            1 => PacketReceiptStatus::Delivered,
            2 => PacketReceiptStatus::Failed,
            3 => PacketReceiptStatus::Culled,
            _ => PacketReceiptStatus::Sent,
        }
    }
}

struct PacketReceiptInner {
    hash: Hash,
    destination: AddressHash,
    identity: Identity,
    sent_at: Instant,
    concluded_at: Mutex<Option<Instant>>,
    timeout: Mutex<Duration>,
    status: AtomicU8,
    proved: AtomicBool,
    proof_packet: Mutex<Option<Packet>>,
    notify: Notify,
    callbacks: Mutex<CallbackSlots>,
}

struct CallbackSlots {
    delivery: Option<ReceiptCallback>,
    timeout: Option<ReceiptCallback>,
}

impl PacketReceipt {
    pub(crate) fn new(hash: Hash, destination: AddressHash, identity: Identity, timeout: Duration) -> Self {
        Self {
            inner: Arc::new(PacketReceiptInner {
                hash,
                destination,
                identity,
                sent_at: Instant::now(),
                concluded_at: Mutex::new(None),
                timeout: Mutex::new(timeout),
                status: AtomicU8::new(PacketReceiptStatus::Sent.into()),
                proved: AtomicBool::new(false),
                proof_packet: Mutex::new(None),
                notify: Notify::new(),
                callbacks: Mutex::new(CallbackSlots {
                    delivery: None,
                    timeout: None,
                }),
            }),
        }
    }

    pub fn hash(&self) -> Hash {
        self.inner.hash
    }

    pub fn destination(&self) -> AddressHash {
        self.inner.destination
    }

    pub fn status(&self) -> PacketReceiptStatus {
        PacketReceiptStatus::from(self.inner.status.load(Ordering::SeqCst))
    }

    pub fn sent_at(&self) -> Instant {
        self.inner.sent_at
    }

    pub fn concluded_at(&self) -> Option<Instant> {
        *self.inner.concluded_at.lock().unwrap()
    }

    pub fn round_trip_time(&self) -> Option<Duration> {
        self.concluded_at().map(|at| at.saturating_duration_since(self.sent_at()))
    }

    pub fn proved(&self) -> bool {
        self.inner.proved.load(Ordering::SeqCst)
    }

    pub fn proof_packet(&self) -> Option<Packet> {
        *self.inner.proof_packet.lock().unwrap()
    }

    pub fn set_timeout(&self, timeout: Duration) {
        *self.inner.timeout.lock().unwrap() = timeout;
    }

    pub fn set_delivery_callback<F>(&self, callback: F)
    where
        F: Fn(PacketReceipt) + Send + Sync + 'static,
    {
        self.inner.callbacks.lock().unwrap().delivery = Some(Arc::new(callback));
    }

    pub fn set_timeout_callback<F>(&self, callback: F)
    where
        F: Fn(PacketReceipt) + Send + Sync + 'static,
    {
        self.inner.callbacks.lock().unwrap().timeout = Some(Arc::new(callback));
    }

    pub async fn wait(&self) -> PacketReceiptStatus {
        if self.status() != PacketReceiptStatus::Sent {
            return self.status();
        }

        self.inner.notify.notified().await;
        self.status()
    }

    pub(crate) fn has_timed_out(&self, now: Instant) -> bool {
        let timeout = *self.inner.timeout.lock().unwrap();
        self.inner.sent_at + timeout <= now
    }

    pub(crate) fn mark_delivered(&self, proof_packet: Packet) -> bool {
        if self.transition_to(PacketReceiptStatus::Delivered) {
            self.inner.proved.store(true, Ordering::SeqCst);
            *self.inner.proof_packet.lock().unwrap() = Some(proof_packet);
            self.run_delivery_callback();
            true
        } else {
            false
        }
    }

    pub(crate) fn mark_timeout(&self) -> bool {
        if self.transition_to(PacketReceiptStatus::Failed) {
            self.run_timeout_callback();
            true
        } else {
            false
        }
    }

    pub(crate) fn mark_culled(&self) -> bool {
        if self.transition_to(PacketReceiptStatus::Culled) {
            self.run_timeout_callback();
            true
        } else {
            false
        }
    }

    pub(crate) fn validate_explicit_proof(&self, proof_hash: &Hash, signature: &[u8]) -> bool {
        if self.hash() != *proof_hash {
            return false;
        }

        self.validate_signature(signature, proof_hash)
    }

    pub(crate) fn validate_implicit_proof(&self, signature: &[u8]) -> bool {
        self.validate_signature(signature, &self.hash())
    }

    fn validate_signature(&self, signature_bytes: &[u8], message: &Hash) -> bool {
        if signature_bytes.len() != SIGNATURE_LENGTH {
            return false;
        }

        let Ok(signature_bytes) = signature_bytes.try_into() else {
            return false;
        };

        let signature = Signature::from_bytes(&signature_bytes);

        self.inner
            .identity
            .verify(message.as_slice(), &signature)
            .is_ok()
    }

    fn transition_to(&self, status: PacketReceiptStatus) -> bool {
        match self.inner.status.compare_exchange(
            PacketReceiptStatus::Sent.into(),
            status.into(),
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => {
                *self.inner.concluded_at.lock().unwrap() = Some(Instant::now());
                self.inner.notify.notify_waiters();
                true
            }
            Err(_) => false,
        }
    }

    fn run_delivery_callback(&self) {
        if let Some(callback) = self
            .inner
            .callbacks
            .lock()
            .unwrap()
            .delivery
            .clone()
        {
            let receipt = self.clone();
            tokio::spawn(async move {
                (callback)(receipt);
            });
        }
    }

    fn run_timeout_callback(&self) {
        if let Some(callback) = self
            .inner
            .callbacks
            .lock()
            .unwrap()
            .timeout
            .clone()
        {
            let receipt = self.clone();
            tokio::spawn(async move {
                (callback)(receipt);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Hash;
    use crate::identity::PrivateIdentity;
    use rand_core::OsRng;

    #[tokio::test]
    async fn receipt_waits_for_delivery() {
        let identity = PrivateIdentity::new_from_rand(OsRng).as_identity().clone();
        let receipt = PacketReceipt::new(
            Hash::new_from_rand(OsRng),
            AddressHash::new_from_rand(OsRng),
            identity,
            Duration::from_millis(100),
        );

        let worker = receipt.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            worker.mark_delivered(Packet::default());
        });

        assert_eq!(receipt.wait().await, PacketReceiptStatus::Delivered);
        assert!(receipt.proved());
        assert!(receipt.round_trip_time().is_some());
    }
}
