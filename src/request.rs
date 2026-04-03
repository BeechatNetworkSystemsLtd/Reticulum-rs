use alloc::sync::Arc;
use core::time::Duration;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use crate::hash::ADDRESS_HASH_SIZE;

pub const REQUEST_ID_LEN: usize = ADDRESS_HASH_SIZE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestStatus {
    Failed = 0x00,
    Sent = 0x01,
    Delivered = 0x02,
    Receiving = 0x03,
    Ready = 0x04,
}

#[derive(Clone, Default)]
pub struct RequestCallbacks {
    pub response: Option<Arc<dyn Fn(RequestReceiptHandle) + Send + Sync>>,
    pub failed: Option<Arc<dyn Fn(RequestReceiptHandle) + Send + Sync>>,
    pub progress: Option<Arc<dyn Fn(RequestReceiptHandle) + Send + Sync>>,
}

pub struct RequestReceipt {
    pub request_id: [u8; REQUEST_ID_LEN],
    pub status: RequestStatus,
    pub response: Option<Vec<u8>>,
    pub progress: f32,
    pub sent_at: Instant,
    pub concluded_at: Option<Instant>,
    pub timeout: Duration,
    callbacks: RequestCallbacks,
}

pub type RequestReceiptHandle = Arc<Mutex<RequestReceipt>>;

impl RequestReceipt {
    pub fn get_status(&self) -> RequestStatus {
        self.status
    }

    pub fn get_response(&self) -> Option<&[u8]> {
        self.response.as_deref()
    }

    pub fn get_progress(&self) -> f32 {
        self.progress
    }
}

#[derive(Default)]
pub struct RequestTracker {
    pending: HashMap<[u8; REQUEST_ID_LEN], RequestReceiptHandle>,
}

impl RequestTracker {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
        }
    }

    pub fn register_request(
        &mut self,
        request_id: [u8; REQUEST_ID_LEN],
        timeout: Duration,
        callbacks: RequestCallbacks,
    ) -> RequestReceiptHandle {
        let receipt = Arc::new(Mutex::new(RequestReceipt {
            request_id,
            status: RequestStatus::Sent,
            response: None,
            progress: 0.0,
            sent_at: Instant::now(),
            concluded_at: None,
            timeout,
            callbacks,
        }));
        self.pending.insert(request_id, receipt.clone());
        receipt
    }

    pub fn mark_delivered(&mut self, request_id: [u8; REQUEST_ID_LEN]) {
        if let Some(receipt) = self.pending.get(&request_id) {
            let mut receipt = receipt.lock().unwrap();
            if receipt.status == RequestStatus::Sent {
                receipt.status = RequestStatus::Delivered;
            }
        }
    }

    pub fn mark_receiving(&mut self, request_id: [u8; REQUEST_ID_LEN], progress: f32) {
        if let Some(receipt) = self.pending.get(&request_id) {
            let mut receipt = receipt.lock().unwrap();
            if receipt.status != RequestStatus::Failed {
                receipt.status = RequestStatus::Receiving;
                receipt.progress = progress;
            }
        }
        self.fire_progress(request_id);
    }

    pub fn record_response(&mut self, request_id: [u8; REQUEST_ID_LEN], response: Vec<u8>) -> bool {
        let receipt = match self.pending.remove(&request_id) {
            Some(receipt) => receipt,
            None => return false,
        };
        {
            let mut receipt_guard = receipt.lock().unwrap();
            if receipt_guard.status == RequestStatus::Failed {
                return false;
            }
            receipt_guard.response = Some(response);
            receipt_guard.progress = 1.0;
            receipt_guard.status = RequestStatus::Ready;
            receipt_guard.concluded_at = Some(Instant::now());
        }
        let callback = {
            let receipt_guard = receipt.lock().unwrap();
            receipt_guard.callbacks.response.clone()
        };
        if let Some(callback) = callback {
            callback(receipt.clone());
        }
        true
    }

    pub fn mark_failed(&mut self, request_id: [u8; REQUEST_ID_LEN]) {
        let receipt = match self.pending.remove(&request_id) {
            Some(receipt) => receipt,
            None => return,
        };
        {
            let mut receipt_guard = receipt.lock().unwrap();
            receipt_guard.status = RequestStatus::Failed;
            receipt_guard.concluded_at = Some(Instant::now());
        }
        let callback = {
            let receipt_guard = receipt.lock().unwrap();
            receipt_guard.callbacks.failed.clone()
        };
        if let Some(callback) = callback {
            callback(receipt.clone());
        }
    }

    pub fn poll_timeouts(&mut self, now: Instant) {
        let timed_out: Vec<[u8; REQUEST_ID_LEN]> = self
            .pending
            .iter()
            .filter_map(|(id, receipt)| {
                let receipt = receipt.lock().unwrap();
                if receipt.status == RequestStatus::Sent
                    || receipt.status == RequestStatus::Delivered
                    || receipt.status == RequestStatus::Receiving
                {
                    if now.duration_since(receipt.sent_at) >= receipt.timeout {
                        return Some(*id);
                    }
                }
                None
            })
            .collect();
        for request_id in timed_out {
            self.mark_failed(request_id);
        }
    }

    fn fire_progress(&self, request_id: [u8; REQUEST_ID_LEN]) {
        if let Some(receipt) = self.pending.get(&request_id) {
            if let Some(callback) = receipt.lock().unwrap().callbacks.progress.clone() {
                callback(receipt.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_tracker_times_out() {
        let mut tracker = RequestTracker::new();
        let req_id = [0x11u8; REQUEST_ID_LEN];
        let receipt = tracker.register_request(req_id, Duration::from_secs(1), RequestCallbacks::default());
        tracker.poll_timeouts(Instant::now() + Duration::from_secs(2));
        assert_eq!(receipt.lock().unwrap().status, RequestStatus::Failed);
    }
}
