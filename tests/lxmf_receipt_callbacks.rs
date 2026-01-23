use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

use reticulum::transport::{DeliveryReceipt, ReceiptHandler, Transport, TransportConfig};

struct Tracker {
    called: Arc<AtomicBool>,
}

impl ReceiptHandler for Tracker {
    fn on_receipt(&self, _receipt: &DeliveryReceipt) {
        self.called.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn transport_emits_delivery_receipt_callback() {
    let called = Arc::new(AtomicBool::new(false));
    let handler = Tracker { called: Arc::clone(&called) };
    let mut transport = Transport::new(TransportConfig::default());
    transport.set_receipt_handler(Box::new(handler)).await;

    transport.emit_receipt_for_test(DeliveryReceipt::new([0u8; 32]));

    assert!(called.load(Ordering::SeqCst));
}
