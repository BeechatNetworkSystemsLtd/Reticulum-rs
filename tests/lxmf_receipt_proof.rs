use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

use reticulum::packet::{Packet, PacketContext, PacketDataBuffer, PacketType};
use reticulum::transport::{DeliveryReceipt, ReceiptHandler, Transport, TransportConfig};

struct Counter {
    count: Arc<AtomicUsize>,
}

impl ReceiptHandler for Counter {
    fn on_receipt(&self, _receipt: &DeliveryReceipt) {
        self.count.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn proof_packet_emits_receipt() {
    let count = Arc::new(AtomicUsize::new(0));
    let handler = Counter { count: Arc::clone(&count) };

    let mut transport = Transport::new(TransportConfig::default());
    transport.set_receipt_handler(Box::new(handler)).await;

    let mut packet = Packet::default();
    packet.header.packet_type = PacketType::Proof;
    packet.context = PacketContext::None;
    packet.data = PacketDataBuffer::new_from_slice(&[1u8; 32]);

    transport.handle_inbound_for_test(packet).await;

    assert_eq!(count.load(Ordering::SeqCst), 1);
}
