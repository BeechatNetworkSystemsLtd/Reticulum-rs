use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::hash::AddressHash;
use crate::packet::Packet;

const CAPACITY_TOTAL: usize = 100_000;
const CAPACITY_PER_DEST: usize = 10_000;
const MAX_SEND_AT_ONCE: usize = 5_000;

pub struct StoreAndForward {
    packets: BTreeMap<AddressHash, Vec<Packet>>,
    found: BTreeSet<AddressHash>,
    name: String,
    total_packets: usize,
}

impl StoreAndForward {
    pub fn new(name: String) -> Self {
        Self {
            packets: BTreeMap::new(),
            found: BTreeSet::new(),
            name,
            total_packets: 0,
        }
    }

    pub fn add(&mut self, destination: &AddressHash, packet: Packet) {
        if self.total_packets == CAPACITY_TOTAL {
            return;
        }

        let packets = self.packets.entry(*destination).or_default();
        if packets.len() >= CAPACITY_PER_DEST {
            return;
        }

        packets.push(packet);
        self.total_packets += 1;

        if packets.len() >= CAPACITY_PER_DEST {
            log::trace!(
                "tp({}): stored packets limit for unknown destination {} reached",
                self.name,
                destination
            );
        }

        if packets.len() >= CAPACITY_TOTAL {
            log::trace!(
                "tp({}): packet capacity for save and forward reached",
                self.name
            );
        }
    }

    pub fn destination_found(&mut self, destination: AddressHash) {
        self.found.insert(destination);
    }

    pub fn to_resend(&mut self) -> BTreeMap<AddressHash, Vec<Packet>> {
        let mut schedule = BTreeMap::new();
        let mut resent_packets = 0;

        let mut waiting = 0;
        for destination in &self.found {
            if let Some(packets) = self.packets.get(destination) {
                waiting += packets.len();
            }
        }

        let quota = if waiting > MAX_SEND_AT_ONCE {
            MAX_SEND_AT_ONCE * 1024 / waiting
        } else {
            1024
        };

        for destination in &self.found {
            if let Some(mut packets) = self.packets.remove(destination) {
                let mut send_now = quota * packets.len() / 1024;
                if send_now > MAX_SEND_AT_ONCE - resent_packets {
                    send_now = MAX_SEND_AT_ONCE - resent_packets
                };

                if send_now < packets.len() {
                    let send_later = packets.split_off(send_now);
                    self.packets.insert(*destination, send_later);
                }

                resent_packets += packets.len();
                log::error!("A {}", resent_packets);
                schedule.insert(*destination, packets);
            }

            if resent_packets >= MAX_SEND_AT_ONCE {
                break;
            }
        }

        self.total_packets -= resent_packets;

        log::trace!(
            "tp({}): forwarding {} stored packets to {} destinations, {} packets left",
            self.name,
            resent_packets,
            self.found.len(),
            self.total_packets
        );

        self.found.clear();

        schedule
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::ADDRESS_HASH_SIZE;

    #[test]
    fn few_packets() {
        let address1 = AddressHash::new_from_slice(&[1u8; ADDRESS_HASH_SIZE]);
        let address2 = AddressHash::new_from_slice(&[2u8; ADDRESS_HASH_SIZE]);
        let address3 = AddressHash::new_from_slice(&[3u8; ADDRESS_HASH_SIZE]);

        let packet1: Packet = Default::default();
        let packet2: Packet = Default::default();

        let mut testee = StoreAndForward::new("test".to_string());

        testee.add(&address1, Default::default());
        testee.add(&address2, Default::default());
        testee.add(&address3, Default::default());

        testee.destination_found(address1);
        testee.destination_found(address2);

        let result = testee.to_resend();

        assert!(result.get(&address1).unwrap().len() == 1);
        assert!(result.get(&address2).unwrap().len() == 1);
        assert!(!result.contains_key(&address3));

        testee.destination_found(address2);

        let result = testee.to_resend();

        assert!(!result.contains_key(&address1));
        assert!(!result.contains_key(&address2));
        assert!(!result.contains_key(&address3));

        testee.destination_found(address3);

        let result = testee.to_resend();

        assert!(result.get(&address3).unwrap().len() == 1);
    }

    #[test]
    fn many_packets() {
        // logic tested here may change in the future
        let address1 = AddressHash::new_from_slice(&[1u8; ADDRESS_HASH_SIZE]);
        let address2 = AddressHash::new_from_slice(&[2u8; ADDRESS_HASH_SIZE]);
        let address3 = AddressHash::new_from_slice(&[3u8; ADDRESS_HASH_SIZE]);

        let expected = MAX_SEND_AT_ONCE / 2;

        let mut testee = StoreAndForward::new("test".to_string());

        for _ in 0..(expected + 500) {
            testee.add(&address1, Default::default());
            testee.add(&address2, Default::default());
        }

        for _ in 0..100 {
            testee.add(&address3, Default::default());
        }

        testee.destination_found(address1);
        testee.destination_found(address2);

        let result = testee.to_resend();

        assert!(result.get(&address1).unwrap().len() <= expected);
        assert!(result.get(&address1).unwrap().len() >= expected - 1);
        assert!(result.get(&address2).unwrap().len() <= expected);
        assert!(result.get(&address2).unwrap().len() >= expected - 1);
    }
}
