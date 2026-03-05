use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::hash::AddressHash;
use crate::packet::Packet;

const CAPACITY_TOTAL: usize = 100_000;
const CAPACITY_PER_DEST: usize = 10_000;

pub struct SaveAndForward {
    packets: BTreeMap<AddressHash, Vec<Packet>>,
    found: BTreeSet<AddressHash>,
    name: String,
    total_packets: usize,
}

impl SaveAndForward {
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

        if !self.packets.contains_key(destination) {
            self.packets.insert(*destination, Vec::new());
        }

        let mut packets = self.packets.get_mut(destination).unwrap();
        if packets.len() >= CAPACITY_PER_DEST {
            return;
        }

        packets.push(packet);
        self.total_packets += 1;

        if packets.len() >= CAPACITY_PER_DEST {
            log::trace!(
                "tp({}): saved packets limit for unknown destination {} reached",
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

        for destination in &self.found {
            if let Some(packets) = self.packets.remove(destination) {
                resent_packets += packets.len();
                schedule.insert(*destination, packets);
            }
        }

        self.total_packets -= resent_packets;

        log::trace!(
            "tp({}): forwarding {} saved packets to {} destinations, {} packets left",
            self.name,
            resent_packets,
            self.found.len(),
            self.total_packets
        );

        self.found.clear();

        schedule
    }
}
