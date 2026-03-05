use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::hash::AddressHash;
use crate::packet::Packet;

pub struct SaveAndForward {
    packets: BTreeMap<AddressHash, Vec<Packet>>,
    found: BTreeSet<AddressHash>,
}

impl SaveAndForward {
    pub fn new() -> Self {
        Self {
            packets: BTreeMap::new(),
            found: BTreeSet::new(),
        }
    }

    pub fn add(&mut self, destination: &AddressHash, packet: Packet) {
        if !self.packets.contains_key(destination) {
            self.packets.insert(*destination, Vec::new());
        }
        self.packets.get_mut(destination).unwrap().push(packet);
    }

    pub fn destination_found(&mut self, destination: AddressHash) {
        self.found.insert(destination);
    }

    pub fn to_resend(&mut self) -> BTreeMap<AddressHash, Vec<Packet>> {
        let mut schedule = BTreeMap::new();

        for destination in &self.found {
            if let Some(packets) = self.packets.remove(destination) {
                schedule.insert(*destination, packets);
            }
        }

        self.found.clear();

        schedule
    }
}
