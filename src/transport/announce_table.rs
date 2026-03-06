use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use tokio::time::{Duration, Instant};

use crate::hash::AddressHash;
use crate::iface::{TxMessage, TxMessageType};
use crate::packet::{
    DestinationType, Header, HeaderType, IfacFlag,
    Packet, PacketContext, PacketType, PropagationType
};

#[derive(Clone)]
pub struct AnnounceEntry {
    pub packet: Packet,
    pub timestamp: Instant,
    pub timeout: Instant,
    pub received_from: AddressHash,
    pub retries: u8,
    pub hops: u8,
    pub response_to_iface: Option<AddressHash>,
}

impl AnnounceEntry {
    pub fn retransmit(
        &mut self,
        transport_id: &AddressHash,
    ) -> Option<TxMessage> {
        if self.retries == 0 || Instant::now() >= self.timeout {
            return None;
        }

        self.retries = self.retries.saturating_sub(1);

        let context = if self.response_to_iface.is_some() {
            PacketContext::PathResponse
        } else {
            PacketContext::None
        };

        let packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type2,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: self.hops,
            },
            ifac: None,
            destination: self.packet.destination,
            transport: Some(transport_id.clone()),
            context,
            data: self.packet.data,
        };

        let tx_type = match self.response_to_iface {
            Some(iface) => TxMessageType::Direct(iface),
            None => TxMessageType::Broadcast(Some(self.received_from)),
        };

        Some(TxMessage { tx_type, packet })

    }
}

struct AnnounceCache {
    newer: Option<BTreeMap<AddressHash, AnnounceEntry>>,
    older: Option<BTreeMap<AddressHash, AnnounceEntry>>,
    capacity: usize
}

impl AnnounceCache {
    fn new(capacity: usize) -> Self {
        Self {
            newer: Some(BTreeMap::new()),
            older: None,
            capacity
        }
    }

    fn insert(&mut self, destination: AddressHash, entry: AnnounceEntry) {
        if self.newer.as_ref().unwrap().len() >= self.capacity {
            self.older = Some(self.newer.take().unwrap());
            self.newer = Some(BTreeMap::new());
        }

        self.newer.as_mut().unwrap().insert(destination, entry);
    }

    fn get(&self, destination: &AddressHash) -> Option<AnnounceEntry> {
        if let Some(ref entry) = self.newer.as_ref().unwrap().get(destination) {
            return Some(AnnounceEntry::clone(entry));
        }

        if let Some(ref older) = self.older {
            return older.get(destination).map(|entry| entry.clone());
        }

        return None;
    }

    fn clear(&mut self) {
        self.newer.as_mut().unwrap().clear();
        self.older = None;
    }
}

pub struct AnnounceTable {
    map: BTreeMap<AddressHash, AnnounceEntry>,
    responses: BTreeMap<AddressHash, AnnounceEntry>,
    cache: AnnounceCache,
}

impl AnnounceTable {
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
            responses: BTreeMap::new(),
            cache: AnnounceCache::new(100000), // TODO make capacity configurable
        }
    }

    pub fn add(
        &mut self,
        announce: &Packet,
        destination: AddressHash,
        received_from: AddressHash
    ) {
        if self.map.contains_key(&destination) {
            return;
        }

        let now = Instant::now();
        let hops = announce.header.hops + 1;

        let entry = AnnounceEntry {
            packet: announce.clone(),
            timestamp: now,
            timeout: now + Duration::from_secs(60),
            received_from,
            retries: 5, // TODO: make this configurable too?
            hops,
            response_to_iface: None,
        };

        self.map.insert(destination, entry);
    }

    fn do_add_response(
        &mut self,
        mut response: AnnounceEntry,
        destination: AddressHash,
        to_iface: AddressHash,
        hops: u8,
    ) {
        response.retries = 1;
        response.hops = hops;
        response.timeout = Instant::now() + Duration::from_secs(60);
        response.response_to_iface = Some(to_iface);

        self.responses.insert(destination, response);
    }

    pub fn add_response(
        &mut self,
        destination: AddressHash,
        to_iface: AddressHash,
        hops: u8
    ) -> bool {
        if let Some(entry) = self.map.get(&destination) {
            self.do_add_response(entry.clone(), destination, to_iface, hops);
            return true;
        }

        if let Some(entry) = self.cache.get(&destination) {
            self.do_add_response(entry.clone(), destination, to_iface, hops);
            return true;
        }

        false
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.responses.clear();
        self.cache.clear();
    }

    pub fn new_packet(
        &mut self,
        dest_hash: &AddressHash,
        transport_id: &AddressHash,
    ) -> Option<TxMessage> {
        // temporary hack
        self.map.get_mut(dest_hash).map_or(None, |e| e.retransmit(transport_id))
    }

    pub fn to_retransmit(
        &mut self,
        transport_id: &AddressHash,
    ) -> Vec<TxMessage> {
        let mut messages = vec![];
        let mut completed = vec![];

        for (destination, ref mut entry) in &mut self.map {
            if self.responses.contains_key(destination) {
                continue;
            }

            if let Some(message) = entry.retransmit(transport_id) {
                messages.push(message);
            } else {
                completed.push(destination.clone());
            }
        }

        let n_announces = messages.len();

        for (_, ref mut entry) in &mut self.responses {
            if let Some(message) = entry.retransmit(transport_id) {
                messages.push(message);
            }
        }

        let n_responses = messages.len() - n_announces;

        self.responses.clear(); // every response is only retransmitted once

        if !(messages.is_empty() && completed.is_empty()) {
            log::trace!(
                "Announce cache: {} retransmitted, {} path responses, {} dropped",
                n_announces,
                n_responses,
                completed.len(),
            );
        }

        for destination in completed {
            if let Some(announce) = self.map.remove(&destination) {
                self.cache.insert(destination, announce);
            }
        }

        messages
    }
}
