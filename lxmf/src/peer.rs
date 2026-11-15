//! LXMPeer - propagation node peer records.
//!
//! Port of the wire-relevant parts of `LXMF/LXMF/LXMPeer.py`: the `to_bytes`
//! / `from_bytes` serialisation of peer state, and the state constants used
//! on the wire during peering and sync. The Python class keeps peer
//! bookkeeping inside the owning `LXMRouter`; the message-store-indexed
//! handled/unhandled lists are represented here as plain transient-id lists.

use std::{string::String, vec::Vec};

use reticulum_core::hash::{AddressHash, Hash, HASH_SIZE};

use crate::error::LxmfError;
use crate::fields::FieldValue;

/// Link request path for peer sync offers.
pub const OFFER_REQUEST_PATH: &str = "/offer";
/// Link request path for client message fetches.
pub const MESSAGE_GET_PATH: &str = "/get";
/// Authenticated control path that schedules a peer sync.
pub const SYNC_REQUEST_PATH: &str = "/pn/peer/sync";
/// Authenticated control path that removes a peer.
pub const UNPEER_REQUEST_PATH: &str = "/pn/peer/unpeer";

/// Peer state: idle.
pub const IDLE: u8 = 0x00;
/// Peer state: sync link being established.
pub const LINK_ESTABLISHING: u8 = 0x01;
/// Peer state: sync link ready.
pub const LINK_READY: u8 = 0x02;
/// Peer state: sync offer sent.
pub const REQUEST_SENT: u8 = 0x03;
/// Peer state: offer response received.
pub const RESPONSE_RECEIVED: u8 = 0x04;
/// Peer state: sync resource transferring.
pub const RESOURCE_TRANSFERRING: u8 = 0x05;

/// Sync error: no link identification received.
pub const ERROR_NO_IDENTITY: u8 = 0xf0;
/// Sync error: access denied.
pub const ERROR_NO_ACCESS: u8 = 0xf1;
/// Sync error: invalid peering key.
pub const ERROR_INVALID_KEY: u8 = 0xf3;
/// Sync error: invalid data.
pub const ERROR_INVALID_DATA: u8 = 0xf4;
/// Sync error: invalid stamp.
pub const ERROR_INVALID_STAMP: u8 = 0xf5;
/// Sync error: throttled.
pub const ERROR_THROTTLED: u8 = 0xf6;
/// Sync error: not found.
pub const ERROR_NOT_FOUND: u8 = 0xfd;
/// Sync error: timed out.
pub const ERROR_TIMEOUT: u8 = 0xfe;

/// Sync strategy: lazy.
pub const STRATEGY_LAZY: u8 = 0x01;
/// Sync strategy: persistent.
pub const STRATEGY_PERSISTENT: u8 = 0x02;
/// Default peer sync strategy.
pub const DEFAULT_SYNC_STRATEGY: u8 = STRATEGY_PERSISTENT;

/// Maximum amount of time a peer can
/// be unreachable before it is removed
pub const MAX_UNREACHABLE: f64 = 14.0 * 24.0 * 60.0 * 60.0;

/// Everytime consecutive time a sync
/// link fails to establish, add this
/// amount off time to wait before the
/// next sync is attempted.
/// Backoff added per failed link establishment, in seconds.
pub const SYNC_BACKOFF_STEP: f64 = 12.0 * 60.0;

/// How long to wait for an answer to
/// peer path requests before deferring
/// sync to later.
/// Seconds to wait for a path response before deferring a sync.
pub const PATH_REQUEST_GRACE: f64 = 7.5;

/// A peering key: the stamp and its work value.
#[derive(Clone, Debug, PartialEq)]
pub struct PeeringKey {
    /// The peering stamp bytes.
    pub stamp: Vec<u8>,
    /// The work value of the peering stamp.
    pub value: i64,
}

/// The persisted (and exchanged) state of an LXMF propagation node peer.
///
/// Field-for-field equivalent of the dictionary produced by
/// `LXMPeer.to_bytes()`. Key insertion order is significant, since the peer
/// data is serialised as an ordered msgpack map.
#[derive(Clone, Debug)]
pub struct PeerData {
    /// Destination hash of the peer's "lxmf.propagation" destination.
    pub destination_hash: AddressHash,
    /// Last announced node timebase of the peer.
    pub peering_timebase: i64,
    /// Whether the peer has been heard from recently.
    pub alive: bool,
    /// Unix timestamp of last contact.
    pub last_heard: f64,
    /// Optional node metadata map (see the `PN_META_*` constants).
    pub metadata: Option<FieldValue>,
    /// Sync strategy (`STRATEGY_LAZY` or `STRATEGY_PERSISTENT`).
    pub sync_strategy: u8,
    /// Peering key for this peer, if generated.
    pub peering_key: Option<PeeringKey>,
    /// Measured link establishment rate in bits per second.
    pub link_establishment_rate: f64,
    /// Measured sync transfer rate in bits per second.
    pub sync_transfer_rate: f64,
    /// Per-transfer propagation limit in kilobytes.
    pub propagation_transfer_limit: Option<f64>,
    /// Per-sync propagation limit in kilobytes.
    pub propagation_sync_limit: Option<i64>,
    /// Required propagation stamp cost.
    pub propagation_stamp_cost: Option<i64>,
    /// Stamp cost flexibility.
    pub propagation_stamp_cost_flexibility: Option<i64>,
    /// Required peering cost.
    /// Required peering cost.
    pub peering_cost: Option<i64>,
    /// Unix timestamp of the last sync attempt.
    pub last_sync_attempt: f64,
    /// Messages offered to this peer.
    pub offered: i64,
    /// Messages transferred to this peer.
    pub outgoing: i64,
    /// Messages received from this peer.
    pub incoming: i64,
    /// Bytes received from this peer.
    pub rx_bytes: i64,
    /// Bytes sent to this peer.
    pub tx_bytes: i64,
    /// Transient IDs of messages this peer already has.
    pub handled_ids: Vec<Hash>,
    /// Transient IDs of messages this peer does not have yet.
    pub unhandled_ids: Vec<Hash>,
}

impl Default for PeerData {
    fn default() -> Self {
        Self {
            destination_hash: AddressHash::new_empty(),
            peering_timebase: 0,
            alive: false,
            last_heard: 0.0,
            metadata: None,
            sync_strategy: DEFAULT_SYNC_STRATEGY,
            peering_key: None,
            link_establishment_rate: 0.0,
            sync_transfer_rate: 0.0,
            propagation_transfer_limit: None,
            propagation_sync_limit: None,
            propagation_stamp_cost: None,
            propagation_stamp_cost_flexibility: None,
            peering_cost: None,
            last_sync_attempt: 0.0,
            offered: 0,
            outgoing: 0,
            incoming: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            handled_ids: Vec::new(),
            unhandled_ids: Vec::new(),
        }
    }
}

impl PeerData {
    /// Create peer data for a propagation destination hash, with all
    /// defaults of the Python `LXMPeer.__init__`.
    pub fn new(destination_hash: AddressHash) -> Self {
        Self {
            destination_hash,
            ..Default::default()
        }
    }

    /// Serialise the peer to msgpack bytes, with the exact key order of the
    /// Python `LXMPeer.to_bytes`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(256 + 64 * (self.handled_ids.len() + self.unhandled_ids.len()));

        let entry = |out: &mut Vec<u8>, key: &str, value: &FieldValue| {
            rmp::encode::write_str(out, key).ok();
            value.pack(out);
        };

        rmp::encode::write_map_len(&mut out, 22).ok();

        entry(
            &mut out,
            "peering_timebase",
            &FieldValue::Int(self.peering_timebase),
        );
        entry(&mut out, "alive", &FieldValue::Bool(self.alive));
        entry(
            &mut out,
            "metadata",
            self.metadata.as_ref().unwrap_or(&FieldValue::Nil),
        );
        entry(&mut out, "last_heard", &FieldValue::F64(self.last_heard));
        entry(
            &mut out,
            "sync_strategy",
            &FieldValue::Int(self.sync_strategy as i64),
        );
        entry(
            &mut out,
            "peering_key",
            &match &self.peering_key {
                Some(key) => FieldValue::Array(vec![
                    FieldValue::Bin(key.stamp.clone()),
                    FieldValue::Int(key.value),
                ]),
                None => FieldValue::Nil,
            },
        );
        entry(
            &mut out,
            "destination_hash",
            &FieldValue::Bin(self.destination_hash.as_slice().to_vec()),
        );
        entry(
            &mut out,
            "link_establishment_rate",
            &FieldValue::F64(self.link_establishment_rate),
        );
        entry(
            &mut out,
            "sync_transfer_rate",
            &FieldValue::F64(self.sync_transfer_rate),
        );
        entry(
            &mut out,
            "propagation_transfer_limit",
            &match self.propagation_transfer_limit {
                Some(limit) => FieldValue::F64(limit),
                None => FieldValue::Nil,
            },
        );
        entry(
            &mut out,
            "propagation_sync_limit",
            &match self.propagation_sync_limit {
                Some(limit) => FieldValue::Int(limit),
                None => FieldValue::Nil,
            },
        );
        entry(
            &mut out,
            "propagation_stamp_cost",
            &match self.propagation_stamp_cost {
                Some(cost) => FieldValue::Int(cost),
                None => FieldValue::Nil,
            },
        );
        entry(
            &mut out,
            "propagation_stamp_cost_flexibility",
            &match self.propagation_stamp_cost_flexibility {
                Some(flexibility) => FieldValue::Int(flexibility),
                None => FieldValue::Nil,
            },
        );
        entry(
            &mut out,
            "peering_cost",
            &match self.peering_cost {
                Some(cost) => FieldValue::Int(cost),
                None => FieldValue::Nil,
            },
        );
        entry(
            &mut out,
            "last_sync_attempt",
            &FieldValue::F64(self.last_sync_attempt),
        );
        entry(&mut out, "offered", &FieldValue::Int(self.offered));
        entry(&mut out, "outgoing", &FieldValue::Int(self.outgoing));
        entry(&mut out, "incoming", &FieldValue::Int(self.incoming));
        entry(&mut out, "rx_bytes", &FieldValue::Int(self.rx_bytes));
        entry(&mut out, "tx_bytes", &FieldValue::Int(self.tx_bytes));

        entry(
            &mut out,
            "handled_ids",
            &FieldValue::Array(
                self.handled_ids
                    .iter()
                    .map(|id| FieldValue::Bin(id.as_slice().to_vec()))
                    .collect(),
            ),
        );
        entry(
            &mut out,
            "unhandled_ids",
            &FieldValue::Array(
                self.unhandled_ids
                    .iter()
                    .map(|id| FieldValue::Bin(id.as_slice().to_vec()))
                    .collect(),
            ),
        );

        out
    }

    /// Deserialise peer data from msgpack bytes, applying the same defaults
    /// for missing keys as the Python `LXMPeer.from_bytes`.
    pub fn from_bytes(peer_bytes: &[u8]) -> Result<Self, LxmfError> {
        let mut rd: &[u8] = peer_bytes;
        let value = FieldValue::unpack(&mut rd)?;
        let FieldValue::Map(entries) = value else {
            return Err(LxmfError::InvalidFormat);
        };

        let mut peer = PeerData::default();

        let mut destination_hash: Option<AddressHash> = None;
        let mut peering_timebase: Option<i64> = None;
        let mut alive: Option<bool> = None;
        let mut last_heard: Option<f64> = None;

        for (key, value) in entries {
            let Some(key) = key.as_str() else {
                continue;
            };
            match key {
                "destination_hash" => match value {
                    FieldValue::Bin(bytes) if bytes.len() == HASH_SIZE / 2 => {
                        let mut hash = [0u8; HASH_SIZE / 2];
                        hash.copy_from_slice(&bytes);
                        destination_hash = Some(AddressHash::new(hash));
                    }
                    _ => return Err(LxmfError::InvalidFormat),
                },
                "peering_timebase" => {
                    peering_timebase = value.as_int();
                }
                "alive" => {
                    alive = Some(matches!(value, FieldValue::Bool(true)));
                }
                "last_heard" => {
                    last_heard = value.as_f64();
                }
                "metadata" => {
                    peer.metadata = match value {
                        FieldValue::Nil => None,
                        other => Some(other),
                    };
                }
                "sync_strategy" => {
                    peer.sync_strategy =
                        value.as_int().unwrap_or(DEFAULT_SYNC_STRATEGY as i64) as u8;
                }
                "peering_key" => {
                    peer.peering_key = match value {
                        FieldValue::Array(items) if items.len() == 2 => {
                            match (&items[0], &items[1]) {
                                (FieldValue::Bin(stamp), FieldValue::Int(value)) => {
                                    Some(PeeringKey {
                                        stamp: stamp.clone(),
                                        value: *value,
                                    })
                                }
                                _ => None,
                            }
                        }
                        _ => None,
                    };
                }
                "link_establishment_rate" => {
                    peer.link_establishment_rate = value.as_f64().unwrap_or(0.0);
                }
                "sync_transfer_rate" => {
                    peer.sync_transfer_rate = value.as_f64().unwrap_or(0.0);
                }
                "propagation_transfer_limit" => {
                    peer.propagation_transfer_limit = value.as_f64();
                }
                "propagation_sync_limit" => {
                    peer.propagation_sync_limit = value.as_int();
                }
                "propagation_stamp_cost" => {
                    peer.propagation_stamp_cost = value.as_int();
                }
                "propagation_stamp_cost_flexibility" => {
                    peer.propagation_stamp_cost_flexibility = value.as_int();
                }
                "peering_cost" => {
                    peer.peering_cost = value.as_int();
                }
                "last_sync_attempt" => {
                    peer.last_sync_attempt = value.as_f64().unwrap_or(0.0);
                }
                "offered" => peer.offered = value.as_int().unwrap_or(0),
                "outgoing" => peer.outgoing = value.as_int().unwrap_or(0),
                "incoming" => peer.incoming = value.as_int().unwrap_or(0),
                "rx_bytes" => peer.rx_bytes = value.as_int().unwrap_or(0),
                "tx_bytes" => peer.tx_bytes = value.as_int().unwrap_or(0),
                "handled_ids" => peer.handled_ids = unpack_id_list(value),
                "unhandled_ids" => peer.unhandled_ids = unpack_id_list(value),
                _ => {}
            }
        }

        // Python raises on missing required keys
        peer.destination_hash = destination_hash.ok_or(LxmfError::InvalidFormat)?;
        peer.peering_timebase = peering_timebase.ok_or(LxmfError::InvalidFormat)?;
        peer.alive = alive.ok_or(LxmfError::InvalidFormat)?;
        peer.last_heard = last_heard.ok_or(LxmfError::InvalidFormat)?;

        Ok(peer)
    }

    /// Whether the peering key satisfies the required peering cost
    /// (`LXMPeer.peering_key_ready`).
    pub fn peering_key_ready(&self) -> bool {
        let Some(peering_cost) = self.peering_cost else {
            return false;
        };
        matches!(&self.peering_key, Some(key) if key.value >= peering_cost)
    }

    /// The work value of the current peering key.
    pub fn peering_key_value(&self) -> Option<i64> {
        self.peering_key.as_ref().map(|key| key.value)
    }

    /// Node name from peer metadata (`LXMPeer.name`).
    pub fn name(&self) -> Option<String> {
        let FieldValue::Map(entries) = self.metadata.as_ref()? else {
            return None;
        };
        for (key, value) in entries {
            if key.as_int() == Some(crate::fields::PN_META_NAME as i64) {
                if let FieldValue::Bin(name) = value {
                    return String::from_utf8(name.clone()).ok();
                }
            }
        }
        None
    }
}

fn unpack_id_list(value: FieldValue) -> Vec<Hash> {
    match value {
        FieldValue::Array(items) => items
            .into_iter()
            .filter_map(|item| match item {
                FieldValue::Bin(bytes) if bytes.len() == HASH_SIZE => {
                    let mut hash = [0u8; HASH_SIZE];
                    hash.copy_from_slice(&bytes);
                    Some(Hash::new(hash))
                }
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}
