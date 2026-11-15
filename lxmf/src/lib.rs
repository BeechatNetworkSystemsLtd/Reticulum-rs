//! # LXMF for Reticulum-rs
//!
//! A Rust port of the [LXMF](https://github.com/markqvist/LXMF) message
//! format and router layer for Reticulum networks.
//!
//! The crate is split the same way as the Python distribution:
//!
//! * [`fields`] - field identifiers and the msgpack value model
//!   (`LXMF/LXMF/LXMF.py` constants)
//! * [`message`] - the [`message::LXMessage`] wire format
//!   (`LXMF/LXMF/LXMessage.py`)
//! * [`stamper`] - hashcash-style stamps (`LXMF/LXMF/LXStamper.py`)
//! * [`peer`] - propagation node peer records (`LXMF/LXMF/LXMPeer.py`)
//! * [`router`] - the [`router::LxmRouter`] over the async `reticulum`
//!   transport (`LXMF/LXMF/LXMRouter.py`)
//!
//! The message-format modules ([`fields`], [`message`], [`stamper`],
//! [`peer`] and the announce app-data helpers below) are fully decoupled
//! from transport and depend only on `reticulum-core`. All packed
//! representations are byte-for-byte identical to the Python reference
//! implementation (verified by golden-vector tests generated from it).

#![warn(missing_docs)]

pub mod error;
pub mod fields;
pub mod message;
pub mod peer;
pub mod router;
pub mod stamper;

use std::{string::String, vec::Vec};

use reticulum_core::destination::DestinationName;
use reticulum_core::hash::AddressHash;
use reticulum_core::identity::Identity;

/// The LXMF application name used for destination naming (`LXMF.APP_NAME`).
pub const APP_NAME: &str = "lxmf";

pub use crate::error::LxmfError;
pub use crate::fields::{
    FieldValue, Fields, FIELD_AUDIO, FIELD_COMMANDS, FIELD_COMMENT, FIELD_CONTINUATION,
    FIELD_CUSTOM_DATA, FIELD_CUSTOM_META, FIELD_CUSTOM_TYPE, FIELD_DEBUG, FIELD_EMBEDDED_LXMS,
    FIELD_EVENT, FIELD_FILE_ATTACHMENTS, FIELD_GROUP, FIELD_ICON_APPEARANCE, FIELD_IMAGE,
    FIELD_NON_SPECIFIC, FIELD_REACTION, FIELD_RENDERER, FIELD_REPLY_QUOTE, FIELD_REPLY_TO,
    FIELD_RESULTS, FIELD_RNR_REFS, FIELD_TELEMETRY, FIELD_TELEMETRY_STREAM, FIELD_THREAD,
    FIELD_TICKET, PN_META_AUTH_BAND, PN_META_CUSTOM, PN_META_NAME, PN_META_SYNC_STRATUM,
    PN_META_SYNC_THROTTLE, PN_META_UTIL_PRESSURE, PN_META_VERSION, SF_COMPRESSION,
};
pub use crate::message::{
    full_hash, truncated_hash, LXMessage, TransportEncryption, CANCELLED, COST_TICKET, DELIVERED,
    DESTINATION_LENGTH, DIRECT, ENCRYPTED_PACKET_MAX_CONTENT, ENCRYPTED_PACKET_MDU,
    ENCRYPTION_DESCRIPTION_AES, ENCRYPTION_DESCRIPTION_EC, ENCRYPTION_DESCRIPTION_UNENCRYPTED,
    FAILED, GENERATING, LINK_PACKET_MAX_CONTENT, LINK_PACKET_MDU, LXMF_OVERHEAD, OPPORTUNISTIC,
    OUTBOUND, PACKET, PAPER, PAPER_MDU, PLAIN_PACKET_MAX_CONTENT, PLAIN_PACKET_MDU, PROPAGATED,
    QR_ERROR_CORRECTION, QR_MAX_STORAGE, REJECTED, REPRESENTATIONS, RESOURCE, SENDING, SENT,
    SIGNATURE_INVALID, SIGNATURE_LENGTH, SOURCE_UNKNOWN, STATES, TICKET_EXPIRY, TICKET_GRACE,
    TICKET_INTERVAL, TICKET_LENGTH, TICKET_RENEW, TIMESTAMP_SIZE, UNKNOWN, UNVERIFIED_REASONS,
    URI_SCHEMA, VALID_METHODS,
};

pub use crate::peer::PeerData;
pub use crate::router::PropagationTransferState;
pub use crate::stamper::{
    generate_stamp, stamp_valid, stamp_value, stamp_workblock, WORKBLOCK_EXPAND_ROUNDS,
    WORKBLOCK_EXPAND_ROUNDS_PEERING, WORKBLOCK_EXPAND_ROUNDS_PN,
};

/// Lowercase hexadecimal representation of `data` (`RNS.hexrep` without
/// delimiters).
pub fn to_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

/// Parse a hexadecimal string into bytes.
pub fn from_hex(hex: &str) -> Result<Vec<u8>, LxmfError> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return Err(LxmfError::InvalidFormat);
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks(2) {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or(LxmfError::InvalidFormat)?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or(LxmfError::InvalidFormat)?;
        out.push((hi * 16 + lo) as u8);
    }
    Ok(out)
}

/// Destination name hash for the LXMF delivery aspect ("lxmf.delivery").
pub fn delivery_name() -> DestinationName {
    DestinationName::new(APP_NAME, "delivery")
}

/// Destination name hash for the LXMF propagation aspect
/// ("lxmf.propagation").
pub fn propagation_name() -> DestinationName {
    DestinationName::new(APP_NAME, "propagation")
}

/// Destination hash for an arbitrary name aspect and identity
/// (`RNS.Destination.hash_from_name_and_identity`).
pub fn destination_hash_for(name: &DestinationName, identity: &Identity) -> AddressHash {
    let mut material = Vec::with_capacity(10 + 16);
    material.extend_from_slice(name.as_name_hash_slice());
    material.extend_from_slice(identity.address_hash.as_slice());
    truncated_hash(&material)
}

/// The "lxmf.delivery" destination hash for `identity`
/// (`RNS.Destination.hash_from_name_and_identity("lxmf.delivery", id)`).
pub fn delivery_destination_hash(identity: &Identity) -> AddressHash {
    destination_hash_for(&delivery_name(), identity)
}

/// The "lxmf.propagation" destination hash for `identity`.
pub fn propagation_destination_hash(identity: &Identity) -> AddressHash {
    destination_hash_for(&propagation_name(), identity)
}

//////////////////////////////////////////////////////////
// The following helper functions makes it easier to      //
// handle and operate on LXMF data in client programs     //
//////////////////////////////////////////////////////////

/// Whether the announce app-data uses the version 0.5.0+ list format.
fn is_list_app_data(app_data: &[u8]) -> bool {
    (0x90..=0x9f).contains(&app_data[0]) || app_data[0] == 0xdc
}

/// Extract the display name from a delivery destination announce
/// app-data blob (`LXMF.display_name_from_app_data`).
pub fn display_name_from_app_data(app_data: Option<&[u8]>) -> Option<String> {
    let app_data = app_data?;
    if app_data.is_empty() {
        return None;
    }

    // Version 0.5.0+ announce format
    if is_list_app_data(app_data) {
        let mut rd: &[u8] = app_data;
        let peer_data = FieldValue::unpack(&mut rd).ok()?;
        let FieldValue::Array(items) = peer_data else {
            return None;
        };
        if items.is_empty() {
            return None;
        }
        match &items[0] {
            // A display name of None (msgpack nil) means unset
            FieldValue::Nil => None,
            FieldValue::Bin(name) => {
                let decoded = String::from_utf8(name.clone()).ok()?;
                Some(decoded.replace('\0', "").trim().to_string())
            }
            _ => None,
        }
    } else {
        // Original announce format
        String::from_utf8(app_data.to_vec()).ok()
    }
}

/// Extract the required stamp cost from a delivery destination announce
/// app-data blob (`LXMF.stamp_cost_from_app_data`).
pub fn stamp_cost_from_app_data(app_data: Option<&[u8]>) -> Option<u8> {
    let app_data = app_data?;
    if app_data.is_empty() {
        return None;
    }

    if is_list_app_data(app_data) {
        let mut rd: &[u8] = app_data;
        let peer_data = FieldValue::unpack(&mut rd).ok()?;
        let FieldValue::Array(items) = peer_data else {
            return None;
        };
        if items.len() < 2 {
            return None;
        }
        items[1].as_int().map(|cost| cost as u8)
    } else {
        None
    }
}

/// Whether the announcing destination signals compression support
/// (`LXMF.compression_support_from_app_data`). Defaults to true when the
/// functionality list is missing.
pub fn compression_support_from_app_data(app_data: Option<&[u8]>) -> bool {
    let Some(app_data) = app_data else {
        return true;
    };
    if app_data.is_empty() {
        return true;
    }

    if is_list_app_data(app_data) {
        let mut rd: &[u8] = app_data;
        let Ok(peer_data) = FieldValue::unpack(&mut rd) else {
            return true;
        };
        let FieldValue::Array(items) = peer_data else {
            return true;
        };
        if items.len() < 3 {
            return true;
        }
        let FieldValue::Array(supported) = &items[2] else {
            return true;
        };
        supported
            .iter()
            .any(|entry| entry.as_int() == Some(SF_COMPRESSION as i64))
    } else {
        true
    }
}

/// Propagation node announce data, as packed by
/// [`router::LxmRouter::get_propagation_node_app_data`] and parsed by
/// [`pn_announce_data_from_app_data`].
#[derive(Clone, Debug)]
pub struct PropagationNodeInfo {
    /// Whether the node supports legacy LXMF propagation.
    pub legacy_support: bool,
    /// Current node timebase (unix seconds).
    pub timebase: i64,
    /// Whether the node is operating as a propagation node.
    pub node_state: bool,
    /// Per-transfer limit for message propagation in kilobytes.
    pub propagation_transfer_limit: i64,
    /// Limit for incoming propagation node syncs in kilobytes.
    pub propagation_sync_limit: i64,
    /// Propagation stamp cost for this node.
    pub stamp_cost: i64,
    /// Stamp cost flexibility.
    pub stamp_cost_flexibility: i64,
    /// Peering cost.
    pub peering_cost: i64,
    /// Node metadata map.
    pub metadata: FieldValue,
}

/// Validate and parse propagation node announce data
/// (`LXMF.pn_announce_data_is_valid` plus the field extraction performed by
/// `LXMFPropagationAnnounceHandler.received_announce`).
pub fn pn_announce_data_from_app_data(app_data: Option<&[u8]>) -> Option<PropagationNodeInfo> {
    let app_data = app_data?;
    if app_data.is_empty() {
        return None;
    }

    let mut rd: &[u8] = app_data;
    let data = FieldValue::unpack(&mut rd).ok()?;
    let FieldValue::Array(items) = data else {
        return None;
    };
    if items.len() < 7 {
        // Insufficient peer data, likely from deprecated LXMF version
        return None;
    }

    let timebase = items[1].as_int()?;
    // Indeterminate propagation node status is invalid
    if !matches!(items[2], FieldValue::Bool(_)) {
        return None;
    }
    let propagation_transfer_limit = items[3].as_int()?;
    let propagation_sync_limit = items[4].as_int()?;

    let FieldValue::Array(costs) = &items[5] else {
        return None;
    };
    if costs.len() < 3 {
        return None;
    }
    let stamp_cost = costs[0].as_int()?;
    let stamp_cost_flexibility = costs[1].as_int()?;
    let peering_cost = costs[2].as_int()?;

    let FieldValue::Map(_) = &items[6] else {
        return None;
    };

    Some(PropagationNodeInfo {
        legacy_support: matches!(items[0], FieldValue::Bool(false)),
        timebase,
        node_state: matches!(items[2], FieldValue::Bool(true)),
        propagation_transfer_limit,
        propagation_sync_limit,
        stamp_cost,
        stamp_cost_flexibility,
        peering_cost,
        metadata: items[6].clone(),
    })
}

/// Validate propagation node announce data
/// (`LXMF.pn_announce_data_is_valid`).
pub fn pn_announce_data_is_valid(app_data: Option<&[u8]>) -> bool {
    pn_announce_data_from_app_data(app_data).is_some()
}

/// Extract the node name from propagation node announce data
/// (`LXMF.pn_name_from_app_data`).
pub fn pn_name_from_app_data(app_data: Option<&[u8]>) -> Option<String> {
    let info = pn_announce_data_from_app_data(app_data)?;
    let FieldValue::Map(entries) = &info.metadata else {
        return None;
    };
    for (key, value) in entries {
        if key.as_int() == Some(PN_META_NAME as i64) {
            if let FieldValue::Bin(name) = value {
                return String::from_utf8(name.clone()).ok();
            }
        }
    }
    None
}

/// Extract the target stamp cost from propagation node announce data
/// (`LXMF.pn_stamp_cost_from_app_data`).
pub fn pn_stamp_cost_from_app_data(app_data: Option<&[u8]>) -> Option<i64> {
    pn_announce_data_from_app_data(app_data).map(|info| info.stamp_cost)
}

/// Pack delivery announce app-data (`LXMRouter.get_announce_app_data`):
/// a msgpack list of `[display_name, stamp_cost, supported_functionality]`.
pub fn pack_announce_app_data(
    display_name: Option<&str>,
    stamp_cost: Option<u8>,
    supported_functionality: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    rmp::encode::write_array_len(&mut out, 3).ok();
    match display_name {
        Some(name) => {
            rmp::encode::write_bin_len(&mut out, name.len() as u32).ok();
            out.extend_from_slice(name.as_bytes());
        }
        None => {
            rmp::encode::write_nil(&mut out).ok();
        }
    }
    match stamp_cost {
        Some(cost) => {
            rmp::encode::write_uint(&mut out, cost as u64).ok();
        }
        None => {
            rmp::encode::write_nil(&mut out).ok();
        }
    }
    rmp::encode::write_array_len(&mut out, supported_functionality.len() as u32).ok();
    for entry in supported_functionality {
        rmp::encode::write_uint(&mut out, *entry as u64).ok();
    }
    out
}

/// Pack propagation node announce app-data
/// (`LXMRouter.get_propagation_node_app_data`).
pub fn pack_propagation_node_app_data(
    legacy_support: bool,
    timebase: i64,
    node_state: bool,
    propagation_transfer_limit: i64,
    propagation_sync_limit: i64,
    stamp_costs: (i64, i64, i64),
    metadata: &FieldValue,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    rmp::encode::write_array_len(&mut out, 7).ok();
    rmp::encode::write_bool(&mut out, legacy_support).ok();
    rmp::encode::write_sint(&mut out, timebase).ok();
    rmp::encode::write_bool(&mut out, node_state).ok();
    rmp::encode::write_sint(&mut out, propagation_transfer_limit).ok();
    rmp::encode::write_sint(&mut out, propagation_sync_limit).ok();
    rmp::encode::write_array_len(&mut out, 3).ok();
    rmp::encode::write_sint(&mut out, stamp_costs.0).ok();
    rmp::encode::write_sint(&mut out, stamp_costs.1).ok();
    rmp::encode::write_sint(&mut out, stamp_costs.2).ok();
    metadata.pack(&mut out);
    out
}
