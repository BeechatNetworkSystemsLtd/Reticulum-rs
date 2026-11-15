//! Tunnel support — Python `RNS.Transport` tunnel endpoints
//! (Phase 6.4).
//!
//! A tunnel endpoint binds paths learned over a (typically ephemeral)
//! interface to a stable `tunnel_id`, so that when the interface
//! re-appears (for example a RNodeMulti transport re-synthesizes its
//! tunnel) the previously known paths are restored instead of being
//! re-discovered.
//!
//! * `synthesize_tunnel` announces `pub_key || iface_hash || random_hash
//!   || signature` on the fixed PLAIN destination
//!   `rnstransport.tunnel.synthesize`
//! * `tunnel_synthesize_handler` validates the signature of the remote
//!   transport identity and establishes (or restores) the tunnel
//! * announces received on a tunneled interface are associated with the
//!   tunnel and restored on re-appearance
//! * tunnel entries expire after `TUNNEL_TIMEOUT` (8 hours)

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use rand_core::OsRng;
use tokio::time::{Duration, Instant};

use crate::destination::DestinationName;
use crate::destination::PlainInputDestination;
use crate::hash::{AddressHash, Hash};
use crate::identity::EmptyIdentity;
use crate::packet::{
    DestinationType, Header, HeaderType, IfacFlag, Packet, PacketContext, PacketDataBuffer,
    PacketType, PropagationType,
};

/// Tunnel table entries are removed if unused for eight hours
/// (Python `Transport.TUNNEL_TIMEOUT`).
pub const TUNNEL_TIMEOUT: Duration = Duration::from_secs(60 * 60 * 8);

/// Wire length of a tunnel synthesize packet:
/// `pub_key(64) || iface_hash(32) || random_hash(16) || signature(64)`
/// (Python `tunnel_synthesize_handler` expected_length).
pub const TUNNEL_SYNTHESIZE_LENGTH: usize = 64 + 32 + 16 + 64;

/// Fixed inbound PLAIN destination for tunnel synthesis
/// (Python `Transport.APP_NAME = "rnstransport"`, aspects
/// `"tunnel", "synthesize"`).
pub fn create_tunnel_synthesize_destination() -> PlainInputDestination {
    PlainInputDestination::new(
        EmptyIdentity {},
        DestinationName::new("rnstransport", "tunnel.synthesize"),
    )
}

/// A path associated with a tunnel
/// (Python tunnel path entry: timestamp, received_from, hops, expires,
/// random_blobs, receiving_interface, packet_hash).
#[derive(Clone, Debug)]
#[allow(dead_code)] // parity fields: consumed by table persistence/restore
pub struct TunnelPath {
    pub received_from: AddressHash,
    pub hops: u8,
    /// When the path expires (`PATHFINDER_E`-style unix-seconds age).
    pub expires: Duration,
    pub packet_hash: Hash,
}

/// One tunnel endpoint.
#[derive(Clone, Debug)]
pub struct TunnelEntry {
    /// The interface the tunnel is currently bound to; `None` when the
    /// tunnel was voided but its paths are retained for restore
    /// (Python `void_tunnel_interface`).
    pub iface: Option<AddressHash>,
    /// Paths learned over this tunnel, by destination hash.
    pub paths: BTreeMap<AddressHash, TunnelPath>,
    pub expires: Instant,
}

/// Result of handling a tunnel (re-)appearance.
#[derive(Debug, Clone)]
pub enum TunnelHandling {
    /// A new tunnel endpoint was established.
    Established,
    /// The tunnel re-appeared; these paths are restore candidates.
    Restored {
        candidates: Vec<(AddressHash, TunnelPath)>,
    },
}

#[derive(Debug, Default)]
pub struct Tunnels {
    /// Tunnel table by tunnel id (Python `Transport.tunnels`).
    map: BTreeMap<AddressHash, TunnelEntry>,
}

#[allow(dead_code)] // parity accessors used by tooling/tests
impl Tunnels {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn get(&self, tunnel_id: &AddressHash) -> Option<&TunnelEntry> {
        self.map.get(tunnel_id)
    }

    /// Iterate all tunnel entries (Python `get_tunnel_table`).
    pub fn iter(&self) -> impl Iterator<Item = (&AddressHash, &TunnelEntry)> {
        self.map.iter()
    }

    pub fn contains(&self, tunnel_id: &AddressHash) -> bool {
        self.map.contains_key(tunnel_id)
    }

    /// The tunnel id currently bound to an interface.
    pub fn tunnel_for_iface(&self, iface: &AddressHash) -> Option<AddressHash> {
        self.map
            .iter()
            .find(|(_, entry)| entry.iface == Some(*iface))
            .map(|(tunnel_id, _)| *tunnel_id)
    }

    /// Handle a validated tunnel synthesis for `tunnel_id` received on
    /// `iface`: establish a new tunnel or prepare the paths of an existing
    /// one for restore
    /// (Python `Transport.handle_tunnel`).
    ///
    /// On re-appearance the caller receives the associated paths as
    /// restore candidates, applies the Python restore rules against the
    /// live path table and reports the paths it declined via
    /// [`Tunnels::finish_restore`].
    pub fn handle_tunnel(
        &mut self,
        tunnel_id: AddressHash,
        iface: AddressHash,
        now: Instant,
    ) -> TunnelHandling {
        let expires = now + TUNNEL_TIMEOUT;

        match self.map.get_mut(&tunnel_id) {
            None => {
                self.map.insert(
                    tunnel_id,
                    TunnelEntry {
                        iface: Some(iface),
                        paths: BTreeMap::new(),
                        expires,
                    },
                );
                TunnelHandling::Established
            }
            Some(entry) => {
                entry.iface = Some(iface);
                entry.expires = expires;

                TunnelHandling::Restored {
                    candidates: entry.paths.clone().into_iter().collect(),
                }
            }
        }
    }

    /// Remove declined paths from the tunnel after a restore round
    /// (Python pops deprecated paths from the tunnel entry).
    pub fn finish_restore(&mut self, tunnel_id: &AddressHash, declined: &[AddressHash]) {
        if let Some(entry) = self.map.get_mut(tunnel_id) {
            for destination in declined {
                entry.paths.remove(destination);
            }
        }
    }

    /// Associate a path learned over a tunnel interface with the tunnel
    /// (Python announce handling: `paths[destination_hash] = [...]`).
    pub fn associate_path(
        &mut self,
        tunnel_id: &AddressHash,
        destination: AddressHash,
        path: TunnelPath,
        now: Instant,
    ) -> bool {
        match self.map.get_mut(tunnel_id) {
            Some(entry) => {
                entry.paths.insert(destination, path);
                entry.expires = now + TUNNEL_TIMEOUT;
                true
            }
            None => false,
        }
    }

    /// Unbind a tunnel from its interface while keeping the learned paths
    /// for a later restore (Python `void_tunnel_interface`).
    pub fn void(&mut self, tunnel_id: &AddressHash) -> bool {
        match self.map.get_mut(tunnel_id) {
            Some(entry) => {
                entry.iface = None;
                true
            }
            None => false,
        }
    }

    /// Remove expired tunnel entries (Python `Transport.jobs` tunnel
    /// cleanup). Returns the number of removed tunnels.
    pub fn clean(&mut self, now: Instant) -> usize {
        let before = self.map.len();
        self.map.retain(|_, entry| now < entry.expires);
        before - self.map.len()
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }

    pub fn insert(&mut self, tunnel_id: AddressHash, entry: TunnelEntry) {
        self.map.insert(tunnel_id, entry);
    }

    /// Drop tunnels bound to `iface`.
    pub fn drop_iface(&mut self, iface: &AddressHash) {
        self.map.retain(|_, entry| entry.iface != Some(*iface));
    }
}

/// A decoded and signature-validated tunnel synthesize packet.
#[derive(Debug, Clone)]
#[allow(dead_code)] // iface_hash kept for parity/debugging
pub struct TunnelSynthesis {
    pub tunnel_id: AddressHash,
    /// The interface the tunnel binds to on the receiving side.
    pub iface_hash: Hash,
}

/// Decode and validate a tunnel synthesize payload
/// (Python `Transport.tunnel_synthesize_handler`): verifies the signature
/// of the remote transport identity over
/// `pub_key || iface_hash || random_hash`.
pub fn decode_tunnel_synthesize(data: &[u8]) -> Option<TunnelSynthesis> {
    if data.len() != TUNNEL_SYNTHESIZE_LENGTH {
        return None;
    }

    let public_key_bytes = &data[..64];
    let iface_hash_bytes = &data[64..96];
    let _random_hash = &data[96..112];
    let signature_bytes = &data[112..176];

    let signed_data = &data[..112];

    // Python `Identity(create_keys=False).load_public_key(pub)` then
    // `validate(signature, signed_data)`: only the signing (ed25519) half
    // of the public key verifies the signature.
    let mut verifying_bytes = [0u8; 32];
    verifying_bytes.copy_from_slice(&public_key_bytes[32..64]);
    // Python `Identity(create_keys=False).load_public_key(pub)` followed
    // by `validate(signature, signed_data)`: build a verification-only
    // identity from the announced public key halves.
    let remote = crate::identity::Identity::new_from_slices(
        &public_key_bytes[..32],
        &public_key_bytes[32..],
    );

    let mut signature = [0u8; 64];
    signature.copy_from_slice(signature_bytes);
    let signature = crate::identity::Signature::from_bytes(&signature);

    if remote.verify(signed_data, &signature).is_err() {
        return None;
    }

    // tunnel_id = full_hash(pub_key || iface_hash)
    let mut tunnel_id_data = [0u8; 96];
    tunnel_id_data[..64].copy_from_slice(public_key_bytes);
    tunnel_id_data[64..].copy_from_slice(iface_hash_bytes);
    let tunnel_id = AddressHash::new_from_hash(&Hash::new_from_slice(&tunnel_id_data));

    let mut iface_hash = [0u8; 32];
    iface_hash.copy_from_slice(iface_hash_bytes);

    Some(TunnelSynthesis {
        tunnel_id,
        iface_hash: Hash::new(iface_hash),
    })
}

/// Build a tunnel synthesize packet for the transport `identity` bound to
/// `iface` (Python `Transport.synthesize_tunnel`).
pub fn synthesize_tunnel_packet(
    identity: &crate::identity::PrivateIdentity,
    iface: &AddressHash,
    destination: AddressHash,
    transport_id: Option<AddressHash>,
) -> Packet {
    let public_key = identity.as_identity().to_bytes();

    // iface_hash: full SHA-256 over the interface address bytes (the
    // Python reference hashes its interface string representation, which
    // is not stable across implementations; tunnel ids coordinate two
    // endpoints of the same stack).
    let iface_hash = Hash::new_from_slice(iface.as_slice()).to_bytes();

    // random_hash: truncated hash of random data
    // (Python `Identity.get_random_hash`).
    let random_hash = Hash::new_from_rand(OsRng);
    let mut random_truncated = [0u8; 16];
    random_truncated.copy_from_slice(&random_hash.to_bytes()[..16]);

    let mut signed_data = [0u8; 112];
    signed_data[..64].copy_from_slice(&public_key);
    signed_data[64..96].copy_from_slice(&iface_hash);
    signed_data[96..].copy_from_slice(&random_truncated);

    let signature = identity.sign(&signed_data).to_bytes();

    let mut data = PacketDataBuffer::new();
    data.safe_write(&signed_data);
    data.safe_write(&signature);

    Packet {
        header: Header {
            ifac_flag: IfacFlag::Open,
            context_flag: false,
            header_type: HeaderType::Type1,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Plain,
            packet_type: PacketType::Data,
            hops: 0,
        },
        ifac: None,
        destination,
        transport: transport_id,
        context: PacketContext::None,
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthesize_roundtrip() {
        let identity = crate::identity::PrivateIdentity::new_from_rand(OsRng);
        let iface = AddressHash::new_from_rand(OsRng);
        let destination = create_tunnel_synthesize_destination().desc.address_hash;

        let packet = synthesize_tunnel_packet(&identity, &iface, destination, None);

        let raw = packet.data.as_slice();
        let decoded = decode_tunnel_synthesize(raw).expect("valid synthesis");

        // tunnel_id = truncated full_hash(pub || iface_hash)
        let mut expected = [0u8; 96];
        expected[..64].copy_from_slice(&identity.as_identity().to_bytes());
        expected[64..].copy_from_slice(&Hash::new_from_slice(iface.as_slice()).to_bytes());
        let expected_id = AddressHash::new_from_hash(&Hash::new_from_slice(&expected));
        assert_eq!(decoded.tunnel_id, expected_id);

        // tampering breaks the signature
        let mut tampered = packet.data.as_slice().to_vec();
        tampered[0] ^= 1;
        assert!(decode_tunnel_synthesize(&tampered).is_none());
    }

    #[test]
    fn tunnel_table_lifecycle() {
        let t0 = Instant::now();
        let mut tunnels = Tunnels::new();
        let tunnel_id = AddressHash::new_from_rand(OsRng);
        let iface = AddressHash::new_from_rand(OsRng);

        assert!(matches!(
            tunnels.handle_tunnel(tunnel_id, iface, t0),
            TunnelHandling::Established
        ));
        assert!(tunnels.contains(&tunnel_id));
        assert_eq!(tunnels.tunnel_for_iface(&iface), Some(tunnel_id));

        // associate a path
        let destination = AddressHash::new_from_rand(OsRng);
        assert!(tunnels.associate_path(
            &tunnel_id,
            destination,
            TunnelPath {
                received_from: AddressHash::new_from_rand(OsRng),
                hops: 2,
                expires: Duration::from_secs(60 * 60 * 24 * 7),
                packet_hash: Hash::new_from_rand(OsRng),
            },
            t0
        ));

        // void: iface unbound, paths kept
        assert!(tunnels.void(&tunnel_id));
        assert_eq!(tunnels.tunnel_for_iface(&iface), None);
        assert_eq!(tunnels.get(&tunnel_id).unwrap().paths.len(), 1);

        // re-appearance offers the path as a restore candidate
        match tunnels.handle_tunnel(tunnel_id, iface, t0) {
            TunnelHandling::Restored { candidates } => {
                assert_eq!(candidates.len(), 1);
                assert_eq!(candidates[0].1.hops, 2);
            }
            _ => panic!("expected restore candidates"),
        }

        // expiry cleans the table
        assert_eq!(
            tunnels.clean(t0 + TUNNEL_TIMEOUT + Duration::from_secs(1)),
            1
        );
        assert!(tunnels.is_empty());
    }
}
