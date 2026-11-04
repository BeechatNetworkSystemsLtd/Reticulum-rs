use std::collections::HashMap;
use tokio::time::{Duration, Instant};

use crate::destination::link::LinkId;
use crate::hash::AddressHash;
use crate::identity::{Identity, Signature};
use crate::packet::{Header, IfacFlag, Packet};

/// Idle lifetime of a validated intermediary link
/// (Python `LINK_TIMEOUT` = `Link.STALE_TIME * 1.25` = 900 s).
const LINK_TIMEOUT: Duration = Duration::from_secs(900);

/// Establishment timeout per hop for intermediary link proofs
/// (Python `Link.ESTABLISHMENT_TIMEOUT_PER_HOP` =
/// `RNS.Reticulum.DEFAULT_PER_HOP_TIMEOUT` = 6 s).
const ESTABLISHMENT_TIMEOUT_PER_HOP: Duration = Duration::from_secs(6);

#[derive(Clone, Copy)]
pub struct LinkEntry {
    /// Transport instance ID of the next hop toward the destination
    /// (Python `IDX_LT_NEXT_HOP`). Kept for parity with the Python link
    /// table entry; relayed link packets preserve their original
    /// addressing, so it is not rewritten on forwarding.
    #[allow(dead_code)]
    pub next_hop: AddressHash,
    /// Interface toward the destination (Python `IDX_LT_NH_IF`).
    pub next_hop_iface: AddressHash,
    /// Interface the link request arrived on — toward the initiator
    /// (Python `IDX_LT_RCVD_IF`).
    pub receiving_iface: AddressHash,
    /// Hops from this node to the link destination at LR time
    /// (Python `IDX_LT_REM_HOPS`).
    pub remaining_hops: u8,
    /// Hop count of the link request when received (Python
    /// `IDX_LT_HOPS`; our wire hops + 1 = Python's internal value).
    pub taken_hops: u8,
    /// Destination the link leads to (Python `IDX_LT_DSTHASH`).
    pub original_destination: AddressHash,
    /// Proof signature verified (Python `IDX_LT_VALIDATED`).
    pub validated: bool,
    pub proof_timeout: Instant,
    /// Last forwarded activity; validated entries expire when idle.
    pub last_activity: Instant,
}

/// What to do with a link-request proof
/// (Python Transport.inbound LRPROOF handling).
pub struct ProofOutcome {
    /// Relay the proof back toward the initiator on this interface.
    pub relay: Option<(Packet, AddressHash)>,
    /// Path-table rebalance: (destination, new hops)
    /// (Python `ALLOW_LINK_PATH_REBALANCE` branch).
    pub path_hops_update: Option<(AddressHash, u8)>,
}

impl LinkEntry {
    /// Python link-data routing rules (Transport.inbound, "Link transport
    /// handling"): same-interface links accept either hop count; on
    /// differing interfaces the packet is forwarded on the opposite
    /// interface of receipt when the hop count matches the expected
    /// value for that direction.
    ///
    /// `observed` is the Python-internal hop count (our wire hops + 1).
    fn outbound_iface_for(&self, ingress_iface: AddressHash, observed: u8) -> Option<AddressHash> {
        if self.next_hop_iface == self.receiving_iface {
            if observed == self.remaining_hops || observed == self.taken_hops {
                return Some(self.next_hop_iface);
            }
        } else if ingress_iface == self.next_hop_iface && observed == self.remaining_hops {
            return Some(self.receiving_iface);
        } else if ingress_iface == self.receiving_iface && observed == self.taken_hops {
            return Some(self.next_hop_iface);
        }

        None
    }
}

/// Rebuild a link-table-forwarded packet. Python relaying keeps the
/// original packet flags byte untouched and only rewrites the hop count
/// (`new_raw = packet.raw[0:1] + hops + packet.raw[2:]`), so the header
/// type and addressing travel unchanged between the link endpoints.
fn forwarded(packet: &Packet, transport: Option<AddressHash>, hops: u8) -> Packet {
    Packet {
        header: Header {
            ifac_flag: IfacFlag::Open,
            hops,
            ..packet.header
        },
        ifac: None,
        destination: packet.destination,
        transport,
        context: packet.context,
        data: packet.data.clone(),
    }
}

pub struct LinkTable(HashMap<LinkId, LinkEntry>);

impl LinkTable {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Record a relayed link request
    /// (Python creates the link entry when relaying an LR in transport).
    #[allow(clippy::too_many_arguments)]
    pub fn add(
        &mut self,
        link_request: &Packet,
        destination: AddressHash,
        receiving_iface: AddressHash,
        next_hop: AddressHash,
        next_hop_iface: AddressHash,
        remaining_hops: u8,
        next_hop_bitrate: u64,
    ) {
        let link_id = LinkId::from(link_request);

        // Python overwrites the link-table entry on every transported
        // link request, so a retried LR after a route or interface
        // change refreshes the forwarding state.
        let now = Instant::now();
        // `extra_link_proof_timeout` of the next-hop interface: one MTU
        // of airtime, or zero when that bitrate is unknown, plus
        // `ESTABLISHMENT_TIMEOUT_PER_HOP * max(1, remaining_hops)`.
        let airtime = if next_hop_bitrate == 0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(
                (1.0 / next_hop_bitrate as f64) * 8.0 * crate::packet::PROTOCOL_MTU as f64,
            )
        };
        let proof_timeout =
            now + airtime + ESTABLISHMENT_TIMEOUT_PER_HOP * remaining_hops.max(1) as u32;

        let entry = LinkEntry {
            next_hop,
            next_hop_iface,
            receiving_iface,
            remaining_hops,
            // Python records the LR's (incremented) hop count; our wire
            // hops are one less, so store wire + 1.
            taken_hops: link_request.header.hops.saturating_add(1),
            original_destination: destination,
            validated: false,
            proof_timeout,
            last_activity: now,
        };

        self.0.insert(link_id, entry);
    }

    /// Original destination of any link entry (validated or not) — used
    /// for identity recall on arriving proofs.
    pub fn original_destination_of(&self, link_id: &LinkId) -> Option<AddressHash> {
        self.0.get(link_id).map(|e| e.original_destination)
    }

    /// Whether the given address is a link-table entry (Python defers
    /// packet-hash insertion for these to keep shared-medium link
    /// transport working).
    pub fn contains_destination(&self, destination: &AddressHash) -> bool {
        self.0.contains_key(destination)
    }

    /// The interface a link-table entry was received on (toward the
    /// initiator), falling back to the next-hop interface toward the
    /// destination for relayed links.
    pub fn iface_of(&self, link_id: &LinkId) -> Option<AddressHash> {
        self.0.get(link_id).map(|e| {
            if e.receiving_iface.is_empty() {
                e.next_hop_iface
            } else {
                e.receiving_iface
            }
        })
    }

    /// Route a keepalive (request or response) on an intermediary link.
    pub fn handle_keepalive(
        &mut self,
        packet: &Packet,
        ingress_iface: AddressHash,
    ) -> Option<(Packet, AddressHash)> {
        let entry = self.0.get_mut(&packet.destination)?;

        // Keepalives are link data with Python-internal hop semantics:
        // requests come from the initiator (taken hops), responses from
        // the destination (remaining hops). The activity timestamp is
        // only refreshed once a valid direction was selected (Python
        // updates `IDX_LT_TIMESTAMP` after transmitting).
        let observed = packet.header.hops.saturating_add(1);
        let iface = entry.outbound_iface_for(ingress_iface, observed)?;
        entry.last_activity = Instant::now();

        Some((
            forwarded(packet, packet.transport, packet.header.hops + 1),
            iface,
        ))
    }

    /// Route ordinary link data on an intermediary link
    /// (Python "Link transport handling").
    pub fn route_link_packet(
        &mut self,
        packet: &Packet,
        ingress_iface: AddressHash,
    ) -> Option<(Packet, AddressHash)> {
        let entry = self.0.get_mut(&packet.destination)?;

        let observed = packet.header.hops.saturating_add(1);
        let iface = entry.outbound_iface_for(ingress_iface, observed)?;

        entry.last_activity = Instant::now();

        Some((
            forwarded(packet, packet.transport, packet.header.hops + 1),
            iface,
        ))
    }

    /// Handle a link-request proof arriving on an intermediary link
    /// (Python Transport.inbound LRPROOF handling): validates the
    /// destination's signature over
    /// `link_id || peer_pub || identity_sig_pub || signalling`, requires
    /// the proof to arrive on the destination-facing interface with the
    /// expected hop count, then relays it toward the initiator and marks
    /// the link validated. Also supports hop/path rebalancing for proofs
    /// with a different hop count.
    pub fn handle_lr_proof(
        &mut self,
        proof: &Packet,
        ingress_iface: AddressHash,
        recalled_identity: Option<&Identity>,
    ) -> ProofOutcome {
        let mut outcome = ProofOutcome {
            relay: None,
            path_hops_update: None,
        };

        let Some(entry) = self.0.get_mut(&proof.destination) else {
            return outcome;
        };

        let data = proof.data.as_slice();

        // proof_data = signature(64) || ephemeral pub(32) [|| signalling(3)]
        if data.len() != 64 + 32 && data.len() != 64 + 32 + 3 {
            log::debug!(
                "link_table: proof for {} has invalid length {}",
                proof.destination,
                data.len()
            );
            return outcome;
        }

        let signalling: &[u8] = if data.len() == 64 + 32 + 3 {
            &data[64 + 32..]
        } else {
            &[]
        };

        // Reconstruct the signed data exactly like the destination's
        // Link.prove(): link_id || pub || sig_pub || signalling.
        let mut signed = Vec::with_capacity(16 + 32 + 32 + signalling.len());
        signed.extend_from_slice(proof.destination.as_slice());
        signed.extend_from_slice(&data[64..64 + 32]);
        if let Some(identity) = recalled_identity {
            // Python peer_sig_pub = destination identity's public key's
            // signing (ed25519) half.
            signed.extend_from_slice(identity.verifying_key_bytes());
        } else {
            outcome.relay = None;
            log::debug!(
                "link_table: no recalled identity for {}, dropping proof",
                entry.original_destination
            );
            return outcome;
        }
        signed.extend_from_slice(signalling);

        let mut signature_bytes = [0u8; 64];
        signature_bytes.copy_from_slice(&data[..64]);
        let signature = Signature::from_bytes(&signature_bytes);

        let verified = recalled_identity
            .map(|identity| identity.verify(&signed, &signature).is_ok())
            .unwrap_or(false);

        if !verified {
            log::debug!(
                "link_table: invalid link request proof signature for {}, dropping",
                proof.destination
            );
            return outcome;
        }

        let observed = proof.header.hops.saturating_add(1);

        // Path rebalancing (Python `ALLOW_LINK_PATH_REBALANCE`): an
        // authenticated proof with a mismatched hop count first updates
        // the expected hops; the equality check below then still
        // validates and relays the very same proof.
        if observed != entry.remaining_hops && ingress_iface == entry.next_hop_iface {
            log::debug!(
                "link_table: re-balancing path to {} from link-request proof ({} -> {})",
                entry.original_destination,
                entry.remaining_hops,
                observed
            );
            entry.remaining_hops = observed;
            outcome.path_hops_update = Some((entry.original_destination, observed));
        }

        if observed == entry.remaining_hops {
            if ingress_iface == entry.next_hop_iface {
                log::trace!(
                    "link_table: link request proof validated for transport via {}",
                    entry.receiving_iface
                );
                entry.validated = true;
                outcome.relay = Some((
                    forwarded(proof, proof.transport, proof.header.hops + 1),
                    entry.receiving_iface,
                ));
            } else {
                log::debug!("link_table: proof received on wrong interface, not transporting");
            }
        } else {
            log::debug!(
                "link_table: proof hop mismatch ({}/{}) not transporting",
                observed,
                entry.remaining_hops
            );
        }

        outcome
    }

    /// Remove stale entries. Unvalidated link requests that timed out are
    /// returned so the caller can mark a one-hop path unresponsive.
    pub fn remove_stale(&mut self) -> Vec<LinkEntry> {
        let mut stale = vec![];
        let mut timed_out = vec![];
        let now = Instant::now();

        for (link_id, entry) in &self.0 {
            if entry.validated {
                if now.saturating_duration_since(entry.last_activity) > LINK_TIMEOUT {
                    stale.push(*link_id);
                }
            } else if entry.proof_timeout <= now {
                stale.push(*link_id);
                timed_out.push(*entry);
            }
        }

        for link_id in stale {
            self.0.remove(&link_id);
        }
        timed_out
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// Drop link-table entries that use `iface` in either direction.
    pub fn drop_iface(&mut self, iface: &AddressHash) {
        self.0
            .retain(|_, entry| entry.next_hop_iface != *iface && entry.receiving_iface != *iface);
    }

    /// Number of entries in the link table (pending + active links).
    ///
    /// Python parity: `RNS.Transport.get_link_count()` returns
    /// `len(Transport.link_table)`.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Link-table rows whose proof has been validated
    /// (Python `Transport.active_link_count`).
    pub fn validated_len(&self) -> usize {
        self.0.values().filter(|entry| entry.validated).count()
    }

    /// Whether the link table is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
