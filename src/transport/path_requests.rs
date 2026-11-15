use alloc::collections::{BTreeMap, BTreeSet};

use rand_core::OsRng;

use tokio::time::{Duration, Instant};

use crate::destination::DestinationName;
use crate::destination::PlainInputDestination;
use crate::hash::AddressHash;
use crate::hash::ADDRESS_HASH_SIZE;
use crate::identity::EmptyIdentity;
use crate::packet::DestinationType;
use crate::packet::Header;
use crate::packet::HeaderType;
use crate::packet::IfacFlag;
use crate::packet::Packet;
use crate::packet::PacketContext;
use crate::packet::PacketDataBuffer;
use crate::packet::PacketType;
use crate::packet::PropagationType;

/// Default timeout for client path requests in seconds
/// (Python `Transport.PATH_REQUEST_TIMEOUT`).
pub const PATH_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// How long an automated path-request timestamp is kept
/// (Python `Transport.PATH_REQUEST_GATE_TIMEOUT`). Longer than the 20s
/// minimum interval, so the gate still sees the timestamp after the 15s
/// ingress exemption has lapsed.
const PATH_REQUEST_GATE_TIMEOUT: Duration = Duration::from_secs(45);

pub fn create_path_request_destination() -> PlainInputDestination {
    PlainInputDestination::new(
        EmptyIdentity {},
        DestinationName::new("rnstransport", "path.request"),
    )
}

pub type TagBytes = Vec<u8>;

/// Maximum remembered (destination, tag) pairs: control packets arrive
/// before the general packet-cache filter, so an unbounded set is a
/// remote OOM vector (Python bounds its remembered request tags).
const MAX_REMEMBERED_TAGS: usize = 4096;

pub fn create_random_tag() -> TagBytes {
    AddressHash::new_from_rand(OsRng).as_slice().into()
}

pub struct PathRequest {
    pub destination: AddressHash,
    pub requesting_transport: Option<AddressHash>,
    pub tag_bytes: TagBytes,
}

impl PathRequest {
    fn decode(data: &[u8], transport_name: &str) -> Option<Self> {
        if data.len() <= ADDRESS_HASH_SIZE {
            log::info!(
                "tp({}): ignoring malformed path request: no {}",
                transport_name,
                if data.len() < ADDRESS_HASH_SIZE {
                    "destination"
                } else {
                    "tag"
                }
            );
            return None;
        }

        let mut destination = [0u8; ADDRESS_HASH_SIZE];
        destination.copy_from_slice(&data[..ADDRESS_HASH_SIZE]);
        let destination = AddressHash::new(destination);

        let mut requesting_transport = None;
        let mut tag_start = ADDRESS_HASH_SIZE;
        let mut tag_end = data.len();

        if data.len() > ADDRESS_HASH_SIZE * 2 {
            requesting_transport = Some(AddressHash::new_from_slice(
                &data[ADDRESS_HASH_SIZE..2 * ADDRESS_HASH_SIZE],
            ));
            tag_start = ADDRESS_HASH_SIZE * 2;
        }

        if tag_end - tag_start > ADDRESS_HASH_SIZE {
            tag_end = tag_start + ADDRESS_HASH_SIZE;
        }

        let tag_bytes = data[tag_start..tag_end].into();

        Some(Self {
            destination,
            requesting_transport,
            tag_bytes,
        })
    }
}

pub struct PathRequests {
    cache: BTreeSet<(AddressHash, TagBytes)>,
    name: String,
    transport_id: Option<AddressHash>,
    controlled_destination: PlainInputDestination,
    /// Outstanding (discovery) path requests sent on behalf of an unknown
    /// destination (Python `Transport.discovery_path_requests`).
    discovery: BTreeMap<AddressHash, PendingDiscovery>,
    /// Path requests issued locally, with the time they were last sent.
    /// Ingress exemption only: entries lapse at `PATH_REQUEST_TIMEOUT`
    /// (15s). This is not the automated-request gate.
    pending: BTreeMap<AddressHash, Instant>,
    /// Last automated path-request time (Python `Transport.path_requests`).
    /// Independent of `pending`. `has_pending` must not remove these:
    /// `request_allowed` still needs them until `PATH_REQUEST_MI` (20s),
    /// and Python keeps the table until `PATH_REQUEST_GATE_TIMEOUT` (45s).
    last_request: BTreeMap<AddressHash, Instant>,
    /// Minimum interval between automated path requests for the same
    /// destination (Python `Transport.PATH_REQUEST_MI`).
    min_request_interval: Duration,
}

/// One in-flight discovery path request
/// (Python `discovery_path_requests[destination_hash]`).
struct PendingDiscovery {
    deadline: Instant,
    /// Wait that produced `deadline`. Elapsed time still counts: a longer
    /// supplied wait extends the deadline by the difference, and a shorter
    /// one does not shrink it.
    wait: Duration,
    ifaces: Vec<AddressHash>,
}

/// Python `max(Transport.PATH_REQUEST_TIMEOUT, Transport.medium_path_timeout())`.
fn discovery_wait(medium_path_timeout: Duration) -> Duration {
    PATH_REQUEST_TIMEOUT.max(medium_path_timeout)
}

fn lengthen_discovery_wait(entry: &mut PendingDiscovery, medium_path_timeout: Duration) {
    let wait = discovery_wait(medium_path_timeout);
    if wait > entry.wait {
        entry.deadline += wait - entry.wait;
        entry.wait = wait;
    }
}

impl PathRequests {
    pub fn new(name: &str, transport_id: Option<AddressHash>) -> Self {
        Self {
            cache: BTreeSet::new(),
            name: name.into(),
            transport_id,
            controlled_destination: create_path_request_destination(),
            discovery: BTreeMap::new(),
            pending: BTreeMap::new(),
            last_request: BTreeMap::new(),
            min_request_interval: Duration::from_secs(20),
        }
    }

    pub fn decode(&mut self, data: &[u8]) -> Option<PathRequest> {
        let path_request = PathRequest::decode(data, &self.name);

        if let Some(ref request) = path_request {
            // Bound the remembered tags: control packets arrive before
            // the general packet-cache filter, so an unbounded set is a
            // remote OOM vector (Python bounds its request tags).
            while self.cache.len() >= MAX_REMEMBERED_TAGS {
                let Some(oldest) = self.cache.iter().next().cloned() else {
                    break;
                };
                self.cache.remove(&oldest);
            }

            let is_new = self
                .cache
                .insert((request.destination, request.tag_bytes.clone()));

            if !is_new {
                log::info!(
                    "tp({}): ignoring duplicate path request for destination {}",
                    self.name,
                    request.destination
                );
                return None;
            }
        }

        path_request
    }

    pub fn generate(&mut self, destination: &AddressHash, tag: Option<TagBytes>) -> Packet {
        let now = Instant::now();
        self.pending.insert(*destination, now);
        self.last_request.insert(*destination, now);

        let mut data = PacketDataBuffer::new_from_slice(destination.as_slice());

        if let Some(transport_id) = self.transport_id {
            data.safe_write(transport_id.as_slice());
        }

        data.safe_write(tag.unwrap_or_else(create_random_tag).as_slice());

        let destination = self.controlled_destination.desc.address_hash;

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
            transport: self.transport_id,
            context: PacketContext::None,
            data,
        }
    }

    /// Whether a locally issued path request for `destination` is still
    /// inside the 15s ingress exemption. Reporting false after
    /// `PATH_REQUEST_TIMEOUT` removes only that exemption. It does not
    /// pop `last_request`: announce handling calls this before the 20s
    /// gate, and Python's membership test does not pop `path_requests`.
    pub fn has_pending(&mut self, destination: &AddressHash) -> bool {
        let now = Instant::now();
        match self.pending.get(destination) {
            Some(at) if now - *at < PATH_REQUEST_TIMEOUT => true,
            Some(_) => {
                self.pending.remove(destination);
                false
            }
            None => false,
        }
    }

    /// Whether a recursive discovery request for `destination` is currently
    /// waiting (Python `Transport.discovery_path_requests`).
    pub fn discovery_pending(&self, destination: &AddressHash) -> bool {
        match self.discovery.get(destination) {
            Some(entry) => Instant::now() < entry.deadline,
            None => false,
        }
    }

    /// Register a waiting discovery path request for `destination`
    /// (Python `max(PATH_REQUEST_TIMEOUT, medium_path_timeout)`).
    ///
    /// `medium_path_timeout` is `Transport.medium_path_timeout()` (zero
    /// when the bitrate is unknown). Pass [`PATH_REQUEST_TIMEOUT`] for the
    /// 15s floor. A value that is already the max is accepted. Returns
    /// `true` when this call started the discovery, so the caller should
    /// forward the path request. Returns `false` when the requestor was
    /// retained on a discovery that is already pending (do not search
    /// again) or when no requesting interface was given.
    ///
    /// Batching does not restart the deadline. Elapsed time still counts:
    /// a longer supplied wait extends it by the difference, and a shorter
    /// one does not shrink it.
    pub fn register_discovery_with_timeout(
        &mut self,
        destination: &AddressHash,
        requesting_iface: Option<AddressHash>,
        medium_path_timeout: Duration,
    ) -> bool {
        let Some(iface) = requesting_iface else {
            return false;
        };
        let wait = discovery_wait(medium_path_timeout);

        if let Some(entry) = self.discovery.get_mut(destination) {
            if Instant::now() < entry.deadline {
                if !entry.ifaces.contains(&iface) {
                    entry.ifaces.push(iface);
                }
                lengthen_discovery_wait(entry, medium_path_timeout);
                return false;
            }
        }

        self.discovery.insert(
            *destination,
            PendingDiscovery {
                deadline: Instant::now() + wait,
                wait,
                ifaces: vec![iface],
            },
        );
        true
    }

    /// A matching announce arrived. Removes the discovery entry and
    /// returns every requesting interface that must be answered, including
    /// requestors batched while the discovery was pending (Python pops
    /// `discovery_path_requests` and retransmits a path response to each
    /// `requesting_interfaces` entry).
    pub fn clear_discovery(&mut self, destination: &AddressHash) -> Option<Vec<AddressHash>> {
        self.discovery.remove(destination).map(|entry| entry.ifaces)
    }

    /// Whether an automated path request for `destination` may be sent now,
    /// honouring `PATH_REQUEST_MI` (Python automated path request gating).
    /// Reads `last_request`, which `has_pending` does not remove. Entries
    /// stay until `PATH_REQUEST_GATE_TIMEOUT` (45s).
    pub fn request_allowed(&mut self, destination: &AddressHash) -> bool {
        let now = Instant::now();
        self.last_request
            .retain(|_, at| now - *at < PATH_REQUEST_GATE_TIMEOUT);
        match self.last_request.get(destination) {
            Some(at) => now - *at >= self.min_request_interval,
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_request_roundtrip() {
        let mut testee = PathRequests::new("", None);

        let dest = AddressHash::new_from_rand(OsRng);

        let encoded = testee.generate(&dest, None);
        let decoded = testee.decode(encoded.data.as_slice()).unwrap();

        assert_eq!(decoded.destination, dest);
    }

    #[test]
    fn pending_requests_expire() {
        let mut testee = PathRequests::new("", None);
        let dest = AddressHash::new_from_rand(OsRng);

        assert!(!testee.has_pending(&dest));

        testee.generate(&dest, None);
        assert!(testee.has_pending(&dest));

        testee.pending.insert(
            dest,
            Instant::now() - PATH_REQUEST_TIMEOUT - Duration::from_secs(1),
        );
        assert!(!testee.has_pending(&dest));
    }

    #[test]
    fn ingress_expiry_leaves_the_request_gate() {
        let mut testee = PathRequests::new("", None);
        let dest = AddressHash::new_from_rand(OsRng);

        testee.generate(&dest, None);
        assert!(testee.has_pending(&dest));
        assert!(!testee.request_allowed(&dest));

        // An announce at 15s expires the ingress exemption and must not
        // make the 20s gate allow another automated request.
        testee.pending.insert(
            dest,
            Instant::now() - PATH_REQUEST_TIMEOUT - Duration::from_secs(1),
        );
        assert!(!testee.has_pending(&dest));
        assert!(
            !testee.request_allowed(&dest),
            "the 20s gate must still see the request timestamp after 15s"
        );

        testee
            .last_request
            .insert(dest, Instant::now() - Duration::from_secs(19));
        assert!(!testee.request_allowed(&dest));

        testee
            .last_request
            .insert(dest, Instant::now() - Duration::from_secs(20));
        assert!(testee.request_allowed(&dest));
    }

    #[test]
    fn discovery_registration_and_batching() {
        let mut testee = PathRequests::new("", None);
        let dest = AddressHash::new_from_rand(OsRng);
        let iface_a = AddressHash::new_from_rand(OsRng);
        let iface_b = AddressHash::new_from_rand(OsRng);

        assert!(!testee.discovery_pending(&dest));
        // A request without a requesting interface registers nothing
        // (Python entries always carry their requesting interface).
        assert!(!testee.register_discovery_with_timeout(&dest, None, PATH_REQUEST_TIMEOUT));
        assert!(!testee.discovery_pending(&dest));

        assert!(testee.register_discovery_with_timeout(&dest, Some(iface_a), PATH_REQUEST_TIMEOUT));
        assert!(testee.discovery_pending(&dest));
        let deadline = testee.discovery.get(&dest).unwrap().deadline;

        // A second in-flight request batches onto the existing entry.
        // The same 15s wait does not move the deadline.
        assert!(!testee.register_discovery_with_timeout(
            &dest,
            Some(iface_b),
            PATH_REQUEST_TIMEOUT
        ));
        assert_eq!(testee.discovery.get(&dest).unwrap().deadline, deadline);
        let batched = testee.clear_discovery(&dest).expect("batched entry");
        assert_eq!(batched, vec![iface_a, iface_b]);
        assert!(!testee.discovery_pending(&dest));
    }

    #[test]
    fn two_requestors_retained_and_answered() {
        let mut testee = PathRequests::new("", None);
        let dest = AddressHash::new_from_rand(OsRng);
        let iface_a = AddressHash::new_from_rand(OsRng);
        let iface_b = AddressHash::new_from_rand(OsRng);

        assert!(testee.register_discovery_with_timeout(
            &dest,
            Some(iface_a),
            Duration::from_secs(40),
        ));
        assert_eq!(testee.discovery.get(&dest).unwrap().ifaces, vec![iface_a]);

        // Second requestor while discovery is already pending. Same
        // interface again must not be answered twice.
        assert!(!testee.register_discovery_with_timeout(
            &dest,
            Some(iface_b),
            Duration::from_secs(40),
        ));
        assert!(!testee.register_discovery_with_timeout(
            &dest,
            Some(iface_a),
            Duration::from_secs(40),
        ));
        assert!(testee.discovery_pending(&dest));
        assert_eq!(
            testee.discovery.get(&dest).unwrap().ifaces,
            vec![iface_a, iface_b]
        );

        let answered = testee
            .clear_discovery(&dest)
            .expect("both requestors answered");
        assert_eq!(answered, vec![iface_a, iface_b]);
        assert!(testee.clear_discovery(&dest).is_none());
        assert!(!testee.discovery_pending(&dest));
    }

    #[test]
    fn discovery_wait_floors_at_path_request_timeout() {
        assert_eq!(discovery_wait(Duration::ZERO), PATH_REQUEST_TIMEOUT);
        assert_eq!(discovery_wait(Duration::from_secs(5)), PATH_REQUEST_TIMEOUT);
        assert_eq!(
            discovery_wait(Duration::from_millis(14_999)),
            PATH_REQUEST_TIMEOUT
        );
        assert_eq!(discovery_wait(PATH_REQUEST_TIMEOUT), PATH_REQUEST_TIMEOUT);
        let longer = Duration::from_secs(40);
        assert_eq!(discovery_wait(longer), longer);
        let just_over = PATH_REQUEST_TIMEOUT + Duration::from_millis(1);
        assert_eq!(discovery_wait(just_over), just_over);

        let mut testee = PathRequests::new("", None);
        let iface = AddressHash::new_from_rand(OsRng);

        assert_deadline_wait(&mut testee, iface, None, PATH_REQUEST_TIMEOUT);
        assert_deadline_wait(
            &mut testee,
            iface,
            Some(Duration::ZERO),
            PATH_REQUEST_TIMEOUT,
        );
        assert_deadline_wait(
            &mut testee,
            iface,
            Some(Duration::from_secs(5)),
            PATH_REQUEST_TIMEOUT,
        );
        assert_deadline_wait(&mut testee, iface, Some(longer), longer);
        assert_deadline_wait(&mut testee, iface, Some(just_over), just_over);
    }

    #[test]
    fn longer_medium_timeout_extends_pending_discovery() {
        let mut testee = PathRequests::new("", None);
        let dest = AddressHash::new_from_rand(OsRng);
        let iface_a = AddressHash::new_from_rand(OsRng);
        let iface_b = AddressHash::new_from_rand(OsRng);

        // Elapsed time still counts: 40s on a pending 15s discovery
        // extends the deadline by 25s. A shorter wait does not shrink it.
        assert!(testee.register_discovery_with_timeout(&dest, Some(iface_a), PATH_REQUEST_TIMEOUT));
        let created = testee.discovery.get(&dest).unwrap().deadline;
        assert_eq!(
            testee.discovery.get(&dest).unwrap().wait,
            PATH_REQUEST_TIMEOUT
        );

        assert!(!testee.register_discovery_with_timeout(
            &dest,
            Some(iface_b),
            Duration::from_secs(40),
        ));
        let before = {
            let entry = testee.discovery.get(&dest).unwrap();
            assert_eq!(entry.wait, Duration::from_secs(40));
            assert_eq!(
                entry.deadline.checked_duration_since(created).unwrap(),
                Duration::from_secs(25)
            );
            assert_eq!(entry.ifaces, vec![iface_a, iface_b]);
            entry.deadline
        };

        // A shorter medium timeout must not shrink the in-flight wait.
        let iface_c = AddressHash::new_from_rand(OsRng);
        assert!(!testee.register_discovery_with_timeout(
            &dest,
            Some(iface_c),
            Duration::from_secs(5),
        ));
        let entry = testee.discovery.get(&dest).unwrap();
        assert_eq!(entry.deadline, before);
        assert_eq!(entry.wait, Duration::from_secs(40));
        assert_eq!(entry.ifaces, vec![iface_a, iface_b, iface_c]);

        // An expired discovery is a new wait, not an answer to the old
        // requestors.
        testee.discovery.get_mut(&dest).unwrap().deadline = Instant::now() - Duration::from_secs(1);
        assert!(!testee.discovery_pending(&dest));
        let iface_d = AddressHash::new_from_rand(OsRng);
        assert!(testee.register_discovery_with_timeout(
            &dest,
            Some(iface_d),
            Duration::from_secs(40),
        ));
        let answered = testee.clear_discovery(&dest).unwrap();
        assert_eq!(answered, vec![iface_d]);
    }

    fn assert_deadline_wait(
        testee: &mut PathRequests,
        iface: AddressHash,
        medium: Option<Duration>,
        expected: Duration,
    ) {
        let dest = AddressHash::new_from_rand(OsRng);
        let before = Instant::now();
        let started = match medium {
            Some(medium) => testee.register_discovery_with_timeout(&dest, Some(iface), medium),
            None => {
                testee.register_discovery_with_timeout(&dest, Some(iface), PATH_REQUEST_TIMEOUT)
            }
        };
        let after = Instant::now();
        assert!(started);
        let entry = testee.discovery.get(&dest).unwrap();
        assert_eq!(entry.wait, expected);
        let span = entry.deadline.duration_since(before);
        let elapsed = after.saturating_duration_since(before);
        assert!(
            span >= expected,
            "deadline span {span:?} shorter than {expected:?}"
        );
        assert!(
            span - expected <= elapsed,
            "deadline span {span:?} exceeds {expected:?} by more than elapsed {elapsed:?}"
        );
    }
}
