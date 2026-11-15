//! Per-interface transport control state — Python `RNS.Interfaces.Interface`
//! parity: interface modes, announce ingress control (burst detection and
//! held announces), path-request ingress/egress limiting and announce egress
//! airtime budgeting (announce cap + queued announces).
//!
//! Python keeps this state directly on interface objects and drives the
//! release timers with `threading.Timer`; here the state lives beside the
//! spawned interface inside the [`crate::iface::InterfaceManager`] and the
//! transport drives it from periodic ticks.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use tokio::time::{Duration, Instant};

use crate::buffer::OutputBuffer;
use crate::hash::AddressHash;
use crate::packet::{Packet, PacketType, PACKET_MDU};
use crate::serde::Serialize;

/// Offset of the 10-byte random blob inside announce data
/// (Python: `KEYSIZE//8 + NAME_HASH_LENGTH//8`).
pub const RANDOM_BLOB_OFFSET: usize =
    crate::identity::PUBLIC_KEY_LENGTH * 2 + crate::destination::NAME_HASH_LENGTH;

/// Interface modes (Python `Interface.MODE_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InterfaceMode {
    #[default]
    Full = 0x01,
    PointToPoint = 0x02,
    AccessPoint = 0x03,
    Roaming = 0x04,
    Boundary = 0x05,
    Gateway = 0x06,
    Internal = 0x07,
}

impl InterfaceMode {
    /// Which interface modes a transport node actively discovers
    /// (sends recursive path requests) paths for
    /// (Python `Interface.DISCOVER_PATHS_FOR`).
    pub const DISCOVER_PATHS_FOR: [InterfaceMode; 4] = [
        InterfaceMode::AccessPoint,
        InterfaceMode::Gateway,
        InterfaceMode::Roaming,
        InterfaceMode::Internal,
    ];

    /// Modes eligible for boundary-mode recursive search
    /// (Python `Interface.BOUNDARY_SEARCH_MODES`).
    pub const BOUNDARY_SEARCH_MODES: [InterfaceMode; 2] =
        [InterfaceMode::Boundary, InterfaceMode::Gateway];

    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0x01 => Self::Full,
            0x02 => Self::PointToPoint,
            0x03 => Self::AccessPoint,
            0x04 => Self::Roaming,
            0x05 => Self::Boundary,
            0x06 => Self::Gateway,
            0x07 => Self::Internal,
            _ => return None,
        })
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name.to_lowercase().as_str() {
            "full" | "default" => Self::Full,
            "pointtopoint" | "point_to_point" | "point-to-point" | "ptp" => Self::PointToPoint,
            "accesspoint" | "access_point" | "access-point" | "ap" => Self::AccessPoint,
            "roaming" => Self::Roaming,
            "boundary" => Self::Boundary,
            "gateway" | "gw" => Self::Gateway,
            "internal" => Self::Internal,
            _ => return None,
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::PointToPoint => "point_to_point",
            Self::AccessPoint => "access_point",
            Self::Roaming => "roaming",
            Self::Boundary => "boundary",
            Self::Gateway => "gateway",
            Self::Internal => "internal",
        }
    }
}

/// Frequency sample counts (Python `Interface.IA_FREQ_SAMPLES` etc.).
const FREQ_SAMPLES: usize = 48;
/// Minimum deque samples before frequencies are trusted
/// (Python `Interface.IC_DEQUE_MIN_SAMPLE`).
const DEQUE_MIN_SAMPLE: usize = 2;
/// Minimum samples before egress path-request limiting
/// (Python `Interface.EC_BURST_MIN_SAMPLES`).
const EC_BURST_MIN_SAMPLES: usize = 2;
/// Quiet samples a path-request burst must survive before it clears
/// (Python hardcodes 3 in `should_ingress_limit_pr`).
const IC_PR_BURST_COOLDOWN: u8 = 3;
/// Announce frequency decay, `1 / AR_MINFREQ_HZ` seconds
/// (Python `Interface.AR_FREQ_DECAY`).
const AR_FREQ_DECAY: Duration = Duration::from_secs(10);
/// Path-request frequency decay (Python `Interface.PR_FREQ_DECAY`).
const PR_FREQ_DECAY: Duration = Duration::from_secs(10);

/// Default announce airtime budget as a fraction of interface airtime.
/// Python's integer `Reticulum.ANNOUNCE_CAP` is 2 percent; the runtime
/// field is `ANNOUNCE_CAP / 100.0`.
pub const ANNOUNCE_CAP: f64 = 0.02;
/// Default interface bitrate in bits per second
/// (Python `Interface.bitrate`). Kept separate from [`ANNOUNCE_CAP`]:
/// the cap is a fraction, not a rate.
pub const DEFAULT_BITRATE: u64 = 62_500;
/// Maximum queued announces per interface
/// (Python `RNS.Reticulum.MAX_QUEUED_ANNOUNCES`).
pub const MAX_QUEUED_ANNOUNCES: usize = 16384;
/// Lifetime of a queued announce entry
/// (Python `RNS.Reticulum.QUEUED_ANNOUNCE_LIFE`).
pub const QUEUED_ANNOUNCE_LIFE: Duration = Duration::from_secs(60 * 60 * 24);
/// Maximum held (ingress limited) announces
/// (Python `Interface.MAX_HELD_ANNOUNCES`).
pub const MAX_HELD_ANNOUNCES: usize = 256;

/// Configurable ingress/egress control parameters with Python defaults
/// (Python `RNS.Reticulum._default_ic_*` / `_default_ec_*`).
#[derive(Debug, Clone, Copy)]
pub struct IfaceControlParams {
    pub ic_max_held_announces: usize,
    pub ic_burst_hold: Duration,
    pub ic_burst_freq_new: f64,
    pub ic_burst_freq: f64,
    pub ic_pr_burst_freq_new: f64,
    pub ic_pr_burst_freq: f64,
    pub ic_new_time: Duration,
    pub ic_burst_penalty: Duration,
    pub ic_held_release_interval: Duration,
    pub ec_pr_freq: f64,
}

impl Default for IfaceControlParams {
    fn default() -> Self {
        Self {
            ic_max_held_announces: MAX_HELD_ANNOUNCES,
            ic_burst_hold: Duration::from_secs(15),
            ic_burst_freq_new: 3.0,
            ic_burst_freq: 10.0,
            ic_pr_burst_freq_new: 3.0,
            ic_pr_burst_freq: 8.0,
            ic_new_time: Duration::from_secs(2 * 60 * 60),
            ic_burst_penalty: Duration::from_secs(15),
            ic_held_release_interval: Duration::from_secs(5),
            ec_pr_freq: 5.0,
        }
    }
}

/// An announce waiting in the egress queue of an interface.
#[derive(Debug, Clone)]
pub struct QueuedAnnounce {
    pub packet: Packet,
    pub queued_at: Instant,
    pub emitted: u64,
}

/// Emission timestamp of an announce packet, taken from the last 5 bytes of
/// the random blob
/// (Python `Transport.announce_emitted`: `int.from_bytes(blob[5:10], "big")`).
pub fn announce_emitted(packet: &Packet) -> u64 {
    let data = packet.data.as_slice();
    let start = RANDOM_BLOB_OFFSET + 5;
    if data.len() >= start + 5 {
        let mut bytes = [0u8; 8];
        bytes[3..8].copy_from_slice(&data[start..start + 5]);
        u64::from_be_bytes(bytes)
    } else {
        0
    }
}

/// Wire size used for airtime accounting
/// (Python uses `len(packet.raw)`, the packed header + payload).
pub fn packet_wire_len(packet: &Packet) -> usize {
    let mut scratch = [0u8; PACKET_MDU + 128];
    let mut output = OutputBuffer::new(&mut scratch);
    match packet.serialize(&mut output) {
        Ok(_) => output.offset(),
        Err(_) => PACKET_MDU,
    }
}

/// Whether a queued announce is stale (Python drops entries older than
/// `QUEUED_ANNOUNCE_LIFE` when processing the queue).
fn queued_is_stale(entry: &QueuedAnnounce, now: Instant) -> bool {
    now > entry.queued_at + QUEUED_ANNOUNCE_LIFE
}

/// Per-interface control state.
pub struct IfaceControlState {
    created: Instant,
    /// Interface mode (Python `Interface.mode`).
    pub mode: InterfaceMode,
    /// Nominal interface bitrate in bits per second
    /// (Python `Interface.bitrate`, default [`DEFAULT_BITRATE`]).
    pub bitrate: u64,
    /// Announce airtime budget fraction (Python `Interface.announce_cap`,
    /// default [`ANNOUNCE_CAP`] = `Reticulum.ANNOUNCE_CAP / 100.0`).
    pub announce_cap: f64,
    /// Ingress control enabled (Python `Interface.ingress_control`).
    pub ingress_control: bool,
    /// When false, `should_ingress_limit` stays false even if
    /// `ingress_control` is on. KISS (including AX.25) and serial set
    /// this false. Path-request limiting is unchanged.
    announce_ingress_limit: bool,
    /// Egress control for path requests (Python `Interface.egress_control`).
    pub egress_control: bool,
    /// Always send recursive path requests out of this interface
    /// (Python `Interface.recursive_prs`).
    pub recursive_prs: bool,
    /// Announces from internal-mode interfaces are accepted
    /// (Python `Interface.announces_from_internal`).
    pub announces_from_internal: bool,
    /// Whether announces are forwarded *to* internal-mode interfaces
    /// (Python `Interface.announces_to_internal`, default None).
    pub announces_to_internal: Option<bool>,
    /// Whether this interface is a local shared-instance client
    /// (Python `is_local_client_interface`: interfaces spawned by a
    /// `LocalInterface` server with `is_local_shared_instance`).
    pub is_local_client: bool,
    /// Tunnel id this interface is currently bound to
    /// (Python `Interface.tunnel_id`).
    pub tunnel_id: Option<AddressHash>,
    /// The interface requested a tunnel synthesis
    /// (Python `Interface.wants_tunnel`).
    pub wants_tunnel: bool,
    /// Path-selection weight (Python `Interface.gravity`, default 0).
    pub gravity: i64,
    /// Per-interface announce rate. `None` means this interface has no
    /// target, so transport does not keep or consult a rate another
    /// interface stored for the same destination.
    pub announce_rate_target: Option<Duration>,
    pub announce_rate_grace: Option<u32>,
    pub announce_rate_penalty: Option<Duration>,

    params: IfaceControlParams,

    announce_allowed_at: Instant,

    ia_freq_deque: VecDeque<Instant>,
    oa_freq_deque: VecDeque<Instant>,
    ip_freq_deque: VecDeque<Instant>,
    op_freq_deque: VecDeque<Instant>,

    ic_burst_active: bool,
    ic_burst_activated: Instant,
    /// Last time the announce burst was still at or above the threshold
    /// (Python `Interface.ic_burst_sustained`). The hold window is measured
    /// from this stamp, so a sustained burst does not expire early.
    ic_burst_sustained: Instant,
    ic_pr_burst_active: bool,
    ic_pr_burst_activated: Instant,
    ic_pr_burst_sustained: Instant,
    /// Remaining quiet observations before a path-request burst clears
    /// (Python `Interface.ic_pr_burst_cooldown`).
    ic_pr_burst_cooldown: u8,
    ic_held_release: Instant,

    /// Announces held due to active ingress limiting
    /// (Python `Interface.held_announces`).
    held_announces: BTreeMap<AddressHash, Packet>,
    /// Queued outbound announces (Python `Interface.announce_queue`).
    announce_queue: Vec<QueuedAnnounce>,
}

impl IfaceControlState {
    pub fn new(now: Instant) -> Self {
        Self {
            created: now,
            mode: InterfaceMode::default(),
            bitrate: DEFAULT_BITRATE,
            announce_cap: ANNOUNCE_CAP,
            ingress_control: true,
            announce_ingress_limit: true,
            egress_control: false,
            recursive_prs: false,
            announces_from_internal: true,
            announces_to_internal: None,
            is_local_client: false,
            tunnel_id: None,
            wants_tunnel: false,
            gravity: 0,
            announce_rate_target: None,
            announce_rate_grace: None,
            announce_rate_penalty: None,
            params: IfaceControlParams::default(),
            announce_allowed_at: now,
            ia_freq_deque: VecDeque::new(),
            oa_freq_deque: VecDeque::new(),
            ip_freq_deque: VecDeque::new(),
            op_freq_deque: VecDeque::new(),
            ic_burst_active: false,
            ic_burst_activated: now,
            ic_burst_sustained: now,
            ic_pr_burst_active: false,
            ic_pr_burst_activated: now,
            ic_pr_burst_sustained: now,
            ic_pr_burst_cooldown: 0,
            ic_held_release: now,
            held_announces: BTreeMap::new(),
            announce_queue: Vec::new(),
        }
    }

    /// Override the configurable control parameters.
    pub fn set_params(&mut self, params: IfaceControlParams) {
        self.params = params;
    }

    /// Enable or disable announce ingress limiting.
    ///
    /// KISS (including AX.25) and serial set this false at spawn.
    /// `ingress_control` still gates path-request bursts.
    pub fn set_announce_ingress_limit(&mut self, enabled: bool) {
        self.announce_ingress_limit = enabled;
    }

    pub fn params(&self) -> &IfaceControlParams {
        &self.params
    }

    pub fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.created)
    }

    // ------------------------------------------------------------------
    // Frequency accounting (Python `received_announce`/`sent_announce`/
    // `received_path_request`/`sent_path_request` and the
    // `*_frequency` calculators).
    // ------------------------------------------------------------------

    fn push_sample(deque: &mut VecDeque<Instant>, now: Instant) {
        if deque.len() == FREQ_SAMPLES {
            deque.pop_front();
        }
        deque.push_back(now);
    }

    /// Account one received announce. Python forwards the sample to the
    /// parent interface for spawned interfaces; the Rust manager calls
    /// this on the parent explicitly.
    pub fn received_announce(&mut self, now: Instant) {
        Self::push_sample(&mut self.ia_freq_deque, now);
    }

    pub fn sent_announce(&mut self, now: Instant) {
        Self::push_sample(&mut self.oa_freq_deque, now);
    }

    pub fn received_path_request(&mut self, now: Instant) {
        Self::push_sample(&mut self.ip_freq_deque, now);
    }

    pub fn sent_path_request(&mut self, now: Instant) {
        Self::push_sample(&mut self.op_freq_deque, now);
    }

    /// `preemptive` counts a packet that has not been sampled yet.
    /// Python adds that 1 after the length check (`outgoing_pr_frequency`).
    fn frequency(
        deque: &mut VecDeque<Instant>,
        decay: Duration,
        min_samples: usize,
        now: Instant,
        preemptive: bool,
    ) -> f64 {
        let n = deque.len();
        if n <= min_samples {
            return 0.0;
        }

        let oldest = deque[0];
        let span = now.saturating_duration_since(oldest);
        if span > decay {
            deque.pop_front();
        }
        let span = span.as_secs_f64();
        if span <= 0.0 {
            0.0
        } else {
            (n + usize::from(preemptive)) as f64 / span
        }
    }

    /// Incoming announce frequency in Hz
    /// (Python `Interface.incoming_announce_frequency`).
    pub fn incoming_announce_frequency(&mut self, now: Instant) -> f64 {
        Self::frequency(
            &mut self.ia_freq_deque,
            AR_FREQ_DECAY,
            DEQUE_MIN_SAMPLE,
            now,
            false,
        )
    }

    /// Outgoing announce frequency in Hz.
    pub fn outgoing_announce_frequency(&mut self, now: Instant) -> f64 {
        Self::frequency(&mut self.oa_freq_deque, AR_FREQ_DECAY, 1, now, false)
    }

    /// Incoming path-request frequency in Hz
    /// (Python `Interface.incoming_pr_frequency`).
    pub fn incoming_pr_frequency(&mut self, now: Instant) -> f64 {
        Self::frequency(
            &mut self.ip_freq_deque,
            PR_FREQ_DECAY,
            DEQUE_MIN_SAMPLE,
            now,
            false,
        )
    }

    /// Outgoing path-request frequency in Hz.
    pub fn outgoing_pr_frequency(&mut self, now: Instant) -> f64 {
        Self::frequency(&mut self.op_freq_deque, PR_FREQ_DECAY, 1, now, false)
    }

    // ------------------------------------------------------------------
    // Ingress limiting (Python `should_ingress_limit`,
    // `should_ingress_limit_pr`, `hold_announce`, `process_held_announces`).
    // ------------------------------------------------------------------

    /// Whether announces should currently be ingress limited.
    pub fn should_ingress_limit(&mut self, now: Instant) -> bool {
        if !self.ingress_control || !self.announce_ingress_limit {
            return false;
        }

        let freq_threshold = if self.age(now) < self.params.ic_new_time {
            self.params.ic_burst_freq_new
        } else {
            self.params.ic_burst_freq
        };
        let ia_freq = self.incoming_announce_frequency(now);

        if self.ic_burst_active {
            let hold_elapsed = now > self.ic_burst_activated + self.params.ic_burst_hold
                && now > self.ic_burst_sustained + self.params.ic_burst_hold;
            if ia_freq < freq_threshold && hold_elapsed {
                if self.ia_freq_deque.len() >= DEQUE_MIN_SAMPLE {
                    self.ic_burst_active = false;
                }
            } else if ia_freq >= freq_threshold {
                self.ic_burst_sustained = now;
            }
            true
        } else if ia_freq > freq_threshold {
            self.ic_burst_active = true;
            self.ic_burst_activated = now;
            self.ic_burst_sustained = now;
            self.ic_held_release = now + self.params.ic_burst_penalty;
            true
        } else {
            false
        }
    }

    /// Whether path requests should currently be ingress limited
    /// (Python `should_ingress_limit_pr`).
    pub fn should_ingress_limit_pr(&mut self, now: Instant) -> bool {
        if !self.ingress_control {
            return false;
        }

        let freq_threshold = if self.age(now) < self.params.ic_new_time {
            self.params.ic_pr_burst_freq_new
        } else {
            self.params.ic_pr_burst_freq
        };
        let ip_freq = self.incoming_pr_frequency(now);

        if self.ic_pr_burst_active {
            let hold_elapsed = now > self.ic_pr_burst_activated + self.params.ic_burst_hold
                && now > self.ic_pr_burst_sustained + self.params.ic_burst_hold;
            if ip_freq < freq_threshold && hold_elapsed {
                if self.ic_pr_burst_cooldown == 0 {
                    self.ic_pr_burst_active = false;
                } else {
                    self.ic_pr_burst_cooldown -= 1;
                }
            } else {
                self.ic_pr_burst_cooldown = IC_PR_BURST_COOLDOWN;
                if ip_freq >= freq_threshold {
                    self.ic_pr_burst_sustained = now;
                }
            }
            true
        } else if ip_freq > freq_threshold {
            self.ic_pr_burst_active = true;
            self.ic_pr_burst_activated = now;
            self.ic_pr_burst_sustained = now;
            self.ic_pr_burst_cooldown = IC_PR_BURST_COOLDOWN;
            true
        } else {
            false
        }
    }

    /// Whether outgoing path requests should be egress limited
    /// (Python `should_egress_limit_pr`).
    pub fn should_egress_limit_pr(&mut self, now: Instant) -> bool {
        if !self.egress_control {
            return false;
        }

        // Frequency is sampled first: it may drop a stale deque entry
        // before the minimum-sample check, matching Python.
        // `preemptive` counts the path request about to be sent.
        let op_freq = Self::frequency(&mut self.op_freq_deque, PR_FREQ_DECAY, 1, now, true);
        op_freq > self.params.ec_pr_freq && self.op_freq_deque.len() >= EC_BURST_MIN_SAMPLES
    }

    /// Hold an announce due to active ingress limiting
    /// (Python `Interface.hold_announce`).
    pub fn hold_announce(&mut self, packet: &Packet, max_hops: u8) {
        if packet.header.hops >= max_hops.saturating_sub(1) {
            return;
        }

        // Replacing an existing entry always succeeds; new entries are
        // bounded by `ic_max_held_announces`.
        if !self.held_announces.contains_key(&packet.destination)
            && self.held_announces.len() >= self.params.ic_max_held_announces
        {
            return;
        }

        self.held_announces.insert(packet.destination, packet.clone());
    }

    /// Release one held announce if the interface is currently able to
    /// process it (Python `Interface.process_held_announces`): releases at
    /// most one announce per `ic_held_release_interval` once the incoming
    /// announce frequency is back under the burst threshold, preferring
    /// announces with the lowest hop count.
    pub fn release_held_announce(&mut self, now: Instant) -> Option<Packet> {
        if self.held_announces.is_empty() || now <= self.ic_held_release {
            return None;
        }

        let freq_threshold = if self.age(now) < self.params.ic_new_time {
            self.params.ic_burst_freq_new
        } else {
            self.params.ic_burst_freq
        };
        if self.incoming_announce_frequency(now) >= freq_threshold {
            return None;
        }

        let selected = self
            .held_announces
            .iter()
            .min_by_key(|(_, packet)| packet.header.hops)
            .map(|(destination, _)| *destination)?;

        self.ic_held_release = now + self.params.ic_held_release_interval;
        self.held_announces.remove(&selected)
    }

    /// Number of currently held announces.
    pub fn held_announces_len(&self) -> usize {
        self.held_announces.len()
    }

    // ------------------------------------------------------------------
    // Egress airtime budgeting (Python outbound announce handling and
    // `Interface.process_announce_queue`).
    // ------------------------------------------------------------------

    /// Wait time imposed by the announce cap for a packet of `size` bytes
    /// (Python: `wait_time = (tx_time / announce_cap)`).
    fn cap_wait_time(&self, size: usize) -> Duration {
        if self.bitrate == 0 {
            return Duration::ZERO;
        }
        let tx_time = (size as f64 * 8.0) / self.bitrate as f64;
        let wait = tx_time / self.announce_cap.max(f64::MIN_POSITIVE);
        Duration::from_secs_f64(wait.max(0.0))
    }

    /// Whether the interface may transmit an announce of `size` bytes right
    /// now. Returns `true` when transmission is allowed (updating the
    /// airtime budget), `false` when it should be queued.
    pub fn try_transmit_announce(&mut self, size: usize, now: Instant) -> bool {
        if !self.announce_queue.is_empty() || self.bitrate == 0 || self.announce_cap <= 0.0 {
            return false;
        }

        if now >= self.announce_allowed_at {
            self.announce_allowed_at = now + self.cap_wait_time(size);
            true
        } else {
            false
        }
    }

    /// Queue an announce for later transmission
    /// (Python `interface.announce_queue.append`): deduplicates by
    /// destination, preferring the most recently emitted announce, and
    /// bounds the queue length.
    pub fn queue_announce(&mut self, packet: Packet, now: Instant) {
        if packet.header.packet_type != PacketType::Announce {
            return;
        }

        let destination = packet.destination;
        let emitted = announce_emitted(&packet);

        if let Some(entry) = self
            .announce_queue
            .iter_mut()
            .find(|entry| entry.packet.destination == destination)
        {
            if emitted > entry.emitted {
                entry.queued_at = now;
                entry.emitted = emitted;
                entry.packet = packet;
            }
            return;
        }

        if self.announce_queue.len() >= MAX_QUEUED_ANNOUNCES {
            return;
        }

        self.announce_queue.push(QueuedAnnounce {
            packet,
            queued_at: now,
            emitted,
        });
    }

    /// Take the next queued announce for transmission if the airtime budget
    /// allows it (Python `Interface.process_announce_queue`): drops stale
    /// entries, selects the entry with the lowest hop count (oldest first)
    /// and reserves the airtime for it.
    pub fn take_queued_announce(&mut self, now: Instant) -> Option<Packet> {
        self.announce_queue
            .retain(|entry| !queued_is_stale(entry, now));

        let selected = self
            .announce_queue
            .iter()
            .enumerate()
            .min_by_key(|(index, entry)| (entry.packet.header.hops, *index))
            .map(|(index, _)| index)?;

        let entry = self.announce_queue.remove(selected);

        let wait_time = self.cap_wait_time(packet_wire_len(&entry.packet));
        self.announce_allowed_at = now + wait_time;

        Some(entry.packet)
    }

    /// Duration until the next queued announce can be transmitted
    /// (used by the transport ticker to sleep efficiently).
    pub fn queued_announce_wait(&self, now: Instant) -> Option<Duration> {
        if self.announce_queue.is_empty() {
            return None;
        }
        Some(self.announce_allowed_at.saturating_duration_since(now))
    }

    /// Number of queued announces.
    pub fn queued_announces_len(&self) -> usize {
        self.announce_queue.len()
    }

    /// Drop every queued announce (Python `Transport.drop_announce_queues`).
    pub fn clear_announce_queue(&mut self) {
        self.announce_queue.clear();
    }
}

/// Feed a new-interface announce burst and hold the next announce when
/// `should_ingress_limit` says so. Returns how many announces were held.
///
/// Ten samples over half a second, scored one second after the first, is
/// above `ic_burst_freq_new` (3 Hz) for a generic interface.
#[cfg(test)]
pub(crate) fn hold_announce_burst(state: &mut IfaceControlState, t0: Instant) -> usize {
    for i in 0..10 {
        state.received_announce(t0 + Duration::from_millis(50 * i));
    }
    let now = t0 + Duration::from_secs(1);
    if state.should_ingress_limit(now) {
        let mut packet = Packet::default();
        packet.header.hops = 1;
        state.hold_announce(&packet, 128);
    }
    state.held_announces_len()
}

// ---------------------------------------------------------------------------
// Tests: timing simulations of the Python control loops.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{
        DestinationType, Header, HeaderType, IfacFlag, PacketContext, PacketDataBuffer,
        PropagationType,
    };

    fn announce_packet(hops: u8, destination: [u8; 16], emitted: u64) -> Packet {
        // announce data: pub key || verifying key || name hash || random
        // blob || signature [|| app data]
        let mut data = PacketDataBuffer::new();
        data.safe_write(&[1u8; crate::identity::PUBLIC_KEY_LENGTH]);
        data.safe_write(&[2u8; crate::identity::PUBLIC_KEY_LENGTH]);
        data.safe_write(&[3u8; crate::destination::NAME_HASH_LENGTH]);
        // random blob: 5 random bytes + 5 byte emission timestamp
        data.safe_write(&[0u8; 5]);
        data.safe_write(&emitted.to_be_bytes()[3..8]);
        data.safe_write(&[4u8; 64]);

        Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                context_flag: false,
                header_type: HeaderType::Type2,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops,
            },
            ifac: None,
            destination: AddressHash::new(destination),
            transport: None,
            context: PacketContext::None,
            data,
        }
    }

    #[test]
    fn ingress_burst_activates_and_holds() {
        let t0 = Instant::now();
        let mut state = IfaceControlState::new(t0);

        // No samples yet: never limited.
        assert!(!state.should_ingress_limit(t0));

        // Simulate a burst: > 3 announces/second right after creation.
        for i in 0..10 {
            state.received_announce(t0 + Duration::from_millis(50 * i));
        }

        assert!(state.should_ingress_limit(t0 + Duration::from_secs(1)));

        let packet = announce_packet(1, [7; 16], 100);
        state.hold_announce(&packet, 128);
        assert_eq!(state.held_announces_len(), 1);

        // Held announces are not released while the burst penalty is active.
        assert!(state
            .release_held_announce(t0 + Duration::from_secs(2))
            .is_none());
    }

    #[test]
    fn disabled_announce_ingress_limit_does_not_hold_burst() {
        let t0 = Instant::now();
        let mut state = IfaceControlState::new(t0);
        state.set_announce_ingress_limit(false);
        assert_eq!(super::hold_announce_burst(&mut state, t0), 0);

        // The same burst is held when the override is left at the default.
        let mut generic = IfaceControlState::new(t0);
        assert!(super::hold_announce_burst(&mut generic, t0) > 0);
    }

    #[test]
    fn held_announces_release_after_burst() {
        let t0 = Instant::now();
        let mut state = IfaceControlState::new(t0);

        // An old interface (past ic_new_time) with threshold 10 Hz.
        let later = t0 + Duration::from_secs(3 * 60 * 60);
        for i in 0..12 {
            state.received_announce(later + Duration::from_millis(60 * i));
        }
        assert!(state.should_ingress_limit(later + Duration::from_secs(1)));

        state.hold_announce(&announce_packet(2, [9; 16], 1), 128);
        state.hold_announce(&announce_packet(5, [8; 16], 1), 128);

        // After the burst hold window with no new announces, one held
        // announce (lowest hops) is released per release interval.
        let release_at = later + Duration::from_secs(60);
        let released = state
            .release_held_announce(release_at)
            .expect("held release");
        assert_eq!(released.header.hops, 2);

        // Not immediately again: release interval gates.
        assert!(state.release_held_announce(release_at).is_none());
        let second = state
            .release_held_announce(release_at + Duration::from_secs(6))
            .expect("second release");
        assert_eq!(second.header.hops, 5);
    }

    #[test]
    fn announce_cap_defers_and_queues() {
        let t0 = Instant::now();
        let mut state = IfaceControlState::new(t0);
        // A slow radio bitrate makes the announce cap bite.
        state.bitrate = 1200;

        let packet = announce_packet(1, [1; 16], 100);
        let size = packet_wire_len(&packet);
        assert!(size > 0);

        assert!(state.try_transmit_announce(size, t0));
        // Budget spent: the next announce must be queued.
        assert!(!state.try_transmit_announce(size, t0 + Duration::from_millis(1)));
        state.queue_announce(packet.clone(), t0 + Duration::from_millis(1));
        assert_eq!(state.queued_announces_len(), 1);

        // After the wait time has elapsed the queued announce is released.
        let wait = state
            .queued_announce_wait(t0 + Duration::from_millis(1))
            .unwrap();
        let taken = state
            .take_queued_announce(t0 + Duration::from_millis(1) + wait)
            .expect("queued announce released");
        assert_eq!(taken.destination, packet.destination);
    }

    #[test]
    fn announce_cap_fraction_waits_tx_time_over_point_zero_two() {
        let t0 = Instant::now();
        let mut state = IfaceControlState::new(t0);
        assert_eq!(state.bitrate, 62_500);
        assert_eq!(state.announce_cap, 0.02);

        let packet = announce_packet(1, [2; 16], 100);
        let size = packet_wire_len(&packet);
        assert!(size > 0);

        let tx_time = (size as f64 * 8.0) / 62_500.0;
        let expected = Duration::from_secs_f64(tx_time / 0.02);
        // The old integer cap (2.0) made this wait ~100× too short.
        let integer_cap_wait = Duration::from_secs_f64(tx_time / 2.0);
        assert!(expected > integer_cap_wait * 50);

        assert!(state.try_transmit_announce(size, t0));
        let early = expected.saturating_sub(Duration::from_millis(1));
        assert!(early > Duration::ZERO);
        assert!(!state.try_transmit_announce(size, t0 + early));
        assert!(state.try_transmit_announce(size, t0 + expected));
    }

    #[test]
    fn ingress_burst_extends_while_sustained() {
        let t0 = Instant::now();
        let mut state = IfaceControlState::new(t0);
        // Past `ic_new_time`, so the steady threshold (10 Hz) applies.
        let origin = t0 + Duration::from_secs(3 * 60 * 60);

        for i in 0..12 {
            state.received_announce(origin + Duration::from_millis(50 * i));
        }
        let activated = origin + Duration::from_millis(50 * 11);
        assert!(state.should_ingress_limit(activated));

        // Another burst before the hold expires refreshes `ic_burst_sustained`.
        let sustain = activated + Duration::from_secs(10);
        for i in 0..48 {
            state.received_announce(sustain + Duration::from_millis(10 * i));
        }
        let sustained_at = sustain + Duration::from_millis(10 * 47);
        assert!(state.should_ingress_limit(sustained_at));

        // Original activation hold has elapsed, but the sustained stamp has not.
        let still = activated + Duration::from_secs(16);
        assert!(state.should_ingress_limit(still));
        assert!(state.should_ingress_limit(still + Duration::from_millis(1)));

        // Once the sustained hold elapses and the rate is quiet, the next
        // call clears the burst (this call still reports limited).
        let quiet = sustained_at + Duration::from_secs(16);
        assert!(state.should_ingress_limit(quiet));
        assert!(!state.should_ingress_limit(quiet + Duration::from_millis(1)));
    }

    #[test]
    fn queued_announces_dedupe_keeps_newest_emitted() {
        let t0 = Instant::now();
        let mut state = IfaceControlState::new(t0);

        let older = announce_packet(1, [4; 16], 1);
        let newer = announce_packet(3, [4; 16], 2);

        state.queue_announce(older, t0);
        state.queue_announce(newer, t0 + Duration::from_secs(1));
        assert_eq!(state.queued_announces_len(), 1);

        let taken = state
            .take_queued_announce(t0 + Duration::from_secs(2))
            .unwrap();
        assert_eq!(announce_emitted(&taken), 2);
    }

    #[test]
    fn queued_announces_prefer_lowest_hops() {
        let t0 = Instant::now();
        let mut state = IfaceControlState::new(t0);

        state.queue_announce(announce_packet(4, [5; 16], 1), t0);
        state.queue_announce(announce_packet(2, [6; 16], 1), t0 + Duration::from_secs(1));
        state.queue_announce(announce_packet(2, [7; 16], 1), t0 + Duration::from_secs(2));

        let taken = state
            .take_queued_announce(t0 + Duration::from_secs(3))
            .unwrap();
        // Equal hops: oldest entry first.
        assert_eq!(taken.destination.as_slice(), &[6u8; 16]);
    }

    #[test]
    fn path_request_burst_limiting() {
        let t0 = Instant::now();
        let mut state = IfaceControlState::new(t0);
        assert!(!state.should_ingress_limit_pr(t0));

        for i in 0..10 {
            state.received_path_request(t0 + Duration::from_millis(30 * i));
        }
        assert!(state.should_ingress_limit_pr(t0 + Duration::from_secs(1)));

        // Egress control is off by default.
        assert!(!state.should_egress_limit_pr(t0 + Duration::from_secs(1)));

        state.egress_control = true;
        for i in 0..10 {
            state.sent_path_request(t0 + Duration::from_secs(2) + Duration::from_millis(10 * i));
        }
        assert!(state.should_egress_limit_pr(t0 + Duration::from_secs(3)));
    }

    #[test]
    fn egress_limit_requires_two_samples() {
        let t0 = Instant::now();
        let mut state = IfaceControlState::new(t0);
        state.egress_control = true;

        // One sample is below `EC_BURST_MIN_SAMPLES` (and the frequency floor).
        state.sent_path_request(t0);
        assert!(!state.should_egress_limit_pr(t0 + Duration::from_millis(10)));

        // Two closely spaced samples are enough. The previous constant of 6
        // would still refuse to limit here.
        state.sent_path_request(t0 + Duration::from_millis(10));
        assert!(state.should_egress_limit_pr(t0 + Duration::from_millis(20)));
    }

    #[test]
    fn path_request_burst_cooldown_counts_down_from_three() {
        let t0 = Instant::now();
        let mut state = IfaceControlState::new(t0);
        let origin = t0 + Duration::from_secs(3 * 60 * 60);

        for i in 0..12 {
            state.received_path_request(origin + Duration::from_millis(40 * i));
        }
        let activated = origin + Duration::from_millis(40 * 11);
        assert!(state.should_ingress_limit_pr(activated));

        // Hold has elapsed and the rate is quiet. Cooldown starts at 3, so
        // three quiet calls decrement it and the fourth clears the burst.
        // Each of those calls still reports limited; the following one does not.
        let quiet = activated + Duration::from_secs(20);
        for step in 0..4 {
            assert!(
                state.should_ingress_limit_pr(quiet + Duration::from_millis(step)),
                "quiet call {step} must stay limited while cooldown drains"
            );
        }
        assert!(!state.should_ingress_limit_pr(quiet + Duration::from_millis(4)));
    }

    #[test]
    fn mode_parsing() {
        assert_eq!(
            InterfaceMode::from_name("roaming"),
            Some(InterfaceMode::Roaming)
        );
        assert_eq!(
            InterfaceMode::from_name("access_point"),
            Some(InterfaceMode::AccessPoint)
        );
        assert_eq!(InterfaceMode::from_u8(0x06), Some(InterfaceMode::Gateway));
        assert_eq!(InterfaceMode::from_name("nope"), None);
        assert!(InterfaceMode::DISCOVER_PATHS_FOR.contains(&InterfaceMode::Roaming));
        assert!(!InterfaceMode::DISCOVER_PATHS_FOR.contains(&InterfaceMode::Boundary));
        assert!(InterfaceMode::BOUNDARY_SEARCH_MODES.contains(&InterfaceMode::Gateway));
    }
}
