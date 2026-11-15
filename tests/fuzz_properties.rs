//! Decoder robustness property tests (Phase 9.2): the same invariants as
//! the cargo-fuzz targets in `fuzz/fuzz_targets/`, runnable on stable in
//! the normal test suite with deterministic pseudo-random corpora.

use rand_core::OsRng;

use reticulum::buffer::InputBuffer;
use reticulum::destination::{DestinationAnnounce, DestinationName, SingleInputDestination};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::hdlc::HdlcDecoder;
use reticulum::iface::ifac::IfacKey;
use reticulum::packet::{
    DestinationType, Header, HeaderType, IfacFlag, Packet, PacketContext, PacketDataBuffer,
    PacketType, PropagationType,
};

/// Simple xorshift corpus generator (deterministic per seed).
struct Corpus(u64);

impl Corpus {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next_u64() >> 24) as u8).collect()
    }
}

#[test]
fn packet_deserialize_never_panics() {
    let mut corpus = Corpus(0x5eed);

    for len in [0, 1, 2, 3, 5, 16, 17, 32, 35, 64, 500, 2048, 4096] {
        for _ in 0..32 {
            let data = corpus.bytes(len);
            let mut input = InputBuffer::new(&data);
            let _ = Packet::deserialize(&mut input);
        }
    }
}

#[test]
fn announce_validation_never_panics() {
    let mut corpus = Corpus(0xfeed);

    for _ in 0..256 {
        let len = (corpus.next_u64() % 300) as usize;
        let data = corpus.bytes(len);

        let mut buffer = PacketDataBuffer::new();
        buffer.safe_write(&data);

        let packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                context_flag: corpus.next_u64() & 1 == 1,
                header_type: HeaderType::Type2,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: (corpus.next_u64() % 8) as u8,
            },
            ifac: None,
            destination: AddressHash::new_from_slice(&corpus.bytes(16)),
            transport: None,
            context: PacketContext::None,
            data: buffer,
        };

        let _ = DestinationAnnounce::validate(&packet);
    }
}

#[test]
fn valid_announce_survives_random_context() {
    // A real announce must validate regardless of surrounding randomness
    // (regression guard against over-strict parsing).
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let mut destination =
        SingleInputDestination::new(identity, DestinationName::new("prop", "announce"));
    let announce = destination
        .announce(OsRng, Some(b"app data"))
        .expect("announce");

    assert!(DestinationAnnounce::validate(&announce).is_ok());
}

#[test]
fn tunnel_synthesis_decode_never_panics() {
    let mut corpus = Corpus(0xdead);

    for len in [0, 1, 16, 100, 175, 176, 177, 200, 500] {
        for _ in 0..16 {
            let data = corpus.bytes(len);
            let _ = reticulum::transport::decode_tunnel_synthesis(&data);
        }
    }
}

#[test]
fn ifac_strip_never_panics() {
    let key = IfacKey::derive(Some("fuzz"), Some("net"), 8).expect("valid IFAC");
    let mut corpus = Corpus(0xbeef);

    for _ in 0..256 {
        let len = (corpus.next_u64() % 128) as usize;
        let data = corpus.bytes(len);
        let _ = key.strip(&data);
    }
}

#[test]
fn hdlc_decode_never_panics() {
    let mut corpus = Corpus(0xcafe);

    for _ in 0..128 {
        let len = (corpus.next_u64() % 1024) as usize;
        let data = corpus.bytes(len);
        let mut decoder = HdlcDecoder::new(2048);
        decoder.feed(&data, |_frame| {});
    }
}
