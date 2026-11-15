//! Criterion benchmarks for transport hot paths (Phase 9.3).

use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::OsRng;

use reticulum::destination::{DestinationAnnounce, DestinationName, SingleInputDestination};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::ifac::IfacKey;
use reticulum::packet::Packet;

fn announce_packet() -> Packet {
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let mut destination =
        SingleInputDestination::new(identity, DestinationName::new("bench", "announce"));

    destination
        .announce(OsRng, Some(b"benchmark app data"))
        .expect("announce")
}

fn bench_announce_validation(c: &mut Criterion) {
    let announce = announce_packet();

    c.bench_function("announce/validate", |b| {
        b.iter(|| DestinationAnnounce::validate(&announce).is_ok())
    });
}

fn bench_ifac_wrap_unwrap(c: &mut Criterion) {
    let key =
        IfacKey::derive(Some("bench-network"), Some("bench-passphrase"), 8).expect("valid IFAC");
    let raw: Vec<u8> = (0..500u16).map(|i| (i % 256) as u8).collect();

    c.bench_function("ifac/wrap-500b", |b| b.iter(|| key.apply(&raw)));

    let wrapped = key.apply(&raw);
    c.bench_function("ifac/unwrap-500b", |b| {
        b.iter(|| key.strip(&wrapped).is_some())
    });
}

fn bench_packet_serialize(c: &mut Criterion) {
    let packet = announce_packet();

    c.bench_function("packet/serialize", |b| {
        b.iter(|| {
            let mut buffer = [0u8; 2048 + 128];
            let mut output = reticulum::buffer::OutputBuffer::new(&mut buffer);
            use reticulum::serde::Serialize;
            packet.serialize(&mut output).is_ok()
        })
    });
}

fn bench_announce_emitted(c: &mut Criterion) {
    let packet = announce_packet();

    c.bench_function("announce/emitted", |b| {
        b.iter(|| reticulum::iface::control::announce_emitted(&packet))
    });
}

fn bench_hdlc_framing(c: &mut Criterion) {
    let data: Vec<u8> = (0..500u16).map(|i| (i % 256) as u8).collect();

    c.bench_function("hdlc/frame-500b", |b| {
        b.iter(|| reticulum::iface::hdlc::Hdlc::encode_frame_vec(&data))
    });
}

criterion_group!(
    benches,
    bench_announce_validation,
    bench_ifac_wrap_unwrap,
    bench_packet_serialize,
    bench_announce_emitted,
    bench_hdlc_framing,
);
criterion_main!(benches);
