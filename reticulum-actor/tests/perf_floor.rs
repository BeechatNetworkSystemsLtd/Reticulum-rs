//! Performance regression floors for the actor hot paths.
//!
//! Criterion benchmarks (see `benches/actor.rs`) are for local,
//! same-machine comparisons; CI machines vary too much for cross-machine
//! baselines. These absolute floors fail loudly when hot paths regress by
//! an order of magnitude, with generous margins for slow runners.

use std::sync::Arc;
use std::time::{Duration, Instant};

use reticulum_actor::types::{Action, AudioBridge, NodeStatus, Update};
use reticulum_actor::App;

struct NullAudioBridge;

impl AudioBridge for NullAudioBridge {
    fn read_frames(&self, _codec: &str, _max_frames: u32) -> Vec<Vec<u8>> {
        Vec::new()
    }

    fn write_frames(&self, _codec: &str, _frames: Vec<Vec<u8>>) {}
}

fn temp_dir(tag: &str) -> String {
    let dir = format!("/tmp/reticulum-actor-perf-{tag}-{}", std::process::id());
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn wait_running(rx: &flume::Receiver<Update>) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Update::NodeStatus(NodeStatus::Running { .. })) => return,
            Ok(_) => continue,
            Err(flume::RecvTimeoutError::Timeout) => continue,
            Err(flume::RecvTimeoutError::Disconnected) => panic!("actor channel closed"),
        }
    }
    panic!("actor did not start");
}

/// The dispatch path (channel send + actor processing + full-state emit)
/// must sustain well above interactive rates; 10k ops/s leaves two orders
/// of magnitude headroom over what the current implementation achieves.
#[test]
fn dispatch_throughput_floor() {
    let (app, rx) = App::new(temp_dir("dispatch"));
    app.dispatch(Action::Start {
        transport_enabled: false,
        identity_address: None,
    });
    wait_running(&rx);

    // A trivial action isolates the dispatch loop itself (channel send,
    // actor turn, full-state snapshot emit) from payload costs like key
    // generation.
    let started = Instant::now();
    let ops = 20_000;
    for _ in 0..ops {
        app.dispatch(Action::GetCapabilities);
    }
    // Wait until the actor catches up: its rev counter advances once per
    // processed message.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let state = app.state();
        if state.rev >= ops as u64 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "actor did not process dispatches"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let elapsed = started.elapsed();
    let throughput = ops as f64 / elapsed.as_secs_f64();
    eprintln!("dispatch throughput: {throughput:.0} ops/s");
    assert!(
        throughput >= 10_000.0,
        "dispatch throughput {throughput:.0} ops/s fell below the 10k ops/s floor"
    );

    app.dispatch(Action::Stop);
}

/// Platform audio callbacks must stay far below the 40-80 ms frame
/// exchange budget; the floor allows 1 ms per callback.
#[test]
fn audio_bridge_callback_latency_floor() {
    let bridge = Arc::new(NullAudioBridge);
    let frame = vec![0u8; 256];

    let iterations = 10_000;
    let started = Instant::now();
    for _ in 0..iterations {
        let frames = bridge.read_frames("raw", 16);
        bridge.write_frames("raw", frames);
        std::hint::black_box(&frame);
    }
    let per_call = started.elapsed() / iterations;
    eprintln!("audio round-trip per callback: {per_call:?}");
    assert!(
        per_call < Duration::from_millis(1),
        "audio bridge round-trip {per_call:?} exceeded the 1 ms floor"
    );
}
