//! Performance guards for the actor hot paths:
//! * `dispatch` throughput (the App command channel),
//! * audio bridge read/write latency (the platform callback boundary).

use std::sync::Arc;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};

use reticulum_actor::types::{Action, AudioBridge, Update};
use reticulum_actor::App;

struct NullAudioBridge;

impl AudioBridge for NullAudioBridge {
    fn read_frames(&self, _codec: &str, _max_frames: u32) -> Vec<Vec<u8>> {
        Vec::new()
    }

    fn write_frames(&self, _codec: &str, frames: Vec<Vec<u8>>) {
        std::hint::black_box(frames);
    }
}

fn bench_dispatch(c: &mut Criterion) {
    let dir = format!("/tmp/reticulum-actor-bench-{}", std::process::id());
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create bench dir");

    let (app, rx) = App::new(dir);
    app.dispatch(Action::Start {
        transport_enabled: false,
        identity_address: None,
    });
    wait_running(&rx);

    let mut group = c.benchmark_group("dispatch");
    group.throughput(criterion::Throughput::Elements(1));
    group.sample_size(50);

    group.bench_function("get_capabilities", |b| {
        b.iter(|| {
            app.dispatch(Action::GetCapabilities);
        })
    });

    // Drain the update queue so queued work does not pile up across runs.
    while rx.try_recv().is_ok() {}
    app.dispatch(Action::Stop);
    group.finish();
}

fn bench_state_snapshot(c: &mut Criterion) {
    let dir = format!("/tmp/reticulum-actor-bench-state-{}", std::process::id());
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create bench dir");

    let (app, rx) = App::new(dir);
    app.dispatch(Action::Start {
        transport_enabled: false,
        identity_address: None,
    });
    wait_running(&rx);

    let mut group = c.benchmark_group("state");
    group.sample_size(50);
    group.bench_function("state_snapshot", |b| b.iter(|| app.state()));

    app.dispatch(Action::Stop);
    group.finish();
}

fn bench_audio_bridge_latency(c: &mut Criterion) {
    let bridge = Arc::new(NullAudioBridge);
    let frame = vec![0u8; 256];

    let mut group = c.benchmark_group("audio_bridge");
    group.measurement_time(Duration::from_secs(3));

    group.bench_function("read_frames", |b| b.iter(|| bridge.read_frames("raw", 16)));
    group.bench_function("write_frames", |b| {
        b.iter(|| bridge.write_frames("raw", vec![frame.clone()]))
    });
    group.finish();
}

fn wait_running(rx: &flume::Receiver<Update>) {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Update::NodeStatus(reticulum_actor::types::NodeStatus::Running { .. })) => return,
            Ok(_) => continue,
            Err(flume::RecvTimeoutError::Timeout) => continue,
            Err(flume::RecvTimeoutError::Disconnected) => panic!("actor channel closed"),
        }
    }
    panic!("actor did not start");
}

criterion_group!(
    benches,
    bench_dispatch,
    bench_state_snapshot,
    bench_audio_bridge_latency
);
criterion_main!(benches);
